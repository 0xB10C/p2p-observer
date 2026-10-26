//! One connection attempt.
//!
//! Single-shot by design: dial, handshake, run the session, report what
//! happened, exit. Nothing here decides when an address is tried again — all
//! retry and backoff timing lives in the address manager, which is the only
//! place that can see an address's whole history.
//!
//! The previous version carried its own retry loops (`initial_connect`,
//! `reconnect_loop`, two attempt counters and a doubling backoff) while the
//! address store separately had a one-hour retry for bad addresses. Two
//! schedules for the same decision meant some cases were handled twice and
//! others not at all.

use bip324::{Role, futures::Protocol};
use common::{
    anyhow::{self, Context, Result},
    tokio::{
        self,
        io::BufReader,
        net::TcpStream,
        time::{Duration, timeout},
    },
    tracing,
    tracing::Instrument,
};
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;

use crate::addresses::book::{Dial, TransportHint};
use crate::addresses::peer_addr::{Net, PeerAddr};
use crate::addresses::policy::{OurFault, Outcome, Reason};
use crate::addresses::{Dialer, Handle};
use crate::protocol::{Config, Session, SessionEnd, run_session};
use crate::transport::{
    Fault, TransportV1Reader, TransportV1Writer, TransportV2Reader, TransportV2Writer,
};

use crate::TARGET_CONNECTION as TARGET;

/// Timeout for TCP connection attempts. The OS default (several minutes with
/// SYN retransmits) is far too long when managing many connections.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Timeout for opening a connection through the Tor SOCKS5 proxy. Covers both
/// talking to the proxy and the circuit it builds, so it is more generous than
/// a direct TCP connect.
const TOR_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// Timeout for the BIP324 transport handshake, which runs before the version
/// handshake and is just as capable of stalling forever against a peer that
/// accepts the connection and then goes quiet.
const V2_TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);

static PEER_ID: AtomicU64 = AtomicU64::new(0);

/// Spawns one task per dial. This is the manager's only way of starting work,
/// and it is behind the [`Dialer`] trait so tests can drive the manager
/// without opening sockets.
pub(crate) struct TaskDialer {
    pub(crate) cfg: Config,
    pub(crate) addrman: Handle,
}

impl Dialer for TaskDialer {
    fn dial(&self, dial: Dial) {
        let cfg = self.cfg.clone();
        let addrman = self.addrman.clone();
        tokio::spawn(attempt(dial, cfg, addrman));
    }
}

/// Run one attempt and report the outcome.
///
/// The [`EndGuard`](crate::addresses::EndGuard) is taken first and dropped last,
/// so the manager hears that the attempt is over even if this task panics or
/// is aborted. Without that the address would stay in the in-flight set
/// forever and never be dialled again.
pub(crate) async fn attempt(dial: Dial, cfg: Config, addrman: Handle) {
    let id = PEER_ID.fetch_add(1, Ordering::Relaxed);
    let span = tracing::info_span!(target: TARGET, "c", id, addr = %dial.addr);

    async move {
        let guard = addrman.end_guard(dial.addr);
        tracing::debug!(target: TARGET, transport = ?dial.transport, "attempting");

        let started = Instant::now();
        let mut user_agent = String::new();
        let (outcome, transport_version, result) =
            match connect_and_run(id, &dial, &cfg, &addrman).await {
                Ok((version, end)) => {
                    let uptime = end.connected_at.elapsed();
                    let reason = classify_session_end(end.error.as_ref());
                    tracing::debug!(target: TARGET, ?uptime, ?reason, "session ended");
                    // Setup is everything before the handshake completed, the
                    // session is the rest. Reported separately so neither is
                    // hidden inside one "duration".
                    let setup = started.elapsed().saturating_sub(uptime);
                    let result = disconnected_result(setup, uptime, reason);
                    // The handshake completed, so this is known -- and the
                    // result event is the only event a session that sent
                    // nothing else produces.
                    user_agent = end.user_agent;
                    (
                        Outcome::Disconnected {
                            uptime_secs: uptime.as_secs() as u32,
                        },
                        // The session ran, so the transport is settled whatever
                        // the hint said going in.
                        Some(u32::from(version)),
                        result,
                    )
                }
                Err(e) => {
                    let outcome = classify(&e, dial.addr.net());
                    tracing::debug!(target: TARGET, ?outcome, "attempt failed: {e:#}");
                    // Only a hint that named a transport tells us what we tried.
                    // Still detecting means the attempt settled nothing.
                    let attempted = match dial.transport {
                        TransportHint::V2 => Some(2),
                        TransportHint::V1Only => Some(1),
                        TransportHint::Unknown => None,
                    };
                    (
                        outcome,
                        attempted,
                        failed_result(outcome, started.elapsed()),
                    )
                }
            };

        // One event per attempt whether or not it reached a session, so the
        // archive shows reachability over time rather than only the contacts
        // that happened to work.
        emit_result(&cfg, id, &dial, transport_version, &user_agent, result);
        guard.finish(outcome);
    }
    .instrument(span)
    .await
}

/// Publish the outcome of an attempt as a research event.
fn disconnected_result(
    setup: Duration,
    uptime: Duration,
    reason: common::events::DisconnectReason,
) -> common::events::connection_result::Result {
    common::events::connection_result::Result::Disconnected(
        common::events::connection_result::Disconnected {
            setup_ms: setup.as_millis() as u64,
            uptime_ms: uptime.as_millis() as u64,
            reason: reason.into(),
        },
    )
}

/// How a session that had started ended.
///
/// Reads the typed [`Fault`] the transport attached if there is one, and falls
/// back to the error kind. Both live here rather than at the point of failure
/// so that every error-to-event mapping is in one file, next to [`classify`].
fn classify_session_end(err: Option<&anyhow::Error>) -> common::events::DisconnectReason {
    use common::events::DisconnectReason as R;

    let Some(err) = err else {
        // The message loop has no path that returns without an error today, so
        // this is reserved for one being added and not thought about here.
        return R::Unknown;
    };

    if let Some(fault) = crate::transport::fault_of(err) {
        return match fault {
            Fault::PeerClosed => R::PeerClosed,
            Fault::Truncated => R::Truncated,
            Fault::Decode => R::DecodeError,
            Fault::V2Decrypt => R::V2DecryptError,
            Fault::Write => R::WriteError,
        };
    }

    if has_kind(err, std::io::ErrorKind::ConnectionReset)
        || has_kind(err, std::io::ErrorKind::BrokenPipe)
        || has_kind(err, std::io::ErrorKind::ConnectionAborted)
    {
        return R::ConnectionReset;
    }
    // An EOF that reached here is one no transport tagged, so where in the
    // stream it landed is unknown; that it ended is not.
    if has_kind(err, std::io::ErrorKind::UnexpectedEof) {
        return R::PeerClosed;
    }
    R::Other
}

/// An attempt that never reached a session, as the oneof variant for it.
///
/// Splits on whether the failure was the peer's or ours, which is the
/// distinction the whole classification exists to make.
fn failed_result(outcome: Outcome, elapsed: Duration) -> common::events::connection_result::Result {
    use common::events::{FailureReason, OurFaultReason, connection_result};

    let setup_ms = elapsed.as_millis() as u64;
    match outcome {
        Outcome::OurFault(reason) => {
            connection_result::Result::OurFault(connection_result::OurFault {
                reason: match reason {
                    OurFault::NetworkUnreachable => OurFaultReason::NetworkUnreachable,
                    OurFault::ProxyUnreachable => OurFaultReason::ProxyUnreachable,
                    OurFault::NetworkDisabled => OurFaultReason::NetworkDisabled,
                }
                .into(),
                setup_ms,
            })
        }
        Outcome::Failed(reason) => connection_result::Result::Failed(connection_result::Failed {
            reason: match reason {
                Reason::ConnectionRefused => FailureReason::ConnectionRefused,
                Reason::HostUnreachable => FailureReason::HostUnreachable,
                Reason::TcpConnectTimeout => FailureReason::TcpConnectTimeout,
                Reason::V2TransportTimeout => FailureReason::V2TransportTimeout,
                Reason::VersionHandshakeTimeout => FailureReason::VersionHandshakeTimeout,
                Reason::V2TransportHandshake => FailureReason::V2TransportHandshake,
                Reason::VersionHandshake => FailureReason::VersionHandshake,
                Reason::UnexpectedEof => FailureReason::UnexpectedEof,
                Reason::Other => FailureReason::Other,
            }
            .into(),
            setup_ms,
        }),
        // Unreachable: a session has its own constructor above.
        Outcome::Disconnected { .. } => {
            connection_result::Result::Failed(connection_result::Failed {
                reason: FailureReason::Unknown.into(),
                setup_ms,
            })
        }
    }
}

/// Publish the outcome of an attempt as a research event.
fn emit_result(
    cfg: &Config,
    id: u64,
    dial: &Dial,
    transport_version: Option<u32>,
    user_agent: &str,
    result: common::events::connection_result::Result,
) {
    crate::emit::send(
        &cfg.event_tx,
        common::events::PeerEvent {
            timestamp_ms: unix_ms(),
            peer_addr: dial.addr.to_string(),
            // Empty on an attempt that never handshook, which is the only case
            // where it is genuinely unknown. A session that ran carries it,
            // because a short session may emit no other event to join against.
            user_agent: user_agent.to_owned(),
            transport_version,
            connection_id: id,
            event: Some(common::events::peer_event::Event::ConnectionResult(
                common::events::ConnectionResult {
                    result: Some(result),
                },
            )),
            ..Default::default()
        },
    );
}

fn unix_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// One attempt for the bootstrap header sync.
///
/// Separate from [`attempt`] because the caller has to see the error — a
/// finished sync is signalled by `SyncComplete` — and because bootstrap runs
/// before the manager is dialling, so there is no in-flight slot to release
/// and no outcome to record.
pub(crate) async fn bootstrap_attempt(
    addr: PeerAddr,
    cfg: &Config,
    addrman: &Handle,
) -> Result<Instant> {
    let id = PEER_ID.fetch_add(1, Ordering::Relaxed);
    let span = tracing::info_span!(target: TARGET, "boot", id, %addr);
    let dial = Dial {
        addr,
        transport: TransportHint::Unknown,
    };
    connect_and_run(id, &dial, cfg, addrman)
        .instrument(span)
        .await
        .map(|(_, end)| end.connected_at)
}

/// Connect with whichever transport the hint calls for, then run the session.
/// Returns the transport version that actually carried the session, and the
/// instant the handshake completed.
///
/// The version is returned rather than inferred from the hint by the caller:
/// a dial that starts out detecting resolves to v1 or v2 here, and the caller
/// has no other way to learn which.
async fn connect_and_run(
    id: u64,
    dial: &Dial,
    cfg: &Config,
    addrman: &Handle,
) -> Result<(u8, SessionEnd)> {
    match dial.transport {
        // Known to speak v2. A failure is a failed attempt, never a reason to
        // fall back and conclude the peer lost the feature.
        TransportHint::V2 => connect_v2(id, dial, cfg, addrman).await.map(|end| (2, end)),

        // v2 did not work last time. Skip straight to v1 and save a round trip.
        TransportHint::V1Only => connect_v1(id, dial, cfg, addrman).await.map(|end| (1, end)),

        // Detecting: we do not know yet what this peer speaks.
        TransportHint::Unknown => {
            match connect_v2(id, dial, cfg, addrman).await {
                Ok(end) => Ok((2, end)),
                Err(e) => {
                    // A TCP-level failure says nothing about which transport
                    // the peer speaks, so there is nothing to learn and
                    // nothing to retry differently.
                    if is_tcp_level(&e) {
                        return Err(e);
                    }
                    // The TCP connection worked and the v2 handshake did not.
                    // Record that before trying v1, so the knowledge survives
                    // even if v1 then fails for an unrelated reason.
                    tracing::trace!(target: TARGET, "v2 handshake failed, trying v1: {e:#}");
                    addrman.v1_only(dial.addr);
                    connect_v1(id, dial, cfg, addrman).await.map(|end| (1, end))
                }
            }
        }
    }
}

/// Apply socket options that matter for long-lived Bitcoin P2P connections.
fn configure_stream(stream: &TcpStream) -> Result<()> {
    // Disable Nagle's algorithm so every write goes on the wire immediately.
    // Without this the kernel buffers small messages until a full MSS
    // accumulates or an ACK arrives, adding invisible latency to pings and
    // request/response exchanges. It also avoids the Nagle+delayed-ACK
    // deadlock where two small back-to-back writes stall because each side
    // waits for the other.
    stream.set_nodelay(true).context("set_nodelay")?;

    // Cap how long the kernel will retransmit unacknowledged data before
    // aborting. The default is effectively unbounded: the OS can spend many
    // minutes retransmitting while the connection still looks alive to us, so
    // a crashed peer or a network partition would go undetected that whole
    // time. Thirty seconds rides out transient loss but notices real failures.
    //
    // Note this only fires when there is unacknowledged data. A peer that
    // acknowledges our bytes and then says nothing is caught by the handshake
    // timeouts instead.
    #[cfg(target_os = "linux")]
    {
        let timeout_ms: u32 = 30_000;
        let ret = unsafe {
            libc::setsockopt(
                stream.as_raw_fd(),
                libc::IPPROTO_TCP,
                libc::TCP_USER_TIMEOUT,
                &timeout_ms as *const _ as *const libc::c_void,
                std::mem::size_of::<u32>() as libc::socklen_t,
            )
        };
        if ret != 0 {
            return Err(std::io::Error::last_os_error()).context("TCP_USER_TIMEOUT");
        }
    }

    Ok(())
}

async fn tor_connect(addr: &PeerAddr, cfg: &Config) -> Result<TcpStream> {
    if !cfg.networks.tor.enabled {
        return Err(Stage::NetworkDisabled)
            .context("attempted to connect to a TorV3 address, but Tor is disabled");
    }
    let proxy: std::net::SocketAddr = cfg
        .networks
        .tor
        .proxy_addr
        .parse()
        .context("invalid SOCKS5 proxy address")?;

    let target = addr.to_string();
    tracing::trace!(target: TARGET, %proxy, %target, "connecting via the Tor SOCKS5 proxy");
    let socks = timeout(
        TOR_CONNECT_TIMEOUT,
        tokio_socks::tcp::socks5::Socks5Stream::connect(proxy, target),
    )
    .await
    .map_err(|_| Stage::TorProxyTimeout)?
    .map_err(|e| anyhow::Error::new(e).context(Stage::ProxyUnreachable))?;

    let stream = socks.into_inner();
    configure_stream(&stream)?;
    Ok(stream)
}

async fn ip_connect(addr: &PeerAddr) -> Result<TcpStream> {
    let socket_addr = addr
        .socket_addr()
        .context("address has no socket address")?;
    let stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(socket_addr))
        .await
        .map_err(|_| Stage::TcpConnectTimeout)?
        .context("TCP connect")?;
    configure_stream(&stream)?;
    Ok(stream)
}

async fn tcp_connect(addr: &PeerAddr, cfg: &Config) -> Result<TcpStream> {
    match addr.net() {
        Net::TorV3 => tor_connect(addr, cfg).await,
        Net::Ipv4 | Net::Ipv6 | Net::Cjdns => ip_connect(addr).await,
        Net::I2p => Err(Stage::NetworkDisabled).context("I2P is not supported yet"),
    }
}

async fn connect_v2(id: u64, dial: &Dial, cfg: &Config, addrman: &Handle) -> Result<SessionEnd> {
    tracing::trace!(target: TARGET, "connecting (v2) ...");
    let stream = tcp_connect(&dial.addr, cfg).await?;
    let raw_fd = stream.as_raw_fd();
    let (reader, writer) = stream.into_split();

    let proto = timeout(
        V2_TRANSPORT_TIMEOUT,
        Protocol::new(
            cfg.magic,
            Role::Initiator,
            None,
            None,
            BufReader::new(reader),
            writer,
        ),
    )
    .await
    .map_err(|_| Stage::V2TransportTimeout)?
    .map_err(|e| anyhow::Error::new(e).context(Stage::V2TransportHandshake))?;

    let (pr, pw) = proto.into_split();
    run_session(
        TransportV2Reader { reader: pr },
        TransportV2Writer { writer: pw },
        Session {
            transport_version: 2,
            connection_id: id,
            addr: dial.addr,
            raw_fd,
            cfg,
            addrman,
        },
    )
    .await
}

async fn connect_v1(id: u64, dial: &Dial, cfg: &Config, addrman: &Handle) -> Result<SessionEnd> {
    tracing::trace!(target: TARGET, "connecting (v1) ...");
    let stream = tcp_connect(&dial.addr, cfg).await?;
    let raw_fd = stream.as_raw_fd();
    let (reader, writer) = stream.into_split();

    run_session(
        TransportV1Reader::new(BufReader::new(reader)),
        TransportV1Writer {
            magic: cfg.magic,
            writer,
        },
        Session {
            transport_version: 1,
            connection_id: id,
            addr: dial.addr,
            raw_fd,
            cfg,
            addrman,
        },
    )
    .await
}

// ── Error classification ─────────────────────────────────────────────────────

/// A failure at a point in the attempt worth telling apart from the others.
///
/// Returned as a typed error rather than recognised from the wording of a
/// context string: grepping prose for "handshake" worked, but it broke
/// silently the moment anyone reworded a message, and it could not separate
/// the two handshakes from each other.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Stage {
    /// Nothing answered the TCP connect.
    TcpConnectTimeout,
    /// The Tor SOCKS5 proxy, or the circuit it was building.
    TorProxyTimeout,
    /// TCP was up; the BIP324 handshake stalled.
    V2TransportTimeout,
    /// TCP and the transport were up; no version message followed.
    VersionHandshakeTimeout,
    /// The BIP324 handshake failed outright rather than stalling.
    V2TransportHandshake,
    /// The version handshake failed outright rather than stalling.
    VersionHandshake,
    /// The Tor proxy is not answering at all.
    ProxyUnreachable,
    /// This network is switched off in the config, or has no transport here.
    NetworkDisabled,
}

impl std::fmt::Display for Stage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Stage::TcpConnectTimeout => "TCP connect timed out",
            Stage::TorProxyTimeout => "Tor SOCKS5 connect timed out",
            Stage::V2TransportTimeout => "BIP324 transport handshake timed out",
            Stage::VersionHandshakeTimeout => "version handshake timed out",
            Stage::V2TransportHandshake => "BIP324 transport handshake failed",
            Stage::VersionHandshake => "version handshake failed",
            Stage::ProxyUnreachable => "Tor SOCKS5 proxy unreachable",
            Stage::NetworkDisabled => "network disabled or unsupported",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Stage {}

/// The stage a failure was tagged with, if any.
///
/// `downcast_ref` on the error rather than a walk over `chain()`: a context
/// value does not appear in the chain as itself, only as its `Display` text, so
/// a chain walk finds a `Stage` only when it happens to be the root error.
/// That is how this was written, and it meant the stages attached with
/// `.context(...)` -- the proxy and both handshakes -- were silently invisible
/// here while the timeout stages, which are root errors, worked.
fn stage_of(err: &anyhow::Error) -> Option<Stage> {
    err.downcast_ref::<Stage>().copied()
}

/// Turn a failure into the outcome the manager should record.
///
/// The important distinction is `OurFault`. A missing route to a network, or a
/// Tor proxy that is not running, says nothing whatsoever about the peer, so
/// it must not count against the address. Running without IPv6 connectivity
/// would otherwise mark every IPv6 address we were ever told about as bad.
fn classify(err: &anyhow::Error, net: Net) -> Outcome {
    if has_kind(err, std::io::ErrorKind::NetworkUnreachable) {
        return Outcome::OurFault(OurFault::NetworkUnreachable);
    }

    match stage_of(err) {
        Some(Stage::NetworkDisabled) => return Outcome::OurFault(OurFault::NetworkDisabled),
        Some(Stage::ProxyUnreachable) => return Outcome::OurFault(OurFault::ProxyUnreachable),
        Some(Stage::TorProxyTimeout) => {
            // The onion service is only reachable through our proxy, so a
            // proxy that will not answer is our problem, not the peer's.
            return Outcome::OurFault(OurFault::ProxyUnreachable);
        }
        Some(Stage::TcpConnectTimeout) => return Outcome::Failed(Reason::TcpConnectTimeout),
        Some(Stage::V2TransportTimeout) => return Outcome::Failed(Reason::V2TransportTimeout),
        Some(Stage::VersionHandshakeTimeout) => {
            return Outcome::Failed(Reason::VersionHandshakeTimeout);
        }
        Some(Stage::V2TransportHandshake) => return Outcome::Failed(Reason::V2TransportHandshake),
        Some(Stage::VersionHandshake) => return Outcome::Failed(Reason::VersionHandshake),
        None => {}
    }

    // A refused connection to an onion address means our proxy is not running.
    if net == Net::TorV3 && has_kind(err, std::io::ErrorKind::ConnectionRefused) {
        return Outcome::OurFault(OurFault::ProxyUnreachable);
    }

    if has_kind(err, std::io::ErrorKind::ConnectionRefused) {
        return Outcome::Failed(Reason::ConnectionRefused);
    }
    if has_kind(err, std::io::ErrorKind::HostUnreachable) {
        // Usually an ICMP unreachable from a router near the destination, so
        // this is evidence about the peer rather than about us.
        return Outcome::Failed(Reason::HostUnreachable);
    }
    if has_kind(err, std::io::ErrorKind::UnexpectedEof) {
        return Outcome::Failed(Reason::UnexpectedEof);
    }
    Outcome::Failed(Reason::Other)
}

/// TCP-level failures, where retrying with a different transport version
/// cannot help.
fn is_tcp_level(err: &anyhow::Error) -> bool {
    has_kind(err, std::io::ErrorKind::ConnectionRefused)
        || has_kind(err, std::io::ErrorKind::NetworkUnreachable)
        || has_kind(err, std::io::ErrorKind::HostUnreachable)
        || is_timed_out(err)
}

fn is_timed_out(err: &anyhow::Error) -> bool {
    if matches!(
        stage_of(err),
        Some(
            Stage::TcpConnectTimeout
                | Stage::TorProxyTimeout
                | Stage::V2TransportTimeout
                | Stage::VersionHandshakeTimeout
        )
    ) {
        return true;
    }
    // A tokio timeout we did not tag, or one from the OS.
    err.chain().any(|c| c.is::<tokio::time::error::Elapsed>())
        || has_kind(err, std::io::ErrorKind::TimedOut)
}

fn has_kind(err: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == kind)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::headertree::HeaderTree;
    use crate::protocol::build_version;
    use crate::transport::{TransportReader, TransportWriter};
    use common::p2p::{Magic, message::NetworkMessage};
    use common::{
        bitcoin::network::Params,
        tokio::{net::TcpListener, sync::mpsc},
        tracing_subscriber,
    };
    use std::sync::{Arc, RwLock};

    const MAGIC: Magic = Magic::REGTEST;

    fn setup() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .try_init();
    }

    fn test_config(event_tx: mpsc::Sender<common::events::PeerEvent>) -> Config {
        Config {
            magic: MAGIC,
            ping_interval: Duration::from_secs(120),
            user_agent: crate::protocol::USER_AGENT.to_owned(),
            event_tx,
            header_tree: Arc::new(RwLock::new(HeaderTree::new(Params::new(
                common::bitcoin::Network::Regtest,
            )))),
            sync_headers: false,
            networks: crate::settings::NetworksConfig::default(),
        }
    }

    /// Complete the server side of the version handshake.
    async fn server_handshake(
        reader: &mut impl TransportReader,
        writer: &mut impl TransportWriter,
    ) {
        loop {
            if let NetworkMessage::Version(_) = reader.recv().await.unwrap() {
                break;
            }
        }
        writer
            .send(build_version(crate::protocol::USER_AGENT, 0))
            .await
            .unwrap();
        writer.send(NetworkMessage::Verack).await.unwrap();
        loop {
            if let NetworkMessage::Verack = reader.recv().await.unwrap() {
                break;
            }
        }
        loop {
            if let NetworkMessage::SendCmpct(_) = reader.recv().await.unwrap() {
                break;
            }
        }
    }

    #[tokio::test]
    async fn test_v1_handshake_mock() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, writer) = stream.into_split();
            let mut r = TransportV1Reader::new(BufReader::new(reader));
            let mut w = TransportV1Writer {
                magic: MAGIC,
                writer,
            };
            server_handshake(&mut r, &mut w).await;
            // Drop -> EOF -> the client's message loop exits.
        });

        let (event_tx, _event_rx) = mpsc::channel(1);
        let (handle, _g, _l, _c) = crate::addresses::channels();
        let dial = Dial {
            addr: PeerAddr::Ipv4([127, 0, 0, 1], listen_addr.port()),
            transport: TransportHint::Unknown,
        };
        let result = connect_v1(0, &dial, &test_config(event_tx), &handle).await;
        server.await.unwrap();
        assert!(result.is_ok(), "connect_v1 failed: {result:?}");
    }

    #[tokio::test]
    async fn test_v2_handshake_mock() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, writer) = stream.into_split();
            let proto = Protocol::new(
                MAGIC,
                Role::Responder,
                None,
                None,
                BufReader::new(reader),
                writer,
            )
            .await
            .unwrap();
            let (pr, pw) = proto.into_split();
            let mut r = TransportV2Reader { reader: pr };
            let mut w = TransportV2Writer { writer: pw };
            server_handshake(&mut r, &mut w).await;
        });

        let (event_tx, _event_rx) = mpsc::channel(1);
        let (handle, _g, _l, _c) = crate::addresses::channels();
        let dial = Dial {
            addr: PeerAddr::Ipv4([127, 0, 0, 1], listen_addr.port()),
            transport: TransportHint::V2,
        };
        let result = connect_v2(0, &dial, &test_config(event_tx), &handle).await;
        server.await.unwrap();
        assert!(result.is_ok(), "connect_v2 failed: {result:?}");
    }

    #[tokio::test]
    async fn test_ping_rtt_event() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, writer) = stream.into_split();
            let mut r = TransportV1Reader::new(BufReader::new(reader));
            let mut w = TransportV1Writer {
                magic: MAGIC,
                writer,
            };
            server_handshake(&mut r, &mut w).await;
            // Respond to the first ping; ignore everything else.
            loop {
                if let NetworkMessage::Ping(nonce) = r.recv().await.unwrap() {
                    w.send(NetworkMessage::Pong(nonce)).await.unwrap();
                    break;
                }
            }
        });

        let (event_tx, mut event_rx) = mpsc::channel(4);
        let mut cfg = test_config(event_tx);
        cfg.ping_interval = Duration::from_millis(50);

        let (handle, _g, _l, _c) = crate::addresses::channels();
        // V1Only, so the attempt goes straight to v1 and matches the v1-only
        // listener above, which accepts exactly once.
        let dial = Dial {
            addr: PeerAddr::Ipv4([127, 0, 0, 1], listen_addr.port()),
            transport: TransportHint::V1Only,
        };
        tokio::spawn(attempt(dial, cfg, handle));

        let mut next = async || {
            common::tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
                .await
                .expect("timed out waiting for an event")
                .expect("event channel closed")
        };

        // The handshake event comes first, before anything the session goes on
        // to emit. That ordering is the point of it: it is what tells a reader
        // what this connection_id refers to.
        let event = next().await;
        let Some(common::events::peer_event::Event::Handshake(hs)) = event.event else {
            panic!("expected Handshake first, got: {:?}", event.event);
        };
        assert_eq!(hs.user_agent, crate::protocol::USER_AGENT);
        assert_eq!(hs.protocol_version, 70016);

        let event = next().await;
        assert!(
            matches!(
                event.event,
                Some(common::events::peer_event::Event::PingRtt(_))
            ),
            "expected PingRtt, got: {:?}",
            event.event,
        );
        server.await.unwrap();
    }

    /// A peer that accepts the connection and then never speaks must not hold
    /// the task open. TCP_USER_TIMEOUT does not help: it only aborts
    /// connections with unacknowledged data, and this peer acknowledges ours.
    #[tokio::test]
    async fn test_silent_peer_aborts_handshake() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(stream);
        });

        let (event_tx, _event_rx) = mpsc::channel(1);
        let (handle, _g, _l, _c) = crate::addresses::channels();
        let dial = Dial {
            addr: PeerAddr::Ipv4([127, 0, 0, 1], listen_addr.port()),
            transport: TransportHint::V1Only,
        };

        let err = connect_v1(0, &dial, &test_config(event_tx), &handle)
            .await
            .expect_err("a silent peer must not yield a session");
        assert!(is_timed_out(&err), "expected a timeout, got: {err:#}");
        // The peer completed TCP and then said nothing, which is the case the
        // split tells apart from a host that never answers at all.
        assert_eq!(
            classify(&err, Net::Ipv4),
            Outcome::Failed(Reason::VersionHandshakeTimeout)
        );
        server.abort();
    }

    /// The attempt always reports back, so the manager can free the slot.
    #[tokio::test]
    async fn test_attempt_always_reports_an_outcome() {
        setup();
        // Nothing listening: the connection is refused immediately.
        let (event_tx, _event_rx) = mpsc::channel(1);
        let (handle, _g, mut life_rx, _c) = crate::addresses::channels();
        let addr = PeerAddr::Ipv4([127, 0, 0, 1], 1);

        attempt(
            Dial {
                addr,
                transport: TransportHint::V1Only,
            },
            test_config(event_tx),
            handle,
        )
        .await;

        match life_rx.try_recv().expect("no outcome reported") {
            crate::addresses::Lifecycle::Ended { addr: got, outcome } => {
                assert_eq!(got, addr);
                assert!(outcome.counts_as_failure());
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_network_unreachable_is_our_fault_not_the_peers() {
        let err = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::NetworkUnreachable))
            .context("TCP connect");
        // Running without an IPv6 route must not mark every IPv6 address bad.
        assert_eq!(
            classify(&err, Net::Ipv6),
            Outcome::OurFault(OurFault::NetworkUnreachable)
        );
        assert!(!Outcome::OurFault(OurFault::NetworkUnreachable).counts_as_failure());
    }

    #[test]
    fn test_refused_is_the_peers_problem() {
        let err = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
            .context("TCP connect");
        assert_eq!(
            classify(&err, Net::Ipv4),
            Outcome::Failed(Reason::ConnectionRefused)
        );
        assert!(is_tcp_level(&err));
    }

    /// A refused connection to an onion address means our Tor proxy is not
    /// running, which is our problem rather than the onion service's.
    #[test]
    fn test_refused_proxy_is_our_fault_for_tor() {
        let err = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
            .context("Tor SOCKS5 connection");
        assert_eq!(
            classify(&err, Net::TorV3),
            Outcome::OurFault(OurFault::ProxyUnreachable)
        );
        // The same error for an IP peer is the peer's problem.
        assert_eq!(
            classify(&err, Net::Ipv4),
            Outcome::Failed(Reason::ConnectionRefused)
        );
    }

    #[test]
    fn test_unexpected_eof_and_other() {
        let eof = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        assert_eq!(
            classify(&eof, Net::Ipv4),
            Outcome::Failed(Reason::UnexpectedEof)
        );
        // Not TCP-level: worth trying the other transport version.
        assert!(!is_tcp_level(&eof));

        let other = anyhow::anyhow!("something else entirely");
        assert_eq!(classify(&other, Net::Ipv4), Outcome::Failed(Reason::Other));
    }

    /// Every fault the transport can tag maps to its own reason, so a clean
    /// close and a message we could not read are never the same record.
    #[test]
    fn test_session_end_reads_the_tagged_fault() {
        use common::events::DisconnectReason as R;

        for (fault, expected) in [
            (Fault::PeerClosed, R::PeerClosed),
            (Fault::Truncated, R::Truncated),
            (Fault::Decode, R::DecodeError),
            (Fault::V2Decrypt, R::V2DecryptError),
            (Fault::Write, R::WriteError),
        ] {
            // Wrapped the way the transport wraps it: an io error underneath,
            // the fault as context, and a prose context on top of that.
            let err = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
                .context(fault)
                .context("v1 header read");
            assert_eq!(classify_session_end(Some(&err)), expected, "{fault:?}");
        }
    }

    #[test]
    fn test_session_end_falls_back_to_the_error_kind() {
        use common::events::DisconnectReason as R;

        // Untagged, because it came from somewhere other than a transport read.
        let reset = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::ConnectionReset));
        assert_eq!(classify_session_end(Some(&reset)), R::ConnectionReset);

        // An EOF no transport tagged says the stream ended but not where.
        let eof = anyhow::Error::from(std::io::Error::from(std::io::ErrorKind::UnexpectedEof));
        assert_eq!(classify_session_end(Some(&eof)), R::PeerClosed);

        let other = anyhow::anyhow!("something else entirely");
        assert_eq!(classify_session_end(Some(&other)), R::Other);

        // No error at all is not "closed cleanly": it is a path that does not
        // exist yet, and saying PEER_CLOSED would invent an observation.
        assert_eq!(classify_session_end(None), R::Unknown);
    }

    /// Recognised from the typed stage, not from the wording of a message —
    /// the point of tagging failures rather than grepping them.
    #[test]
    fn test_handshake_failure_is_recognised() {
        let err = anyhow::Error::new(Stage::V2TransportHandshake).context("boom");
        assert_eq!(
            classify(&err, Net::Ipv4),
            Outcome::Failed(Reason::V2TransportHandshake)
        );
        assert!(
            !is_tcp_level(&err),
            "a handshake failure should allow a v1 fallback"
        );

        // The way the code actually attaches it: the stage is the context over
        // an underlying io error, not the root. This stayed untested, and the
        // chain walk stage_of used could not see it -- so every v2 handshake
        // failure, version handshake failure and unreachable proxy was
        // reported as something else.
        let as_context =
            anyhow::Error::new(std::io::Error::other("boom")).context(Stage::V2TransportHandshake);
        assert_eq!(
            classify(&as_context, Net::Ipv4),
            Outcome::Failed(Reason::V2TransportHandshake)
        );

        let version = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            .context(Stage::VersionHandshake);
        assert_eq!(
            classify(&version, Net::Ipv4),
            Outcome::Failed(Reason::VersionHandshake),
            "the stage outranks the EOF underneath it"
        );

        let proxy = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::ConnectionRefused))
            .context(Stage::ProxyUnreachable);
        assert_eq!(
            classify(&proxy, Net::TorV3),
            Outcome::OurFault(OurFault::ProxyUnreachable),
            "a refused proxy is ours, not the onion service's"
        );
    }

    /// The four timeouts are told apart, which a single TIMED_OUT could not do.
    #[test]
    fn test_timeouts_are_distinguished() {
        for (stage, want) in [
            (Stage::TcpConnectTimeout, Reason::TcpConnectTimeout),
            (Stage::V2TransportTimeout, Reason::V2TransportTimeout),
            (
                Stage::VersionHandshakeTimeout,
                Reason::VersionHandshakeTimeout,
            ),
        ] {
            let err = anyhow::Error::new(stage).context("dialling");
            assert_eq!(classify(&err, Net::Ipv4), Outcome::Failed(want));
            assert!(is_timed_out(&err), "{stage:?} should read as a timeout");
        }

        // A Tor proxy that will not answer is ours, not the peer's.
        let err = anyhow::Error::new(Stage::TorProxyTimeout).context("dialling");
        assert_eq!(
            classify(&err, Net::TorV3),
            Outcome::OurFault(OurFault::ProxyUnreachable)
        );
    }

    /// A network switched off in the config is our doing, not the address's.
    #[test]
    fn test_disabled_network_is_our_fault() {
        let err = anyhow::Error::new(Stage::NetworkDisabled).context("Tor is disabled");
        assert_eq!(
            classify(&err, Net::TorV3),
            Outcome::OurFault(OurFault::NetworkDisabled)
        );
        assert!(!classify(&err, Net::TorV3).counts_as_failure());
    }

    #[test]
    fn test_disabled_networks_are_not_dialled() {
        // Belt and braces: pick() filters these out, but a stale Dial must
        // not open a Tor connection when Tor is off.
        let cfg = test_config(mpsc::channel(1).0);
        assert!(!cfg.networks.tor.enabled);
        let addr = PeerAddr::TorV3([7u8; 32], 8333);
        let err = futures_block_on(tor_connect(&addr, &cfg)).expect_err("Tor is disabled");
        assert!(format!("{err:#}").contains("Tor is disabled"));
    }

    /// Minimal blocking executor for the one synchronous test above.
    fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }
}
