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
use common::tokio::time::Instant;
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
#[cfg(not(test))]
const V2_TRANSPORT_TIMEOUT: Duration = Duration::from_secs(30);
/// Shortened under test, the way the version handshake's deadline is, so the
/// stalled-handshake cases do not take half a minute each.
#[cfg(test)]
const V2_TRANSPORT_TIMEOUT: Duration = Duration::from_secs(2);

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
                    let result = disconnected_result(setup, uptime, reason, &end);
                    let outcome = session_outcome(&end, uptime.as_secs() as u32);
                    user_agent = end.user_agent;
                    (
                        outcome,
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
    end: &crate::protocol::SessionEnd,
) -> common::events::connection_result::Result {
    common::events::connection_result::Result::Disconnected(
        common::events::connection_result::Disconnected {
            setup_ms: setup.as_millis() as u64,
            uptime_ms: uptime.as_millis() as u64,
            reason: reason.into(),
            messages_by_command: end.messages_by_command.clone().into_iter().collect(),
            messages_other: end.messages_other,
            unsolicited_pongs: end.unsolicited_pongs,
            undecodable: end.undecodable,
            getheaders_ignored: end.getheaders_ignored,
        },
    )
}

/// How the address book should judge a session that ran to its end.
///
/// Two of the three are verdicts on the peer rather than on the address, and
/// neither is a disconnect to judge by its length: a peer on another chain was
/// hung up on by us, and one that broke the protocol has earned a wait that
/// has nothing to do with how long it managed to stay up.
fn session_outcome(end: &crate::protocol::SessionEnd, uptime_secs: u32) -> Outcome {
    let err = end.error.as_ref();
    if err.is_some_and(|e| crate::protocol::other_chain_of(e).is_some()) {
        return Outcome::OtherChain;
    }
    if err.is_some_and(is_violation) {
        return Outcome::Violated;
    }
    Outcome::Disconnected {
        uptime_secs,
        // The handshake completed, so this is known -- and the result event is
        // the only event a session that sent nothing else produces.
        silent: end.silent(),
    }
}

/// Whether the error that ended a session was the peer breaking the protocol.
///
/// Strictly what the protocol forbids: a header declaring a payload above the
/// message limit, and an INV above the item limit. Deliberately not a decode
/// failure, which is as likely to be a message we have not learned to read as
/// one the peer invented -- the observer counts those and reads on, which is
/// the whole stance of the tool -- and not a ping timeout either, which is a
/// peer gone quiet rather than a peer in the wrong.
fn is_violation(err: &anyhow::Error) -> bool {
    matches!(crate::transport::fault_of(err), Some(Fault::Oversized))
        || err
            .downcast_ref::<crate::protocol::ProtocolViolation>()
            .is_some()
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

    // Our own verdict, not a transport failure: we hung up because the peer
    // is following a chain we refuse.
    if crate::protocol::other_chain_of(err).is_some() {
        return R::OtherChain;
    }

    if let Some(fault) = crate::transport::fault_of(err) {
        return match fault {
            Fault::PeerClosed => R::PeerClosed,
            Fault::Truncated => R::Truncated,
            Fault::Decode => R::DecodeError,
            Fault::Oversized => R::OversizedMessage,
            Fault::WrongMagic => R::WrongMagic,
            Fault::V2Decrypt => R::V2DecryptError,
            Fault::Write => R::WriteError,
        };
    }

    // Our own deadline rather than anything the transport saw, so it is read
    // from the type the message loop ended with.
    if err.downcast_ref::<crate::protocol::PingTimeout>().is_some() {
        return R::PingTimeout;
    }
    if err
        .downcast_ref::<crate::protocol::ProtocolViolation>()
        .is_some()
    {
        return R::ProtocolViolation;
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
        // Unreachable: both of these are sessions that ran, and a session has
        // its own constructor above.
        Outcome::OtherChain | Outcome::Violated | Outcome::Disconnected { .. } => {
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
    async move {
        // The manager is not dialling yet, but the session still reports
        // itself connected, and only an Ended releases that. Without one the
        // seed stayed "connected" for the life of the process and was never
        // dialled again once it had served the sync.
        let guard = addrman.end_guard(addr);
        match connect_and_run(id, &dial, cfg, addrman).await {
            Ok((_, end)) => {
                // A bootstrap peer on another chain, or one that breaks the
                // protocol, is no more use for the sync than for anything
                // else, and is judged the same way.
                let uptime_secs = end.connected_at.elapsed().as_secs() as u32;
                guard.finish(session_outcome(&end, uptime_secs));
                Ok(end.connected_at)
            }
            Err(e) => {
                guard.finish(classify(&e, addr.net()));
                Err(e)
            }
        }
    }
    .instrument(span)
    .await
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
        .map_err(|e| anyhow::Error::new(e).context(Stage::ProxyAddrInvalid))
        .with_context(|| format!("proxy_addr {:?}", cfg.networks.tor.proxy_addr))?;

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
        TransportV2Reader::new(pr),
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
        TransportV1Reader::new(BufReader::new(reader), cfg.magic),
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
    /// The configured Tor proxy address is not a socket address, so there is
    /// no proxy to reach.
    ProxyAddrInvalid,
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
            Stage::ProxyAddrInvalid => "configured Tor SOCKS5 proxy address is not an address",
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
        Some(Stage::ProxyAddrInvalid) => {
            // A proxy address we cannot parse is a mistake in our config, and
            // it fails every onion dial. Reported as an unreachable proxy
            // because that is what it is from here: there is no proxy to try.
            return Outcome::OurFault(OurFault::ProxyUnreachable);
        }
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
///
/// A stalled BIP324 handshake is the one timeout this excludes: it can only
/// happen once TCP is up, so the peer was reached and the v1 fallback is
/// exactly what it is for. A version handshake that stalled stays in, for the
/// opposite reason -- the BIP324 transport came up, so the peer does speak v2
/// and v1 would be a step backwards.
fn is_tcp_level(err: &anyhow::Error) -> bool {
    if matches!(stage_of(err), Some(Stage::V2TransportTimeout)) {
        return false;
    }
    has_kind(err, std::io::ErrorKind::ConnectionRefused)
        || has_kind(err, std::io::ErrorKind::NetworkUnreachable)
        || has_kind(err, std::io::ErrorKind::HostUnreachable)
        || is_timed_out(err)
}

/// Whether the attempt ran out of time, wherever it had got to. Which of
/// those timeouts ends the attempt is [`is_tcp_level`]'s question, not this
/// one's.
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
    use crate::addresses::Lifecycle;
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
            connections: crate::connections::Registry::new(),
            magic: MAGIC,
            ping_interval: Duration::from_secs(120),
            user_agent: crate::protocol::USER_AGENT.to_owned(),
            event_tx,
            header_tree: Arc::new(RwLock::new(HeaderTree::new(Params::new(
                common::bitcoin::Network::Regtest,
            )))),
            sync_headers: false,
            probe_compact_blocks: false,
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
            let mut r = TransportV1Reader::new(BufReader::new(reader), Magic::REGTEST);
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
            let mut r = TransportV2Reader::new(pr);
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
            let mut r = TransportV1Reader::new(BufReader::new(reader), Magic::REGTEST);
            let mut w = TransportV1Writer {
                magic: MAGIC,
                writer,
            };
            server_handshake(&mut r, &mut w).await;
            // Answer pings for as long as the client is there, rather than
            // answering one and dropping the socket. With the interval at
            // fifty milliseconds the session can write its next ping before
            // the pong is read, and a peer that has gone turns that write
            // into an error: the session then ends with WriteError and never
            // emits the measurement this test is about. Slow execution makes
            // that the usual outcome rather than the rare one, which is how
            // coverage instrumentation found it.
            while let Ok(msg) = r.recv().await {
                if let NetworkMessage::Ping(nonce) = msg
                    && w.send(NetworkMessage::Pong(nonce)).await.is_err()
                {
                    return;
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
        // The server now outlives the measurement by design, so it is stopped
        // rather than waited for.
        server.abort();
    }

    /// A peer that accepts the connection and then never speaks must not hold
    /// the task open. TCP_USER_TIMEOUT does not help: it only aborts
    /// connections with unacknowledged data, and this peer acknowledges ours.
    /// The seed serves the sync and must then be dialled like any other
    /// address, which takes an Ended reaching the manager. There was none.
    #[tokio::test]
    async fn test_bootstrap_releases_the_seed() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        // Bootstrap dials with the transport unknown, so v2 goes first and
        // the v1 retry is the session. A v2 opener is a random key that by
        // design never begins with the v1 magic: hang up on it at once rather
        // than leave the client waiting out its transport timeout.
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(async move {
                    use common::tokio::io::AsyncReadExt as _;
                    let (mut reader, writer) = stream.into_split();
                    let mut magic = [0u8; 4];
                    if reader.read_exact(&mut magic).await.is_err() || magic != MAGIC.to_bytes() {
                        return;
                    }
                    let reader = std::io::Cursor::new(magic.to_vec()).chain(reader);
                    let mut r = TransportV1Reader::new(BufReader::new(reader), Magic::REGTEST);
                    let mut w = TransportV1Writer {
                        magic: MAGIC,
                        writer,
                    };
                    server_handshake(&mut r, &mut w).await;
                });
            }
        });

        let (event_tx, _events) = mpsc::channel(16);
        let cfg = test_config(event_tx);
        let (handle, _g, mut life_rx, _c) = crate::addresses::channels();
        let addr = PeerAddr::Ipv4([127, 0, 0, 1], listen_addr.port());

        let result = common::tokio::time::timeout(
            Duration::from_secs(5),
            bootstrap_attempt(addr, &cfg, &handle),
        )
        .await
        .expect("bootstrap timed out");
        assert!(result.is_ok(), "bootstrap failed: {result:?}");

        // What the session told the manager: Connected, and then the Ended
        // that releases it -- the message that used to be missing.
        let mut connected = false;
        let mut ended = false;
        while let Ok(msg) = life_rx.try_recv() {
            match msg {
                Lifecycle::Connected { addr: a, .. } if a == addr => connected = true,
                Lifecycle::Ended {
                    addr: a,
                    outcome: Outcome::Disconnected { .. },
                } if a == addr => ended = true,
                _ => {}
            }
        }
        assert!(connected, "the sync session should have reported connected");
        assert!(ended, "the seed was never released");
    }

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

    /// A peer that completed TCP and then never answered the BIP324 opener
    /// still gets its v1 attempt.
    ///
    /// The stall is no evidence about the transport: the peer was reached,
    /// which is the whole condition for the fallback, and it may well answer a
    /// v1 version message. Without the attempt nothing ever settles the hint,
    /// so it stays `Unknown` and every later dial spends the transport timeout
    /// over again -- the address is then effectively unreachable for good.
    #[tokio::test]
    async fn test_a_stalled_v2_handshake_still_tries_v1() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();

        // Accepts both attempts -- the v2 opener and then the v1 version --
        // and answers neither. Both are held open, because a close would be an
        // EOF rather than the stall this is about.
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            let (second, _) = listener.accept().await.unwrap();
            tokio::time::sleep(Duration::from_secs(60)).await;
            drop(first);
            drop(second);
        });

        let (event_tx, _event_rx) = mpsc::channel(1);
        let (handle, _g, mut life_rx, _c) = crate::addresses::channels();
        let addr = PeerAddr::Ipv4([127, 0, 0, 1], listen_addr.port());
        let dial = Dial {
            addr,
            transport: TransportHint::Unknown,
        };

        let err = connect_and_run(0, &dial, &test_config(event_tx), &handle)
            .await
            .expect_err("a silent peer must not yield a session");
        // The v1 attempt ran and reached its own deadline, so what comes out
        // is the version handshake's timeout rather than the transport's.
        assert_eq!(
            classify(&err, Net::Ipv4),
            Outcome::Failed(Reason::VersionHandshakeTimeout),
            "the v1 fallback should have run: {err:#}"
        );
        // And the verdict was filed before the retry, so later dials skip v2
        // instead of stalling again.
        let mut v1_only = false;
        while let Ok(msg) = life_rx.try_recv() {
            if matches!(msg, Lifecycle::V1Only { addr: a } if a == addr) {
                v1_only = true;
            }
        }
        assert!(v1_only, "the v2 stall was never recorded as v1-only");
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
    /// Our own verdict on the peer's chain, which is neither a transport
    /// fault nor an io error, and must not be read as one.
    #[test]
    fn test_session_end_reads_the_other_chain_verdict() {
        use crate::headertree::HeaderError;
        use crate::protocol::OtherChain;
        use common::events::DisconnectReason as R;

        let err = anyhow::Error::new(OtherChain {
            reason: HeaderError::ForkBelowCheckpoint,
        })
        .context("handling headers");
        assert_eq!(classify_session_end(Some(&err)), R::OtherChain);

        // And an ordinary close is still an ordinary close.
        let closed = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            .context(Fault::PeerClosed);
        assert_eq!(classify_session_end(Some(&closed)), R::PeerClosed);
    }

    /// The address book backs a peer off for breaking the protocol, so what
    /// counts as breaking it has to be exactly the two limits and not every
    /// unhappy ending.
    #[test]
    fn test_only_a_broken_limit_is_a_violation() {
        let oversized = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::InvalidData))
            .context(Fault::Oversized)
            .context("v1 header read");
        assert!(is_violation(&oversized));

        let inv = anyhow::Error::new(crate::protocol::ProtocolViolation(
            "inv of 50001 items".to_owned(),
        ))
        .context("handling inv");
        assert!(is_violation(&inv));

        // A message we could not read may be one we never learned to read, so
        // it is counted and read past rather than held against the peer.
        let undecodable = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::InvalidData))
            .context(Fault::Decode);
        assert!(!is_violation(&undecodable));

        // Gone quiet is not the same as in the wrong.
        let quiet = anyhow::Error::new(crate::protocol::PingTimeout {
            waited: std::time::Duration::from_secs(20 * 60),
        });
        assert!(!is_violation(&quiet));

        let closed = anyhow::Error::new(std::io::Error::from(std::io::ErrorKind::UnexpectedEof))
            .context(Fault::PeerClosed);
        assert!(!is_violation(&closed));
    }

    #[test]
    fn test_session_end_reads_the_tagged_fault() {
        use common::events::DisconnectReason as R;

        for (fault, expected) in [
            (Fault::PeerClosed, R::PeerClosed),
            (Fault::Truncated, R::Truncated),
            (Fault::Decode, R::DecodeError),
            (Fault::Oversized, R::OversizedMessage),
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

    /// The socket options are applied, not merely attempted.
    ///
    /// `configure_stream` could return `Ok` having done nothing and no test
    /// noticed. Neither option is visible afterwards and both matter: nodelay
    /// decides whether a ping waits on the kernel for an ACK, and
    /// TCP_USER_TIMEOUT is the only thing that ends a connection whose peer
    /// has stopped acknowledging -- the handshake timeouts are long gone by
    /// then, and a peer that acknowledges and then says nothing is the ping
    /// deadline's business instead.
    ///
    /// Nodelay is asserted off first, so the test shows the call changed it
    /// rather than agreeing with the default.
    #[tokio::test]
    async fn test_the_socket_options_are_applied() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept = tokio::spawn(async move { listener.accept().await.unwrap() });
        let stream = common::tokio::net::TcpStream::connect(addr).await.unwrap();
        let _server = accept.await.unwrap();

        assert!(
            !stream.nodelay().unwrap(),
            "nodelay is off until something sets it"
        );
        configure_stream(&stream).unwrap();
        assert!(stream.nodelay().unwrap(), "nodelay was not set");

        #[cfg(target_os = "linux")]
        {
            use std::os::unix::io::AsRawFd;
            let mut ms: u32 = 0;
            let mut len = std::mem::size_of::<u32>() as libc::socklen_t;
            let ret = unsafe {
                libc::getsockopt(
                    stream.as_raw_fd(),
                    libc::IPPROTO_TCP,
                    libc::TCP_USER_TIMEOUT,
                    &mut ms as *mut _ as *mut libc::c_void,
                    &mut len,
                )
            };
            assert_eq!(ret, 0, "getsockopt: {}", std::io::Error::last_os_error());
            assert_eq!(
                ms, 30_000,
                "TCP_USER_TIMEOUT is what bounds a connection whose peer has gone"
            );
        }
    }

    /// Every TCP-level failure is recognised as one, whichever it was.
    ///
    /// This decides whether a failed v2 attempt is retried over v1. A TCP
    /// failure says nothing about which transport the peer speaks, so the
    /// attempt ends there -- and if one were not recognised, the fallback
    /// would run `addrman.v1_only(addr)` first, writing a permanent v1-only
    /// verdict about a peer we never reached. A transient network failure
    /// would cost that address its chance at v2 for good. The line is drawn at
    /// "was the peer reached", which is why a stalled BIP324 handshake is on
    /// the other side of it despite being a timeout.
    ///
    /// The chain is four `or`s and only the first was tested, so each of the
    /// others could have been an `and` -- which, over mutually exclusive error
    /// kinds, means always false.
    #[test]
    fn test_every_tcp_level_failure_is_recognised() {
        for kind in [
            std::io::ErrorKind::ConnectionRefused,
            std::io::ErrorKind::NetworkUnreachable,
            std::io::ErrorKind::HostUnreachable,
            std::io::ErrorKind::TimedOut,
        ] {
            let err = anyhow::Error::from(std::io::Error::from(kind)).context("TCP connect");
            assert!(is_tcp_level(&err), "{kind:?} is a TCP-level failure");
        }

        // And a timeout of our own, however it is expressed. The version
        // handshake's is here because the BIP324 transport came up first: the
        // peer speaks v2, so there is nothing for v1 to find out.
        for stage in [
            Stage::TcpConnectTimeout,
            Stage::TorProxyTimeout,
            Stage::VersionHandshakeTimeout,
        ] {
            let err = anyhow::Error::new(stage).context("dialling");
            assert!(is_tcp_level(&err), "{stage:?} is a timeout");
            assert!(is_timed_out(&err), "{stage:?} is a timeout");
        }

        // A stalled BIP324 handshake is a timeout too, but not one that ends
        // the attempt: it can only happen with TCP already up, so the peer was
        // reached and v1 is still worth asking.
        let stalled = anyhow::Error::new(Stage::V2TransportTimeout).context("dialling");
        assert!(is_timed_out(&stalled));
        assert!(
            !is_tcp_level(&stalled),
            "a stalled v2 handshake must leave the v1 fallback to run"
        );

        // What is not: a failure after the connection was up, which is the
        // case the v1 fallback exists for.
        for kind in [
            std::io::ErrorKind::UnexpectedEof,
            std::io::ErrorKind::InvalidData,
            std::io::ErrorKind::ConnectionReset,
        ] {
            let err = anyhow::Error::from(std::io::Error::from(kind)).context("v2 handshake");
            assert!(
                !is_tcp_level(&err),
                "{kind:?} happened after the connection was up"
            );
        }
    }

    /// Every shape of a connection going away under us reads as a reset.
    ///
    /// Three error kinds mean it, joined by `or`s, and only the first was
    /// tested -- so the other two could have fallen through to `OTHER`, which
    /// is the field an operator reads to tell a peer hanging up from a network
    /// that broke.
    #[test]
    fn test_every_reset_shaped_end_reads_as_a_reset() {
        use common::events::DisconnectReason as R;
        for kind in [
            std::io::ErrorKind::ConnectionReset,
            std::io::ErrorKind::BrokenPipe,
            std::io::ErrorKind::ConnectionAborted,
        ] {
            let err = anyhow::Error::from(std::io::Error::from(kind));
            assert_eq!(
                classify_session_end(Some(&err)),
                R::ConnectionReset,
                "{kind:?}"
            );
        }
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

    /// A proxy address we cannot parse is our configuration, not the onion
    /// service's doing.
    ///
    /// One typo in `networks.tor.proxy_addr` fails every onion dial, and
    /// counting those as failures would back off and eventually drop every
    /// onion address in the book over a mistake of ours.
    #[test]
    fn test_an_unparseable_proxy_addr_is_our_fault() {
        let mut cfg = test_config(mpsc::channel(1).0);
        cfg.networks.tor.enabled = true;
        cfg.networks.tor.proxy_addr = "not-an-address".to_owned();
        let addr = PeerAddr::TorV3([7u8; 32], 8333);
        let err =
            futures_block_on(tor_connect(&addr, &cfg)).expect_err("the proxy address is not one");
        assert_eq!(
            classify(&err, Net::TorV3),
            Outcome::OurFault(OurFault::ProxyUnreachable)
        );
        assert!(!classify(&err, Net::TorV3).counts_as_failure());
    }

    /// Minimal blocking executor for the synchronous tests above.
    fn futures_block_on<F: std::future::Future>(fut: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(fut)
    }
}
