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

use crate::addrman::book::{Dial, TransportHint};
use crate::addrman::peer_addr::{Net, PeerAddr};
use crate::addrman::policy::{Outcome, Reason};
use crate::addrman::{Dialer, Handle};
use crate::protocol::{Config, Session, run_session};
use crate::transport::{
    TransportV1Reader, TransportV1Writer, TransportV2Reader, TransportV2Writer,
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
/// The [`EndGuard`](crate::addrman::EndGuard) is taken first and dropped last,
/// so the manager hears that the attempt is over even if this task panics or
/// is aborted. Without that the address would stay in the in-flight set
/// forever and never be dialled again.
pub(crate) async fn attempt(dial: Dial, cfg: Config, addrman: Handle) {
    let id = PEER_ID.fetch_add(1, Ordering::Relaxed);
    let span = tracing::info_span!(target: TARGET, "c", id, addr = %dial.addr);

    async move {
        let guard = addrman.end_guard(dial.addr);
        tracing::debug!(target: TARGET, transport = ?dial.transport, "attempting");

        match connect_and_run(id, &dial, &cfg, &addrman).await {
            Ok(connected_at) => {
                let uptime = connected_at.elapsed();
                tracing::debug!(target: TARGET, ?uptime, "session ended");
                guard.finish(Outcome::Disconnected {
                    uptime_secs: uptime.as_secs() as u32,
                });
            }
            Err(e) => {
                let outcome = classify(&e, dial.addr.net());
                tracing::debug!(target: TARGET, ?outcome, "attempt failed: {e:#}");
                guard.finish(outcome);
            }
        }
    }
    .instrument(span)
    .await
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
}

/// Connect with whichever transport the hint calls for, then run the session.
/// Returns the instant the handshake completed.
async fn connect_and_run(id: u64, dial: &Dial, cfg: &Config, addrman: &Handle) -> Result<Instant> {
    match dial.transport {
        // Known to speak v2. A failure is a failed attempt, never a reason to
        // fall back and conclude the peer lost the feature.
        TransportHint::V2 => connect_v2(id, dial, cfg, addrman).await,

        // v2 did not work last time. Skip straight to v1 and save a round trip.
        TransportHint::V1Only => connect_v1(id, dial, cfg, addrman).await,

        TransportHint::Unknown => {
            match connect_v2(id, dial, cfg, addrman).await {
                ok @ Ok(_) => ok,
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
                    connect_v1(id, dial, cfg, addrman).await
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
        anyhow::bail!("attempted to connect to a TorV3 address, but Tor is disabled");
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
    .context("Tor SOCKS5 connect timed out")?
    .context("Tor SOCKS5 connection")?;

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
        .context("TCP connect timed out")?
        .context("TCP connect")?;
    configure_stream(&stream)?;
    Ok(stream)
}

async fn tcp_connect(addr: &PeerAddr, cfg: &Config) -> Result<TcpStream> {
    match addr.net() {
        Net::TorV3 => tor_connect(addr, cfg).await,
        Net::Ipv4 | Net::Ipv6 | Net::Cjdns => ip_connect(addr).await,
        Net::I2p => anyhow::bail!("I2P is not supported yet"),
    }
}

async fn connect_v2(id: u64, dial: &Dial, cfg: &Config, addrman: &Handle) -> Result<Instant> {
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
    .context("BIP324 transport handshake timed out")?
    .context("BIP324 transport handshake")?;

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

async fn connect_v1(id: u64, dial: &Dial, cfg: &Config, addrman: &Handle) -> Result<Instant> {
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

/// Turn a failure into the outcome the manager should record.
///
/// The important distinction is `OurFault`. A missing route to a network, or a
/// Tor proxy that is not running, says nothing whatsoever about the peer, so
/// it must not count against the address. Running without IPv6 connectivity
/// would otherwise mark every IPv6 address we were ever told about as bad.
fn classify(err: &anyhow::Error, net: Net) -> Outcome {
    if has_kind(err, std::io::ErrorKind::NetworkUnreachable) {
        return Outcome::OurFault;
    }

    // A Tor address can only be reached through our proxy, so a failure to
    // reach the proxy itself is our problem, not the onion service's.
    if net == Net::TorV3 && is_proxy_failure(err) {
        return Outcome::OurFault;
    }

    if has_kind(err, std::io::ErrorKind::ConnectionRefused) {
        return Outcome::Failed(Reason::ConnectionRefused);
    }
    if has_kind(err, std::io::ErrorKind::HostUnreachable) {
        // Usually an ICMP unreachable from a router near the destination, so
        // this is evidence about the peer rather than about us.
        return Outcome::Failed(Reason::HostUnreachable);
    }
    if is_timed_out(err) {
        return Outcome::Failed(Reason::TimedOut);
    }
    if has_kind(err, std::io::ErrorKind::UnexpectedEof) {
        return Outcome::Failed(Reason::UnexpectedEof);
    }
    if mentions(err, "handshake") {
        return Outcome::Failed(Reason::HandshakeFailed);
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

fn is_proxy_failure(err: &anyhow::Error) -> bool {
    has_kind(err, std::io::ErrorKind::ConnectionRefused) || mentions(err, "SOCKS5")
}

fn is_timed_out(err: &anyhow::Error) -> bool {
    // One of our explicit tokio::time::timeout wrappers fired.
    if err.chain().any(|c| c.is::<tokio::time::error::Elapsed>()) {
        return true;
    }
    has_kind(err, std::io::ErrorKind::TimedOut)
}

fn has_kind(err: &anyhow::Error, kind: std::io::ErrorKind) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == kind)
    })
}

fn mentions(err: &anyhow::Error, needle: &str) -> bool {
    format!("{err:#}").contains(needle)
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
        let (handle, _g, _l, _c) = crate::addrman::channels();
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
        let (handle, _g, _l, _c) = crate::addrman::channels();
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

        let (handle, _g, _l, _c) = crate::addrman::channels();
        // V1Only, so the attempt goes straight to v1 and matches the v1-only
        // listener above, which accepts exactly once.
        let dial = Dial {
            addr: PeerAddr::Ipv4([127, 0, 0, 1], listen_addr.port()),
            transport: TransportHint::V1Only,
        };
        tokio::spawn(attempt(dial, cfg, handle));

        let event = common::tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("timed out waiting for a ping_rtt event")
            .expect("event channel closed");

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
        let (handle, _g, _l, _c) = crate::addrman::channels();
        let dial = Dial {
            addr: PeerAddr::Ipv4([127, 0, 0, 1], listen_addr.port()),
            transport: TransportHint::V1Only,
        };

        let err = connect_v1(0, &dial, &test_config(event_tx), &handle)
            .await
            .expect_err("a silent peer must not yield a session");
        assert!(is_timed_out(&err), "expected a timeout, got: {err:#}");
        assert_eq!(classify(&err, Net::Ipv4), Outcome::Failed(Reason::TimedOut));
        server.abort();
    }

    /// The attempt always reports back, so the manager can free the slot.
    #[tokio::test]
    async fn test_attempt_always_reports_an_outcome() {
        setup();
        // Nothing listening: the connection is refused immediately.
        let (event_tx, _event_rx) = mpsc::channel(1);
        let (handle, _g, mut life_rx, _c) = crate::addrman::channels();
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
            crate::addrman::Lifecycle::Ended { addr: got, outcome } => {
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
        assert_eq!(classify(&err, Net::Ipv6), Outcome::OurFault);
        assert!(!Outcome::OurFault.counts_as_failure());
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
        assert_eq!(classify(&err, Net::TorV3), Outcome::OurFault);
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

    #[test]
    fn test_handshake_failure_is_recognised() {
        let err = anyhow::anyhow!("boom").context("BIP324 transport handshake");
        assert_eq!(
            classify(&err, Net::Ipv4),
            Outcome::Failed(Reason::HandshakeFailed)
        );
        assert!(
            !is_tcp_level(&err),
            "a handshake failure should allow a v1 fallback"
        );
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
