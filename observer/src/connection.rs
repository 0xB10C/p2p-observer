use bip324::{Role, futures::Protocol};
use common::{
    anyhow::{self, Context, Result},
    tokio::{
        self,
        io::BufReader,
        net::TcpStream,
        sync::mpsc,
        time::{Duration, sleep, timeout},
    },
    tracing,
    tracing::Instrument,
};
#[cfg(target_os = "linux")]
use libc;
use std::os::unix::io::AsRawFd;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::addresses::{BadReason, NetAddr, PeerAddr, StatusUpdate};
use crate::protocol::{Config, run_session};
use crate::transport::{
    TransportV1Reader, TransportV1Writer, TransportV2Reader, TransportV2Writer,
};
use common::p2p::ServiceFlags;

use crate::TARGET_CONNECTION as TARGET;

/// Initial wait before the first reconnect attempt after a failure.
/// Doubles on each consecutive failure, reset to this value after a successful connection.
const BACKOFF_BASE: Duration = Duration::from_secs(1);

/// Maximum number of attempts when connecting to a peer for the first time.
const MAX_INITIAL_ATTEMPTS: u32 = 2;
/// Maximum number of reconnect attempts after a peer we once successfully connected to drops us.
/// With BACKOFF_BASE doubling each attempt: 2s, 4s, 8s, 16s, 32s, 64s, 128s, 256s.
const MAX_RECONNECT_ATTEMPTS: u32 = 8;

/// Timeout for TCP connection attempts. The OS default (several minutes with SYN retransmits)
/// is far too long when managing many connections.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// A connection shorter than this is considered a likely eviction (peer is full).
const EVICTION_THRESHOLD: Duration = Duration::from_secs(31);
/// Minimum wait before retrying after a short-lived successful connection, to avoid
/// hammering a peer that is repeatedly evicting us.
const EVICTION_COOLDOWN: Duration = Duration::from_secs(60);

static PEER_ID: AtomicU64 = AtomicU64::new(0);

/// Per-peer connection state. Drives the full lifecycle for a single peer:
/// initial connect, message loop, and reconnect loop.
pub struct Connection {
    id: u64,
    cfg: Config,
    status_tx: mpsc::Sender<StatusUpdate>,
    new_addr_tx: mpsc::Sender<Vec<PeerAddr>>,
    peer: PeerAddr,
    /// Once we've connected via v2, never fall back to v1.
    skip_v1_fallback: bool,
}

/// Apply socket-level options that improve latency and reliability for
/// long-lived Bitcoin P2P connections.
fn configure_stream(stream: &TcpStream) -> Result<()> {
    // Disable Nagle's algorithm so every write goes on the wire immediately.
    // Without this the kernel buffers small messages until a full MSS
    // accumulates or an ACK arrives, adding invisible latency to pings and
    // request/response exchanges. It also avoids the Nagle+delayed-ACK
    // deadlock where two small back-to-back writes stall because each side
    // waits for the other.
    stream.set_nodelay(true).context("set_nodelay")?;

    // Cap how long the kernel will retransmit unacknowledged data before
    // aborting the connection. The default is unbounded — the OS can spend
    // many minutes retransmitting while the connection appears alive to us.
    // A dead peer (crashed node, network partition) would go undetected for
    // that entire window, stalling the reconnect loop. 30 seconds is long
    // enough to ride out transient packet loss but short enough to detect
    // real failures promptly.
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

impl Connection {
    pub fn new(
        cfg: Config,
        status_tx: mpsc::Sender<StatusUpdate>,
        new_addr_tx: mpsc::Sender<Vec<PeerAddr>>,
        peer: PeerAddr,
    ) -> Self {
        Self {
            id: PEER_ID.fetch_add(1, Ordering::Relaxed),
            cfg,
            status_tx,
            new_addr_tx,
            peer,
            skip_v1_fallback: false,
        }
    }

    pub async fn run(mut self) {
        let span = tracing::info_span!(target: TARGET, "c", id = self.id, addr = %self.peer.addr);
        async move {
            tracing::debug!(target: TARGET, "opening new connection");
            crate::ACTIVE_TASKS.fetch_add(1, Ordering::Relaxed);
            if self.initial_connect().await {
                // initial connection succeeded. Retry for a bit on the next connection drop.
                self.reconnect_loop().await;
            }
            crate::ACTIVE_TASKS.fetch_sub(1, Ordering::Relaxed);
        }
        .instrument(span)
        .await
    }

    /// Tries to connect for the first time, up to `MAX_INITIAL_ATTEMPTS` attempts.
    /// Hard errors (refused, unreachable) give up immediately.
    /// Returns true if we connected at least once (triggering the reconnect loop).
    async fn initial_connect(&mut self) -> bool {
        let mut backoff = BACKOFF_BASE;
        for attempt in 1..=MAX_INITIAL_ATTEMPTS {
            match self.try_connect().await {
                Ok(_) => return true,
                Err(e) => {
                    let bad = |reason| StatusUpdate::Bad {
                        addr: self.peer.addr.clone(),
                        at: unix_secs(),
                        reason,
                    };

                    if is_network_unreachable(&e) {
                        tracing::debug!(target: TARGET, "network unreachable");
                        let _ = self
                            .status_tx
                            .send(bad(BadReason::NetworkUnreachable))
                            .await;
                        return false;
                    }

                    if is_connection_refused(&e) {
                        tracing::debug!(target: TARGET, "connection refused");
                        let _ = self.status_tx.send(bad(BadReason::ConnectionRefused)).await;
                        return false;
                    }

                    if is_host_unreachable(&e) {
                        tracing::debug!(target: TARGET, "host unreachable");
                        let _ = self.status_tx.send(bad(BadReason::HostUnreachable)).await;
                        return false;
                    }

                    // Don't early exit for these:
                    if is_timed_out(&e) {
                        tracing::debug!(target: TARGET, "connection timed out");
                        let _ = self.status_tx.send(bad(BadReason::TimedOut)).await;
                    }

                    if is_unexpected_eof(&e) {
                        tracing::debug!(target: TARGET, "unexpected EOF");
                        let _ = self.status_tx.send(bad(BadReason::UnexpectedEOF)).await;
                    }

                    if attempt >= MAX_INITIAL_ATTEMPTS {
                        tracing::debug!(target: TARGET, attempt, error=%e, "initial connect failed, giving up");
                        return false;
                    }
                    backoff *= 2;
                    tracing::trace!(target: TARGET,
                        error = format!("{:#}", e),
                        "initial connect failed, retrying in {}s", backoff.as_secs()
                    );
                    sleep(backoff).await;
                }
            }
        }
        false
    }

    /// Reconnects to a peer we've previously connected to, up to `MAX_RECONNECT_ATTEMPTS` per drop.
    async fn reconnect_loop(&mut self) {
        let mut backoff = BACKOFF_BASE;
        let mut attempts = 0u32;

        loop {
            let result = self.try_connect().await;
            attempts += 1;
            backoff *= 2;

            match result {
                Ok(connected_at) => {
                    let _ = self
                        .status_tx
                        .send(StatusUpdate::Good {
                            addr: self.peer.addr.clone(),
                            at: unix_secs(),
                            services: None,
                        })
                        .await;
                    let uptime = connected_at.elapsed();

                    // Reset backoff if the connection was stable long enough.
                    if uptime > backoff {
                        backoff = BACKOFF_BASE;
                        attempts = 0;
                    }

                    let uptime_str = format!("{:?}", uptime);
                    if uptime < EVICTION_THRESHOLD {
                        tracing::debug!(target: TARGET,
                            "connection lost after only {uptime_str}. Cooling down for {}s",
                            EVICTION_COOLDOWN.as_secs(),
                        );
                        sleep(EVICTION_COOLDOWN).await;
                    }

                    let backoff_secs = backoff.as_secs();
                    tracing::warn!(target: TARGET,
                        "connection lost after {uptime_str}. reconnecting in {backoff_secs}s"
                    );
                }
                Err(e) => {
                    if is_network_unreachable(&e) {
                        tracing::debug!(target: TARGET, "network unreachable, stopping reconnect");
                        break;
                    }
                    let backoff_secs = backoff.as_secs();
                    tracing::trace!(target: TARGET,
                        error = format!("{:#}", e),
                        "re-connect failed; retrying in {backoff_secs}s (attempt={attempts})"
                    );
                }
            }

            if attempts >= MAX_RECONNECT_ATTEMPTS {
                tracing::debug!(target: TARGET, attempts, "giving up re-connect");
                break;
            }

            sleep(backoff).await;
        }
    }

    async fn tor_connect(&self) -> Result<TcpStream> {
        if self.cfg.tor.enabled {
            anyhow::bail!("attempted to connect to TorV3 address, but Tor is disabled");
        }
        // Connect via Tor SOCKS5 proxy
        let socks_addr: std::net::SocketAddr = self
            .cfg
            .tor
            .proxy_addr
            .parse()
            .context("invalid SOCKS5 proxy address")?;

        // Extract the stored onion address
        let target = if let NetAddr::TorV3(addr, port) = &self.peer.addr {
            format!("{}:{}", addr, port)
        } else {
            unreachable!("is_tor is true, so this must be TorV3")
        };

        tracing::trace!(target: TARGET, proxy=%socks_addr, %target, "connecting via Tor SOCKS5");
        let socks_stream = tokio_socks::tcp::socks5::Socks5Stream::connect(socks_addr, target)
            .await
            .context("Tor SOCKS5 connection")?;
        let stream = socks_stream.into_inner();
        configure_stream(&stream)?;
        Ok(stream)
    }

    async fn ip_connect(&self) -> Result<TcpStream> {
        let socket_addr = self
            .peer
            .addr
            .to_socket_addr()
            .context("not an IPv4 or IPv6 address")?;
        let stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(socket_addr))
            .await
            .context("TCP connect timeout")?
            .context("TCP connect")?;
        configure_stream(&stream)?;
        Ok(stream)
    }

    /// Connect to a peer, using Tor SOCKS5 proxy if the peer is an onion address and Tor is enabled.
    async fn tcp_connect(&self) -> Result<TcpStream> {
        match self.peer.addr {
            NetAddr::TorV3(..) => self.tor_connect().await,
            NetAddr::Ipv4(..) | NetAddr::Ipv6(..) => self.ip_connect().await,
            _ => {
                tracing::warn!(target: TARGET, addr=%self.peer.addr, "tcp_connect not implemented for");
                anyhow::bail!("tcp_connect not implemented for address type")
            }
        }
    }

    /// Attempts a v2 connection, falling back to v1 on failure.
    /// Once v2 has succeeded once, `skip_v1_fallback` is set and v1 is never tried again.
    pub async fn try_connect(&mut self) -> Result<Instant> {
        // We set ServiceFlags::NONE on addresses we don't know, so also try a V2 connection there.
        if !self.peer.services().has(ServiceFlags::P2P_V2)
            && self.peer.services().has(ServiceFlags::NONE)
        {
            tracing::trace!(target: TARGET, services=%self.peer.services(), "not attemping a v2 connection, as ServiceFlags indicate this node does not support P2Pv2");
            return self.connect_v1().await;
        }
        if self.skip_v1_fallback {
            tracing::trace!(target: TARGET, "not attemping a v1 connection, as we were previously connected as v2 to this node");
            return self.connect_v2().await;
        }
        match self.connect_v2().await {
            ok @ Ok(_) => {
                self.skip_v1_fallback = true;
                ok
            }
            Err(e) => {
                if is_tcp_connect_error(&e) {
                    return Err(e);
                }
                tracing::trace!(target: TARGET, "trying transport v1 as v2 failed: {e:#}");
                self.connect_v1().await
            }
        }
    }

    async fn connect_v2(&self) -> Result<Instant> {
        tracing::trace!(target: TARGET, "connecting (v2) ...");
        let stream = self.tcp_connect().await?;
        let raw_fd = stream.as_raw_fd();
        let (reader, writer) = stream.into_split();
        let proto = Protocol::new(
            self.cfg.magic,
            Role::Initiator,
            None,
            None,
            BufReader::new(reader),
            writer,
        )
        .await?;
        let (pr, pw) = proto.into_split();
        run_session(
            TransportV2Reader { reader: pr },
            TransportV2Writer { writer: pw },
            2,
            self.id,
            &self.peer.addr,
            raw_fd,
            &self.cfg,
            &self.status_tx,
            &self.new_addr_tx,
        )
        .await
    }

    async fn connect_v1(&self) -> Result<Instant> {
        tracing::trace!(target: TARGET, "connecting (v1) ...");
        let stream = self.tcp_connect().await?;
        let raw_fd = stream.as_raw_fd();
        let (reader, writer) = stream.into_split();
        run_session(
            TransportV1Reader::new(BufReader::new(reader)),
            TransportV1Writer {
                magic: self.cfg.magic,
                writer,
            },
            1,
            self.id,
            &self.peer.addr,
            raw_fd,
            &self.cfg,
            &self.status_tx,
            &self.new_addr_tx,
        )
        .await
    }
}

// ── Error classification ──────────────────────────────────────────────────────

fn is_network_unreachable(err: &common::anyhow::Error) -> bool {
    has_io_error_kind(err, std::io::ErrorKind::NetworkUnreachable)
}

fn is_host_unreachable(err: &common::anyhow::Error) -> bool {
    has_io_error_kind(err, std::io::ErrorKind::HostUnreachable)
}

fn is_unexpected_eof(err: &common::anyhow::Error) -> bool {
    has_io_error_kind(err, std::io::ErrorKind::UnexpectedEof)
}

/// Returns true for TCP-level errors where retrying with a different transport
/// version (v1 vs v2) would not help.
fn is_tcp_connect_error(err: &common::anyhow::Error) -> bool {
    is_connection_refused(err)
        || is_network_unreachable(err)
        || is_host_unreachable(err)
        || is_timed_out(err)
}

fn is_connection_refused(err: &common::anyhow::Error) -> bool {
    has_io_error_kind(err, std::io::ErrorKind::ConnectionRefused)
}

fn is_timed_out(err: &common::anyhow::Error) -> bool {
    // Our explicit tokio::time::timeout fired.
    if err.chain().any(|c| c.is::<tokio::time::error::Elapsed>()) {
        return true;
    }
    // OS-level timeout (rare when our explicit timeout is shorter, but possible).
    has_io_error_kind(err, std::io::ErrorKind::TimedOut)
}

fn has_io_error_kind(err: &common::anyhow::Error, kind: std::io::ErrorKind) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == kind)
    })
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addresses::{NetAddr, PeerAddr};
    use crate::headertree::HeaderTree;
    use crate::protocol::build_version;
    use crate::transport::{
        TransportReader, TransportV1Reader, TransportV1Writer, TransportV2Reader,
        TransportV2Writer, TransportWriter,
    };
    use bip324::{Role, futures::Protocol};
    use common::p2p::{Magic, ServiceFlags};
    use common::{
        bitcoin::network::Params,
        p2p::message::NetworkMessage,
        tokio::{io::BufReader, net::TcpListener, sync::mpsc},
        tracing_subscriber,
    };
    use std::sync::{Arc, RwLock};

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
            .send(build_version(crate::protocol::USER_AGENT))
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

    const MAGIC: Magic = Magic::REGTEST;

    fn setup() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .try_init();
    }

    #[tokio::test]
    async fn test_v1_handshake_mock() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, writer) = stream.into_split();
            let mut r = TransportV1Reader::new(BufReader::new(reader));
            let mut w = TransportV1Writer {
                magic: MAGIC,
                writer,
            };
            server_handshake(&mut r, &mut w).await;
            // Drop → EOF → client message loop exits → connect_v1 returns Ok
        });

        let net_addr = NetAddr::Ipv4("127.0.0.1".parse().unwrap(), addr.port());
        let (status_tx, _status_rx) = mpsc::channel(1);
        let (tx, _rx) = mpsc::channel::<Vec<PeerAddr>>(1);
        let (event_tx, _event_rx) = mpsc::channel(1);
        let cfg = Config {
            magic: MAGIC,
            ping_interval: Duration::from_secs(120),
            user_agent: crate::protocol::USER_AGENT.to_owned(),
            event_tx,
            header_tree: Arc::new(RwLock::new(HeaderTree::new(Params::new(
                common::bitcoin::Network::Regtest,
            )))),
            sync_headers: false,
            tor: crate::settings::TorConfig::default(),
        };
        let conn = Connection::new(
            cfg,
            status_tx,
            tx,
            PeerAddr::new(net_addr, ServiceFlags::NONE),
        );
        let result = conn.connect_v1().await;
        server.await.unwrap();
        assert!(result.is_ok(), "connect_v1 failed: {result:?}");
    }

    #[tokio::test]
    async fn test_v2_handshake_mock() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

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

        let net_addr = NetAddr::Ipv4("127.0.0.1".parse().unwrap(), addr.port());
        let (status_tx, _status_rx) = mpsc::channel(1);
        let (tx, _rx) = mpsc::channel::<Vec<PeerAddr>>(1);
        let (event_tx, _event_rx) = mpsc::channel(1);
        let cfg = Config {
            magic: MAGIC,
            ping_interval: Duration::from_secs(120),
            user_agent: crate::protocol::USER_AGENT.to_owned(),
            event_tx,
            header_tree: Arc::new(RwLock::new(HeaderTree::new(Params::new(
                common::bitcoin::Network::Regtest,
            )))),
            sync_headers: false,
            tor: crate::settings::TorConfig::default(),
        };
        let conn = Connection::new(
            cfg,
            status_tx,
            tx,
            PeerAddr::new(net_addr, ServiceFlags::P2P_V2),
        );
        let result = conn.connect_v2().await;
        server.await.unwrap();
        assert!(result.is_ok(), "connect_v2 failed: {result:?}");
    }

    #[tokio::test]
    async fn test_ping_rtt_event() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, writer) = stream.into_split();
            let mut r = TransportV1Reader::new(BufReader::new(reader));
            let mut w = TransportV1Writer {
                magic: MAGIC,
                writer,
            };
            server_handshake(&mut r, &mut w).await;
            // Respond to the first ping; ignore everything else (GetAddr, SendHeaders, ...)
            loop {
                match r.recv().await.unwrap() {
                    NetworkMessage::Ping(nonce) => {
                        w.send(NetworkMessage::Pong(nonce)).await.unwrap();
                        break;
                    }
                    _ => {}
                }
            }
        });

        let net_addr = NetAddr::Ipv4("127.0.0.1".parse().unwrap(), addr.port());
        let (status_tx, _status_rx) = mpsc::channel(1);
        let (addr_tx, _addr_rx) = mpsc::channel::<Vec<PeerAddr>>(1);
        let (event_tx, mut event_rx) = mpsc::channel(4);
        let cfg = Config {
            magic: MAGIC,
            ping_interval: Duration::from_millis(50),
            user_agent: crate::protocol::USER_AGENT.to_owned(),
            event_tx,
            header_tree: Arc::new(RwLock::new(HeaderTree::new(Params::new(
                common::bitcoin::Network::Regtest,
            )))),
            sync_headers: false,
            tor: crate::settings::TorConfig::default(),
        };
        tokio::spawn(
            Connection::new(
                cfg,
                status_tx,
                addr_tx,
                PeerAddr::new(net_addr, ServiceFlags::NONE),
            )
            .run(),
        );

        let event = common::tokio::time::timeout(Duration::from_secs(2), event_rx.recv())
            .await
            .expect("timed out waiting for ping_rtt event")
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
}
