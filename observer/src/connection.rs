use bip324::{Role, futures::Protocol};
use common::{
    anyhow::{Context, Result},
    p2p::{
        Magic, ProtocolVersion, ServiceFlags, address,
        address::{AddrV2Message, Address},
        message::NetworkMessage,
        message_blockdata::Inventory,
        message_compact_blocks::SendCmpct,
        message_network::{self, UserAgent},
    },
    tokio::{
        self,
        io::BufReader,
        net::TcpStream,
        sync::mpsc,
        time::{Duration, interval, sleep, timeout},
    },
    tracing,
    tracing::Instrument,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::addresses::{NetAddr, StatusUpdate};
use crate::transport::{Transport, TransportV1, TransportV2};

pub(crate) const MAGIC: Magic = Magic::SIGNET;
const USER_AGENT: &str = "/p2p-observer:0.1.0/";

/// Initial wait before the first reconnect attempt after a failure.
/// Doubles on each consecutive failure, reset to this value after a successful connection.
const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// How many consecutive failed connection attempts to make before giving up.
/// With BACKOFF_BASE doubling each attempt: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s.
const MAX_RECONNECT_ATTEMPTS: u32 = 8;

/// Timeout for TCP connection attempts. The OS default (several minutes with SYN retransmits)
/// is far too long when managing many connections.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How many consecutive TCP timeouts to tolerate before giving up on a peer we have
/// never successfully connected to. Timeouts are a softer signal than ConnectionRefused
/// (the node might be firewalled), so we allow a small number of retries before giving up.
const MAX_TIMEOUT_ATTEMPTS_UNSEEN: u32 = 2;

/// How often to send a ping to measure round-trip time.
const PING_INTERVAL: Duration = Duration::from_secs(120);

/// Whether to request high-bandwidth compact block relay (BIP152).
/// In high-bandwidth mode the peer sends compact blocks directly without an INV first,
/// at the cost of higher bandwidth. In low-bandwidth mode (false) the peer sends an INV
/// and we request the compact block via GETDATA. Low-bandwidth is sufficient for observation.
const HIGH_BANDWIDTH_COMPACT_BLOCKS: bool = false;

static PEER_ID: AtomicU64 = AtomicU64::new(0);

/// Information collected from the peer during the version handshake.
struct HandshakeInfo {
    version: message_network::VersionMessage,
    #[allow(dead_code)]
    send_headers: bool,
    #[allow(dead_code)]
    send_addr_v2: bool,
}

/// A live connection to a peer, created after a successful version handshake.
struct Connection<T: Transport> {
    transport: T,
    new_addr_tx: mpsc::Sender<Vec<NetAddr>>,
    #[allow(dead_code)]
    handshake_info: HandshakeInfo,
    /// Last SendCmpct received from the peer.
    #[allow(dead_code)]
    send_cmpct: Option<SendCmpct>,
}

pub async fn connect_with_retry(
    addr: NetAddr,
    status_tx: mpsc::Sender<StatusUpdate>,
    new_addr_tx: mpsc::Sender<Vec<NetAddr>>,
) {
    let id = PEER_ID.fetch_add(1, Ordering::Relaxed);
    let span = tracing::info_span!("c", id, addr = %addr);

    async move {
        let Some(socket_addr) = addr.to_socket_addr() else {
            tracing::debug!("no TCP address, skipping");
            let _ = status_tx.send(StatusUpdate::TaskDone(addr)).await;
            return;
        };
        retry_loop(&addr, socket_addr, status_tx, new_addr_tx).await
    }
    .instrument(span)
    .await
}

async fn retry_loop(
    addr: &NetAddr,
    socket_addr: SocketAddr,
    status_tx: mpsc::Sender<StatusUpdate>,
    new_addr_tx: mpsc::Sender<Vec<NetAddr>>,
) {
    let mut backoff = BACKOFF_BASE;
    let mut attempts = 0u32;
    let mut timeout_attempts = 0u32;
    let mut skip_v1_fallback = false;
    let mut ever_connected = false;

    loop {
        let result = try_connect(socket_addr, &mut skip_v1_fallback, &new_addr_tx).await;

        attempts += 1;
        backoff *= 2;

        match result {
            Ok(connected_at) => {
                ever_connected = true;
                let uptime = connected_at.elapsed();
                // Only reset backoff if the connection was stable long enough — otherwise
                // a peer that immediately evicts us after the handshake would reset the
                // backoff on every attempt, causing a reconnect flood.
                if uptime > backoff {
                    backoff = BACKOFF_BASE;
                    attempts = 0;
                }
                let _ = status_tx
                    .send(StatusUpdate::LastSeen {
                        addr: addr.clone(),
                        at: unix_secs(),
                    })
                    .await;
                tracing::trace!(
                    uptime = format!("{:?}", uptime),
                    "connection lost. reconnecting in {backoff:.1?}"
                );
            }
            Err(e) => {
                if is_network_unreachable(&e) {
                    tracing::info!("network unreachable, not retrying");
                    let _ = status_tx
                        .send(StatusUpdate::NetworkUnreachable(addr.clone()))
                        .await;
                    break;
                }

                if is_timed_out(&e) {
                    timeout_attempts += 1;
                    if !ever_connected && timeout_attempts >= MAX_TIMEOUT_ATTEMPTS_UNSEEN {
                        tracing::info!(timeout_attempts, "timed out repeatedly, not retrying");
                        let _ = status_tx.send(StatusUpdate::TimedOut(addr.clone())).await;
                        break;
                    }
                } else {
                    timeout_attempts = 0;
                }

                if !ever_connected {
                    if is_connection_refused(&e) {
                        tracing::info!("connection refused on first attempt, not retrying");
                        let _ = status_tx
                            .send(StatusUpdate::ConnectionRefused(addr.clone()))
                            .await;
                        break;
                    } else if is_host_unreachable(&e) {
                        tracing::info!("host unreachable on first attempt, not retrying");
                        let _ = status_tx
                            .send(StatusUpdate::HostUnreachable(addr.clone()))
                            .await;
                        break;
                    }
                }

                tracing::trace!(
                    attempts,
                    backoff_ms = backoff.as_millis(),
                    error = format!("{:?}", e),
                    "failed to connect, retrying.."
                );
            }
        }

        if attempts >= MAX_RECONNECT_ATTEMPTS {
            tracing::info!(attempts, "giving up");
            if !ever_connected {
                let _ = status_tx.send(StatusUpdate::Offline(addr.clone())).await;
            }
            break;
        }

        sleep(backoff).await;
    }
    let _ = status_tx.send(StatusUpdate::TaskDone(addr.clone())).await;
}

/// Attempts a v2 connection, falling back to v1 on failure.
/// Once v2 has succeeded once, `skip_v1_fallback` is set and v1 is never tried again —
/// a peer is very unlikely to downgrade, and skipping the fallback avoids wasting an
/// attempt on a protocol the peer has already proven it doesn't need.
async fn try_connect(
    addr: SocketAddr,
    skip_v1_fallback: &mut bool,
    new_addr_tx: &mpsc::Sender<Vec<NetAddr>>,
) -> Result<Instant> {
    if *skip_v1_fallback {
        return connect_v2(addr, MAGIC, new_addr_tx).await;
    }
    match connect_v2(addr, MAGIC, new_addr_tx).await {
        ok @ Ok(_) => {
            *skip_v1_fallback = true;
            ok
        }
        Err(e) => {
            // If we run into a TCP connection error, we don't need to
            // retry a v1 connection.
            if is_tcp_connect_error(&e) {
                return Err(e);
            }
            tracing::trace!("v2 failed ({e}), trying v1");
            connect_v1(addr, MAGIC, new_addr_tx).await
        }
    }
}

/// Returns the `Instant` at which the version handshake completed, once the connection drops.
async fn connect_v2(
    addr: SocketAddr,
    magic: Magic,
    new_addr_tx: &mpsc::Sender<Vec<NetAddr>>,
) -> Result<Instant> {
    tracing::trace!("connecting (v2) ...");
    let stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("TCP connect timeout")?
        .context("TCP connect")?;
    let (reader, writer) = stream.into_split();
    let proto = Protocol::new(
        magic,
        Role::Initiator,
        None,
        None,
        BufReader::new(reader),
        writer,
    )
    .await?;
    let mut transport = TransportV2 { proto };

    let info = version_handshake(&mut transport).await?;
    let connected_at = Instant::now();
    let conn_span = tracing::info_span!("", v = 2, ua = %info.version.user_agent);

    tracing::trace!("v2 connection established");
    transport.send(NetworkMessage::GetAddr).await?;
    let mut conn = Connection {
        transport,
        new_addr_tx: new_addr_tx.clone(),
        handshake_info: info,
        send_cmpct: None,
    };
    if let Err(e) = conn.run().instrument(conn_span).await {
        tracing::debug!("v2 connection error: {e}");
    }
    Ok(connected_at)
}

/// Returns the `Instant` at which the version handshake completed, once the connection drops.
async fn connect_v1(
    addr: SocketAddr,
    magic: Magic,
    new_addr_tx: &mpsc::Sender<Vec<NetAddr>>,
) -> Result<Instant> {
    tracing::trace!("connecting (v1) ...");
    let stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("TCP connect timeout")?
        .context("TCP connect")?;
    let (reader, writer) = stream.into_split();
    let mut transport = TransportV1 {
        magic,
        reader: BufReader::new(reader),
        writer,
    };

    let info = version_handshake(&mut transport).await?;
    let connected_at = Instant::now();
    let conn_span = tracing::info_span!("", v = 1, ua = %info.version.user_agent);

    tracing::trace!("v1 connection established");
    transport.send(NetworkMessage::GetAddr).await?;
    let mut conn = Connection {
        transport,
        new_addr_tx: new_addr_tx.clone(),
        handshake_info: info,
        send_cmpct: None,
    };
    if let Err(e) = conn.run().instrument(conn_span).await {
        tracing::debug!("v1 connection error: {e}");
    }
    Ok(connected_at)
}

async fn version_handshake(transport: &mut impl Transport) -> Result<HandshakeInfo> {
    transport.send(build_version()).await?;

    let mut peer_version: Option<message_network::VersionMessage> = None;
    let mut got_verack = false;
    let mut send_headers = false;
    let mut send_addr_v2 = false;

    while !(peer_version.is_some() && got_verack) {
        match transport.recv().await? {
            NetworkMessage::Version(v) => {
                tracing::debug!(
                    version = u32::from(v.version),
                    ua = v.user_agent.to_string(),
                    "received version"
                );
                // Advertise addrv2 support (BIP155)
                transport.send(NetworkMessage::SendAddrV2).await?;
                transport.send(NetworkMessage::Verack).await?;
                peer_version = Some(v);
            }
            NetworkMessage::Verack => {
                tracing::trace!("handshake complete");
                got_verack = true;
            }
            NetworkMessage::SendHeaders => {
                tracing::debug!("received sendheaders (during version handshake)");
                send_headers = true;
            }
            NetworkMessage::SendAddrV2 => {
                tracing::debug!("received sendaddrv2 (during version handshake)");
                send_addr_v2 = true;
            }
            other => tracing::debug!("ignored during handshake: {:?}", other),
        }
    }

    // Request compact block announcements (version 2 = segwit).
    transport
        .send(NetworkMessage::SendCmpct(SendCmpct {
            send_compact: HIGH_BANDWIDTH_COMPACT_BLOCKS,
            version: 2,
        }))
        .await?;

    Ok(HandshakeInfo {
        version: peer_version.expect("loop invariant: version is Some when loop exits"),
        send_headers,
        send_addr_v2,
    })
}

impl<T: Transport> Connection<T> {
    /// Main message loop — runs until the peer disconnects or an error occurs.
    async fn run(&mut self) -> Result<()> {
        let mut ping_timer = interval(PING_INTERVAL);
        ping_timer.tick().await; // skip the immediate first tick

        // Note: peer.recv() is not cancel-safe — if the ping timer fires while a read_exact
        // is mid-header, the partial bytes are lost. In practice this is rare and the worst
        // outcome is a parse error and reconnect, which is acceptable for an observer.
        loop {
            tokio::select! {
                _ = ping_timer.tick() => self.send_ping().await?,
                msg = self.transport.recv() => self.handle_message(msg?).await?,
            }
        }
    }

    async fn send_ping(&mut self) -> Result<()> {
        let nonce = unix_ms();
        tracing::trace!(ts_ms = nonce, "sending ping");
        self.transport.send(NetworkMessage::Ping(nonce)).await
    }

    async fn handle_message(&mut self, msg: NetworkMessage) -> Result<()> {
        match msg {
            NetworkMessage::Ping(nonce) => self.handle_ping(nonce).await?,
            NetworkMessage::Pong(nonce) => self.handle_pong(nonce),
            NetworkMessage::Inv(inv) => self.handle_inv(inv.0).await?,
            NetworkMessage::Headers(headers) => self.handle_headers(headers.0),
            NetworkMessage::CmpctBlock(cmpct) => self.handle_cmpct_block(cmpct),
            NetworkMessage::Addr(payload) => self.handle_addr(&payload.0),
            NetworkMessage::AddrV2(payload) => self.handle_addrv2(&payload.0),
            NetworkMessage::SendCmpct(sc) => self.handle_send_cmpct(sc),
            // Not expected after the version handshake.
            NetworkMessage::SendHeaders => self.handle_send_headers(),
            NetworkMessage::SendAddrV2 => self.handle_send_addr_v2(),
            other => tracing::debug!("received: {:?}", other),
        }
        Ok(())
    }

    async fn handle_inv(&mut self, inv: Vec<Inventory>) -> Result<()> {
        let mut getdata = Vec::new();

        for item in inv {
            match item {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                    // log the inv, but don't request the full block
                    tracing::info!(%hash, "inv: block");
                }
                Inventory::CompactBlock(hash) => {
                    tracing::info!(%hash, "inv: compact block");
                    getdata.push(Inventory::CompactBlock(hash));
                }
                _ => {}
            }
        }

        if !getdata.is_empty() {
            self.transport
                .send(NetworkMessage::GetData(
                    common::p2p::message::InventoryPayload(getdata),
                ))
                .await?;
        }

        Ok(())
    }

    fn handle_headers(&self, headers: Vec<common::bitcoin::block::Header>) {
        for header in headers {
            let hash = header.block_hash();
            tracing::info!(%hash, "header announcement");
        }
    }

    fn handle_cmpct_block(&self, cmpct: common::p2p::message_compact_blocks::CmpctBlock) {
        let hash = cmpct.compact_block.header.block_hash();
        tracing::info!(%hash, "compact block");
    }

    async fn handle_ping(&mut self, nonce: u64) -> Result<()> {
        tracing::trace!(nonce, "received ping");
        self.transport.send(NetworkMessage::Pong(nonce)).await
    }

    fn handle_pong(&self, nonce: u64) {
        let rtt_ms = unix_ms().saturating_sub(nonce);
        tracing::debug!(rtt_ms, "pong");
    }

    fn handle_addr(&self, addrs: &[(u32, Address)]) {
        tracing::trace!(num = addrs.len(), "received addr");
        let converted: Vec<NetAddr> = addrs
            .iter()
            .filter_map(|(_, a)| NetAddr::try_from(a).ok())
            .collect();
        if !converted.is_empty() {
            let _ = self.new_addr_tx.try_send(converted);
        }
    }

    fn handle_addrv2(&self, addrs: &[AddrV2Message]) {
        tracing::trace!(num = addrs.len(), "received addrv2");
        let converted: Vec<NetAddr> = addrs
            .iter()
            .filter_map(|m| NetAddr::try_from(m).ok())
            .collect();
        if !converted.is_empty() {
            let _ = self.new_addr_tx.try_send(converted);
        }
    }

    fn handle_send_cmpct(&mut self, sc: SendCmpct) {
        tracing::debug!(
            send_compact = sc.send_compact,
            version = sc.version,
            "received sendcmpct"
        );
        self.send_cmpct = Some(sc);
    }

    fn handle_send_headers(&self) {
        tracing::warn!("received sendheaders outside of handshake");
    }

    fn handle_send_addr_v2(&self) {
        tracing::warn!("received sendaddrv2 outside of handshake");
    }
}

/// Check if the root cause of the error is a "network unreachable" OS error.
fn is_network_unreachable(err: &common::anyhow::Error) -> bool {
    has_io_error_kind(err, std::io::ErrorKind::NetworkUnreachable)
}

/// Check if the root cause of the error is a "no route to host" OS error.
fn is_host_unreachable(err: &common::anyhow::Error) -> bool {
    has_io_error_kind(err, std::io::ErrorKind::HostUnreachable)
}

/// Check if the error is a TCP-level connect failure (e.g. connection refused)
/// where falling back to a different transport version would not help.
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

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn build_version() -> NetworkMessage {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64;

    NetworkMessage::Version(message_network::VersionMessage {
        version: ProtocolVersion::WTXID_RELAY_VERSION,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp,
        receiver: address::Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            ServiceFlags::NONE,
        ),
        sender: address::Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            ServiceFlags::NONE,
        ),
        // Since we don't accept inbound connections, we don't have to fear about
        // connecting to ourself. The peer likely won't use zero to open a connection
        // at the same time, so this should be fine.
        nonce: 0,
        user_agent: UserAgent::from_nonstandard(USER_AGENT),
        start_height: 0,
        relay: false,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{Transport, TransportV1, TransportV2};
    use bip324::{Role, futures::Protocol};
    use common::{
        p2p::message::NetworkMessage,
        tokio::{io::BufReader, net::TcpListener, sync::mpsc},
        tracing_subscriber,
    };

    /// Complete the server side of the version handshake.
    ///
    /// Waits for the client's VERSION, responds with VERSION + VERACK, then
    /// drains the client's VERACK and SENDCMPCT before returning.
    async fn server_handshake(transport: &mut impl Transport) {
        loop {
            if let NetworkMessage::Version(_) = transport.recv().await.unwrap() {
                break;
            }
        }
        transport.send(build_version()).await.unwrap();
        transport.send(NetworkMessage::Verack).await.unwrap();
        loop {
            if let NetworkMessage::Verack = transport.recv().await.unwrap() {
                break;
            }
        }
        loop {
            if let NetworkMessage::SendCmpct(_) = transport.recv().await.unwrap() {
                break;
            }
        }
    }

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
            let mut transport = TransportV1 {
                magic: MAGIC,
                reader: BufReader::new(reader),
                writer,
            };
            server_handshake(&mut transport).await;
            // Drop → EOF → client message_loop exits → connect_v1 returns Ok
        });

        let (tx, _rx) = mpsc::channel(1);
        let result = connect_v1(addr, MAGIC, &tx).await;
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
            let mut transport = TransportV2 { proto };
            server_handshake(&mut transport).await;
        });

        let (tx, _rx) = mpsc::channel(1);
        let result = connect_v2(addr, MAGIC, &tx).await;
        server.await.unwrap();
        assert!(result.is_ok(), "connect_v2 failed: {result:?}");
    }

    /// Test v1 handshake against a real bitcoind. Only tests the handshake, not the message loop
    /// (the message loop is already covered by the mock tests).
    #[tokio::test]
    async fn test_v1_bitcoind() {
        setup();
        let exe = bitcoind::exe_path().unwrap();
        let mut conf = bitcoind::Conf::default();
        conf.p2p = bitcoind::P2P::Yes;
        conf.args.push("-v2transport=0");
        let node = bitcoind::Node::with_conf(exe, &conf).unwrap();
        let addr = node.params.p2p_socket.unwrap();

        let stream = TcpStream::connect(addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let mut transport = TransportV1 {
            magic: Magic::REGTEST,
            reader: BufReader::new(reader),
            writer,
        };
        version_handshake(&mut transport)
            .await
            .expect("v1 handshake failed");
    }

    /// Test v2 (BIP324) handshake against a real bitcoind.
    #[tokio::test]
    async fn test_v2_bitcoind() {
        setup();
        let exe = bitcoind::exe_path().unwrap();
        let mut conf = bitcoind::Conf::default();
        conf.p2p = bitcoind::P2P::Yes;
        conf.args.push("-v2transport=1");
        let node = bitcoind::Node::with_conf(exe, &conf).unwrap();
        let addr = node.params.p2p_socket.unwrap();

        let stream = TcpStream::connect(addr).await.unwrap();
        let (reader, writer) = stream.into_split();
        let proto = Protocol::new(
            Magic::REGTEST,
            Role::Initiator,
            None,
            None,
            BufReader::new(reader),
            writer,
        )
        .await
        .expect("BIP324 handshake failed");
        let mut transport = TransportV2 { proto };
        version_handshake(&mut transport)
            .await
            .expect("v2 version handshake failed");
    }
}
