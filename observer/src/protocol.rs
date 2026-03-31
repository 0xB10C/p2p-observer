use common::{
    anyhow::Result,
    p2p::{
        ProtocolVersion, ServiceFlags, address,
        address::{AddrV2Message, Address},
        message::NetworkMessage,
        message_blockdata::Inventory,
        message_compact_blocks::SendCmpct,
        message_network::{self, UserAgent},
    },
    tokio::{
        self,
        sync::mpsc,
        time::{Duration, interval},
    },
    tracing,
    tracing::Instrument,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::addresses::{NetAddr, StatusUpdate};
use crate::transport::Transport;

use crate::TARGET_PROTOCOL as TARGET;

pub(crate) const USER_AGENT: &str = "/p2p-observer:0.1.0/";

/// How often to send a ping to measure round-trip time.
const PING_INTERVAL: Duration = Duration::from_secs(120);

/// Whether to request high-bandwidth compact block relay (BIP152).
/// In high-bandwidth mode the peer sends compact blocks directly without an INV first,
/// at the cost of higher bandwidth. In low-bandwidth mode (false) the peer sends an INV
/// and we request the compact block via GETDATA. Low-bandwidth is sufficient for observation.
const HIGH_BANDWIDTH_COMPACT_BLOCKS: bool = false;

/// Information collected from the peer during the version handshake.
pub(crate) struct HandshakeInfo {
    pub(crate) version: message_network::VersionMessage,
    #[allow(dead_code)]
    pub(crate) send_addr_v2: bool,
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
    /// Minimum fee rate the peer will accept for relay (BIP133).
    #[allow(dead_code)]
    fee_filter: Option<common::bitcoin::FeeRate>,
}

/// Run the Bitcoin P2P session on an already-established transport.
///
/// Performs the version handshake, then drives the message loop until the
/// peer disconnects. Returns the `Instant` at which the handshake completed.
///
/// `v` is the transport version (1 or 2) used only for the tracing span.
pub(crate) async fn run_session(
    mut transport: impl Transport,
    v: u8,
    addr: &NetAddr,
    status_tx: &mpsc::Sender<StatusUpdate>,
    new_addr_tx: &mpsc::Sender<Vec<NetAddr>>,
) -> Result<Instant> {
    let info = version_handshake(&mut transport).await?;
    let connected_at = Instant::now();
    let conn_span = tracing::info_span!(target: TARGET, "", v = v, ua = %info.version.user_agent);

    let _ = status_tx
        .send(StatusUpdate::Good {
            addr: addr.clone(),
            at: unix_secs(),
        })
        .await;
    tracing::trace!(target: TARGET, "connection established");
    transport.send(NetworkMessage::GetAddr).await?;
    let mut conn = Connection {
        transport,
        new_addr_tx: new_addr_tx.clone(),
        handshake_info: info,
        send_cmpct: None,
        fee_filter: None,
    };
    crate::IN_MESSAGE_LOOP.fetch_add(1, Ordering::Relaxed);
    if let Err(e) = conn.run().instrument(conn_span).await {
        tracing::debug!(target: TARGET, "connection error: {e}");
    }
    crate::IN_MESSAGE_LOOP.fetch_sub(1, Ordering::Relaxed);
    Ok(connected_at)
}

pub(crate) async fn version_handshake(transport: &mut impl Transport) -> Result<HandshakeInfo> {
    transport.send(build_version()).await?;

    let mut peer_version: Option<message_network::VersionMessage> = None;
    let mut got_verack = false;
    let mut send_addr_v2 = false;

    while !(peer_version.is_some() && got_verack) {
        match transport.recv().await? {
            NetworkMessage::Version(v) => {
                tracing::debug!(target: TARGET,
                    version = u32::from(v.version),
                    ua = v.user_agent.to_string(),
                    "received version"
                );
                // Advertise addrv2 support (BIP155).
                transport.send(NetworkMessage::SendAddrV2).await?;
                transport.send(NetworkMessage::Verack).await?;
                peer_version = Some(v);
            }
            NetworkMessage::Verack => {
                tracing::trace!(target: TARGET, "handshake complete");
                got_verack = true;
            }
            NetworkMessage::SendAddrV2 => {
                tracing::trace!(target: TARGET, "received sendaddrv2 (during version handshake)");
                send_addr_v2 = true;
            }
            other => tracing::warn!(target: TARGET, "ignored during handshake: {:?}", other),
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
        send_addr_v2,
    })
}

impl<T: Transport> Connection<T> {
    /// Main message loop — runs until the peer disconnects or an error occurs.
    async fn run(&mut self) -> Result<()> {
        let mut ping_timer = interval(PING_INTERVAL);
        ping_timer.tick().await; // skip the immediate first tick

        // Note: transport.recv() is not cancel-safe — if the ping timer fires while a
        // read_exact is mid-header, the partial bytes are lost. In practice this is rare
        // and the worst outcome is a parse error and reconnect, acceptable for an observer.
        loop {
            tokio::select! {
                _ = ping_timer.tick() => self.send_ping().await?,
                msg = self.transport.recv() => self.handle_message(msg?).await?,
            }
        }
    }

    async fn send_ping(&mut self) -> Result<()> {
        let nonce = unix_ms();
        tracing::trace!(target: TARGET, ts_ms = nonce, "sending ping");
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
            NetworkMessage::FeeFilter(rate) => self.handle_fee_filter(rate),
            NetworkMessage::GetHeaders(_) => self.handle_get_headers().await?,
            NetworkMessage::SendHeaders => self.handle_send_headers(),
            NetworkMessage::SendAddrV2 => self.handle_send_addr_v2(),
            other => tracing::trace!(target: TARGET, "received: {:?}", other),
        }
        Ok(())
    }

    async fn handle_inv(&mut self, inv: Vec<Inventory>) -> Result<()> {
        let mut getdata = Vec::new();

        for item in inv {
            match item {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => {
                    tracing::info!(target: TARGET, %hash, "inv: block");
                }
                Inventory::CompactBlock(hash) => {
                    tracing::info!(target: TARGET, %hash, "inv: compact block");
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
            tracing::info!(target: TARGET, %hash, "header announcement");
        }
    }

    fn handle_cmpct_block(&self, cmpct: common::p2p::message_compact_blocks::CmpctBlock) {
        let hash = cmpct.compact_block.header.block_hash();
        tracing::info!(target: TARGET, %hash, "compact block");
    }

    async fn handle_ping(&mut self, nonce: u64) -> Result<()> {
        tracing::trace!(target: TARGET, nonce, "received ping");
        self.transport.send(NetworkMessage::Pong(nonce)).await
    }

    fn handle_pong(&self, nonce: u64) {
        let rtt_ms = unix_ms().saturating_sub(nonce);
        tracing::debug!(target: TARGET, rtt_ms, "pong");
    }

    fn handle_addr(&self, addrs: &[(u32, Address)]) {
        let converted: Vec<NetAddr> = addrs
            .iter()
            .filter_map(|(_, a)| NetAddr::try_from(a).ok())
            .collect();
        tracing::debug!(target: TARGET, received = addrs.len(), parsed = converted.len(), "addr");
        if !converted.is_empty() {
            let _ = self.new_addr_tx.try_send(converted);
        }
    }

    fn handle_addrv2(&self, addrs: &[AddrV2Message]) {
        let converted: Vec<NetAddr> = addrs
            .iter()
            .filter_map(|m| NetAddr::try_from(m).ok())
            .collect();
        tracing::debug!(target: TARGET, received = addrs.len(), parsed = converted.len(), "addrv2");
        if !converted.is_empty() {
            let _ = self.new_addr_tx.try_send(converted);
        }
    }

    fn handle_send_cmpct(&mut self, sc: SendCmpct) {
        tracing::debug!(target: TARGET,
            send_compact = sc.send_compact,
            version = sc.version,
            "received sendcmpct"
        );
        self.send_cmpct = Some(sc);
    }

    fn handle_fee_filter(&mut self, rate: common::bitcoin::FeeRate) {
        tracing::debug!(target: TARGET, rate=rate.to_sat_per_vb_ceil(), "received feefilter");
        self.fee_filter = Some(rate);
    }

    async fn handle_get_headers(&mut self) -> Result<()> {
        tracing::debug!(target: TARGET, "received getheaders, responding with empty headers");
        self.transport
            .send(NetworkMessage::Headers(
                common::p2p::message::HeadersMessage(vec![]),
            ))
            .await
    }

    fn handle_send_headers(&self) {
        tracing::debug!(target: TARGET, "received sendheaders");
    }

    fn handle_send_addr_v2(&self) {
        tracing::warn!(target: TARGET, "received sendaddrv2 outside of handshake");
    }
}

pub(crate) fn build_version() -> NetworkMessage {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::{TransportV1, TransportV2};
    use bip324::{Role, futures::Protocol};
    use common::{
        p2p::Magic,
        tokio::{io::BufReader, net::TcpStream},
        tracing_subscriber,
    };

    fn setup() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .try_init();
    }

    /// Test v1 handshake against a real bitcoind.
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
