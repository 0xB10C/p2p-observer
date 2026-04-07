use common::{
    anyhow::Result,
    bitcoin::{BlockHash, bip152},
    p2p::{
        ProtocolVersion, ServiceFlags, address,
        address::{AddrV2Message, Address},
        message::NetworkMessage,
        message_blockdata::{GetHeadersMessage, Inventory},
        message_compact_blocks::{BlockTxn, GetBlockTxn, SendCmpct},
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
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::RawFd;
use std::sync::atomic::Ordering;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::addresses::{NetAddr, PeerAddr, StatusUpdate};
use crate::headertree::HeaderTree;
use crate::transport::{TransportReader, TransportWriter};

use crate::TARGET_PROTOCOL as TARGET;

/// Sentinel value indicating header sync is complete. Used to signal that
/// a connection should close after the initial header sync phase.
#[derive(Debug, Clone)]
pub(crate) struct SyncComplete;

impl std::fmt::Display for SyncComplete {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "header sync complete")
    }
}

impl std::error::Error for SyncComplete {}

pub(crate) const USER_AGENT: &str = "/p2p-observer:0.1.0/";

#[derive(Clone)]
pub(crate) struct Config {
    pub(crate) magic: common::p2p::Magic,
    pub(crate) ping_interval: Duration,
    pub(crate) user_agent: String,
    pub(crate) event_tx: mpsc::Sender<common::events::PeerEvent>,
    pub(crate) header_tree: Arc<RwLock<HeaderTree>>,
    pub(crate) sync_headers: bool,
    pub(crate) networks: crate::settings::NetworksConfig,
}

/// We want get high-bandwidth compact block relay (BIP152).
/// In high-bandwidth mode the peer sends compact blocks directly without an INV first.
/// We can then ask for a transaction via getblocktxn to learn how long it took the peer
/// to validate the block.
const HIGH_BANDWIDTH_COMPACT_BLOCKS: bool = true;

/// Per-connection state and statistics accumulated during the session.
struct ConnectionStats {
    /// Last SendCmpct received from the peer.
    #[allow(dead_code)]
    send_cmpct: Option<SendCmpct>,
    /// Minimum fee rate the peer will accept for relay (BIP133).
    #[allow(dead_code)]
    fee_filter: Option<common::bitcoin::FeeRate>,
    /// Rolling window of last 10 RTT samples in milliseconds.
    rtt_history: VecDeque<u32>,
    /// Most recently sampled OS-level TCP statistics.
    tcp: Option<crate::tcp::TcpStats>,
}

impl ConnectionStats {
    fn new() -> Self {
        Self {
            send_cmpct: None,
            fee_filter: None,
            rtt_history: VecDeque::new(),
            tcp: None,
        }
    }

    fn record_rtt(&mut self, rtt_ms: u32) {
        self.rtt_history.push_back(rtt_ms);
        if self.rtt_history.len() > 10 {
            self.rtt_history.pop_front();
        }
    }
}

/// Information collected from the peer during the version handshake.
pub(crate) struct HandshakeInfo {
    pub(crate) version: message_network::VersionMessage,
    #[allow(dead_code)]
    pub(crate) send_addr_v2: bool,
    /// Peer announced BIP339 wtxid-based transaction relay support.
    #[allow(dead_code)]
    pub(crate) wtxid_relay: bool,
}

/// A live connection to a peer, created after a successful version handshake.
struct Connection<R: TransportReader, W: TransportWriter> {
    reader: R,
    writer: W,
    new_addr_tx: mpsc::Sender<Vec<PeerAddr>>,
    handshake_info: HandshakeInfo,
    stats: ConnectionStats,
    /// Raw file descriptor of the TCP socket, used to query OS-level TCP stats.
    raw_fd: RawFd,
    ping_interval: Duration,
    addr: NetAddr,
    transport_version: u8,
    connection_id: u64,
    event_tx: mpsc::Sender<common::events::PeerEvent>,
    header_tree: Arc<RwLock<HeaderTree>>,
    sync_headers: bool,
}

/// Run the Bitcoin P2P session on an already-established transport.
///
/// Performs the version handshake, then drives the message loop until the
/// peer disconnects. Returns the `Instant` at which the handshake completed.
///
/// `v` is the transport version (1 or 2) used only for the tracing span.
pub(crate) async fn run_session(
    mut reader: impl TransportReader,
    mut writer: impl TransportWriter,
    v: u8,
    connection_id: u64,
    addr: &NetAddr,
    raw_fd: RawFd,
    cfg: &Config,
    status_tx: &mpsc::Sender<StatusUpdate>,
    new_addr_tx: &mpsc::Sender<Vec<PeerAddr>>,
) -> Result<Instant> {
    let (_, tip_height) = &cfg.header_tree.read().unwrap().tip();
    let info = version_handshake(
        &mut reader,
        &mut writer,
        &cfg.user_agent,
        *tip_height as i32,
    )
    .await?;
    let connected_at = Instant::now();
    let conn_span = tracing::info_span!(target: TARGET, "", v, sh=info.version.start_height, ua = %info.version.user_agent);

    let _ = status_tx
        .send(StatusUpdate::Good {
            addr: addr.clone(),
            at: unix_secs(),
            services: Some(info.version.services),
        })
        .await;
    tracing::trace!(target: TARGET, "connection established");

    let mut conn = Connection {
        reader,
        writer,
        new_addr_tx: new_addr_tx.clone(),
        handshake_info: info,
        stats: ConnectionStats::new(),
        raw_fd,
        ping_interval: cfg.ping_interval,
        addr: addr.clone(),
        transport_version: v,
        connection_id,
        event_tx: cfg.event_tx.clone(),
        header_tree: cfg.header_tree.clone(),
        sync_headers: cfg.sync_headers,
    };
    crate::IN_MESSAGE_LOOP.fetch_add(1, Ordering::Relaxed);
    if let Err(e) = conn.run().instrument(conn_span).await {
        tracing::debug!(target: TARGET, "connection error: {e}");
    }
    crate::IN_MESSAGE_LOOP.fetch_sub(1, Ordering::Relaxed);
    Ok(connected_at)
}

pub(crate) async fn version_handshake(
    reader: &mut impl TransportReader,
    writer: &mut impl TransportWriter,
    user_agent: &str,
    tip_height: i32,
) -> Result<HandshakeInfo> {
    writer.send(build_version(user_agent, tip_height)).await?;

    let mut peer_version: Option<message_network::VersionMessage> = None;
    let mut got_verack = false;
    let mut send_addr_v2 = false;
    let mut wtxid_relay = false;

    while !(peer_version.is_some() && got_verack) {
        match reader.recv().await? {
            NetworkMessage::Version(v) => {
                tracing::debug!(target: TARGET,
                    version = u32::from(v.version),
                    ua = v.user_agent.to_string(),
                    "received version"
                );
                // utreexod (btcd-based, version 70013, ua "/btcwire:0.5.0/utreexod:0.5.0/")
                // rejects any message between version and verack, including
                // sendaddrv2. Skip it for this peer to avoid a "reject" disconnect.
                let skip_sendaddrv2 = u32::from(v.version) == 70013
                    && v.user_agent.to_string() == "/btcwire:0.5.0/utreexod:0.5.0/";
                if !skip_sendaddrv2 {
                    writer.send(NetworkMessage::SendAddrV2).await?;
                }
                if v.version >= ProtocolVersion::WTXID_RELAY_VERSION {
                    writer.send(NetworkMessage::WtxidRelay).await?;
                }
                writer.send(NetworkMessage::Verack).await?;

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
            NetworkMessage::WtxidRelay => {
                tracing::trace!(target: TARGET, "received wtxidrelay (during version handshake)");
                wtxid_relay = true;
            }
            other => tracing::warn!(target: TARGET, "ignored during handshake: {:?}", other),
        }
    }

    Ok(HandshakeInfo {
        version: peer_version.expect("loop invariant: version is Some when loop exits"),
        send_addr_v2,
        wtxid_relay,
    })
}

impl<R: TransportReader, W: TransportWriter> Connection<R, W> {
    /// Main message loop — runs until the peer disconnects or an error occurs.
    async fn run(&mut self) -> Result<()> {
        let mut ping_timer = interval(self.ping_interval);
        ping_timer.tick().await; // skip the immediate first tick

        // tell this peer we want to get compact blocks from it
        self.writer
            .send(NetworkMessage::SendCmpct(SendCmpct {
                send_compact: HIGH_BANDWIDTH_COMPACT_BLOCKS,
                version: 2,
            }))
            .await?;

        // request addresses from this peer
        self.writer.send(NetworkMessage::GetAddr).await?;

        // request headers (BIP130) from this peer
        self.writer.send(NetworkMessage::SendHeaders).await?;

        // Ask the peer about headers we don't yet have. During bootstrap sync
        // (sync_headers=true), this is the primary sync mechanism. During normal
        // operation, this ensures new connections contribute any headers they know about.
        self.send_getheaders().await?;

        // recv() is cancel-safe: both v1 and v2 readers preserve partial read
        // state across cancellations, so the ping timer can fire without losing bytes.
        loop {
            tokio::select! {
                _ = ping_timer.tick() => self.send_ping().await?,
                msg = self.reader.recv() => self.handle_message(msg?).await?,
            }
        }
    }

    async fn send_ping(&mut self) -> Result<()> {
        self.stats.tcp = crate::tcp::tcp_info(self.raw_fd);
        let nonce = unix_ms();
        tracing::trace!(target: TARGET, ts_ms = nonce,
            tcp_srtt_us = self.stats.tcp.as_ref().map(|t| t.srtt_us),
            "sending ping"
        );
        self.writer.send(NetworkMessage::Ping(nonce)).await
    }

    async fn handle_message(&mut self, msg: NetworkMessage) -> Result<()> {
        match msg {
            NetworkMessage::Ping(nonce) => self.handle_ping(nonce).await?,
            NetworkMessage::Pong(nonce) => self.handle_pong(nonce),
            NetworkMessage::Inv(inv) => self.handle_inv(inv.0).await?,
            NetworkMessage::Headers(headers) => self.handle_headers(headers.0).await?,
            NetworkMessage::CmpctBlock(cmpct) => self.handle_cmpct_block(cmpct).await?,
            NetworkMessage::Addr(payload) => self.handle_addr(&payload.0),
            NetworkMessage::AddrV2(payload) => self.handle_addrv2(&payload.0),
            NetworkMessage::SendCmpct(sc) => self.handle_send_cmpct(sc),
            NetworkMessage::FeeFilter(rate) => self.handle_fee_filter(rate),
            NetworkMessage::GetHeaders(msg) => self.handle_get_headers(msg).await?,
            NetworkMessage::SendHeaders => self.handle_send_headers(),
            NetworkMessage::SendAddrV2 => self.handle_send_addr_v2(),
            NetworkMessage::BlockTxn(msg) => self.handle_blocktxn(msg).await,
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
                    self.emit_block_announcement(hash, common::events::AnnouncementType::Inv);
                }
                Inventory::CompactBlock(hash) => {
                    tracing::info!(target: TARGET, %hash, "inv: compact block");
                    self.emit_block_announcement(hash, common::events::AnnouncementType::Inv);
                    getdata.push(Inventory::CompactBlock(hash));
                }
                _ => {}
            }
        }

        if !getdata.is_empty() {
            self.writer
                .send(NetworkMessage::GetData(
                    common::p2p::message::InventoryPayload(getdata),
                ))
                .await?;
        }

        Ok(())
    }

    async fn handle_headers(&mut self, headers: Vec<common::bitcoin::block::Header>) -> Result<()> {
        if headers.is_empty() {
            if self.sync_headers {
                let (tip, height) = self.header_tree.read().unwrap().tip();
                tracing::info!(target: TARGET, %tip, height, "header sync complete");
                return Err(SyncComplete.into());
            }
            return Ok(());
        }

        let (accepted, err) = self.header_tree.write().unwrap().insert_batch(&headers);
        let (tip, height) = self.header_tree.read().unwrap().tip();

        if accepted > 0 {
            tracing::info!(target: TARGET, accepted, height, %tip, "headers inserted");
        }
        if let Some(e) = &err {
            tracing::warn!(target: TARGET, "header insert error: {e}");
        }

        if !self.sync_headers {
            for header in &headers {
                let hash = header.block_hash();
                self.emit_block_announcement(hash, common::events::AnnouncementType::Headers);
            }
        }

        if self.sync_headers && accepted > 0 {
            self.send_getheaders().await?;
        }

        Ok(())
    }

    async fn handle_cmpct_block(
        &mut self,
        cmpct: common::p2p::message_compact_blocks::CmpctBlock,
    ) -> Result<()> {
        let hash = cmpct.compact_block.header.block_hash();
        self.emit_block_announcement(hash, common::events::AnnouncementType::CompactBlock);
        tracing::info!(target: TARGET, %hash, "compact block");
        self.request_compact_block_coinbase(hash).await
    }

    fn emit_block_announcement(
        &self,
        hash: common::bitcoin::BlockHash,
        announcement_type: common::events::AnnouncementType,
    ) {
        let tcp_stats = self.stats.tcp.as_ref().map(|t| common::events::TcpStats {
            srtt_us: u64::from(t.srtt_us),
            rttvar_us: u64::from(t.rttvar_us),
            total_retrans: u64::from(t.total_retrans),
            snd_cwnd: u64::from(t.snd_cwnd),
        });
        self.emit_event(common::events::peer_event::Event::BlockAnnouncement(
            common::events::BlockAnnouncement {
                block_hash: hash.to_string(),
                announcement_type: announcement_type.into(),
                rtt_ms: self.stats.rtt_history.back().copied().map(u64::from),
                tcp_stats,
            },
        ));
    }

    // Requesting a coinbase for a compact block (which we already know through the)
    // prefilled transactions, allows us to see when the other side has finished
    // validation of the compact block. Due to the request round-trip-time, this
    // is only interesting when expecting validation times of more than 100ms.
    // This is the case for e.g.:
    // https://delvingbitcoin.org/t/consensus-cleanup-demo-of-slow-blocks-on-signet/2367
    async fn request_compact_block_coinbase(&mut self, hash: BlockHash) -> Result<()> {
        tracing::trace!(target: TARGET, %hash, "requesting coinbase for cmpctblock");
        self.writer
            .send(NetworkMessage::GetBlockTxn(GetBlockTxn {
                txs_request: bip152::BlockTransactionsRequest {
                    block_hash: hash,
                    indexes: vec![0],
                },
            }))
            .await?;
        self.emit_block_announcement(hash, common::events::AnnouncementType::Getblocktxn);
        Ok(())
    }

    async fn handle_blocktxn(&mut self, blocktxn: BlockTxn) {
        let hash = blocktxn.transactions.block_hash;
        tracing::trace!(target: TARGET, %hash, txns=blocktxn.transactions.transactions.len(), "received blocktxn for cmptblock");
        self.emit_block_announcement(hash, common::events::AnnouncementType::Blocktxn);
    }

    async fn handle_ping(&mut self, nonce: u64) -> Result<()> {
        tracing::trace!(target: TARGET, nonce, "received ping");
        self.writer.send(NetworkMessage::Pong(nonce)).await
    }

    fn emit_event(&self, event: common::events::peer_event::Event) {
        let _ = self.event_tx.try_send(common::events::PeerEvent {
            timestamp_ms: unix_ms(),
            peer_addr: self.addr.to_string(),
            user_agent: self.handshake_info.version.user_agent.to_string(),
            transport_version: self.transport_version as u32,
            connection_id: self.connection_id,
            event: Some(event),
        });
    }

    fn handle_pong(&mut self, nonce: u64) {
        let rtt_ms = unix_ms().saturating_sub(nonce);
        tracing::debug!(target: TARGET, rtt_ms, "pong");
        self.stats.record_rtt(rtt_ms as u32);
        self.emit_event(common::events::peer_event::Event::PingRtt(
            common::events::PingRtt { rtt_ms },
        ));
    }

    fn handle_addr(&self, addrs: &[(u32, Address)]) {
        let converted: Vec<PeerAddr> = addrs
            .iter()
            .filter_map(|(_, a)| PeerAddr::try_from(a).ok())
            .collect();
        tracing::debug!(target: TARGET, received = addrs.len(), parsed = converted.len(), "addr");
        if !converted.is_empty() {
            let _ = self.new_addr_tx.try_send(converted);
        }
    }

    fn handle_addrv2(&self, addrs: &[AddrV2Message]) {
        let converted: Vec<PeerAddr> = addrs
            .iter()
            .filter_map(|m| PeerAddr::try_from(m).ok())
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
        self.stats.send_cmpct = Some(sc);
    }

    fn handle_fee_filter(&mut self, rate: common::bitcoin::FeeRate) {
        tracing::debug!(target: TARGET, rate=rate.to_sat_per_vb_ceil(), "received feefilter");
        self.stats.fee_filter = Some(rate);
    }

    async fn handle_get_headers(&mut self, msg: GetHeadersMessage) -> Result<()> {
        let headers = self
            .header_tree
            .read()
            .unwrap()
            .get_headers_from_locator(&msg.locator_hashes, msg.stop_hash);
        tracing::debug!(target: TARGET, count = headers.len(), "responding to getheaders");
        self.writer
            .send(NetworkMessage::Headers(
                common::p2p::message::HeadersMessage(headers),
            ))
            .await
    }

    async fn send_getheaders(&mut self) -> Result<()> {
        let locator = self.header_tree.read().unwrap().build_locator();
        let (_, height) = self.header_tree.read().unwrap().tip();
        tracing::debug!(target: TARGET, height, locator_len = locator.len(), "sending getheaders");
        self.writer
            .send(NetworkMessage::GetHeaders(GetHeadersMessage {
                version: ProtocolVersion::WTXID_RELAY_VERSION,
                locator_hashes: locator,
                stop_hash: BlockHash::from_byte_array([0; 32]),
            }))
            .await
    }

    fn handle_send_headers(&self) {
        tracing::debug!(target: TARGET, "received sendheaders");
    }

    fn handle_send_addr_v2(&self) {
        tracing::warn!(target: TARGET, "received sendaddrv2 outside of handshake");
    }
}

pub(crate) fn build_version(user_agent: &str, start_height: i32) -> NetworkMessage {
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
        user_agent: UserAgent::from_nonstandard(user_agent),
        start_height,
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
    use crate::transport::{
        TransportV1Reader, TransportV1Writer, TransportV2Reader, TransportV2Writer,
    };
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
        let mut r = TransportV1Reader::new(BufReader::new(reader));
        let mut w = TransportV1Writer {
            magic: Magic::REGTEST,
            writer,
        };
        version_handshake(&mut r, &mut w, USER_AGENT, 0)
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
        let (pr, pw) = proto.into_split();
        let mut r = TransportV2Reader { reader: pr };
        let mut w = TransportV2Writer { writer: pw };
        version_handshake(&mut r, &mut w, USER_AGENT, 0)
            .await
            .expect("v2 version handshake failed");
    }
}
