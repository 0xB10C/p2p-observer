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
        time::{Duration, interval, timeout},
    },
    tracing,
    tracing::Instrument,
};
use std::collections::VecDeque;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::RawFd;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::addresses::{Handle, book::Gossiped, peer_addr::PeerAddr, policy};
use crate::headertree::{HeaderError, HeaderTree};
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

/// Maximum time allowed for the version handshake once the transport is up.
///
/// Without this a peer that completes the TCP (and BIP324) handshake and then
/// simply never sends a version message holds the connection task forever:
/// TCP_USER_TIMEOUT only aborts a connection with unacknowledged data, and such
/// a peer is acknowledging everything we send. The task would never finish, so
/// its slot in the active-address set is never released either.
#[cfg(not(test))]
const VERSION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);
/// Shortened under test so the silent-peer case doesn't take half a minute.
#[cfg(test)]
const VERSION_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(2);

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

/// Longest user agent kept from a version message, in characters. Bitcoin
/// Core cuts at the same length (MAX_SUBVERSION_LENGTH); the string ends up
/// in every event and log line of the connection, so a peer does not get to
/// pick its size.
const MAX_USER_AGENT_CHARS: usize = 256;

/// The user agent as the peer sent it, cut to [`MAX_USER_AGENT_CHARS`].
fn cap_user_agent(ua: &str) -> String {
    ua.chars().take(MAX_USER_AGENT_CHARS).collect()
}

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
    pub(crate) send_addr_v2: bool,
    /// Peer announced BIP339 wtxid-based transaction relay support.
    pub(crate) wtxid_relay: bool,
}

/// What a session that ran and then ended leaves for the attempt's result.
///
/// The error is carried out rather than logged and dropped, because it is the
/// only thing that says *how* a session ended: without it a peer that closed
/// cleanly after three hours and one that sent a message we could not decode
/// produce the same record.
#[derive(Debug)]
pub(crate) struct SessionEnd {
    /// When the handshake completed, so the caller can split setup from uptime.
    pub(crate) connected_at: Instant,
    /// What ended the session. `None` only if the message loop returned
    /// without an error, which it has no path to do today.
    pub(crate) error: Option<common::anyhow::Error>,
    /// The peer's user agent, known because the handshake completed.
    pub(crate) user_agent: String,
}

/// A live connection to a peer, created after a successful version handshake.
struct Connection<R: TransportReader, W: TransportWriter> {
    reader: R,
    writer: W,
    addrman: Handle,
    /// Token bucket over gossiped addresses, so one peer cannot grow the book
    /// as fast as it can send.
    addr_tokens: f64,
    addr_tokens_updated: Instant,
    /// Set while we are expecting the reply to our own GETADDR. That reply is
    /// solicited, so it is not charged against the bucket.
    getaddr_outstanding: bool,
    handshake_info: HandshakeInfo,
    stats: ConnectionStats,
    /// Raw file descriptor of the TCP socket, used to query OS-level TCP stats.
    raw_fd: RawFd,
    ping_interval: Duration,
    addr: PeerAddr,
    transport_version: u8,
    connection_id: u64,
    event_tx: mpsc::Sender<common::events::PeerEvent>,
    header_tree: Arc<RwLock<HeaderTree>>,
    sync_headers: bool,
    /// The missing block this connection last asked its peer about, so the
    /// same peer announcing the same block twice is not asked twice. How many
    /// peers ask is the tree's decision.
    asked_for: Option<BlockHash>,
}

/// Everything a session needs besides the transport itself.
pub(crate) struct Session<'a> {
    /// Transport version: 1 for plaintext, 2 for BIP324. Reported in the
    /// tracing span and on every emitted event.
    pub(crate) transport_version: u8,
    pub(crate) connection_id: u64,
    pub(crate) addr: PeerAddr,
    /// Raw file descriptor of the TCP socket, used to query OS-level TCP stats.
    pub(crate) raw_fd: RawFd,
    pub(crate) cfg: &'a Config,
    pub(crate) addrman: &'a Handle,
}

/// Run the Bitcoin P2P session on an already-established transport.
///
/// Performs the version handshake, then drives the message loop until the
/// peer disconnects. Returns the `Instant` at which the handshake completed.
pub(crate) async fn run_session(
    mut reader: impl TransportReader,
    mut writer: impl TransportWriter,
    session: Session<'_>,
) -> Result<SessionEnd> {
    let Session {
        transport_version,
        connection_id,
        addr,
        raw_fd,
        cfg,
        addrman,
    } = session;

    let (_, tip_height) = &cfg.header_tree.read().unwrap().tip();
    let info = timeout(
        VERSION_HANDSHAKE_TIMEOUT,
        version_handshake(
            &mut reader,
            &mut writer,
            &cfg.user_agent,
            *tip_height as i32,
        ),
    )
    .await
    .map_err(|_| crate::connection::Stage::VersionHandshakeTimeout)?
    .map_err(|e| e.context(crate::connection::Stage::VersionHandshake))?;
    let connected_at = Instant::now();
    let conn_span = tracing::info_span!(target: TARGET, "", v = transport_version, sh=info.version.start_height, ua = %info.version.user_agent);

    // The peer's own version message is the most trustworthy source of its
    // service flags, so hand them straight to the manager.
    addrman.connected(addr, info.version.services.to_u64(), transport_version);
    tracing::trace!(target: TARGET, "connection established");

    // Before anything else this connection emits, so a reader learns what the
    // connection_id refers to when the connection opens rather than when it
    // closes -- which may be hours later, or never, if the archiver stops
    // first.
    emit_handshake(cfg, connection_id, addr, transport_version, &info);

    let mut conn = Connection {
        reader,
        writer,
        addrman: addrman.clone(),
        addr_tokens: policy::ADDR_BURST,
        addr_tokens_updated: Instant::now(),
        getaddr_outstanding: false,
        handshake_info: info,
        stats: ConnectionStats::new(),
        raw_fd,
        ping_interval: cfg.ping_interval,
        addr,
        transport_version,
        connection_id,
        event_tx: cfg.event_tx.clone(),
        header_tree: cfg.header_tree.clone(),
        sync_headers: cfg.sync_headers,
        asked_for: None,
    };
    // The session running out is not an error: the peer disconnected, which is
    // an ordinary outcome. The caller turns the elapsed time into
    // Outcome::Disconnected, and the manager decides when to try again.
    //
    // The error that ended it goes back to the caller all the same. It is what
    // tells a clean close apart from a reset or a message we could not read,
    // and it is only available here.
    let error = match conn.run().instrument(conn_span).await {
        Ok(()) => None,
        Err(e) => {
            tracing::debug!(target: TARGET, "connection error: {e}");
            Some(e)
        }
    };
    Ok(SessionEnd {
        connected_at,
        error,
        user_agent: conn.handshake_info.version.user_agent.to_string(),
    })
}

/// Publish what the peer said about itself in its version message.
fn emit_handshake(
    cfg: &Config,
    connection_id: u64,
    addr: PeerAddr,
    transport_version: u8,
    info: &HandshakeInfo,
) {
    let version = &info.version;
    crate::emit::send(
        &cfg.event_tx,
        common::events::PeerEvent {
            timestamp_ms: unix_ms(),
            peer_addr: addr.to_string(),
            user_agent: version.user_agent.to_string(),
            transport_version: Some(u32::from(transport_version)),
            connection_id,
            event: Some(common::events::peer_event::Event::Handshake(
                common::events::Handshake {
                    protocol_version: u32::from(version.version),
                    services: version.services.to_u64(),
                    start_height: version.start_height,
                    relay: version.relay,
                    peer_timestamp: version.timestamp,
                    // As sent, zeros included: peers routinely leave this
                    // field blank, and "0.0.0.0:0" is the observation rather
                    // than a value to clean up. Empty only if the bytes were
                    // not an address at all.
                    addr_recv: version
                        .receiver
                        .socket_addr()
                        .map(|s| s.to_string())
                        .unwrap_or_default(),
                    sendaddrv2: info.send_addr_v2,
                    wtxid_relay: info.wtxid_relay,
                    user_agent: version.user_agent.to_string(),
                },
            )),
            ..Default::default()
        },
    );
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
            NetworkMessage::Version(mut v) => {
                v.user_agent =
                    UserAgent::from_nonstandard(cap_user_agent(&v.user_agent.to_string()));
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
        self.getaddr_outstanding = true;
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
                    // An inv carries no header, so a block we do not know is
                    // only reachable by asking for headers.
                    if !self.header_tree.read().unwrap().contains(&hash) {
                        self.recover_headers(hash, false).await?;
                    }
                }
                Inventory::CompactBlock(hash) => {
                    tracing::info!(target: TARGET, %hash, "inv: compact block");
                    self.emit_block_announcement(hash, common::events::AnnouncementType::Inv);
                    getdata.push(Inventory::CompactBlock(hash));
                    if !self.header_tree.read().unwrap().contains(&hash) {
                        self.recover_headers(hash, false).await?;
                    }
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

        let accepted = self.accept_headers(&headers).await?;

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

    /// Offer headers to the tree, and ask this peer for more if they show the
    /// tree to be behind. Returns how many were new.
    async fn accept_headers(
        &mut self,
        headers: &[common::bitcoin::block::Header],
    ) -> Result<usize> {
        let (accepted, err) = self.header_tree.write().unwrap().insert_batch(headers);
        let (tip, height) = self.header_tree.read().unwrap().tip();

        if accepted > 0 {
            tracing::info!(target: TARGET, accepted, height, %tip, "headers inserted");
        }
        match err {
            // The parent is missing: the tree is behind, and only a getheaders
            // catches it up. During the initial sync that cannot happen, since
            // headers arrive in order from our own request.
            Some(HeaderError::OrphanHeader) if !self.sync_headers => {
                tracing::debug!(target: TARGET, height, "orphan header: the tree is behind");
                // The newest header is the block the peer is announcing, and
                // having sent the header it provably has it.
                if let Some(newest) = headers.last() {
                    self.recover_headers(newest.block_hash(), true).await?;
                }
            }
            Some(e) => tracing::warn!(target: TARGET, "header insert error: {e}"),
            None => {}
        }
        Ok(accepted)
    }

    /// Ask this peer for headers because an announcement has just shown the
    /// tree to be behind.
    ///
    /// Nothing else re-synchronises the tree once the initial sync is done, and
    /// a missed block used to leave it permanently behind: every later
    /// single-header announcement was an orphan, and only a new connection's
    /// start-of-session getheaders could catch it up -- which on a quiet
    /// network is hours. Throttled through the tree, because a new block
    /// reaches us from every connection at once and a few requests are enough.
    /// `missing` is the announced block the tree lacks; `proven` whether the
    /// announcement carried its header.
    async fn recover_headers(&mut self, missing: BlockHash, proven: bool) -> Result<()> {
        if self.asked_for == Some(missing) {
            return Ok(());
        }
        if !self
            .header_tree
            .write()
            .unwrap()
            .recovery_due(missing, proven, Instant::now())
        {
            return Ok(());
        }
        self.asked_for = Some(missing);
        tracing::info!(target: TARGET, %missing, "header tree is behind, requesting headers");
        self.send_getheaders().await
    }

    async fn handle_cmpct_block(
        &mut self,
        cmpct: common::p2p::message_compact_blocks::CmpctBlock,
    ) -> Result<()> {
        let header = cmpct.compact_block.header;
        let hash = header.block_hash();
        self.emit_block_announcement(hash, common::events::AnnouncementType::CompactBlock);
        tracing::info!(target: TARGET, %hash, "compact block");
        self.accept_headers(&[header]).await?;
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
        crate::emit::send(
            &self.event_tx,
            common::events::PeerEvent {
                timestamp_ms: unix_ms(),
                peer_addr: self.addr.to_string(),
                user_agent: self.handshake_info.version.user_agent.to_string(),
                // Always known here: nothing is emitted before the handshake.
                transport_version: Some(self.transport_version as u32),
                connection_id: self.connection_id,
                event: Some(event),
                ..Default::default()
            },
        );
    }

    fn handle_pong(&mut self, nonce: u64) {
        let rtt_ms = unix_ms().saturating_sub(nonce);
        tracing::debug!(target: TARGET, rtt_ms, "pong");
        self.stats.record_rtt(rtt_ms as u32);
        let tcp_stats = self.stats.tcp.as_ref().map(|t| common::events::TcpStats {
            srtt_us: u64::from(t.srtt_us),
            rttvar_us: u64::from(t.rttvar_us),
            total_retrans: u64::from(t.total_retrans),
            snd_cwnd: u64::from(t.snd_cwnd),
        });
        self.emit_event(common::events::peer_event::Event::PingRtt(
            common::events::PingRtt { rtt_ms, tcp_stats },
        ));
    }

    fn handle_addr(&mut self, addrs: &[(u32, Address)]) {
        // The announced nTime goes on the published event and no further: see
        // `Gossiped::ntime`.
        let parsed: Vec<Gossiped> = addrs
            .iter()
            .filter_map(|(ntime, a)| {
                Some(Gossiped {
                    addr: PeerAddr::try_from(a).ok()?,
                    services: a.services.to_u64(),
                    ntime: *ntime,
                })
            })
            .collect();
        self.offer_gossip(common::events::AddrMessage::Addr, addrs.len(), parsed);
    }

    fn handle_addrv2(&mut self, addrs: &[AddrV2Message]) {
        let parsed: Vec<Gossiped> = addrs
            .iter()
            .filter_map(|m| {
                Some(Gossiped {
                    addr: PeerAddr::try_from(m).ok()?,
                    services: m.services.to_u64(),
                    ntime: m.time,
                })
            })
            .collect();
        self.offer_gossip(common::events::AddrMessage::Addrv2, addrs.len(), parsed);
    }

    /// Rate-limit gossiped addresses and hand the survivors to the manager.
    ///
    /// A token bucket per connection, as Bitcoin Core does it: this is the
    /// single most effective bound on how fast the book grows, because inventing
    /// addresses is free and sending them costs the peer almost nothing.
    /// The reply to our own GETADDR is exempt -- we asked for it, and the
    /// protocol caps it at 1000 entries anyway.
    ///
    /// The research event is emitted with everything that was announced, before
    /// the rate limit takes effect, so a flood shows up in the archive instead
    /// of vanishing. That is also what makes crawl bias measurable after the
    /// fact: the source peer is on the event, so the share of the book owed to
    /// any one peer can be worked out offline.
    fn offer_gossip(
        &mut self,
        message: common::events::AddrMessage,
        received: usize,
        mut parsed: Vec<Gossiped>,
    ) {
        let solicited = std::mem::take(&mut self.getaddr_outstanding);

        let mut rate_limited = 0;
        if !solicited {
            let elapsed = self.addr_tokens_updated.elapsed().as_secs_f64();
            self.addr_tokens_updated = Instant::now();
            self.addr_tokens =
                (self.addr_tokens + elapsed * policy::ADDR_RATE_PER_SEC).min(policy::ADDR_BURST);

            let allowed = self.addr_tokens.floor().max(0.0) as usize;
            if parsed.len() > allowed {
                rate_limited = parsed.len() - allowed;
                // Rare, and says something: this peer is announcing faster
                // than we are willing to learn.
                // `kind`, not `message`: tracing reserves that field name for
                // the log text itself.
                tracing::debug!(target: TARGET,
                    kind = ?message, received, rate_limited,
                    "rate-limiting gossiped addresses"
                );
            }
            // Spend a token per address we keep, not per address announced:
            // the bucket is about how fast we are willing to learn.
            self.addr_tokens -= (parsed.len() - rate_limited) as f64;
        }

        self.emit_event(common::events::peer_event::Event::AddressAnnouncement(
            common::events::AddressAnnouncement {
                message: message.into(),
                // Still pre-truncation here, so this is the parse shortfall
                // rather than anything the rate limit did.
                unparsed: (received - parsed.len()) as u32,
                addresses: parsed
                    .iter()
                    .map(|g| common::events::GossipedAddress {
                        addr: g.addr.to_string(),
                        services: g.services,
                        ntime: g.ntime,
                    })
                    .collect(),
            },
        ));

        // Entries we could not turn into an address — an AddrV2 type we do not
        // understand, say. Rare, and the only part of the parse worth a line:
        // the usual case, where everything parsed, says nothing by definition.
        //
        // There is deliberately no line for the message itself. Every addr
        // message would produce one, and the event emitted just above already
        // carries the counts, the flags and the addresses, so anyone wanting
        // per-message detail can read the stream instead.
        if parsed.len() < received {
            tracing::debug!(target: TARGET,
                kind = ?message, received, unparsed = received - parsed.len(),
                "dropped gossiped addresses we could not parse"
            );
        }

        parsed.truncate(parsed.len() - rate_limited);
        if !parsed.is_empty() {
            self.addrman.gossip(parsed);
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

    // ── A connection with no peer behind it ──────────────────────────────────
    //
    // The handlers never read, so the reader can refuse; the writer keeps what
    // was sent so a test can see what a handler asked the peer for.

    struct NoReads;
    impl TransportReader for NoReads {
        async fn recv(&mut self) -> Result<NetworkMessage> {
            Err(common::anyhow::anyhow!("this test does not read"))
        }
    }

    struct Captured(Vec<NetworkMessage>);
    impl TransportWriter for Captured {
        async fn send(&mut self, msg: NetworkMessage) -> Result<()> {
            self.0.push(msg);
            Ok(())
        }
    }

    /// Everything a Connection needs besides the transport, kept alive for as
    /// long as the test holds it: the event receiver so emits do not fail, the
    /// manager channels so the handle has somewhere to send.
    struct Harness {
        conn: Connection<NoReads, Captured>,
        _events: mpsc::Receiver<common::events::PeerEvent>,
        _manager: (
            mpsc::Receiver<Vec<Gossiped>>,
            mpsc::UnboundedReceiver<crate::addresses::Lifecycle>,
            mpsc::Receiver<crate::addresses::Command>,
        ),
    }

    fn harness(tree: Arc<RwLock<HeaderTree>>) -> Harness {
        let (event_tx, events) = mpsc::channel(64);
        let (addrman, g, l, c) = crate::addresses::channels();
        let NetworkMessage::Version(version) = build_version(USER_AGENT, 0) else {
            unreachable!()
        };
        let conn = Connection {
            reader: NoReads,
            writer: Captured(Vec::new()),
            addrman,
            addr_tokens: policy::ADDR_BURST,
            addr_tokens_updated: Instant::now(),
            getaddr_outstanding: false,
            handshake_info: HandshakeInfo {
                version,
                send_addr_v2: false,
                wtxid_relay: false,
            },
            stats: ConnectionStats::new(),
            raw_fd: -1,
            ping_interval: Duration::from_secs(120),
            addr: PeerAddr::Ipv4([127, 0, 0, 1], 18444),
            transport_version: 1,
            connection_id: 7,
            event_tx,
            header_tree: tree,
            sync_headers: false,
            asked_for: None,
        };
        Harness {
            conn,
            _events: events,
            _manager: (g, l, c),
        }
    }

    fn compact_block(
        header: common::bitcoin::block::Header,
    ) -> common::p2p::message_compact_blocks::CmpctBlock {
        common::p2p::message_compact_blocks::CmpctBlock {
            compact_block: bip152::HeaderAndShortIds {
                header,
                nonce: 0,
                short_ids: Vec::new(),
                prefilled_txs: Vec::new(),
            },
        }
    }

    fn getheaders_sent(w: &Captured) -> usize {
        w.0.iter()
            .filter(|m| matches!(m, NetworkMessage::GetHeaders(_)))
            .count()
    }

    #[test]
    fn test_user_agent_is_capped() {
        let short = "/Satoshi:29.0.0/";
        assert_eq!(cap_user_agent(short), short);
        let long = "x".repeat(MAX_USER_AGENT_CHARS + 50);
        assert_eq!(cap_user_agent(&long).chars().count(), MAX_USER_AGENT_CHARS);
    }

    /// A compact block carries a header, and the tree takes it the same way as
    /// one from a HEADERS message.
    #[tokio::test]
    async fn test_compact_block_header_joins_the_tree() {
        use crate::headertree::testing::{mine_header, regtest_params};
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let (genesis, _) = tree.read().unwrap().tip();
        let h1 = mine_header(genesis, 1_700_000_000, 1);

        let mut h = harness(tree.clone());
        h.conn.handle_cmpct_block(compact_block(h1)).await.unwrap();

        assert!(tree.read().unwrap().contains(&h1.block_hash()));
        assert_eq!(tree.read().unwrap().tip().1, 1);
        // Connected straight on, so nothing to recover; the only request is
        // the probe for the coinbase.
        assert_eq!(getheaders_sent(&h.conn.writer), 0);
        assert!(
            h.conn
                .writer
                .0
                .iter()
                .any(|m| matches!(m, NetworkMessage::GetBlockTxn(_)))
        );
    }

    /// An announcement whose parent we do not have means the tree is behind,
    /// and the only way back is to ask -- a few peers, however many announce,
    /// and each of them once.
    #[tokio::test]
    async fn test_orphan_announcement_asks_a_few_peers_once_each() {
        use crate::headertree::testing::{mine_header, regtest_params};
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let (genesis, _) = tree.read().unwrap().tip();
        let h1 = mine_header(genesis, 1_700_000_000, 1);
        let h2 = mine_header(h1.block_hash(), 1_700_000_060, 2);

        // Four connections sharing the tree, as every connection does.
        let mut conns: Vec<_> = (0..4).map(|_| harness(tree.clone())).collect();
        conns[0]
            .conn
            .handle_cmpct_block(compact_block(h2))
            .await
            .unwrap();
        // The same peer announcing the same block again is not asked again.
        conns[0].conn.handle_headers(vec![h2]).await.unwrap();
        for c in &mut conns[1..] {
            c.conn.handle_headers(vec![h2]).await.unwrap();
        }

        assert!(
            !tree.read().unwrap().contains(&h2.block_hash()),
            "orphan stays out"
        );
        let sent: Vec<usize> = conns
            .iter()
            .map(|c| getheaders_sent(&c.conn.writer))
            .collect();
        assert_eq!(sent, vec![1, 1, 1, 0], "three peers asked, once each");
    }

    /// An inv carries only a hash. A hash we do not know is the same signal.
    #[tokio::test]
    async fn test_inv_for_an_unknown_block_asks_for_headers() {
        use crate::headertree::testing::{mine_header, regtest_params};
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let (genesis, _) = tree.read().unwrap().tip();
        let unknown = mine_header(genesis, 1_700_000_000, 1).block_hash();

        let mut h = harness(tree.clone());
        // A block we already have is not a reason to ask.
        h.conn
            .handle_inv(vec![Inventory::Block(genesis)])
            .await
            .unwrap();
        assert_eq!(getheaders_sent(&h.conn.writer), 0);

        h.conn
            .handle_inv(vec![Inventory::Block(unknown)])
            .await
            .unwrap();
        assert_eq!(getheaders_sent(&h.conn.writer), 1);

        // An inv says nothing about whether the peer has validated the block,
        // so while a request is out another inv for it waits.
        let mut other = harness(tree.clone());
        other
            .conn
            .handle_inv(vec![Inventory::Block(unknown)])
            .await
            .unwrap();
        assert_eq!(getheaders_sent(&other.conn.writer), 0);
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
