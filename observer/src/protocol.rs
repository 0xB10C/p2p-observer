use common::{
    anyhow::Result,
    bitcoin::{BlockHash, bip152},
    p2p::{
        ProtocolVersion, ServiceFlags, address,
        address::{AddrV2Message, Address},
        message::{CommandString, NetworkMessage},
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
use std::collections::{BTreeMap, VecDeque};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::os::unix::io::RawFd;
use std::sync::{Arc, RwLock};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::addresses::{Handle, book::Gossiped, peer_addr::PeerAddr, policy};
use crate::connections::{self, Registry};
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

/// The peer sent a header from a chain we will never accept, so the session
/// ends. Carries why the tree refused it.
///
/// A sentinel error rather than a quiet return, for the same reason
/// [`SyncComplete`] is one: the message loop's only way out is an error, and
/// the caller needs to tell this apart from a peer that went away -- it
/// decides both what the connection result says and how long the address
/// manager leaves the address alone.
#[derive(Debug, Clone)]
pub(crate) struct OtherChain {
    pub(crate) reason: HeaderError,
}

impl std::fmt::Display for OtherChain {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "peer is on another chain: {}", self.reason)
    }
}

impl std::error::Error for OtherChain {}

/// The other-chain verdict carried by an error, if it carries one.
pub(crate) fn other_chain_of(err: &common::anyhow::Error) -> Option<&OtherChain> {
    err.downcast_ref::<OtherChain>()
        .or_else(|| err.chain().find_map(|c| c.downcast_ref::<OtherChain>()))
}

/// The peer stopped answering pings, see [`PING_TIMEOUT`].
///
/// A type rather than a message so that the session end is recognised by what
/// it is, the way [`crate::transport::Fault`] and [`crate::connection::Stage`]
/// are: the alternative is matching on prose.
#[derive(Debug, Clone, Copy)]
pub(crate) struct PingTimeout {
    /// How long we had been waiting for an answer.
    pub(crate) waited: Duration,
}

impl std::fmt::Display for PingTimeout {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "no pong in {} seconds, with a ping outstanding",
            self.waited.as_secs()
        )
    }
}

impl std::error::Error for PingTimeout {}

/// The peer went outside a protocol limit, so the session is over.
///
/// Carries its own description because there is nothing else to read it from:
/// the limit that was broken is the observation.
#[derive(Debug, Clone)]
pub(crate) struct ProtocolViolation(pub(crate) String);

impl std::fmt::Display for ProtocolViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for ProtocolViolation {}

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
    /// The live sessions of this observer, which this connection adds itself
    /// to once its handshake is done.
    pub(crate) connections: Arc<Registry>,
    pub(crate) sync_headers: bool,
    /// Ask for the coinbase of every compact block, see `probe_compact_blocks`
    /// in the settings.
    pub(crate) probe_compact_blocks: bool,
    pub(crate) networks: crate::settings::NetworksConfig,
}

/// We want high-bandwidth compact block relay (BIP152): the peer sends a new
/// block as a compact block straight away, without an INV first, which is the
/// earliest a passive observer hears of it. With `probe_compact_blocks` on we
/// then ask for a transaction via getblocktxn to learn how long it took the
/// peer to have the block in hand.
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

/// The most headers a HEADERS message can carry and still be an announcement.
///
/// Core announces at most this many at once (its MAX_BLOCKS_TO_ANNOUNCE); a
/// reply to getheaders carries up to two thousand. Above the limit the message
/// is a sync response -- our request being answered, not the peer telling us
/// about a block -- and emitting one announcement per header turned a single
/// reply into a thousand events that read as a thousand new blocks.
const MAX_HEADERS_ANNOUNCED: usize = 8;

/// The most blocks one INV may announce before the rest are only counted.
///
/// The same reasoning as [`MAX_HEADERS_ANNOUNCED`], and the same number: more
/// block items than Core would ever announce at once is not a peer telling us
/// about blocks. We never send getblocks either, so nothing we asked for comes
/// back this way.
///
/// Past the cap the items are not acted on at all, rather than emitted and
/// discarded later: every one of them costs a lookup in the header tree, an
/// event, a log line and -- for a block the tree lacks -- a turn through the
/// recovery throttle, which takes the tree's write lock. An INV is one message
/// from one peer and must not be able to buy fifty thousand of those.
const MAX_BLOCK_INVS_ANNOUNCED: usize = MAX_HEADERS_ANNOUNCED;

/// The most items an INV may carry at all, past which the session ends.
///
/// The protocol's own limit, which Core disconnects over. Nothing legitimate
/// comes close: a peer announcing blocks sends a handful.
const MAX_INV_SIZE: usize = common::p2p::message::MAX_INV_SIZE;

/// How many unanswered pings to remember.
///
/// A pong's nonce is the millisecond the ping was sent, which is what makes an
/// RTT out of it -- so a nonce we have no record of sending yields a number in
/// the trillions rather than a latency. At the default ping interval ten
/// outstanding pings is twenty minutes of patience with a slow peer, past
/// which an answer is treated as one we never asked for.
const OUTSTANDING_PINGS: usize = 10;

/// How long a ping may go unanswered before the session is over.
///
/// Nothing else ends a session with a peer that acknowledges our packets and
/// answers none of them. TCP_USER_TIMEOUT only fires on data a peer leaves
/// unacknowledged, so to the kernel such a connection is in perfect health,
/// and the task holds its socket, its buffers and the address's slot in the
/// active set for as long as the process runs. Bitcoin Core gives a peer the
/// same twenty minutes (its TIMEOUT_INTERVAL) before dropping it.
const PING_TIMEOUT: Duration = Duration::from_secs(20 * 60);

/// Tokens for answering a GETHEADERS, and how fast they come back.
///
/// The one request a peer can make of us that is cheap to send and expensive
/// to answer: a locator is a few hundred bytes, the reply is up to two
/// thousand headers -- a hundred and sixty kilobytes -- copied out of the tree
/// under its read lock, which every connection inserting a header then waits
/// for. Nothing stopped a peer asking in a loop.
///
/// A peer asks once when the session opens, and again only if it announces a
/// block whose parent it thinks we lack. We announce nothing, so that is rare:
/// four to start with and one every thirty seconds is far more than any
/// implementation uses, and it holds what one peer can draw out of us to a
/// reply every thirty seconds.
///
/// Not a reflection -- TCP cannot be reflected, so a peer asking has to take
/// the bytes itself. What the limit protects is the uplink, which is finite
/// and shared with the job of reaching every other peer, against an asker
/// spending a hundred bytes per request in the direction that is cheap for
/// them.
///
/// Over the limit the request is dropped rather than answered late or
/// answered empty. An empty HEADERS means "I have nothing after your
/// locator", which is a claim about the chain and not about our patience, and
/// a peer that believes it may stop asking the one question we want asked.
const GETHEADERS_BURST: f64 = 4.0;
const GETHEADERS_RATE_PER_SEC: f64 = 1.0 / 30.0;

/// Distinct commands counted per session.
///
/// The command string comes off the wire, so the key space belongs to the
/// peer. Past the cap everything lands in one bucket rather than growing a map
/// a peer controls the size of.
const MESSAGES_BY_COMMAND_CAP: usize = 64;

/// Per-connection state and statistics accumulated during the session.
struct ConnectionStats {
    /// Rolling window of last 10 RTT samples in milliseconds.
    rtt_history: VecDeque<u32>,
    /// Nonces of pings sent and not yet answered, oldest first.
    outstanding_pings: VecDeque<u64>,
    /// Pongs carrying a nonce we never sent.
    unsolicited_pongs: u32,
    /// GETHEADERS we did not answer, having run out of tokens.
    getheaders_ignored: u32,
    /// When the peer last answered a ping, or the handshake if it never has.
    ///
    /// The deadline runs from here rather than from the oldest outstanding
    /// ping, because [`OUTSTANDING_PINGS`] forgets the oldest once the queue
    /// is full: at a short ping interval the front of that queue is never more
    /// than a few minutes old, however long the peer has been quiet.
    last_pong: Instant,
    /// Messages received from the peer, by command.
    messages_by_command: BTreeMap<String, u32>,
    /// Messages received whose command did not fit the cap.
    messages_other: u32,
}

impl ConnectionStats {
    fn new() -> Self {
        Self {
            rtt_history: VecDeque::new(),
            outstanding_pings: VecDeque::new(),
            unsolicited_pongs: 0,
            getheaders_ignored: 0,
            last_pong: Instant::now(),
            messages_by_command: BTreeMap::new(),
            messages_other: 0,
        }
    }

    /// Remember a ping we just sent, forgetting the oldest if we are now
    /// tracking more than we care to.
    fn record_ping(&mut self, nonce: u64) {
        self.outstanding_pings.push_back(nonce);
        if self.outstanding_pings.len() > OUTSTANDING_PINGS {
            self.outstanding_pings.pop_front();
        }
    }

    /// Whether this pong answers a ping we sent, consuming it if so.
    ///
    /// Older pings are left alone rather than discarded: a peer that answers
    /// out of order is answering all the same, and dropping them here would
    /// turn its next reply into an unsolicited one.
    fn claim_pong(&mut self, nonce: u64) -> bool {
        match self.outstanding_pings.iter().position(|n| *n == nonce) {
            Some(i) => {
                self.outstanding_pings.remove(i);
                self.last_pong = Instant::now();
                true
            }
            None => {
                self.unsolicited_pongs = self.unsolicited_pongs.saturating_add(1);
                false
            }
        }
    }

    /// How long the peer has owed us an answer, once that is too long.
    ///
    /// `None` while nothing is outstanding: a peer we have not pinged owes us
    /// nothing, and silence on its own is not something to disconnect over --
    /// a peer that only listens is still a peer worth observing.
    fn ping_timed_out(&self, now: Instant) -> Option<Duration> {
        let waited = now.saturating_duration_since(self.last_pong);
        (!self.outstanding_pings.is_empty() && waited >= PING_TIMEOUT).then_some(waited)
    }

    /// Count one received message against its command.
    fn record_message(&mut self, command: &str) {
        if let Some(count) = self.messages_by_command.get_mut(command) {
            *count = count.saturating_add(1);
        } else if self.messages_by_command.len() < MESSAGES_BY_COMMAND_CAP {
            self.messages_by_command.insert(command.to_owned(), 1);
        } else {
            self.messages_other = self.messages_other.saturating_add(1);
        }
    }

    /// The totals as they stand, for the registry.
    fn counters(&self) -> connections::Counters {
        connections::Counters {
            messages: self
                .messages_by_command
                .values()
                .map(|n| u64::from(*n))
                .sum::<u64>()
                + u64::from(self.messages_other),
            unsolicited_pongs: self.unsolicited_pongs,
            // The window the connection keeps, so the lowest here is the
            // lowest of the recent samples rather than of the session.
            rtt_ms: self.rtt_history.back().copied(),
            min_rtt_ms: self.rtt_history.iter().min().copied(),
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
    pub(crate) messages_by_command: BTreeMap<String, u32>,
    pub(crate) messages_other: u32,
    pub(crate) unsolicited_pongs: u32,
    /// Messages skipped because their payload would not deserialize.
    pub(crate) undecodable: u32,
    /// GETHEADERS left unanswered by the rate limit.
    pub(crate) getheaders_ignored: u32,
}

impl SessionEnd {
    /// Whether the peer sent nothing at all after the handshake. Such a
    /// session taught us nothing, and the address manager backs off a peer
    /// that keeps producing them.
    pub(crate) fn silent(&self) -> bool {
        self.messages_by_command.is_empty() && self.messages_other == 0
    }
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
    /// The same, over answering GETHEADERS, see [`GETHEADERS_BURST`].
    getheaders_tokens: f64,
    getheaders_tokens_updated: Instant,
    /// Set while we are expecting the reply to our own GETADDR. That reply is
    /// solicited, so it is not charged against the bucket. Taken by the first
    /// addr message that is not the peer's own self-announcement.
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
    connections: Arc<Registry>,
    sync_headers: bool,
    /// The missing block this connection last asked its peer about, so the
    /// same peer announcing the same block twice is not asked twice. How many
    /// peers ask is the tree's decision.
    asked_for: Option<BlockHash>,
    probe_compact_blocks: bool,
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

    // Held for the life of the session: dropping it takes the session out of
    // the registry, so a task that ends, panics or is cancelled cannot leave
    // a connection in there that is no longer running.
    let _registered = cfg
        .connections
        .register(connection_id, live(addr, transport_version, &info));

    let mut conn = Connection {
        reader,
        writer,
        addrman: addrman.clone(),
        addr_tokens: policy::ADDR_BURST,
        addr_tokens_updated: Instant::now(),
        getheaders_tokens: GETHEADERS_BURST,
        getheaders_tokens_updated: Instant::now(),
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
        connections: cfg.connections.clone(),
        sync_headers: cfg.sync_headers,
        asked_for: None,
        probe_compact_blocks: cfg.probe_compact_blocks,
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
        messages_by_command: conn.stats.messages_by_command,
        messages_other: conn.stats.messages_other,
        unsolicited_pongs: conn.stats.unsolicited_pongs,
        undecodable: conn.reader.undecodable(),
        getheaders_ignored: conn.stats.getheaders_ignored,
    })
}

/// What the registry holds about a session that has just handshaken: the
/// peer's claims as made, and no counters yet.
fn live(addr: PeerAddr, transport_version: u8, info: &HandshakeInfo) -> connections::Live {
    let version = &info.version;
    connections::Live {
        addr,
        transport_version,
        connected_ms: unix_ms(),
        user_agent: version.user_agent.to_string(),
        protocol_version: u32::from(version.version),
        services: version.services.to_u64(),
        start_height: version.start_height,
        relay: version.relay,
        sendaddrv2: info.send_addr_v2,
        wtxid_relay: info.wtxid_relay,
        addr_recv: version
            .receiver
            .socket_addr()
            .map(|s| s.to_string())
            .unwrap_or_default(),
        peer_timestamp: version.timestamp,
        counters: connections::Counters::default(),
        updated_ms: 0,
    }
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
                    nonce: version.nonce,
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
                _ = ping_timer.tick() => self.ping_tick().await?,
                msg = self.reader.recv() => self.handle_message(msg?).await?,
            }
        }
    }

    /// The ping timer fired: either the peer has owed us an answer for too
    /// long, or it gets another ping.
    ///
    /// Checked here rather than on its own timer: the deadline is twenty
    /// minutes and the interval is minutes, so the tick is a fine enough
    /// grain, and one timer is one place where the session can end.
    async fn ping_tick(&mut self) -> Result<()> {
        if let Some(waited) = self.stats.ping_timed_out(Instant::now()) {
            tracing::debug!(target: TARGET,
                waited_secs = waited.as_secs(),
                "peer stopped answering pings"
            );
            return Err(PingTimeout { waited }.into());
        }
        self.send_ping().await
    }

    async fn send_ping(&mut self) -> Result<()> {
        let nonce = unix_ms();
        tracing::trace!(target: TARGET, ts_ms = nonce, "sending ping");
        self.stats.record_ping(nonce);
        // The ping timer is the registry's refresh timer too: it is the one
        // thing a long session does on a schedule, so the totals there are
        // never more than a ping interval old and nothing else has to wake up
        // to keep them so.
        self.connections
            .refresh(self.connection_id, self.stats.counters(), nonce);
        self.writer.send(NetworkMessage::Ping(nonce)).await
    }

    async fn handle_message(&mut self, msg: NetworkMessage) -> Result<()> {
        self.stats.record_message(msg.command().as_ref());
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
            NetworkMessage::Unknown { command, payload } => self.handle_unknown(&command, &payload),
            other => tracing::trace!(target: TARGET, "received: {:?}", other),
        }
        Ok(())
    }

    async fn handle_inv(&mut self, inv: Vec<Inventory>) -> Result<()> {
        if inv.len() > MAX_INV_SIZE {
            return Err(ProtocolViolation(format!(
                "inv of {} items, over the protocol's {MAX_INV_SIZE}",
                inv.len()
            ))
            .into());
        }

        // Counted before anything is emitted, so each announcement from this
        // message can report how many blocks it came with -- the same thing
        // `batch_size` says for a HEADERS announcement, and the only place the
        // size of a flood survives into the stream.
        let blocks = inv
            .iter()
            .filter(|i| {
                matches!(
                    i,
                    Inventory::Block(_) | Inventory::WitnessBlock(_) | Inventory::CompactBlock(_)
                )
            })
            .count();
        let mut getdata = Vec::new();
        let mut announced = 0;

        for item in inv {
            let (hash, compact) = match item {
                Inventory::Block(hash) | Inventory::WitnessBlock(hash) => (hash, false),
                Inventory::CompactBlock(hash) => (hash, true),
                _ => continue,
            };
            if announced >= MAX_BLOCK_INVS_ANNOUNCED {
                // Nothing further in the message is acted on, and the count
                // above already has its size.
                break;
            }
            announced += 1;

            tracing::info!(target: TARGET, %hash, compact, "inv: block");
            let known = self.header_tree.read().unwrap().seen(&hash);
            self.emit_block_announcement(
                hash,
                common::events::AnnouncementType::Inv,
                blocks as u32,
                !known,
                None,
            );
            if compact {
                getdata.push(Inventory::CompactBlock(hash));
            }
            // An inv carries no header, so a block we do not know is only
            // reachable by asking for headers.
            if !known {
                self.recover_headers(hash, false).await?;
            }
        }

        if blocks > announced {
            tracing::debug!(target: TARGET,
                blocks,
                announced,
                "inv announces more blocks than we act on"
            );
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

        // Taken before the insertion below, which is what makes "new to us"
        // mean anything.
        let known_before: Vec<bool> = {
            let tree = self.header_tree.read().unwrap();
            headers.iter().map(|h| tree.seen(&h.block_hash())).collect()
        };
        let (accepted, other_chain) = self.accept_headers(&headers).await?;

        if !self.sync_headers {
            if headers.len() > MAX_HEADERS_ANNOUNCED {
                tracing::debug!(target: TARGET, count = headers.len(), "headers are a sync response, not an announcement");
            } else {
                for (header, known) in headers.iter().zip(known_before) {
                    self.emit_block_announcement(
                        header.block_hash(),
                        common::events::AnnouncementType::Headers,
                        headers.len() as u32,
                        !known,
                        None,
                    );
                }
            }
        }

        // The announcements are out, so the block and the reason it has no
        // height are recorded. Now the session ends.
        if let Some(reason) = other_chain {
            return Err(OtherChain { reason }.into());
        }

        if self.sync_headers && accepted > 0 {
            self.send_getheaders().await?;
        }

        Ok(())
    }

    /// Offer headers to the tree, and ask this peer for more if they show the
    /// tree to be behind. Returns how many were new.
    /// Returns how many headers were new, and the verdict when the peer has
    /// just shown itself to be on a chain we refuse. The verdict is handed
    /// back rather than raised here so the caller can publish the
    /// announcement first: the block it carried is an observation, and the
    /// archive should have it along with the reason it has no height.
    async fn accept_headers(
        &mut self,
        headers: &[common::bitcoin::block::Header],
    ) -> Result<(usize, Option<HeaderError>)> {
        let (accepted, err) = self.header_tree.write().unwrap().insert_batch(headers);
        let (tip, height) = self.header_tree.read().unwrap().tip();

        if accepted > 0 {
            tracing::info!(target: TARGET, accepted, height, %tip, "headers inserted");
        }
        let mut other_chain = None;
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
            // Rejected, or built on something that was. A peer that sends us
            // a header of a chain we refuse is telling us which chain it
            // follows, which is the one thing worth acting on here.
            Some(e) => {
                tracing::debug!(target: TARGET, "header not placed: {e}");
                if e.is_other_chain() {
                    other_chain = Some(e);
                }
            }
            None => {}
        }
        Ok((accepted, other_chain))
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
        // Not missing: refused. Asking for it again would fetch the same
        // chain and refuse it again.
        if self
            .header_tree
            .read()
            .unwrap()
            .rejection_of(&missing)
            .is_some()
        {
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
        tracing::info!(target: TARGET, %hash, "compact block");
        let known = self.header_tree.read().unwrap().seen(&hash);
        let shape = common::events::CompactBlockShape {
            short_ids: cmpct.compact_block.short_ids.len() as u32,
            prefilled_txs: cmpct.compact_block.prefilled_txs.len() as u32,
        };
        let (_, other_chain) = self.accept_headers(&[header]).await?;
        self.emit_block_announcement(
            hash,
            common::events::AnnouncementType::CompactBlock,
            1,
            !known,
            Some(shape),
        );
        if let Some(reason) = other_chain {
            return Err(OtherChain { reason }.into());
        }
        if self.probe_compact_blocks {
            self.request_compact_block_coinbase(hash).await?;
        }
        Ok(())
    }

    fn emit_block_announcement(
        &self,
        hash: common::bitcoin::BlockHash,
        announcement_type: common::events::AnnouncementType,
        batch_size: u32,
        new_to_us: bool,
        compact_block: Option<common::events::CompactBlockShape>,
    ) {
        use common::events::{AnnouncementType, Unplaced};
        // Looked up after any insertion, so a header just accepted has one.
        let (height, unplaced) = {
            let tree = self.header_tree.read().unwrap();
            let height = tree.height_of(&hash);
            let unplaced = match (height, tree.rejection_of(&hash)) {
                (Some(_), _) => None,
                (None, Some(reason)) => Some(unplaced_for(reason)),
                // No header has been seen for a bare inv; any other
                // announcement carried one, so the tree lacks its parent.
                (None, None) if announcement_type == AnnouncementType::Inv => {
                    Some(Unplaced::NoHeader)
                }
                (None, None) => Some(Unplaced::Orphan),
            };
            (height, unplaced)
        };
        self.emit_event(common::events::peer_event::Event::BlockAnnouncement(
            common::events::BlockAnnouncement {
                block_hash: hash.to_string(),
                announcement_type: announcement_type.into(),
                // Sampled here rather than taken from the last ping: the point
                // of the stats on a block announcement is the state of the
                // path at the moment the block arrived, and the last ping can
                // be a whole ping interval ago.
                tcp_stats: self.sample_tcp_stats(),
                batch_size,
                height,
                new_to_us,
                compact_block,
                unplaced: unplaced.map(i32::from),
            },
        ));
    }

    fn emit_compact_block_probe(&self, hash: BlockHash, stage: common::events::ProbeStage) {
        self.emit_event(common::events::peer_event::Event::CompactBlockProbe(
            common::events::CompactBlockProbe {
                block_hash: hash.to_string(),
                stage: stage.into(),
                tcp_stats: self.sample_tcp_stats(),
            },
        ));
    }

    /// Read the socket's current statistics, for an event that wants the path
    /// as it is now rather than as it was at the last ping.
    fn sample_tcp_stats(&self) -> Option<common::events::TcpStats> {
        crate::tcp::tcp_info(self.raw_fd)
            .as_ref()
            .map(tcp_stats_event)
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
        self.emit_compact_block_probe(hash, common::events::ProbeStage::Requested);
        Ok(())
    }

    async fn handle_blocktxn(&mut self, blocktxn: BlockTxn) {
        let hash = blocktxn.transactions.block_hash;
        tracing::trace!(target: TARGET, %hash, txns=blocktxn.transactions.transactions.len(), "received blocktxn for cmptblock");
        self.emit_compact_block_probe(hash, common::events::ProbeStage::Answered);
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
        // The nonce is the millisecond the ping went out, so one we have no
        // record of sending is not a late RTT -- it is unix time, and would
        // land a sample in the trillions. Count the peer's behaviour and
        // publish nothing.
        if !self.stats.claim_pong(nonce) {
            tracing::debug!(target: TARGET, nonce, "pong for a ping we never sent");
            return;
        }
        let rtt_ms = unix_ms().saturating_sub(nonce);
        tracing::debug!(target: TARGET, rtt_ms, "pong");
        self.stats.record_rtt(rtt_ms as u32);
        // Sampled as the pong arrives, like every other TCP sample in the
        // stream: the path as this event happened, not as the ping went out.
        let tcp_stats = self.sample_tcp_stats();
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
        self.offer_addrv2(addrs.len(), addrs);
    }

    /// `received` is how many entries the message declared, which is more
    /// than `addrs` holds when some would not parse.
    fn offer_addrv2(&mut self, received: usize, addrs: &[AddrV2Message]) {
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
        self.offer_gossip(common::events::AddrMessage::Addrv2, received, parsed);
    }

    /// A message the decoder left as raw bytes: a command it does not know, or
    /// one it knows whose payload it rejected and the transport handed up
    /// anyway (see `transport::undecodable`).
    fn handle_unknown(&mut self, command: &CommandString, payload: &[u8]) {
        if command.as_ref() == "addrv2" {
            // The decoder knows addrv2, so this is a message it rejected.
            // It refuses the whole message over one entry it does not like;
            // read around that entry and keep the rest.
            let (received, entries) = parse_addrv2_leniently(payload);
            tracing::debug!(target: TARGET, received, parsed = entries.len(), "addrv2 read leniently");
            self.offer_addrv2(received, &entries);
        } else {
            tracing::trace!(target: TARGET,
                command = command.as_ref(), len = payload.len(), "received an unknown message"
            );
        }
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
        // A peer announces its own address on its own schedule, and usually
        // gets that one-entry message out before it answers our GETADDR. It
        // is not the reply, so it must not take the flag: that left the real
        // reply charged against the bucket, which it drained for the rest of
        // the session, and archived as unsolicited.
        let self_announcement = received == 1 && parsed.len() == 1 && parsed[0].addr == self.addr;
        let solicited = !self_announcement && std::mem::take(&mut self.getaddr_outstanding);

        // Refilled whether or not this message will be charged, so the level
        // reported below means the same thing on both paths. Harmless to the
        // limiter: the refill is capped and monotonic in elapsed time, so
        // doing it in two steps lands where one step would have.
        let elapsed = self.addr_tokens_updated.elapsed().as_secs_f64();
        self.addr_tokens_updated = Instant::now();
        self.addr_tokens =
            (self.addr_tokens + elapsed * policy::ADDR_RATE_PER_SEC).min(policy::ADDR_BURST);
        let tokens = self.addr_tokens;

        let mut rate_limited = 0;
        if !solicited {
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
                // Nothing else in the stream records that we asked, so without
                // this the limiter's behaviour cannot be reconstructed from an
                // archive: a solicited announcement is not charged at all.
                solicited,
                // What the limiter discarded, and the bucket it discarded it
                // against. Both are observer policy, and both are here because
                // the alternative is a reader re-deriving them from constants
                // that live in the binary.
                rate_limited: rate_limited as u32,
                rate_limit_tokens: tokens,
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
        self.emit_event(common::events::peer_event::Event::SendCmpct(
            common::events::SendCmpct {
                high_bandwidth: sc.send_compact,
                version: sc.version,
            },
        ));
    }

    fn handle_fee_filter(&mut self, rate: common::bitcoin::FeeRate) {
        tracing::debug!(target: TARGET, ?rate, "received feefilter");
        self.emit_event(common::events::peer_event::Event::FeeFilter(
            common::events::FeeFilter {
                // The wire value is whole sat/kvB, so the floor is exact.
                feerate_sat_per_kvb: rate.to_sat_per_kvb_floor(),
            },
        ));
    }

    /// Whether this GETHEADERS gets an answer, spending a token if it does.
    ///
    /// The same token bucket as gossiped addresses, refilled on read so there
    /// is no timer to keep: see [`GETHEADERS_BURST`].
    fn may_answer_getheaders(&mut self) -> bool {
        let elapsed = self.getheaders_tokens_updated.elapsed().as_secs_f64();
        self.getheaders_tokens_updated = Instant::now();
        self.getheaders_tokens =
            (self.getheaders_tokens + elapsed * GETHEADERS_RATE_PER_SEC).min(GETHEADERS_BURST);
        if self.getheaders_tokens < 1.0 {
            return false;
        }
        self.getheaders_tokens -= 1.0;
        true
    }

    async fn handle_get_headers(&mut self, msg: GetHeadersMessage) -> Result<()> {
        if !self.may_answer_getheaders() {
            self.stats.getheaders_ignored = self.stats.getheaders_ignored.saturating_add(1);
            tracing::debug!(target: TARGET,
                locator_len = msg.locator_hashes.len(),
                ignored = self.stats.getheaders_ignored,
                "not answering getheaders: out of tokens"
            );
            return Ok(());
        }
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

/// Why the tree refused a header, as the archive says it.
fn unplaced_for(reason: HeaderError) -> common::events::Unplaced {
    use common::events::Unplaced;
    match reason {
        HeaderError::OrphanHeader => Unplaced::Orphan,
        HeaderError::WeakerChain => Unplaced::WeakerChain,
        HeaderError::InvalidPow | HeaderError::TargetTooEasy => Unplaced::InvalidPow,
        HeaderError::CheckpointMismatch => Unplaced::CheckpointMismatch,
        HeaderError::ForkBelowCheckpoint => Unplaced::ForkBelowCheckpoint,
    }
}

/// Read an addrv2 payload the decoder rejected, keeping the entries it would
/// have accepted.
///
/// rust-bitcoin decodes the message as one value and refuses all of it over a
/// single entry it does not like, and one such entry is common: btcd gossips
/// IPv4 addresses as IPv4-mapped IPv6 under the IPv6 network id, which BIP155
/// forbids, so its thousand-entry reply to our getaddr failed on the first of
/// them on every connection. Each entry carries its own length, so the bad
/// entry can be stepped over and the rest kept.
///
/// Returns the entry count the message declared and the entries that parsed.
/// Stops at the first entry whose framing cannot be followed; what came before
/// it is kept.
fn parse_addrv2_leniently(payload: &[u8]) -> (usize, Vec<AddrV2Message>) {
    use common::bitcoin::consensus::{
        Decodable, deserialize,
        encode::{ReadExt, WriteExt},
    };

    let mut r = std::io::Cursor::new(payload);
    let Ok(count) = r.read_compact_size() else {
        return (0, Vec::new());
    };
    // Every entry takes at least nine bytes, so a count that could not fit is
    // not one to report as received.
    let count = usize::try_from(count)
        .unwrap_or(usize::MAX)
        .min(payload.len() / 9);
    let mut entries = Vec::new();

    for _ in 0..count {
        let Ok(time) = u32::consensus_decode(&mut r) else {
            break;
        };
        let Ok(services) = r.read_compact_size() else {
            break;
        };
        let Ok(network) = r.read_u8() else {
            break;
        };
        let Ok(len) = r.read_compact_size() else {
            break;
        };
        let start = r.position() as usize;
        let Some(addr) = usize::try_from(len)
            .ok()
            .and_then(|len| payload.get(start..start.checked_add(len)?))
        else {
            break;
        };
        r.set_position((start + addr.len()) as u64);
        let Ok(port) = u16::consensus_decode(&mut r) else {
            break;
        };

        // The address alone goes to the decoder, so it still judges every
        // entry; it just no longer judges the message by one of them.
        let mut raw = vec![network];
        raw.emit_compact_size(len).expect("writing to a Vec");
        raw.extend_from_slice(addr);
        if let Ok(addr) = deserialize::<address::AddrV2>(&raw) {
            entries.push(AddrV2Message {
                time,
                services: ServiceFlags::from(services),
                addr,
                // Big-endian on the wire, as the decoder reads it.
                port: port.swap_bytes(),
            });
        }
    }
    (count, entries)
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
        nonce: rand::random(),
        user_agent: UserAgent::from_nonstandard(user_agent),
        start_height,
        relay: false,
    })
}

pub(crate) fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Turn a sampled socket into the event form.
///
/// The optional fields stay optional: on a platform that does not report a
/// minimum RTT or a loss estimate, absent is the truth and zero would be a
/// claim of no loss and no distance.
fn tcp_stats_event(t: &crate::tcp::TcpStats) -> common::events::TcpStats {
    common::events::TcpStats {
        srtt_us: t.srtt_us,
        rttvar_us: t.rttvar_us,
        total_retrans: t.total_retrans,
        snd_cwnd: t.snd_cwnd,
        min_rtt_us: t.min_rtt_us,
        lost: t.lost,
        reordering: t.reordering,
        delivery_rate: t.delivery_rate,
        bytes_received: t.bytes_received,
    }
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
        events: mpsc::Receiver<common::events::PeerEvent>,
        _manager: (
            mpsc::Receiver<Vec<Gossiped>>,
            mpsc::UnboundedReceiver<crate::addresses::Lifecycle>,
            mpsc::Receiver<crate::addresses::Command>,
        ),
    }

    fn harness(tree: Arc<RwLock<HeaderTree>>) -> Harness {
        // Roomier than the gossip shedding threshold, so address
        // announcements reach the tests too.
        let (event_tx, events) = mpsc::channel(crate::emit::GOSSIP_SHED_BELOW + 64);
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
            getheaders_tokens: GETHEADERS_BURST,
            getheaders_tokens_updated: Instant::now(),
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
            connections: Registry::new(),
            sync_headers: false,
            asked_for: None,
            probe_compact_blocks: false,
        };
        Harness {
            conn,
            events,
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

    fn headers_sent(w: &Captured) -> usize {
        w.0.iter()
            .filter(|m| matches!(m, NetworkMessage::Headers(_)))
            .count()
    }

    fn getheaders_sent(w: &Captured) -> usize {
        w.0.iter()
            .filter(|m| matches!(m, NetworkMessage::GetHeaders(_)))
            .count()
    }

    #[test]
    fn test_version_nonce_is_fresh() {
        let nonce = |msg: NetworkMessage| match msg {
            NetworkMessage::Version(v) => v.nonce,
            other => panic!("not a version message: {other:?}"),
        };
        let first = nonce(build_version(USER_AGENT, 0));
        let second = nonce(build_version(USER_AGENT, 0));
        assert_ne!(first, 0);
        assert_ne!(first, second);
    }

    /// A peer may ask for headers faster than we are willing to answer: the
    /// first few asks get a reply, the rest are dropped and counted. The reply
    /// is up to two thousand headers for a locator of a few hundred bytes,
    /// which is the whole reason this is metered.
    #[tokio::test]
    async fn test_getheaders_is_answered_only_so_often() {
        use crate::headertree::testing::{mine_header, regtest_params};
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let (genesis, _) = tree.read().unwrap().tip();
        let h1 = mine_header(genesis, 1_700_000_000, 1);
        tree.write().unwrap().insert_batch(&[h1]);
        let mut h = harness(tree);
        let ask = GetHeadersMessage {
            version: ProtocolVersion::WTXID_RELAY_VERSION,
            locator_hashes: vec![genesis],
            stop_hash: BlockHash::from_byte_array([0; 32]),
        };

        let burst = GETHEADERS_BURST as usize;
        for _ in 0..burst + 3 {
            h.conn.handle_get_headers(ask.clone()).await.unwrap();
        }
        // Answered while there were tokens, counted after that, and the
        // session stays up either way: asking often is not a protocol
        // violation, and hanging up would change what we are here to watch.
        assert_eq!(headers_sent(&h.conn.writer), burst);
        assert_eq!(h.conn.stats.getheaders_ignored, 3);

        // Tokens come back with time.
        h.conn.getheaders_tokens_updated = h
            .conn
            .getheaders_tokens_updated
            .checked_sub(Duration::from_secs(60))
            .expect("a monotonic clock older than a minute");
        h.conn.handle_get_headers(ask).await.unwrap();
        assert_eq!(headers_sent(&h.conn.writer), burst + 1);
        assert_eq!(h.conn.stats.getheaders_ignored, 3);
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

        assert!(tree.read().unwrap().height_of(&h1.block_hash()).is_some());
        assert_eq!(tree.read().unwrap().tip().1, 1);
        // Announced with its height, and as the first time we saw it.
        let Some(common::events::peer_event::Event::BlockAnnouncement(a)) =
            h.events.try_recv().unwrap().event
        else {
            panic!("expected a block announcement first");
        };
        assert_eq!(a.height, Some(1));
        assert!(a.new_to_us);
        // The test block is empty, and says so; an inv would say nothing.
        let shape = a.compact_block.expect("a compact block carries its shape");
        assert_eq!((shape.short_ids, shape.prefilled_txs), (0, 0));
        // The same block from another peer: same height, no longer new.
        h.conn.handle_cmpct_block(compact_block(h1)).await.unwrap();
        let Some(common::events::peer_event::Event::BlockAnnouncement(b)) =
            h.events.try_recv().unwrap().event
        else {
            panic!("expected a block announcement for the repeat");
        };
        assert_eq!(b.height, Some(1));
        assert!(!b.new_to_us);
        // Connected straight on, so nothing to recover, and the coinbase probe
        // is off unless asked for: no request of any kind went out.
        assert_eq!(getheaders_sent(&h.conn.writer), 0);
        assert!(h.conn.writer.0.is_empty());
        assert!(h.events.try_recv().is_err());
    }

    /// The coinbase probe is opt-in: one getblocktxn per peer per block is a
    /// cost only a validation-time study wants to pay. Switched on, the request
    /// and the answer each publish their half of the probe.
    #[tokio::test]
    async fn test_compact_block_probe_is_opt_in() {
        use crate::headertree::testing::{mine_header, regtest_params};
        use common::events::{ProbeStage, peer_event::Event};
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let (genesis, _) = tree.read().unwrap().tip();
        let h1 = mine_header(genesis, 1_700_000_000, 1);
        let mut h = harness(tree);
        h.conn.probe_compact_blocks = true;

        h.conn.handle_cmpct_block(compact_block(h1)).await.unwrap();
        let Some(Event::BlockAnnouncement(_)) = h.events.try_recv().unwrap().event else {
            panic!("expected the announcement first");
        };
        let Some(Event::CompactBlockProbe(p)) = h.events.try_recv().unwrap().event else {
            panic!("expected the probe request");
        };
        assert_eq!(p.stage, ProbeStage::Requested as i32);
        assert_eq!(p.block_hash, h1.block_hash().to_string());
        assert!(
            h.conn
                .writer
                .0
                .iter()
                .any(|m| matches!(m, NetworkMessage::GetBlockTxn(_)))
        );

        h.conn
            .handle_blocktxn(BlockTxn {
                transactions: bip152::BlockTransactions {
                    block_hash: h1.block_hash(),
                    transactions: vec![],
                },
            })
            .await;
        let Some(Event::CompactBlockProbe(p)) = h.events.try_recv().unwrap().event else {
            panic!("expected the probe answer");
        };
        assert_eq!(p.stage, ProbeStage::Answered as i32);
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
            tree.read().unwrap().height_of(&h2.block_hash()).is_none(),
            "orphan stays out"
        );
        let sent: Vec<usize> = conns
            .iter()
            .map(|c| getheaders_sent(&c.conn.writer))
            .collect();
        assert_eq!(sent, vec![1, 1, 1, 0], "three peers asked, once each");
        let Some(common::events::peer_event::Event::BlockAnnouncement(a)) =
            conns[1].events.try_recv().unwrap().event
        else {
            panic!("expected an announcement");
        };
        assert_eq!(
            (a.height, a.unplaced()),
            (None, common::events::Unplaced::Orphan)
        );
    }

    /// A peer that sends a header from a chain we refuse is announced with the
    /// reason, nobody is asked for its headers, and the session ends.
    #[tokio::test]
    async fn test_a_refused_chain_is_announced_and_ends_the_session() {
        use crate::headertree::{Checkpoint, testing::mine_header, testing::regtest_params};
        use common::events::{Unplaced, peer_event::Event};
        let (genesis, _) = HeaderTree::new(regtest_params()).tip();
        let mut chain = Vec::new();
        let mut prev = genesis;
        for i in 0..5u32 {
            let h = mine_header(prev, 1_700_000_000 + i, 0);
            prev = h.block_hash();
            chain.push(h);
        }
        let checkpoint = Checkpoint {
            height: 3,
            hash: chain[2].block_hash(),
        };
        let mut tree = HeaderTree::with_checkpoints(regtest_params(), vec![checkpoint]);
        tree.insert_batch(&chain);
        let tree = Arc::new(RwLock::new(tree));

        // A fork below the checkpoint, announced block by block from two
        // connections, as its peers would announce it.
        let f1 = mine_header(chain[0].block_hash(), 1_700_000_100, 7);
        let f2 = mine_header(f1.block_hash(), 1_700_000_160, 7);
        let mut a = harness(tree.clone());
        let mut b = harness(tree.clone());
        let announced = |h: &mut Harness| match h.events.try_recv().unwrap().event {
            Some(Event::BlockAnnouncement(a)) => (a.height, a.unplaced()),
            other => panic!("not a block announcement: {other:?}"),
        };

        // The announcement goes out first -- the block is an observation --
        // and then the session ends with the verdict on it.
        let err = a.conn.handle_headers(vec![f1]).await.unwrap_err();
        assert_eq!(announced(&mut a), (None, Unplaced::ForkBelowCheckpoint));
        let verdict = other_chain_of(&err).expect("an other-chain verdict");
        assert_eq!(verdict.reason, HeaderError::ForkBelowCheckpoint);

        // The second peer, on the same chain one block further on, gets the
        // same answer: the fork's own parent is refused, so the descendant is
        // refused for the same reason without asking anyone.
        let err = b.conn.handle_headers(vec![f2]).await.unwrap_err();
        assert_eq!(announced(&mut b), (None, Unplaced::ForkBelowCheckpoint));
        assert!(other_chain_of(&err).is_some());

        // An inv for a block the tree has already refused is not news and
        // not worth a getheaders, and it is no longer "new to us" either:
        // before, every announcement of an unplaceable block was a first
        // sighting, so two peers on a fork counted as two blocks each time.
        b.conn
            .handle_inv(vec![Inventory::Block(f2.block_hash())])
            .await
            .unwrap();
        let Some(Event::BlockAnnouncement(seen)) = b.events.try_recv().unwrap().event else {
            panic!("expected an announcement");
        };
        assert_eq!(
            (seen.height, seen.unplaced()),
            (None, Unplaced::ForkBelowCheckpoint)
        );
        assert!(!seen.new_to_us);
        assert_eq!(getheaders_sent(&a.conn.writer), 0);
        assert_eq!(getheaders_sent(&b.conn.writer), 0);
    }

    /// Being behind is not being on another chain: an orphan leaves the
    /// session alone and asks the peer for headers, as it always did.
    #[tokio::test]
    async fn test_an_orphan_does_not_end_the_session() {
        use crate::headertree::testing::{mine_header, regtest_params};
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let (genesis, _) = tree.read().unwrap().tip();
        let h1 = mine_header(genesis, 1_700_000_000, 1);
        let h2 = mine_header(h1.block_hash(), 1_700_000_060, 2);

        let mut h = harness(tree);
        // h2's parent is missing, so the tree is behind rather than wrong.
        h.conn.handle_headers(vec![h2]).await.unwrap();
        assert_eq!(getheaders_sent(&h.conn.writer), 1);
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
        let Some(common::events::peer_event::Event::BlockAnnouncement(a)) =
            h.events.try_recv().unwrap().event
        else {
            panic!("expected an announcement for the known block");
        };
        assert_eq!((a.height, a.new_to_us), (Some(0), false));
        assert!(a.compact_block.is_none());

        h.conn
            .handle_inv(vec![Inventory::Block(unknown)])
            .await
            .unwrap();
        assert_eq!(getheaders_sent(&h.conn.writer), 1);
        let Some(common::events::peer_event::Event::BlockAnnouncement(a)) =
            h.events.try_recv().unwrap().event
        else {
            panic!("expected an announcement for the unknown block");
        };
        assert_eq!((a.height, a.new_to_us), (None, true));
        assert_eq!(a.unplaced(), common::events::Unplaced::NoHeader);

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

    fn block_hashes(n: usize) -> Vec<Inventory> {
        (0..n)
            .map(|i| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
                Inventory::Block(BlockHash::from_byte_array(bytes))
            })
            .collect()
    }

    /// An inv past the protocol's own limit ends the session. No
    /// implementation sends one by accident, and the alternative is doing
    /// fifty thousand lookups because a peer asked us to.
    #[tokio::test]
    async fn test_an_inv_over_the_protocol_limit_ends_the_session() {
        use crate::headertree::testing::regtest_params;
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let mut h = harness(tree);

        let err = h
            .conn
            .handle_inv(block_hashes(MAX_INV_SIZE + 1))
            .await
            .expect_err("an inv over the limit");
        assert!(err.downcast_ref::<ProtocolViolation>().is_some(), "{err:#}");
        assert!(h.events.try_recv().is_err(), "nothing should be announced");
    }

    /// Under that limit but far above an announcement: the first few blocks
    /// are announced, the rest are only counted. Without the cap one message
    /// became tens of thousands of events, which both floods the queue and
    /// reads back as a block storm that never happened.
    #[tokio::test]
    async fn test_an_inv_flood_announces_only_its_first_blocks() {
        use crate::headertree::testing::regtest_params;
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let mut h = harness(tree);

        let flood = 500;
        h.conn.handle_inv(block_hashes(flood)).await.unwrap();

        let mut announced = 0;
        while let Ok(event) = h.events.try_recv() {
            let Some(common::events::peer_event::Event::BlockAnnouncement(a)) = event.event else {
                continue;
            };
            // Every announcement says how big the message really was, so the
            // flood is still visible in the stream.
            assert_eq!(a.batch_size, flood as u32);
            announced += 1;
        }
        assert_eq!(announced, MAX_BLOCK_INVS_ANNOUNCED);
    }

    #[test]
    fn test_a_pong_claims_the_ping_it_answers() {
        let mut stats = ConnectionStats::new();
        stats.record_ping(1_000);
        stats.record_ping(2_000);

        // Out of order is still an answer, and the other ping stays claimable.
        assert!(stats.claim_pong(2_000));
        assert!(stats.claim_pong(1_000));
        assert_eq!(stats.unsolicited_pongs, 0);

        // The same nonce twice is one answer and one invention.
        assert!(!stats.claim_pong(1_000));
        assert_eq!(stats.unsolicited_pongs, 1);
    }

    #[test]
    fn test_a_pong_we_never_asked_for_is_counted_not_timed() {
        let mut stats = ConnectionStats::new();
        // The shape of the bug this prevents: nonce 0 would have produced an
        // rtt_ms of the current unix time in milliseconds.
        assert!(!stats.claim_pong(0));
        assert_eq!(stats.unsolicited_pongs, 1);
        assert!(stats.rtt_history.is_empty());
    }

    #[test]
    fn test_only_the_last_few_pings_stay_claimable() {
        let mut stats = ConnectionStats::new();
        for nonce in 0..(OUTSTANDING_PINGS as u64 + 2) {
            stats.record_ping(nonce + 1);
        }
        // The two oldest fell out, so answering them now reads as unsolicited.
        assert!(!stats.claim_pong(1));
        assert!(!stats.claim_pong(2));
        assert!(stats.claim_pong(3));
        assert_eq!(stats.unsolicited_pongs, 2);
    }

    #[test]
    fn test_a_peer_that_stops_answering_pings_runs_out_of_time() {
        let mut stats = ConnectionStats::new();
        let handshake = stats.last_pong;

        // Nothing outstanding: a peer that only listens owes us nothing,
        // however long it has been quiet.
        assert!(stats.ping_timed_out(handshake + PING_TIMEOUT * 2).is_none());

        stats.record_ping(1);
        assert!(stats.ping_timed_out(handshake + PING_TIMEOUT / 2).is_none());
        let waited = stats
            .ping_timed_out(handshake + PING_TIMEOUT)
            .expect("the deadline has passed with a ping outstanding");
        assert!(waited >= PING_TIMEOUT, "{waited:?}");

        // Filling the queue past what it remembers must not reset the clock:
        // the deadline runs from the last answer, not from the oldest ping
        // still in the queue.
        for nonce in 2..(OUTSTANDING_PINGS as u64 + 4) {
            stats.record_ping(nonce);
        }
        assert!(stats.ping_timed_out(handshake + PING_TIMEOUT).is_some());

        // An answer puts the deadline off, from the moment it arrived.
        assert!(stats.claim_pong(5));
        let answered = stats.last_pong;
        assert!(answered >= handshake);
        assert!(stats.ping_timed_out(answered + PING_TIMEOUT / 2).is_none());
        assert!(stats.ping_timed_out(answered + PING_TIMEOUT).is_some());
    }

    #[test]
    fn test_message_counts_are_capped_by_command() {
        let mut stats = ConnectionStats::new();
        stats.record_message("inv");
        stats.record_message("inv");
        stats.record_message("addrv2");
        assert_eq!(stats.messages_by_command.get("inv"), Some(&2));
        assert_eq!(stats.messages_by_command.get("addrv2"), Some(&1));
        assert_eq!(stats.messages_other, 0);

        // A peer naming a new command every time cannot grow the map past the
        // cap; the overflow is counted instead.
        for i in 0..MESSAGES_BY_COMMAND_CAP {
            stats.record_message(&format!("cmd{i}"));
        }
        assert_eq!(stats.messages_by_command.len(), MESSAGES_BY_COMMAND_CAP);
        assert!(stats.messages_other > 0);
        // Commands already counted keep counting after the cap is reached.
        stats.record_message("inv");
        assert_eq!(stats.messages_by_command.get("inv"), Some(&3));
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
        let mut r = TransportV2Reader::new(pr);
        let mut w = TransportV2Writer { writer: pw };
        version_handshake(&mut r, &mut w, USER_AGENT, 0)
            .await
            .expect("v2 version handshake failed");
    }

    /// What a peer says about itself after verack is published as it arrives,
    /// not held in a field nobody reads.
    #[tokio::test]
    async fn test_feefilter_and_sendcmpct_are_published() {
        use crate::headertree::testing::regtest_params;
        use common::events::peer_event::Event;
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let mut h = harness(tree);

        h.conn
            .handle_fee_filter(common::bitcoin::FeeRate::from_sat_per_kvb(1_000));
        h.conn.handle_send_cmpct(SendCmpct {
            send_compact: true,
            version: 2,
        });

        let Some(Event::FeeFilter(f)) = h.events.try_recv().unwrap().event else {
            panic!("expected a fee filter event");
        };
        assert_eq!(f.feerate_sat_per_kvb, 1_000);
        let Some(Event::SendCmpct(s)) = h.events.try_recv().unwrap().event else {
            panic!("expected a sendcmpct event");
        };
        assert!(s.high_bandwidth);
        assert_eq!(s.version, 2);
    }

    /// The peer's own one-entry announcement is not the reply to our GETADDR,
    /// so it leaves the flag for the message that is.
    #[tokio::test]
    async fn test_self_announcement_does_not_answer_getaddr() {
        use crate::headertree::testing::regtest_params;
        use common::events::peer_event::Event;
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let mut h = harness(tree);
        let gossip = |addr| Gossiped {
            addr,
            services: 0,
            ntime: 0,
        };
        let solicited = |h: &mut Harness| match h.events.try_recv().unwrap().event {
            Some(Event::AddressAnnouncement(a)) => a.solicited,
            other => panic!("not an address announcement: {other:?}"),
        };

        h.conn.getaddr_outstanding = true;
        let own = h.conn.addr;
        h.conn
            .offer_gossip(common::events::AddrMessage::Addrv2, 1, vec![gossip(own)]);
        assert!(!solicited(&mut h));
        assert!(h.conn.getaddr_outstanding);

        let reply = vec![
            gossip(PeerAddr::Ipv4([10, 0, 0, 1], 8333)),
            gossip(PeerAddr::Ipv4([10, 0, 0, 2], 8333)),
        ];
        h.conn
            .offer_gossip(common::events::AddrMessage::Addrv2, 2, reply);
        assert!(solicited(&mut h));
        assert!(!h.conn.getaddr_outstanding);

        // Another peer's single address is not a self-announcement either.
        h.conn.getaddr_outstanding = true;
        let other = vec![gossip(PeerAddr::Ipv4([10, 0, 0, 3], 8333))];
        h.conn
            .offer_gossip(common::events::AddrMessage::Addrv2, 1, other);
        assert!(solicited(&mut h));
    }

    /// An addrv2 payload with one entry the decoder rejects between two it
    /// accepts, as btcd sends them.
    fn addrv2_with_a_rejected_entry() -> (Vec<u8>, Vec<AddrV2Message>) {
        use common::bitcoin::consensus::{encode::WriteExt, serialize};
        let good = |last: u8| AddrV2Message {
            time: 1_700_000_000,
            services: ServiceFlags::NETWORK,
            addr: address::AddrV2::Ipv4(Ipv4Addr::new(10, 0, 0, last)),
            port: 8333,
        };
        let mut payload = Vec::new();
        payload.emit_compact_size(3u64).unwrap();
        payload.extend(serialize(&good(1)));
        // An IPv4 address under the IPv6 network id.
        payload.extend(1_700_000_000u32.to_le_bytes());
        payload.emit_compact_size(1u64).unwrap();
        payload.extend([2, 16]);
        payload.extend([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 10, 0, 0, 2]);
        payload.extend(8333u16.to_be_bytes());
        payload.extend(serialize(&good(3)));
        (payload, vec![good(1), good(3)])
    }

    /// One entry the decoder rejects no longer costs the rest of the message.
    #[test]
    fn test_addrv2_is_read_around_a_rejected_entry() {
        use common::bitcoin::consensus::deserialize;
        let (payload, kept) = addrv2_with_a_rejected_entry();
        // The decoder itself still refuses the message whole.
        assert!(deserialize::<common::p2p::message::AddrV2Payload>(&payload).is_err());

        let (received, entries) = parse_addrv2_leniently(&payload);
        assert_eq!(received, 3);
        assert_eq!(entries, kept);

        // Framing that cannot be followed ends the read, keeping what came
        // before it and never panicking.
        let (received, entries) = parse_addrv2_leniently(&payload[..payload.len() - 3]);
        assert_eq!(received, 3);
        assert_eq!(entries, kept[..1]);
        assert_eq!(parse_addrv2_leniently(&[]), (0, Vec::new()));
        assert_eq!(
            parse_addrv2_leniently(&[0xfe, 0xff, 0xff, 0xff, 0xff]),
            (0, Vec::new())
        );
    }

    /// The rejected message reaches the archive as an announcement with the
    /// entries that parsed and the one that did not counted.
    #[tokio::test]
    async fn test_undecodable_addrv2_is_still_announced() {
        use crate::headertree::testing::regtest_params;
        use common::events::peer_event::Event;
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let mut h = harness(tree);
        let (payload, kept) = addrv2_with_a_rejected_entry();

        h.conn.handle_unknown(
            &CommandString::try_from("addrv2".to_owned()).unwrap(),
            &payload,
        );

        let Some(Event::AddressAnnouncement(a)) = h.events.try_recv().unwrap().event else {
            panic!("expected an address announcement");
        };
        assert_eq!(a.unparsed, 1);
        assert_eq!(a.addresses.len(), kept.len());
        assert_eq!(a.addresses[0].addr, "10.0.0.1:8333");
        assert_eq!(a.addresses[1].addr, "10.0.0.3:8333");
    }

    /// A reply to our own getheaders is not the peer announcing blocks, however
    /// many headers it holds; a short HEADERS message is, and says how many.
    #[tokio::test]
    async fn test_bulk_headers_are_not_announcements() {
        use crate::headertree::testing::{mine_header, regtest_params};
        let tree = Arc::new(RwLock::new(HeaderTree::new(regtest_params())));
        let (mut prev, _) = tree.read().unwrap().tip();
        let mut chain = Vec::new();
        for i in 0..(MAX_HEADERS_ANNOUNCED as u8 + 1) {
            let h = mine_header(prev, 1_700_000_000 + u32::from(i) * 60, i + 1);
            prev = h.block_hash();
            chain.push(h);
        }
        let mut h = harness(tree.clone());

        // One over the limit: a sync response. Inserted, nothing announced.
        h.conn.handle_headers(chain.clone()).await.unwrap();
        assert_eq!(tree.read().unwrap().tip().1, chain.len() as u32);
        assert!(h.events.try_recv().is_err());

        // Two headers: an announcement each, and each says it came with one
        // other -- the mark of a peer catching us up rather than announcing.
        h.conn.handle_headers(chain[..2].to_vec()).await.unwrap();
        for _ in 0..2 {
            let ev = h.events.try_recv().unwrap();
            let Some(common::events::peer_event::Event::BlockAnnouncement(b)) = ev.event else {
                panic!("expected a block announcement, got {:?}", ev.event);
            };
            assert_eq!(b.batch_size, 2);
        }
        assert!(h.events.try_recv().is_err());
    }
}
