//! A peer that does not play by the rules, driven over a real socket.
//!
//! The limits in [`crate::protocol`] and [`crate::transport`] are each unit
//! tested against a mock reader, which proves the handler's arithmetic but not
//! that the limit is reachable: between a peer and a handler sit the framing,
//! the decoder and the session loop, any of which can swallow or transform
//! what the handler was meant to see. These tests sit on the other side of all
//! of it -- a listener speaking v1 by hand, saying things no well-behaved peer
//! would -- and check what came back out, including the disconnect reason the
//! session published, which is the only part of this an operator ever sees.

use std::sync::{Arc, RwLock};
use std::time::Duration;

use common::bitcoin::BlockHash;
use common::bitcoin::hashes::sha256d;
use common::events::{
    DisconnectReason, PeerEvent, connection_result, connection_result::Disconnected, peer_event,
};
use common::p2p::{
    Magic, ProtocolVersion,
    message::{MAX_INV_SIZE, NetworkMessage},
    message_blockdata::{GetHeadersMessage, Inventory},
};
use common::tokio::{
    self,
    io::{AsyncWriteExt, BufReader},
    net::{
        TcpListener,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::mpsc,
    task::JoinHandle,
    time::timeout,
};

use crate::addresses::book::{Dial, TransportHint};
use crate::addresses::peer_addr::PeerAddr;
use crate::addresses::policy;
use crate::connection::attempt;
use crate::headertree::HeaderTree;
use crate::headertree::testing::{mine_header, regtest_params};
use crate::protocol::{Config, GETHEADERS_BURST, build_version};
use crate::transport::{TransportReader, TransportV1Reader, TransportV1Writer, TransportWriter};

const MAGIC: Magic = Magic::REGTEST;

/// Generous: every one of these finishes in milliseconds when it works, and
/// what is being tested is that the session ends at all.
const WAIT: Duration = Duration::from_secs(10);

fn setup() {
    let _ = common::tracing_subscriber::fmt()
        .with_max_level(common::tracing::Level::DEBUG)
        .try_init();
}

/// A header tree with `count` blocks on top of regtest genesis, so that a
/// getheaders has something to be answered with.
fn tree_with(count: usize) -> Arc<RwLock<HeaderTree>> {
    let mut tree = HeaderTree::new(regtest_params());
    let mut prev = tree.tip().0;
    let headers: Vec<_> = (0..count)
        .map(|i| {
            let h = mine_header(prev, 1_700_000_000 + i as u32, 1);
            prev = h.block_hash();
            h
        })
        .collect();
    if !headers.is_empty() {
        let (accepted, err) = tree.insert_batch(&headers);
        assert_eq!(accepted, count, "mined chain was not accepted: {err:?}");
    }
    Arc::new(RwLock::new(tree))
}

fn config(event_tx: mpsc::Sender<PeerEvent>, header_tree: Arc<RwLock<HeaderTree>>) -> Config {
    Config {
        connections: crate::connections::Registry::new(),
        magic: MAGIC,
        ping_interval: Duration::from_secs(120),
        user_agent: crate::protocol::USER_AGENT.to_owned(),
        event_tx,
        header_tree,
        sync_headers: false,
        probe_compact_blocks: false,
        networks: crate::settings::NetworksConfig::default(),
    }
}

/// A v1 wire frame, built by hand so that a test can lie in it.
///
/// `declared_len` overrides the length field without changing the payload,
/// which is how a peer claims to be sending more than it does.
fn frame(command: &str, payload: &[u8], declared_len: Option<u32>) -> Vec<u8> {
    assert!(command.len() <= 12);
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&MAGIC.to_bytes());
    let mut name = [0u8; 12];
    name[..command.len()].copy_from_slice(command.as_bytes());
    out.extend_from_slice(&name);
    out.extend_from_slice(&declared_len.unwrap_or(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&sha256d::Hash::hash(payload).to_byte_array()[..4]);
    out.extend_from_slice(payload);
    out
}

/// The peer: a listener that completes the handshake with the real codec and
/// then does whatever the test says.
struct Peer {
    r: TransportV1Reader<BufReader<OwnedReadHalf>>,
    w: TransportV1Writer<OwnedWriteHalf>,
}

impl Peer {
    /// Takes the connection the observer is about to make and handshakes.
    async fn accept(listener: TcpListener) -> Self {
        let (stream, _) = listener.accept().await.expect("accepting the dial");
        let (reader, writer) = stream.into_split();
        let mut peer = Peer {
            r: TransportV1Reader::new(BufReader::new(reader), MAGIC),
            w: TransportV1Writer {
                magic: MAGIC,
                writer,
            },
        };
        while !matches!(peer.recv().await, NetworkMessage::Version(_)) {}
        peer.send(build_version(crate::protocol::USER_AGENT, 0))
            .await;
        peer.send(NetworkMessage::Verack).await;
        while !matches!(peer.recv().await, NetworkMessage::Verack) {}
        // The last thing the observer sends unprompted, so once it is here the
        // session proper has started and nothing the test sends can race it.
        while !matches!(peer.recv().await, NetworkMessage::SendCmpct(_)) {}
        peer
    }

    async fn send(&mut self, msg: NetworkMessage) {
        self.w.send(msg).await.expect("sending to the observer");
    }

    /// Bytes straight onto the socket, bypassing the codec: the only way to
    /// say something the codec would refuse to build.
    async fn send_raw(&mut self, bytes: &[u8]) {
        self.w
            .writer
            .write_all(bytes)
            .await
            .expect("writing raw bytes");
    }

    async fn recv(&mut self) -> NetworkMessage {
        timeout(WAIT, self.r.recv())
            .await
            .expect("the observer said nothing in time")
            .expect("reading from the observer")
    }

    /// Hangs up and reads everything the observer had already sent, which is
    /// what a test counts replies in. Consuming the peer is the point: the
    /// observer keeps answering for as long as the socket is open, so the
    /// count is only well defined once it is closed.
    async fn hang_up_and_drain(mut self) -> Vec<NetworkMessage> {
        drop(self.w);
        let mut seen = Vec::new();
        let _ = timeout(WAIT, async {
            while let Ok(msg) = self.r.recv().await {
                seen.push(msg);
            }
        })
        .await;
        seen
    }
}

/// The observer's side: the connection attempt, the events it emits, and the
/// manager channels it reports to.
struct Observed {
    events: mpsc::Receiver<PeerEvent>,
    task: JoinHandle<()>,
    /// Held only so the session's reports to the manager have somewhere to
    /// go; dropping them would turn every report into an error.
    _manager: (
        mpsc::Receiver<Vec<crate::addresses::book::Gossiped>>,
        mpsc::UnboundedReceiver<crate::addresses::Lifecycle>,
        mpsc::Receiver<crate::addresses::Command>,
    ),
}

/// Brings a peer and the observer together: a listener on a loopback port, a
/// real connection attempt to it, and the handshake done.
///
/// `blocks` is how long a chain the observer has, since that decides what it
/// can answer a getheaders with. `tune` adjusts the session config before it
/// starts.
async fn meet(blocks: usize, tune: impl FnOnce(&mut Config)) -> (Peer, Observed) {
    setup();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();

    // Roomier than the gossip shedding threshold, so an address announcement
    // reaches the test rather than being dropped on the way.
    let (event_tx, events) = mpsc::channel(crate::emit::GOSSIP_SHED_BELOW + 64);
    let mut cfg = config(event_tx, tree_with(blocks));
    tune(&mut cfg);

    let (handle, gossip, life, cmd) = crate::addresses::channels();
    let dial = Dial {
        // V1Only so the attempt goes straight to v1 and meets the listener,
        // which accepts exactly once.
        addr: PeerAddr::Ipv4([127, 0, 0, 1], port),
        transport: TransportHint::V1Only,
    };
    let task = tokio::spawn(attempt(dial, cfg, handle));
    let peer = Peer::accept(listener).await;
    (
        peer,
        Observed {
            events,
            task,
            _manager: (gossip, life, cmd),
        },
    )
}

impl Observed {
    /// Waits for the session to be reported finished and returns the report.
    ///
    /// What a session made of a misbehaving peer leaves the process as is this
    /// one message -- the reason, the counts, the skipped frames -- so it is
    /// what these tests assert on rather than any internal state.
    async fn disconnected(&mut self) -> Disconnected {
        timeout(WAIT, async {
            while let Some(event) = self.events.recv().await {
                if let Some(peer_event::Event::ConnectionResult(res)) = event.event
                    && let Some(connection_result::Result::Disconnected(d)) = res.result
                {
                    return d;
                }
            }
            panic!("the event channel closed before the session was reported");
        })
        .await
        .expect("the session was not reported finished in time")
    }

    /// Waits for the attempt task to finish, so a test can tell "the session
    /// ended" from "the session is still sitting there".
    async fn ended(self) {
        timeout(WAIT, self.task)
            .await
            .expect("the session did not end")
            .expect("the session task panicked");
    }

    /// The next `n` address announcements the session published.
    ///
    /// What the limiter did is visible nowhere else: an addr message is
    /// answered with nothing, and what survives the limiter goes to the
    /// address manager, which these tests do not hold.
    async fn announcements(&mut self, n: usize) -> Vec<common::events::AddressAnnouncement> {
        let events = &mut self.events;
        timeout(WAIT, async move {
            let mut found = Vec::new();
            while let Some(event) = events.recv().await {
                if let Some(peer_event::Event::AddressAnnouncement(a)) = event.event {
                    found.push(a);
                    if found.len() == n {
                        return found;
                    }
                }
            }
            panic!(
                "the event channel closed after {} of {n} announcements",
                found.len()
            );
        })
        .await
        .unwrap_or_else(|_| panic!("fewer than {n} address announcements arrived"))
    }
}

/// Reads the reason off a session report.
fn reason(d: &Disconnected) -> DisconnectReason {
    DisconnectReason::try_from(d.reason).unwrap_or(DisconnectReason::Unknown)
}

/// A getheaders with this locator and no stop hash.
fn ask_from(locator: Vec<BlockHash>) -> NetworkMessage {
    NetworkMessage::GetHeaders(GetHeadersMessage {
        version: ProtocolVersion::WTXID_RELAY_VERSION,
        locator_hashes: locator,
        stop_hash: BlockHash::from_byte_array([0; 32]),
    })
}

/// A locator hash that matches nothing, so the answer starts after genesis.
fn nowhere(n: u16) -> BlockHash {
    let mut bytes = [0u8; 32];
    bytes[..2].copy_from_slice(&n.to_le_bytes());
    BlockHash::from_byte_array(bytes)
}

/// How many headers came back in each answer.
fn answers(replies: &[NetworkMessage]) -> Vec<usize> {
    replies
        .iter()
        .filter_map(|m| match m {
            NetworkMessage::Headers(h) => Some(h.0.len()),
            _ => None,
        })
        .collect()
}

/// A peer claiming to send more than the protocol allows is refused on the
/// strength of the claim, before the bytes it would need are reserved.
#[tokio::test]
async fn test_an_oversized_message_is_refused_and_named() {
    let (mut peer, mut observed) = meet(1, |_| {}).await;
    let too_big = common::p2p::message::MAX_MSG_SIZE as u32 + 1;
    peer.send_raw(&frame("block", &[], Some(too_big))).await;
    let end = observed.disconnected().await;
    assert_eq!(reason(&end), DisconnectReason::OversizedMessage);
    observed.ended().await;
}

/// An inv over the protocol's own limit ends the session as a violation, and
/// not as an unexplained decode failure.
///
/// Worth checking from out here because the limit sits behind the decoder: a
/// vector that large is also near rust-bitcoin's own decoding limit, and if
/// that one tripped first the handler's check would be unreachable and the
/// reason an operator saw would be the wrong one.
#[tokio::test]
async fn test_an_inv_over_the_protocol_limit_is_named_a_violation() {
    let (mut peer, mut observed) = meet(1, |_| {}).await;
    let invs: Vec<Inventory> = (0..MAX_INV_SIZE + 1)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[..8].copy_from_slice(&(i as u64).to_le_bytes());
            Inventory::Block(BlockHash::from_byte_array(bytes))
        })
        .collect();
    peer.send(NetworkMessage::Inv(common::p2p::message::InventoryPayload(
        invs,
    )))
    .await;
    let end = observed.disconnected().await;
    assert_eq!(reason(&end), DisconnectReason::ProtocolViolation);
    observed.ended().await;
}

/// Asking for headers as fast as the socket allows draws a few answers and
/// then nothing, and costs the peer nothing else: asking often is rude rather
/// than an offence, and hanging up would end the session we are here to watch.
#[tokio::test]
async fn test_a_getheaders_flood_is_answered_only_so_often() {
    const ASKS: usize = 40;
    let (mut peer, mut observed) = meet(3, |_| {}).await;
    for _ in 0..ASKS {
        peer.send(ask_from(vec![nowhere(0)])).await;
    }
    let answered = answers(&peer.hang_up_and_drain().await);

    // The burst, and at most one more token for the time the flood itself
    // took to read.
    let burst = GETHEADERS_BURST as usize;
    assert!(
        (1..=burst + 1).contains(&answered.len()),
        "{ASKS} asks drew {} answers, expected at most {}",
        answered.len(),
        burst + 1
    );

    // It was the peer that hung up, not us, and every ask was still counted:
    // ignoring a question is not the same as not hearing it.
    let end = observed.disconnected().await;
    assert_eq!(reason(&end), DisconnectReason::PeerClosed);
    assert_eq!(end.messages_by_command.get("getheaders"), Some(&40));
    observed.ended().await;
}

/// A locator longer than any implementation builds is answered once, and the
/// answer is bounded by the chain rather than by the locator.
#[tokio::test]
async fn test_an_overlong_locator_gets_one_bounded_answer() {
    let (mut peer, observed) = meet(5, |_| {}).await;
    peer.send(ask_from((0..500).map(nowhere).collect())).await;
    let answered = answers(&peer.hang_up_and_drain().await);
    assert_eq!(answered, vec![5]);
    drop(observed);
}

/// A payload that does not match the checksum in its header ends the session,
/// and is not counted as the message it claimed to be.
///
/// The frame says `ping` and carries eight bytes, which is exactly what a
/// valid ping is -- only the checksum is wrong. Before, the decoder failed
/// somewhere inside, the frame was handed up as an unparseable message, and it
/// was counted under the command it claimed: a peer could inflate any
/// command's count with garbage, and keep a session open indefinitely doing
/// it. A checksum that does not match says the bytes are corrupt, which makes
/// the length that found the next frame boundary untrustworthy too, so there
/// is nothing to carry on to.
#[tokio::test]
async fn test_a_corrupt_payload_ends_the_session_and_is_not_counted() {
    let (mut peer, mut observed) = meet(1, |_| {}).await;
    let mut f = frame("ping", &[0u8; 8], None);
    f[20] ^= 0xff;
    peer.send_raw(&f).await;

    let end = observed.disconnected().await;
    assert_eq!(reason(&end), DisconnectReason::DecodeError);
    assert_eq!(
        end.messages_by_command.get("ping"),
        None,
        "a corrupt frame was counted as the message it claimed to be"
    );
    assert_eq!(end.undecodable, 0, "a corrupt frame is not an unread one");
    observed.ended().await;
}

/// A payload that matches its checksum and still will not parse is skipped,
/// counted as unread, and the session carries on.
///
/// This is the case the skipping is for: our parser being behind a peer's,
/// which is not the peer's fault and not worth the rest of the session. The
/// frame below is a well-formed one whose body claims more entries than it
/// carries.
#[tokio::test]
async fn test_an_unparseable_payload_is_skipped_and_the_session_carries_on() {
    let (mut peer, mut observed) = meet(2, |_| {}).await;
    // 0xfd introduces a two-byte count, and nothing follows it.
    peer.send_raw(&frame("addrv2", &[0xfd], None)).await;

    // Still talking to us afterwards, which is the whole point.
    peer.send(ask_from(vec![nowhere(0)])).await;
    let answered = answers(&peer.hang_up_and_drain().await);
    assert_eq!(answered, vec![2]);

    let end = observed.disconnected().await;
    assert_eq!(reason(&end), DisconnectReason::PeerClosed);
    assert_eq!(end.undecodable, 1);
    assert_eq!(end.messages_by_command.get("addrv2"), Some(&1));
    observed.ended().await;
}

/// A second version message after the handshake is ignored rather than taken
/// as a correction or an offence.
///
/// Core disconnects for this; we are not a node and have nothing to protect
/// from it, but what the peer said about itself has already been published
/// under this connection id and must not be quietly replaced by a later
/// claim.
#[tokio::test]
async fn test_a_replayed_version_does_not_change_what_was_published() {
    let (mut peer, mut observed) = meet(1, |_| {}).await;
    peer.send(build_version("/liar:9.9.9/", 999_999)).await;
    peer.send(ask_from(vec![nowhere(0)])).await;
    let answered = answers(&peer.hang_up_and_drain().await);
    assert_eq!(answered, vec![1], "the session did not survive the replay");

    let end = observed.disconnected().await;
    assert_eq!(reason(&end), DisconnectReason::PeerClosed);
    assert_eq!(end.messages_by_command.get("version"), Some(&1));
    observed.ended().await;
}

/// `count` gossiped addresses, all of them parseable and distinct.
///
/// 198.18.0.0/15 is the benchmarking range: reserved, so nothing here names a
/// host anyone runs.
fn gossip(count: usize) -> Vec<(u32, common::p2p::address::Address)> {
    use common::p2p::address::Address;
    (0..count)
        .map(|i| {
            let addr = std::net::SocketAddr::from((
                std::net::Ipv4Addr::new(198, 18 + (i >> 8) as u8, (i & 0xff) as u8, 1),
                8333,
            ));
            (
                1_700_000_000,
                Address::new(&addr, common::p2p::ServiceFlags::NETWORK),
            )
        })
        .collect()
}

/// A peer's ping is answered, with the nonce the peer chose.
///
/// The one reply in the protocol that a peer draws its own conclusion from:
/// Core disconnects a peer that has not ponged within twenty minutes, and a
/// pong carrying the wrong nonce is not an answer. So an observer that stopped
/// ponging, or ponged with a nonce of its own, would be dropped by everything
/// it connects to -- and nothing in the process would say why, because from
/// here it looks like peers hanging up for their own reasons.
#[tokio::test]
async fn test_a_ping_is_answered_with_the_nonce_the_peer_chose() {
    let (mut peer, observed) = meet(1, |_| {}).await;
    const NONCE: u64 = 0x0123_4567_89ab_cdef;
    peer.send(NetworkMessage::Ping(NONCE)).await;
    let replies = peer.hang_up_and_drain().await;
    assert!(
        replies
            .iter()
            .any(|m| matches!(m, NetworkMessage::Pong(n) if *n == NONCE)),
        "no pong carrying our nonce came back: {replies:?}"
    );
    observed.ended().await;
}

/// A peer cannot make us learn addresses faster than the bucket allows.
///
/// Nothing caps how many addresses an addr message may carry, so the token
/// bucket is the whole of what stands between a peer and an address book of
/// its choosing. Three messages is what it takes to see it work, because the
/// first one is free on purpose: it is the reply to our own getaddr, and
/// charging the reply to a question we asked would drain the bucket for the
/// rest of the session.
///
/// Asserted on the published event rather than on the address book, because
/// the event is where the limiter's account of itself lives -- what it
/// discarded, and the bucket it discarded it against -- and an archive is the
/// only place that can be read back later.
#[tokio::test]
async fn test_a_peer_cannot_announce_addresses_faster_than_the_bucket() {
    let (mut peer, mut observed) = meet(1, |_| {}).await;
    let burst = policy::ADDR_BURST as usize;

    for _ in 0..3 {
        peer.send(NetworkMessage::Addr(common::p2p::message::AddrPayload(
            gossip(burst),
        )))
        .await;
    }
    let announced = observed.announcements(3).await;
    for (i, a) in announced.iter().enumerate() {
        assert_eq!(a.addresses.len(), burst, "message {i}");
        assert_eq!(a.unparsed, 0, "the test's addresses did not parse");
    }

    // The reply to our getaddr: taken in full and charged nothing.
    assert!(announced[0].solicited);
    assert_eq!(announced[0].rate_limited, 0);
    assert_eq!(announced[0].rate_limit_tokens, policy::ADDR_BURST);

    // The next thousand are unsolicited and fit in the burst. The level is
    // reported before this message is charged, which is why it still reads
    // full.
    assert!(!announced[1].solicited, "only the first reply is solicited");
    assert_eq!(
        announced[1].rate_limited, 0,
        "the burst is meant to be free"
    );
    assert_eq!(
        announced[1].rate_limit_tokens,
        policy::ADDR_BURST,
        "the getaddr reply was charged against the bucket"
    );

    // And the thousand after that meet an empty bucket. The refill is a tenth
    // of an address a second, so a test that takes a moment has not earned
    // one.
    assert!(!announced[2].solicited);
    assert_eq!(
        announced[2].rate_limited, burst as u32,
        "the third thousand was not shed; the bucket held {}",
        announced[2].rate_limit_tokens
    );
    assert!(
        announced[2].rate_limit_tokens < 1.0,
        "the bucket refilled during the test: {}",
        announced[2].rate_limit_tokens
    );
    // Still reported in full: what the limiter dropped is said in
    // `rate_limited`, not by leaving the addresses out of the archive.
    assert_eq!(announced[2].addresses.len(), burst);

    let _ = peer.hang_up_and_drain().await;
    observed.ended().await;
}
