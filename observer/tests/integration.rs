//! End to end: the whole observer, against a real bitcoind and a real NATS
//! server.
//!
//! Every part of this is unit tested on its own already. What is not, and
//! cannot be, is the wiring: that the event channel the connection tasks were
//! handed is the one the publisher reads, that the subjects it publishes on
//! are the ones a consumer subscribes to, that the data directory the header
//! tree is loaded from is the one it is saved to, and that a restart finds
//! what the last run left behind. A channel plugged into the wrong end is
//! invisible to every test that does not start the program.
//!
//! Needs a `nats-server` binary, found through `NATS_SERVER_BINARY` (the nix
//! shell sets it); without it the tests are skipped. bitcoind comes from the
//! `bitcoind` dev-dependency, which the nix shell points at its own build.

use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddrV4;
use std::time::{Duration, Instant};

use common::events::{PeerEvent, peer_event};
use common::futures_util::StreamExt;
use common::prost::Message;
use common::serde_json::Value;
use common::tokio::sync::oneshot;
use common::tokio::time::timeout;
use common::{async_nats, tokio};
use observer::Config;
use testsupport::{NatsServer, TempDir};

/// How many blocks the node mines before the observer is pointed at it. Enough
/// that a tip height can only have come from a real sync, few enough to be
/// instant.
const BLOCKS: usize = 12;

/// Long enough for a handshake, a header sync and a ping on a loopback regtest
/// node by a wide margin, short enough that a hang fails the test rather than
/// the job.
const WAIT: Duration = Duration::from_secs(30);

/// The subject suffix each kind of event is published on.
///
/// Spelled out here rather than read from the observer on purpose: this is the
/// side of the contract a consumer sees, and a test that asked the publisher
/// what it publishes on would agree with any answer it gave. `unknown` is the
/// publisher's fallback for an event whose oneof it does not recognise, which
/// can only happen by forgetting to extend it -- and nothing is listening on
/// that subject.
fn kind_of(event: &PeerEvent) -> &'static str {
    match &event.event {
        Some(peer_event::Event::PingRtt(_)) => "ping_rtt",
        Some(peer_event::Event::BlockAnnouncement(_)) => "block_announcement",
        Some(peer_event::Event::AddressAnnouncement(_)) => "address_announcement",
        Some(peer_event::Event::ConnectionResult(_)) => "connection_result",
        Some(peer_event::Event::Handshake(_)) => "handshake",
        Some(peer_event::Event::CompactBlockProbe(_)) => "compact_block_probe",
        Some(peer_event::Event::FeeFilter(_)) => "fee_filter",
        Some(peer_event::Event::SendCmpct(_)) => "send_cmpct",
        None => "unknown",
    }
}

/// A regtest node with a chain, listening for peers.
struct Node {
    node: bitcoind::Node,
    p2p: SocketAddrV4,
}

impl Node {
    fn start(blocks: usize) -> Self {
        // A random regtest address to mine to.
        const REGTEST_ADDR: &str = "bcrt1qs758ursh4q9z627kt3pp5yysm78ddny6txaqgw";
        let to = REGTEST_ADDR
            .parse::<bitcoind::client::bitcoin::Address<_>>()
            .unwrap()
            .assume_checked();

        let exe = bitcoind::exe_path().unwrap();
        let mut conf = bitcoind::Conf::default();
        conf.p2p = bitcoind::P2P::Yes;
        let node = bitcoind::Node::with_conf(exe, &conf).unwrap();
        node.client.generate_to_address(blocks, &to).unwrap();
        let p2p = node.params.p2p_socket.expect("the node has no p2p port");
        Node { node, p2p }
    }

    fn addr(&self) -> String {
        self.p2p.to_string()
    }

    fn best_block_hash(&self) -> String {
        self.node.client.get_best_block_hash().unwrap().0
    }
}

/// A configuration pointing at this test's NATS server and directory.
///
/// `bootstrap` empty is both how the restart below proves it read the header
/// tree off disk rather than syncing it again, and how a peer can be made to
/// arrive through the address manager instead.
fn config(nats_url: &str, datadir: &TempDir, bootstrap: Vec<String>) -> Config {
    Config {
        network: "regtest".to_owned(),
        datadir: datadir.path().to_path_buf(),
        nats_url: nats_url.to_owned(),
        bootstrap_addrs: bootstrap,
        // The ping is what produces an event on a session that is otherwise
        // idle, and these tests want one promptly.
        ping_interval_secs: 1,
        ..Default::default()
    }
}

/// Watches the event subjects, checking every event that arrives against the
/// subject it arrived on and remembering what it has seen, so a failure can
/// say what did show up.
struct Events {
    sub: async_nats::Subscriber,
    seen: BTreeSet<String>,
}

impl Events {
    async fn subscribe(client: &async_nats::Client) -> Self {
        Events {
            sub: client
                .subscribe("p2p-observer.regtest.*")
                .await
                .expect("subscribing to the event subjects"),
            seen: BTreeSet::new(),
        }
    }

    /// Reads events until one of each named kind has arrived, returning them
    /// by kind.
    ///
    /// Taking a set rather than one kind at a time is what makes it
    /// order-free: two things a peer sends unprompted arrive in whichever
    /// order it sent them, and a test that insisted on one of them first would
    /// consume the other while waiting.
    async fn expect_kinds(&mut self, kinds: &[&str]) -> BTreeMap<String, PeerEvent> {
        let mut pending: BTreeSet<&str> = kinds.iter().copied().collect();
        let mut found = BTreeMap::new();
        let Self { sub, seen } = self;
        let outcome = timeout(WAIT, async {
            while let Some(msg) = sub.next().await {
                let event =
                    PeerEvent::decode(&msg.payload[..]).expect("decoding a published event");
                let kind = kind_of(&event);
                seen.insert(msg.subject.to_string());
                // Checked for every event, not just the awaited ones: this is
                // the mapping a consumer filters on.
                assert_eq!(
                    msg.subject.as_str(),
                    format!("p2p-observer.regtest.{kind}"),
                    "a {kind} event was published on the wrong subject"
                );
                if pending.remove(kind) {
                    found.insert(kind.to_owned(), event);
                }
                if pending.is_empty() {
                    return;
                }
            }
            panic!("the event subscription ended while waiting for {pending:?}");
        })
        .await;
        if outcome.is_err() {
            panic!("no {pending:?} event within {WAIT:?}; saw {:?}", self.seen);
        }
        found
    }
}

/// Asks the observer's own RPC interface a question, over the same NATS server
/// the events go through.
///
/// Retries while NATS answers that nobody is subscribed: the observer's RPC
/// task comes up a moment after the process starts, and a test that asks
/// first would be testing the race rather than the reply.
async fn rpc(client: &async_nats::Client, method: &str, payload: &str) -> Value {
    let subject = format!("p2p-observer.regtest.rpc.{method}");
    let deadline = Instant::now() + WAIT;
    loop {
        let attempt = timeout(
            WAIT,
            client.request(subject.clone(), payload.to_owned().into()),
        )
        .await
        .unwrap_or_else(|_| panic!("no reply on {subject} within {WAIT:?}"));
        match attempt {
            Ok(reply) => {
                return common::serde_json::from_slice(&reply.payload)
                    .expect("the RPC reply is not JSON");
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(e) => panic!("request on {subject}: {e}"),
        }
    }
}

/// Asks the same question until the answer satisfies `done`, and says what the
/// last answer was if it never does.
///
/// For state that arrives rather than being there: nothing the observer
/// publishes says "the header sync is finished". A node does not re-announce
/// blocks it had before we connected, so there is no event to wait for, and
/// the handshake -- the one thing that does arrive -- happens before the first
/// `getheaders` goes out. A test that asked once right after the handshake
/// would be asking whether the sync had already won a race, which on a busy
/// runner it sometimes has not.
async fn rpc_until(
    client: &async_nats::Client,
    method: &str,
    payload: &str,
    expected: &str,
    done: impl Fn(&Value) -> bool,
) -> Value {
    let deadline = Instant::now() + WAIT;
    loop {
        let answer = rpc(client, method, payload).await;
        if done(&answer) {
            return answer;
        }
        if Instant::now() >= deadline {
            panic!("{method} never {expected} within {WAIT:?}; last answer: {answer}");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// A running observer, stoppable the way the signal handler stops it.
struct Running {
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

fn start(cfg: Config) -> Running {
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(observer::run(cfg, async {
        let _ = stopped.await;
    }));
    Running { stop, task }
}

impl Running {
    /// Stops it and waits for [`observer::run`] to return, which it promises
    /// not to do before the state is written out.
    async fn stop(self, what: &str) {
        let _ = self.stop.send(());
        timeout(WAIT, self.task)
            .await
            .unwrap_or_else(|_| panic!("the {what} observer did not return after being stopped"))
            .unwrap_or_else(|e| panic!("the {what} observer panicked: {e}"));
    }
}

/// The path the observer syncs, publishes, persists and reloads along.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_the_observer_syncs_publishes_and_persists() {
    let Some(nats) = NatsServer::start().await else {
        eprintln!("skipping: NATS_SERVER_BINARY is not set");
        return;
    };
    let client = nats.client().await;
    let node = Node::start(BLOCKS);
    let datadir = TempDir::new("observer-integration");

    // Subscribed before the observer starts, so nothing it publishes while
    // coming up is missed.
    let mut events = Events::subscribe(&client).await;
    let observer = start(config(nats.url(), &datadir, vec![node.addr()]));

    // What the peer told us about itself, and what it said unprompted right
    // after -- three kinds, each on its own subject.
    let found = events
        .expect_kinds(&["handshake", "fee_filter", "send_cmpct"])
        .await;
    let handshake = &found["handshake"];
    assert!(
        handshake.user_agent.contains("Satoshi"),
        "the handshake came from something other than Core: {:?}",
        handshake.user_agent
    );
    assert_eq!(handshake.peer_addr, node.addr());

    // ── The chain reached the tree, which the RPC reads ─────────────────────
    //
    // Waited for rather than asserted on the spot: the handshake arrives
    // before the sync does, so the height is a thing that becomes true.
    let tips = rpc_until(
        &client,
        "headertree.tips",
        "",
        "reached the node's height",
        |tips| {
            tips.as_array()
                .and_then(|tips| tips.first())
                .and_then(|tip| tip["height"].as_u64())
                == Some(BLOCKS as u64)
        },
    )
    .await;
    let tip = &tips.as_array().expect("tips is an array")[0];
    assert_eq!(tip["status"].as_str(), Some("active"));
    assert_eq!(
        tip["hash"].as_str(),
        Some(node.best_block_hash().as_str()),
        "the observer's tip is not the node's tip"
    );

    // ── Stopping writes the state out ───────────────────────────────────────
    observer.stop("first").await;

    let network_dir = datadir.path().join("regtest");
    for name in ["headers.bin", "addresses.bin"] {
        let path = network_dir.join(name);
        let len = std::fs::metadata(&path)
            .unwrap_or_else(|e| panic!("{} was not written: {e}", path.display()))
            .len();
        assert!(len > 0, "{} is empty", path.display());
    }

    // ── A restart reads both files rather than starting over ────────────────
    //
    // No bootstrap peer this time, so there is nowhere for a height or an
    // address to come from except the files the last run left.
    let observer = start(config(nats.url(), &datadir, Vec::new()));

    let tips = rpc(&client, "headertree.tips", "").await;
    assert_eq!(
        tips.as_array().expect("tips is an array")[0]["height"].as_u64(),
        Some(BLOCKS as u64),
        "the header tree did not come back from disk"
    );
    let addresses = rpc(&client, "addresses.info", "").await;
    assert!(
        addresses["total"].as_u64().unwrap_or(0) >= 1,
        "the address book did not come back from disk: {addresses:?}"
    );

    observer.stop("restarted").await;
}

/// A peer that arrives through the address manager rather than as a bootstrap
/// address, and is then measured.
///
/// The bootstrap path above is deliberately not the manager's: it is
/// sequential and ends as soon as the headers are in, so the session it opens
/// is gone long before a ping is due. This is the ordinary path -- an address
/// handed to the RPC, picked up on the next tick, dialled, handshaked and
/// pinged -- and the round trip time it reports is the tool's main output.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_an_address_handed_to_the_rpc_is_dialled_and_measured() {
    let Some(nats) = NatsServer::start().await else {
        eprintln!("skipping: NATS_SERVER_BINARY is not set");
        return;
    };
    let client = nats.client().await;
    let node = Node::start(1);
    let datadir = TempDir::new("observer-dialled");

    let mut events = Events::subscribe(&client).await;
    let observer = start(config(nats.url(), &datadir, Vec::new()));

    // Nothing to dial until this, which is also what proves the dial came
    // from the manager rather than from the bootstrap path.
    let added = rpc(
        &client,
        "addresses.add",
        &common::serde_json::json!([node.addr()]).to_string(),
    )
    .await;
    assert_eq!(added["added"].as_u64(), Some(1), "{added:?}");
    assert_eq!(
        added["rejected"].as_array().map(Vec::len),
        Some(0),
        "{added:?}"
    );

    // The handshake says it was dialled; the ping says it is being measured.
    let found = events.expect_kinds(&["handshake", "ping_rtt"]).await;
    assert_eq!(found["handshake"].peer_addr, node.addr());
    let Some(peer_event::Event::PingRtt(rtt)) = &found["ping_rtt"].event else {
        unreachable!()
    };
    // A loopback round trip is fast but not instant in wall-clock terms; all
    // this has to show is that the number was measured rather than defaulted.
    assert!(rtt.rtt_ms < 10_000, "implausible loopback rtt: {rtt:?}");

    // The session is live and the registry knows it, which is what the RPC
    // answers from -- no event says what is connected right now.
    let conns = rpc(&client, "connections.list", "").await;
    let listed = conns["connections"]
        .as_array()
        .expect("connections is an array");
    assert_eq!(listed.len(), 1, "expected exactly our one peer: {conns:?}");
    assert_eq!(listed[0]["addr"].as_str(), Some(node.addr().as_str()));

    observer.stop("dialling").await;
}
