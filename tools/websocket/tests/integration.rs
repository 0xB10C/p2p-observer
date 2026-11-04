//! End-to-end: events published to a real NATS server reach websocket
//! clients, filtered by what each client subscribed to.
//!
//! Needs a `nats-server` binary, found through `NATS_SERVER_BINARY` (the nix
//! shell sets it); without it the test is skipped.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use common::events::{Handshake, PeerEvent, PingRtt, peer_event};
use common::futures_util::{SinkExt, StreamExt};
use common::prost::Message;
use common::serde_json::{self, Value};
use common::tokio::net::TcpStream;
use common::tokio::sync::{oneshot, watch};
use common::tokio::time::timeout;
use common::{async_nats, tokio};
use testsupport::NatsServer;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use websocket::{Args, run};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const WAIT: Duration = Duration::from_secs(5);

struct Harness {
    _nats: NatsServer,
    publisher: async_nats::Client,
    addr: SocketAddr,
    shutdown: watch::Sender<bool>,
}

impl Harness {
    async fn start() -> Option<Self> {
        let _ = common::tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .try_init();
        let nats = NatsServer::start().await?;
        let publisher = nats.client().await;
        let args = Args {
            nats_url: nats.url().to_owned(),
            network: None,
            listen: "127.0.0.1:0".to_owned(),
            asmap: Some(format!("{}/tests/fixtures/asmap.raw", env!("CARGO_MANIFEST_DIR")).into()),
            // Long enough that every status update in these tests is the one
            // a subscribing client asks for, rather than a tick arriving by
            // luck.
            status_interval_secs: 3600,
        };
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (bound_tx, bound_rx) = oneshot::channel();
        tokio::spawn(async move {
            run(args, shutdown_rx, Some(bound_tx)).await.unwrap();
        });
        let addr = timeout(WAIT, bound_rx).await.unwrap().unwrap();
        Some(Harness {
            _nats: nats,
            publisher,
            addr,
            shutdown,
        })
    }

    /// A connected client that has sent `subscriptions` and seen its hello.
    async fn client(&self, subscriptions: &str) -> Ws {
        let (mut ws, _) = connect_async(format!("ws://{}", self.addr)).await.unwrap();
        let hello = next_json(&mut ws, "hello").await;
        assert_eq!(hello["hello"]["asmap"], true);
        assert!(hello["hello"]["server_time_ms"].as_u64().unwrap() > 0);
        ws.send(WsMessage::text(subscriptions)).await.unwrap();
        // The subscription is applied before the next event is handled only
        // once the server has read it; a round trip of our own would need a
        // reply the protocol does not have, so publish after this returns.
        tokio::time::sleep(Duration::from_millis(200)).await;
        ws
    }

    async fn publish(&self, network: &str, kind: &str, event: &PeerEvent) {
        self.publisher
            .publish(
                format!("p2p-observer.{network}.{kind}"),
                event.encode_to_vec().into(),
            )
            .await
            .unwrap();
        self.publisher.flush().await.unwrap();
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

async fn next_json(ws: &mut Ws, what: &str) -> Value {
    loop {
        let msg = timeout(WAIT, ws.next())
            .await
            .unwrap_or_else(|_| panic!("no {what} within the timeout"));
        match msg.expect("stream open").expect("websocket read") {
            WsMessage::Text(text) => {
                return serde_json::from_str(text.as_str()).unwrap();
            }
            _ => continue,
        }
    }
}

/// Nothing arrives within a short wait. Not a proof, but it catches an event
/// a client never asked for.
async fn expect_silence(ws: &mut Ws) {
    if let Ok(msg) = timeout(Duration::from_millis(400), ws.next()).await {
        panic!("expected no message, got {msg:?}");
    }
}

fn event(conn: u64, addr: &str, inner: peer_event::Event) -> PeerEvent {
    PeerEvent {
        connection_id: conn,
        timestamp_ms: websocket::now_ms(),
        peer_addr: addr.to_owned(),
        user_agent: "/Satoshi:31.1.0/".to_owned(),
        transport_version: Some(2),
        dropped_events: 0,
        instance_id: 42,
        dropped_by_kind: None,
        event: Some(inner),
    }
}

fn handshake() -> peer_event::Event {
    peer_event::Event::Handshake(Handshake {
        protocol_version: 70016,
        services: 0x409,
        start_height: 5,
        relay: true,
        peer_timestamp: 1_700_000_000,
        addr_recv: "1.2.3.4:0".to_owned(),
        sendaddrv2: true,
        wtxid_relay: true,
        user_agent: "/Satoshi:31.1.0/".to_owned(),
        nonce: 0x1234_5678_9abc_def0,
    })
}

#[tokio::test]
async fn test_subscribed_events_reach_clients_enriched() {
    let Some(h) = Harness::start().await else {
        eprintln!("NATS_SERVER_BINARY not set, skipping");
        return;
    };
    let mut ws = h.client(r#"{"handshakes":true}"#).await;

    h.publish(
        "signet",
        "handshake",
        &event(1, "250.1.2.3:38333", handshake()),
    )
    .await;

    let msg = next_json(&mut ws, "handshake event").await;
    let ev = &msg["event"];
    assert_eq!(ev["network"], "signet");
    assert_eq!(ev["peer_addr"], "250.1.2.3:38333");
    assert_eq!(ev["connection_id"], 1);
    assert_eq!(ev["instance_id"], 42);
    assert_eq!(ev["transport_version"], 2);
    assert_eq!(ev["event"]["Handshake"]["start_height"], 5);
    assert_eq!(ev["event"]["Handshake"]["protocol_version"], 70016);
    // The asmap fixture maps this address, so the peer arrives with its
    // autonomous system and the page does not need the map.
    assert_eq!(ev["ip"]["asn"], 1000);
}

/// The status update is the observer's own answer about its live sessions,
/// forwarded with the peer's autonomous system filled in, and a client that
/// subscribes gets one without waiting for the interval.
#[tokio::test]
async fn test_status_updates_come_from_the_observer_rpc() {
    let Some(h) = Harness::start().await else {
        eprintln!("NATS_SERVER_BINARY not set, skipping");
        return;
    };

    // Stand in for an observer: answer connections.list the way it does.
    let mut rpc = h
        .publisher
        .subscribe("p2p-observer.signet.rpc.connections.list")
        .await
        .unwrap();
    let replier = h.publisher.clone();
    tokio::spawn(async move {
        while let Some(msg) = rpc.next().await {
            let reply = serde_json::json!({
                "taken_ms": 1_700_000_060_000u64,
                "instance_id": 42u64,
                "connected": 1,
                "dialing": 3,
                "connections": [{
                    "connection_id": 7,
                    "addr": "250.1.2.3:38333",
                    "user_agent": "/Satoshi:31.1.0/",
                    "start_height": 5,
                }],
            })
            .to_string();
            if let Some(reply_to) = msg.reply {
                replier.publish(reply_to, reply.into()).await.unwrap();
            }
        }
    });

    // Without --network the tool learns which observers exist from their
    // events, so one has to arrive before there is anything to poll.
    let mut events = h.client(r#"{"handshakes":true}"#).await;
    h.publish(
        "signet",
        "handshake",
        &event(1, "250.1.2.3:38333", handshake()),
    )
    .await;
    next_json(&mut events, "handshake event").await;

    let mut ws = h.client(r#"{"connection_status":true}"#).await;
    let msg = next_json(&mut ws, "status update").await;
    let status = &msg["status"];
    assert_eq!(status["network"], "signet");
    // Passed through as the observer sent it.
    assert_eq!(status["connected"], 1);
    assert_eq!(status["dialing"], 3);
    assert_eq!(status["instance_id"], 42);
    let c = &status["connections"][0];
    assert_eq!(c["connection_id"], 7);
    assert_eq!(c["user_agent"], "/Satoshi:31.1.0/");
    // Added here, from the asmap, exactly as on an event.
    assert_eq!(c["ip"]["asn"], 1000);

    // A client that did not ask for it gets none of this.
    expect_silence(&mut events).await;
}

#[tokio::test]
async fn test_unsubscribed_kinds_are_not_sent() {
    let Some(h) = Harness::start().await else {
        eprintln!("NATS_SERVER_BINARY not set, skipping");
        return;
    };
    let mut ws = h.client(r#"{"handshakes":true}"#).await;

    // A kind this client did not ask for, on a network it does see.
    h.publish(
        "signet",
        "ping_rtt",
        &event(
            2,
            "250.1.2.3:38333",
            peer_event::Event::PingRtt(PingRtt {
                rtt_ms: 33,
                tcp_stats: None,
            }),
        ),
    )
    .await;
    expect_silence(&mut ws).await;

    // Asking for it afterwards is enough; there is no snapshot to catch up
    // on, so only what arrives from now on is sent.
    ws.send(WsMessage::text(r#"{"ping_rtt":true}"#))
        .await
        .unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    h.publish(
        "signet",
        "ping_rtt",
        &event(
            2,
            "250.1.2.3:38333",
            peer_event::Event::PingRtt(PingRtt {
                rtt_ms: 44,
                tcp_stats: None,
            }),
        ),
    )
    .await;
    let msg = next_json(&mut ws, "ping event").await;
    assert_eq!(msg["event"]["event"]["PingRtt"]["rtt_ms"], 44);
}

#[tokio::test]
async fn test_a_client_that_asked_for_nothing_gets_nothing() {
    let Some(h) = Harness::start().await else {
        eprintln!("NATS_SERVER_BINARY not set, skipping");
        return;
    };
    let mut ws = h.client("{}").await;
    h.publish(
        "signet",
        "handshake",
        &event(1, "250.1.2.3:38333", handshake()),
    )
    .await;
    expect_silence(&mut ws).await;
}

/// A client cannot drive the status poll in a loop.
///
/// The on-demand poll is there so a page asking for the status does not wait
/// out the interval -- which the operator may have set to an hour -- and it
/// lets an unauthenticated client decide when an observer is asked. Nothing
/// above it limits how often: the read loop takes subscription messages for as
/// long as a client sends them, and each one that cannot be answered from the
/// cache puts an RPC request per network on the wire.
///
/// The cache is what normally closes that door, after the first answer. It is
/// empty exactly when no observer is answering -- which is when a relay asking
/// faster is the last thing anyone wants. So this test keeps it empty, the way
/// an observer in trouble would, and counts.
#[tokio::test]
async fn test_a_client_cannot_drive_the_status_poll_in_a_loop() {
    let Some(h) = Harness::start().await else {
        eprintln!("skipping: NATS_SERVER_BINARY is not set");
        return;
    };

    // An observer that answers by refusing. A refusal is not cached, so every
    // ask reaches here -- and counting is the point.
    let asked = Arc::new(AtomicUsize::new(0));
    let mut requests = h
        .publisher
        .subscribe("p2p-observer.*.rpc.connections.list")
        .await
        .unwrap();
    let replier = h.publisher.clone();
    let counted = Arc::clone(&asked);
    let answering = tokio::spawn(async move {
        while let Some(msg) = requests.next().await {
            counted.fetch_add(1, Ordering::Relaxed);
            if let Some(reply_to) = msg.reply {
                let _ = replier
                    .publish(reply_to, br#"{"error":"not today"}"#.to_vec().into())
                    .await;
            }
        }
    });

    // One event, so the relay knows of a network to ask about at all.
    h.publish(
        "signet",
        "ping_rtt",
        &event(
            1,
            "1.2.3.4:38333",
            peer_event::Event::PingRtt(PingRtt {
                rtt_ms: 5,
                tcp_stats: None,
            }),
        ),
    )
    .await;
    tokio::time::sleep(Duration::from_millis(200)).await;

    let mut ws = h.client(r#"{"connection_status":true}"#).await;
    let deadline = Instant::now() + Duration::from_secs(1);
    let mut sent = 0u32;
    while Instant::now() < deadline {
        ws.send(WsMessage::text(r#"{"connection_status":true}"#))
            .await
            .unwrap();
        sent += 1;
    }
    // Let anything already in flight land before counting.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let asked = asked.load(Ordering::Relaxed);
    assert!(
        asked <= 2,
        "{sent} subscription messages drew {asked} requests out of the relay"
    );
    answering.abort();
}
