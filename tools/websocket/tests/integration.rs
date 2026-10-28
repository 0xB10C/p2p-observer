//! End-to-end: events published to a real NATS server reach websocket
//! clients, filtered by what each client subscribed to.
//!
//! Needs a `nats-server` binary, found through `NATS_SERVER_BINARY` (the nix
//! shell sets it); without it the test is skipped.

use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::events::{Handshake, PeerEvent, PingRtt, peer_event};
use common::futures_util::{SinkExt, StreamExt};
use common::prost::Message;
use common::serde_json::{self, Value};
use common::tokio::net::{TcpListener, TcpStream};
use common::tokio::sync::{oneshot, watch};
use common::tokio::time::timeout;
use common::{async_nats, tokio};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{MaybeTlsStream, WebSocketStream, connect_async};
use websocket::{Args, run};

type Ws = WebSocketStream<MaybeTlsStream<TcpStream>>;

const WAIT: Duration = Duration::from_secs(5);

struct NatsServer {
    child: Child,
    url: String,
}

impl NatsServer {
    async fn start() -> Option<Self> {
        let binary = std::env::var("NATS_SERVER_BINARY").ok()?;
        // Take a free port; the small window until nats-server binds it is
        // fine for a test.
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = Command::new(binary)
            .args(["-a", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning nats-server");
        // Wrapped first so the process is killed on every path, including
        // the panic below.
        let server = NatsServer {
            child,
            url: format!("nats://127.0.0.1:{port}"),
        };
        for _ in 0..50 {
            if async_nats::connect(&server.url).await.is_ok() {
                return Some(server);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("nats-server did not come up on {}", server.url);
    }
}

impl Drop for NatsServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

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
        let publisher = async_nats::connect(&nats.url).await.unwrap();
        let args = Args {
            nats_url: nats.url.clone(),
            network: None,
            listen: "127.0.0.1:0".to_owned(),
            asmap: Some(format!("{}/tests/fixtures/asmap.raw", env!("CARGO_MANIFEST_DIR")).into()),
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
