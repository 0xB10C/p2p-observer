//! End-to-end: events published to a real NATS server show up on `/metrics`.
//!
//! Needs a `nats-server` binary, found through `NATS_SERVER_BINARY` (the nix
//! shell sets it); without it the tests are skipped.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use common::events::connection_result::{Disconnected, Result as AttemptResult};
use common::events::{
    AnnouncementType, BlockAnnouncement, ConnectionResult, DisconnectReason, FeeFilter, Handshake,
    PeerEvent, PingRtt, peer_event,
};
use common::prost::Message;
use common::tokio::io::{AsyncReadExt, AsyncWriteExt};
use common::tokio::net::{TcpListener, TcpStream};
use common::tokio::sync::{oneshot, watch};
use common::tokio::time::timeout;
use common::{async_nats, tokio};
use metrics::{Args, run};

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
    async fn start(network: Option<&str>) -> Option<Self> {
        let _ = common::tracing_subscriber::fmt()
            .with_env_filter("debug")
            .with_test_writer()
            .try_init();
        let nats = NatsServer::start().await?;
        let publisher = async_nats::connect(&nats.url).await.unwrap();
        let args = Args {
            nats_url: nats.url.clone(),
            network: network.map(str::to_owned),
            listen: "127.0.0.1:0".to_owned(),
        };
        let (shutdown, shutdown_rx) = watch::channel(false);
        let (bound_tx, bound_rx) = oneshot::channel();
        tokio::spawn(async move {
            run(args, shutdown_rx, Some(bound_tx)).await.unwrap();
        });
        let addr = timeout(WAIT, bound_rx).await.unwrap().unwrap();
        // The subscription is made after the listener is bound; a publish
        // before it exists is lost, and the protocol has no reply to wait
        // for.
        tokio::time::sleep(Duration::from_millis(300)).await;
        Some(Harness {
            _nats: nats,
            publisher,
            addr,
            shutdown,
        })
    }

    async fn publish(&self, network: &str, kind: &str, event: &PeerEvent) {
        self.publish_raw(
            &format!("p2p-observer.{network}.{kind}"),
            event.encode_to_vec(),
        )
        .await;
    }

    async fn publish_raw(&self, subject: &str, payload: Vec<u8>) {
        self.publisher
            .publish(subject.to_owned(), payload.into())
            .await
            .unwrap();
        self.publisher.flush().await.unwrap();
    }

    /// One scrape, as the body text.
    async fn scrape(&self, path: &str) -> (u16, String) {
        let mut stream = TcpStream::connect(self.addr).await.unwrap();
        stream
            .write_all(format!("GET {path} HTTP/1.1\r\nHost: localhost\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut response = Vec::new();
        timeout(WAIT, stream.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        let text = String::from_utf8(response).unwrap();
        let status: u16 = text
            .split_ascii_whitespace()
            .nth(1)
            .and_then(|s| s.parse().ok())
            .expect("a status line");
        let body = text
            .split_once("\r\n\r\n")
            .map(|(_, body)| body.to_owned())
            .unwrap_or_default();
        (status, body)
    }

    /// Scrapes until `sample` is present, since a publish returns before the
    /// tool has read the event.
    async fn scrape_until(&self, sample: &Sample) -> Exposition {
        let deadline = Instant::now() + WAIT;
        loop {
            let (status, body) = self.scrape("/metrics").await;
            assert_eq!(status, 200);
            let exposition = parse(&body);
            if exposition.contains_key(sample) {
                return exposition;
            }
            assert!(Instant::now() < deadline, "no {sample:?} in:\n{body}");
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        let _ = self.shutdown.send(true);
    }
}

/// A series: name and labels, order-free.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct Sample {
    name: String,
    labels: BTreeMap<String, String>,
}

fn sample(name: &str, labels: &[(&str, &str)]) -> Sample {
    Sample {
        name: name.to_owned(),
        labels: labels
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

type Exposition = BTreeMap<Sample, f64>;

/// Parses the text format far enough to look samples up by name and labels.
fn parse(body: &str) -> Exposition {
    let mut out = BTreeMap::new();
    for line in body.lines() {
        if line.starts_with('#') || line.is_empty() {
            continue;
        }
        let (series, value) = line.rsplit_once(' ').expect("a value");
        let (name, labels) = match series.split_once('{') {
            Some((name, rest)) => {
                let rest = rest.strip_suffix('}').expect("closing brace");
                let labels = rest
                    .split("\",")
                    .filter(|s| !s.is_empty())
                    .map(|pair| {
                        let (k, v) = pair.split_once("=\"").expect("a label");
                        (k.to_owned(), v.trim_end_matches('"').to_owned())
                    })
                    .collect();
                (name.to_owned(), labels)
            }
            None => (series.to_owned(), BTreeMap::new()),
        };
        out.insert(Sample { name, labels }, value.parse().expect("a number"));
    }
    out
}

fn event(connection_id: u64, timestamp_ms: u64, kind: peer_event::Event) -> PeerEvent {
    PeerEvent {
        connection_id,
        timestamp_ms,
        peer_addr: "1.2.3.4:38333".to_owned(),
        user_agent: "/Satoshi:28.1.0/".to_owned(),
        transport_version: Some(2),
        dropped_events: 3,
        instance_id: 42,
        dropped_by_kind: None,
        event: Some(kind),
    }
}

fn announcement(hash: &str, new_to_us: bool) -> peer_event::Event {
    peer_event::Event::BlockAnnouncement(BlockAnnouncement {
        block_hash: hash.to_owned(),
        announcement_type: AnnouncementType::Headers as i32,
        tcp_stats: None,
        batch_size: 1,
        height: Some(100),
        new_to_us,
        compact_block: None,
    })
}

#[tokio::test]
async fn test_events_become_metrics() {
    let Some(h) = Harness::start(None).await else {
        eprintln!("NATS_SERVER_BINARY not set, skipping");
        return;
    };

    let hs = Handshake {
        protocol_version: 70016,
        services: 1 | 8,
        start_height: 95,
        relay: true,
        peer_timestamp: 1_000_000,
        addr_recv: "0.0.0.0:0".to_owned(),
        sendaddrv2: true,
        wtxid_relay: true,
        user_agent: "/Satoshi:28.1.0(fork)/".to_owned(),
    };
    h.publish(
        "signet",
        "handshake",
        &event(1, 1_000_000_000, peer_event::Event::Handshake(hs)),
    )
    .await;
    let ping = PingRtt {
        rtt_ms: 120,
        tcp_stats: None,
    };
    h.publish(
        "signet",
        "ping_rtt",
        &event(1, 1_000_001_000, peer_event::Event::PingRtt(ping)),
    )
    .await;
    h.publish(
        "signet",
        "block_announcement",
        &event(1, 1_000_010_000, announcement("ab", true)),
    )
    .await;
    h.publish(
        "signet",
        "block_announcement",
        &event(2, 1_000_012_500, announcement("ab", false)),
    )
    .await;
    let result = ConnectionResult {
        result: Some(AttemptResult::Disconnected(Disconnected {
            setup_ms: 400,
            uptime_ms: 60_000,
            reason: DisconnectReason::PeerClosed as i32,
            messages_by_command: [("ping".to_owned(), 2)].into(),
            messages_other: 0,
            unsolicited_pongs: 0,
        })),
    };
    h.publish(
        "signet",
        "connection_result",
        &event(
            1,
            1_000_020_000,
            peer_event::Event::ConnectionResult(result),
        ),
    )
    .await;
    // Not an event subject: the RPC ones have one more token.
    h.publish_raw("p2p-observer.signet.rpc.addresses", b"{}".to_vec())
        .await;
    h.publish_raw("p2p-observer.signet.handshake", vec![0xff, 0xff])
        .await;
    // Published last, so once it is there everything above has been read.
    let fee = FeeFilter {
        feerate_sat_per_kvb: 1000,
    };
    h.publish(
        "signet",
        "fee_filter",
        &event(1, 1_000_030_000, peer_event::Event::FeeFilter(fee)),
    )
    .await;

    let m = h
        .scrape_until(&sample(
            "p2pobserver_fee_filters_total",
            &[("network", "signet")],
        ))
        .await;
    let get = |name: &str, labels: &[(&str, &str)]| {
        *m.get(&sample(name, labels))
            .unwrap_or_else(|| panic!("no {name} {labels:?} in {m:#?}"))
    };
    let net = ("network", "signet");

    // The pipeline.
    assert_eq!(
        get("p2pobserver_events_total", &[net, ("kind", "handshake")]),
        1.0
    );
    assert_eq!(
        get(
            "p2pobserver_events_total",
            &[net, ("kind", "block_announcement")]
        ),
        2.0
    );
    assert_eq!(get("p2pobserver_undecodable_events_total", &[net]), 1.0);
    assert_eq!(get("p2pobserver_observer_dropped_events", &[net]), 3.0);
    assert_eq!(
        get("p2pobserver_last_event_timestamp_seconds", &[net]),
        1_000_030.0
    );
    assert_eq!(get("p2pobserver_event_delay_seconds_count", &[net]), 6.0);
    assert!(get("p2pobserver_start_timestamp_seconds", &[]) > 0.0);
    assert!(m.keys().all(|s| s.name.starts_with("p2pobserver_")));
    assert!(
        m.keys()
            .all(|s| s.labels.get("network").is_none_or(|n| n == "signet"))
    );

    // The network.
    assert_eq!(
        get("p2pobserver_handshakes_total", &[net, ("transport", "v2")]),
        1.0
    );
    assert_eq!(
        get(
            "p2pobserver_handshake_user_agents_total",
            &[net, ("user_agent", "Satoshi:28.1.0")]
        ),
        1.0
    );
    assert_eq!(
        get(
            "p2pobserver_handshake_services_total",
            &[net, ("service", "witness")]
        ),
        1.0
    );
    assert_eq!(
        get(
            "p2pobserver_handshake_features_total",
            &[net, ("feature", "wtxid_relay")]
        ),
        1.0
    );
    assert!(!m.contains_key(&sample(
        "p2pobserver_handshake_features_total",
        &[net, ("feature", "addr_recv")]
    )));
    assert_eq!(get("p2pobserver_ping_rtt_seconds_sum", &[net]), 0.12);
    assert_eq!(
        get("p2pobserver_blocks_total", &[net, ("type", "headers")]),
        1.0
    );
    assert_eq!(get("p2pobserver_best_height", &[net]), 100.0);
    assert_eq!(
        get(
            "p2pobserver_block_propagation_seconds_count",
            &[net, ("type", "headers")]
        ),
        1.0
    );
    assert_eq!(
        get(
            "p2pobserver_block_propagation_seconds_sum",
            &[net, ("type", "headers")]
        ),
        2.5
    );
    assert_eq!(
        get(
            "p2pobserver_connection_attempts_total",
            &[net, ("result", "disconnected"), ("reason", "peer_closed")]
        ),
        1.0
    );
    assert_eq!(
        get("p2pobserver_session_duration_seconds_sum", &[net]),
        60.0
    );
    assert_eq!(
        get(
            "p2pobserver_session_messages_total",
            &[net, ("command", "ping")]
        ),
        2.0
    );
    assert_eq!(
        get("p2pobserver_fee_filter_sat_per_kvb_sum", &[net]),
        1000.0
    );

    let (status, body) = h.scrape("/elsewhere").await;
    assert_eq!(status, 404);
    assert!(body.contains("/metrics"));
    let (status, body) = h.scrape("/").await;
    assert_eq!(status, 200);
    assert!(body.contains("p2pobserver_events_total"));
}

#[tokio::test]
async fn test_network_filter() {
    let Some(h) = Harness::start(Some("signet")).await else {
        eprintln!("NATS_SERVER_BINARY not set, skipping");
        return;
    };
    let fee = || peer_event::Event::FeeFilter(FeeFilter::default());
    h.publish("mainnet", "fee_filter", &event(1, 0, fee()))
        .await;
    h.publish("signet", "fee_filter", &event(1, 0, fee())).await;
    let m = h
        .scrape_until(&sample(
            "p2pobserver_fee_filters_total",
            &[("network", "signet")],
        ))
        .await;
    assert!(!m.contains_key(&sample(
        "p2pobserver_fee_filters_total",
        &[("network", "mainnet")]
    )));
    assert!(!m.contains_key(&sample(
        "p2pobserver_events_total",
        &[("network", "mainnet"), ("kind", "fee_filter")]
    )));
}
