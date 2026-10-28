//! websocket: subscribes to p2p-observer events on NATS and forwards them to
//! browsers over a websocket.
//!
//! The tool holds nothing. An event is decoded, tagged with the network it
//! came from, and written to the clients that asked for that kind of event;
//! nothing is accumulated between events. What the pages show -- the open
//! connections, how a block spread -- is built in the browser from the same
//! stream, so the server cost per client is one serialisation per event
//! whether a page is showing fifty connections or fifty thousand.
//!
//! A client starts with no subscriptions and sends a JSON object such as
//! `{"handshakes": true, "ping_rtt": true}` to choose the event kinds it
//! wants; a later object replaces the choice. Each event arrives as
//! `{"event": …}`: the protobuf `PeerEvent` as JSON, plus the `network` and,
//! with `--asmap`, the `ip` information of the peer. On connect the server
//! sends one `{"hello": …}` with its clock, so a page can relate event
//! timestamps to its own time.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use common::anyhow::{Context, Result};
use common::clap::Parser;
use common::events::{PeerEvent, peer_event};
use common::futures_util::{SinkExt, StreamExt};
use common::prost::Message;
use common::serde::{Deserialize, Serialize};
use common::serde_json;
use common::tokio::net::{TcpListener, TcpStream};
use common::tokio::sync::{Mutex, mpsc, oneshot, watch};
use common::tokio::{self, task::JoinHandle};
use common::{async_nats, tracing};
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tokio_tungstenite::{WebSocketStream, accept_async};

pub mod ipinfo;

use ipinfo::{IpInfo, IpLookup};

pub const TARGET: &str = "websocket";
/// Largest subscription message accepted from a client.
const MAX_CLIENT_MESSAGE: usize = 512;
/// Messages queued per client before it is considered too slow and dropped.
/// A block arrives at every connection at once, so this has to hold a burst
/// of one event per connection.
const CLIENT_QUEUE: usize = 16_384;

/// Forward p2p-observer events to browsers over a websocket
#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Args {
    /// The NATS server to subscribe to
    #[arg(short = 'a', long, default_value = "nats://localhost:4222")]
    pub nats_url: String,

    /// Only events of this network; all networks by default
    #[arg(short, long)]
    pub network: Option<String>,

    /// The address the websocket server listens on
    #[arg(short, long, default_value = "127.0.0.1:47484")]
    pub listen: String,

    /// An asmap file for IP to ASN lookups, e.g. latest_asmap.dat from
    /// https://github.com/bitcoin-core/asmap-data. Without it events carry no
    /// ASN information
    #[arg(long)]
    pub asmap: Option<PathBuf>,
}

impl Args {
    /// The NATS subject to subscribe to. `*` for the event kind keeps the
    /// RPC subjects out, which have one more token.
    pub fn subject(&self) -> String {
        format!("p2p-observer.{}.*", self.network.as_deref().unwrap_or("*"))
    }
}

/// The network token of an event subject, `p2p-observer.<network>.<kind>`.
pub fn network_of(subject: &str) -> Option<&str> {
    let mut parts = subject.split('.');
    match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("p2p-observer"), Some(network), Some(_), None) => Some(network),
        _ => None,
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

/// What a client wants to receive. Sent by the client as JSON; every field
/// defaults to `false`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "common::serde", default, deny_unknown_fields)]
pub struct ClientSubscriptions {
    pub ping_rtt: bool,
    pub block_announcements: bool,
    /// Can be a lot of data: every gossiped address is in the event.
    pub address_announcements: bool,
    pub connection_results: bool,
    pub handshakes: bool,
    pub compact_block_probes: bool,
    pub fee_filters: bool,
    pub send_cmpcts: bool,
}

impl ClientSubscriptions {
    fn wants(&self, event: &PeerEvent) -> bool {
        match &event.event {
            Some(peer_event::Event::PingRtt(_)) => self.ping_rtt,
            Some(peer_event::Event::BlockAnnouncement(_)) => self.block_announcements,
            Some(peer_event::Event::AddressAnnouncement(_)) => self.address_announcements,
            Some(peer_event::Event::ConnectionResult(_)) => self.connection_results,
            Some(peer_event::Event::Handshake(_)) => self.handshakes,
            Some(peer_event::Event::CompactBlockProbe(_)) => self.compact_block_probes,
            Some(peer_event::Event::FeeFilter(_)) => self.fee_filters,
            Some(peer_event::Event::SendCmpct(_)) => self.send_cmpcts,
            None => false,
        }
    }

    fn any(&self) -> bool {
        *self != Self::default()
    }
}

/// An event with the network from its subject and, when an asmap is loaded,
/// the autonomous system of the peer.
#[derive(Debug, Serialize)]
#[serde(crate = "common::serde")]
pub struct TaggedEvent<'a> {
    pub network: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<IpInfo>,
    #[serde(flatten)]
    pub event: &'a PeerEvent,
}

/// What the server says for itself when a client connects. The clock is here
/// because event timestamps come from the observer's clock, which a page has
/// to relate to its own; `asmap` tells a page whether to expect `ip`.
#[derive(Debug, Serialize)]
#[serde(crate = "common::serde")]
pub struct Hello {
    pub server_time_ms: u64,
    pub asmap: bool,
}

/// Everything sent to a client is one of these, JSON-encoded as an object
/// with a single key naming the variant.
#[derive(Debug, Serialize)]
#[serde(crate = "common::serde", rename_all = "snake_case")]
pub enum Outgoing<'a> {
    Hello(Hello),
    Event(TaggedEvent<'a>),
}

struct Client {
    tx: mpsc::Sender<Arc<str>>,
    subscriptions: ClientSubscriptions,
}

type Clients = Arc<Mutex<HashMap<SocketAddr, Client>>>;

struct Shared {
    clients: Clients,
    lookup: IpLookup,
}

/// The peer's autonomous system, or `None` without an asmap and for an
/// address no asmap covers, such as an onion address.
fn ip_info(lookup: &IpLookup, peer_addr: &str) -> Option<IpInfo> {
    if !lookup.available() {
        return None;
    }
    let ip = peer_addr.parse::<SocketAddr>().ok()?.ip();
    if !ipinfo::is_routable(ip) {
        return None;
    }
    lookup.lookup(ip)
}

/// Runs the tool until `shutdown` turns true. `bound_addr` receives the
/// listening address once bound (useful with `--listen 127.0.0.1:0`).
pub async fn run(
    args: Args,
    mut shutdown: watch::Receiver<bool>,
    bound_addr: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let lookup = match &args.asmap {
        Some(path) => {
            let lookup = IpLookup::from_file(path)?;
            tracing::info!(target: TARGET, path = %path.display(), "loaded asmap");
            lookup
        }
        None => {
            tracing::info!(target: TARGET, "no --asmap given, events carry no ASN information");
            IpLookup::none()
        }
    };
    let shared = Arc::new(Shared {
        clients: Arc::new(Mutex::new(HashMap::new())),
        lookup,
    });

    let nats = async_nats::connect(&args.nats_url)
        .await
        .with_context(|| format!("connecting to {}", args.nats_url))?;
    let subject = args.subject();
    let mut sub = nats
        .subscribe(subject.clone())
        .await
        .with_context(|| format!("subscribing to {subject}"))?;
    nats.flush().await.context("flushing the subscription")?;
    tracing::info!(target: TARGET, url = %args.nats_url, subject, "connected to NATS");

    let nats_task: JoinHandle<()> = {
        let shared = Arc::clone(&shared);
        tokio::spawn(async move {
            while let Some(msg) = sub.next().await {
                let Some(network) = network_of(&msg.subject) else {
                    tracing::debug!(target: TARGET, subject = %msg.subject, "ignoring subject");
                    continue;
                };
                match PeerEvent::decode(msg.payload.as_ref()) {
                    Ok(event) => handle_event(&shared, network, &event).await,
                    Err(e) => {
                        tracing::warn!(target: TARGET, subject = %msg.subject, "cannot decode event: {e}")
                    }
                }
            }
            tracing::warn!(target: TARGET, "NATS subscription ended");
        })
    };

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("binding websocket server to {}", args.listen))?;
    let local_addr = listener.local_addr().context("reading bound address")?;
    tracing::info!(target: TARGET, %local_addr, "websocket server listening");
    if let Some(tx) = bound_addr {
        let _ = tx.send(local_addr);
    }

    loop {
        tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok((stream, addr)) => {
                    let shared = Arc::clone(&shared);
                    tokio::spawn(async move {
                        if let Err(e) = handle_client(stream, addr, shared).await {
                            tracing::debug!(target: TARGET, client = %addr, "client ended with error: {e}");
                        }
                    });
                }
                Err(e) => tracing::warn!(target: TARGET, "accept failed: {e}"),
            },
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
        }
    }
    tracing::info!(target: TARGET, "shutting down");
    nats_task.abort();
    shared.clients.lock().await.clear();
    Ok(())
}

/// Sends `text` to the clients `wants` selects, dropping clients whose
/// queue is full: a browser that cannot keep up must not stall the rest.
async fn broadcast(
    clients: &Clients,
    text: Arc<str>,
    wants: impl Fn(&ClientSubscriptions) -> bool,
) {
    let mut clients = clients.lock().await;
    let mut slow = Vec::new();
    for (addr, client) in clients.iter() {
        if wants(&client.subscriptions) && client.tx.try_send(Arc::clone(&text)).is_err() {
            slow.push(*addr);
        }
    }
    for addr in slow {
        tracing::warn!(target: TARGET, client = %addr, "client too slow, dropping it");
        clients.remove(&addr);
    }
}

/// Serialises the event once for all clients that want it, and not at all
/// when none does -- the common case for the address gossip, which no page
/// subscribes to by default.
async fn handle_event(shared: &Shared, network: &str, event: &PeerEvent) {
    let wanted = shared
        .clients
        .lock()
        .await
        .values()
        .any(|c| c.subscriptions.wants(event));
    if !wanted {
        return;
    }
    let tagged = TaggedEvent {
        network,
        ip: ip_info(&shared.lookup, &event.peer_addr),
        event,
    };
    let Some(text) = encode("event", Outgoing::Event(tagged)) else {
        return;
    };
    broadcast(&shared.clients, text, |s| s.wants(event)).await;
}

fn encode<T: Serialize>(what: &str, value: T) -> Option<Arc<str>> {
    match serde_json::to_string(&value) {
        Ok(json) => Some(json.into()),
        Err(e) => {
            tracing::error!(target: TARGET, "cannot serialise {what}: {e}");
            None
        }
    }
}

async fn handle_client(stream: TcpStream, addr: SocketAddr, shared: Arc<Shared>) -> Result<()> {
    let websocket: WebSocketStream<TcpStream> = accept_async(stream).await?;
    let (mut outgoing, mut incoming) = websocket.split();
    let (tx, mut rx) = mpsc::channel::<Arc<str>>(CLIENT_QUEUE);
    shared.clients.lock().await.insert(
        addr,
        Client {
            tx: tx.clone(),
            subscriptions: ClientSubscriptions::default(),
        },
    );
    tracing::info!(target: TARGET, client = %addr, "client connected");

    let writer = tokio::spawn(async move {
        while let Some(text) = rx.recv().await {
            if outgoing.send(WsMessage::text(text.as_ref())).await.is_err() {
                break;
            }
        }
        let _ = outgoing.close().await;
    });

    let hello = Outgoing::Hello(Hello {
        server_time_ms: now_ms(),
        asmap: shared.lookup.available(),
    });
    if let Some(text) = encode("hello", hello) {
        let _ = tx.send(text).await;
    }

    while let Some(msg) = incoming.next().await {
        let msg = match msg {
            Ok(msg) => msg,
            Err(e) => {
                tracing::debug!(target: TARGET, client = %addr, "read error: {e}");
                break;
            }
        };
        match msg {
            WsMessage::Close(_) => break,
            WsMessage::Text(text) => {
                if text.is_empty() || text.len() > MAX_CLIENT_MESSAGE {
                    tracing::warn!(target: TARGET, client = %addr, len = text.len(), "bad subscription message size, disconnecting");
                    break;
                }
                let subs: ClientSubscriptions = match serde_json::from_str(text.as_str()) {
                    Ok(subs) => subs,
                    Err(e) => {
                        tracing::warn!(target: TARGET, client = %addr, "invalid subscription message, disconnecting: {e}");
                        break;
                    }
                };
                tracing::debug!(target: TARGET, client = %addr, ?subs, "subscriptions updated");
                let mut clients = shared.clients.lock().await;
                let Some(client) = clients.get_mut(&addr) else {
                    break;
                };
                client.subscriptions = subs;
                if !subs.any() {
                    tracing::debug!(target: TARGET, client = %addr, "client subscribed to nothing");
                }
            }
            _ => {}
        }
    }
    shared.clients.lock().await.remove(&addr);
    writer.abort();
    tracing::info!(target: TARGET, client = %addr, "client disconnected");
    Ok(())
}

/// Sets up logging for the binary, honouring `RUST_LOG` the way the rest of
/// the workspace does and defaulting to info.
pub fn init_logging() {
    common::tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(
            common::tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| common::tracing_subscriber::EnvFilter::new("info")),
        )
        .init();
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::events::{FeeFilter, PingRtt};

    fn parse(args: &[&str]) -> Args {
        Args::try_parse_from(["websocket"].iter().chain(args)).unwrap()
    }

    #[test]
    fn test_subject_from_network() {
        assert_eq!(parse(&[]).subject(), "p2p-observer.*.*");
        assert_eq!(
            parse(&["--network", "signet"]).subject(),
            "p2p-observer.signet.*"
        );
        assert_eq!(parse(&[]).listen, "127.0.0.1:47484");
    }

    #[test]
    fn test_network_of_subject() {
        assert_eq!(network_of("p2p-observer.signet.ping_rtt"), Some("signet"));
        assert_eq!(network_of("p2p-observer.signet.rpc.addresses.info"), None);
        assert_eq!(network_of("other.signet.ping_rtt"), None);
        assert_eq!(network_of("p2p-observer.signet"), None);
    }

    #[test]
    fn test_subscriptions_default_to_nothing() {
        let subs: ClientSubscriptions = serde_json::from_str("{}").unwrap();
        assert_eq!(subs, ClientSubscriptions::default());
        assert!(!subs.any());
        let subs: ClientSubscriptions = serde_json::from_str(r#"{"handshakes":true}"#).unwrap();
        assert!(subs.handshakes && !subs.ping_rtt && subs.any());
        // The state streams the tool used to serve are gone, and a client
        // asking for one is told rather than silently subscribed to nothing.
        assert!(serde_json::from_str::<ClientSubscriptions>(r#"{"peers":true}"#).is_err());
    }

    fn ev(inner: peer_event::Event) -> PeerEvent {
        PeerEvent {
            connection_id: 3,
            timestamp_ms: 5,
            peer_addr: "1.2.3.4:5".to_owned(),
            user_agent: "/x/".to_owned(),
            transport_version: Some(1),
            dropped_events: 0,
            instance_id: 1,
            dropped_by_kind: None,
            event: Some(inner),
        }
    }

    #[test]
    fn test_subscription_filters_event_kinds() {
        let ping = ev(peer_event::Event::PingRtt(PingRtt::default()));
        let fee = ev(peer_event::Event::FeeFilter(FeeFilter::default()));
        let subs = ClientSubscriptions {
            fee_filters: true,
            ..Default::default()
        };
        assert!(!subs.wants(&ping));
        assert!(subs.wants(&fee));
        assert!(!ClientSubscriptions::default().wants(&fee));
    }

    #[test]
    fn test_outgoing_event_shape() {
        let event = ev(peer_event::Event::FeeFilter(FeeFilter {
            feerate_sat_per_kvb: 1000,
        }));
        let json = serde_json::to_value(Outgoing::Event(TaggedEvent {
            network: "signet",
            ip: None,
            event: &event,
        }))
        .unwrap();
        assert_eq!(json["event"]["network"], "signet");
        assert_eq!(json["event"]["connection_id"], 3);
        assert_eq!(json["event"]["peer_addr"], "1.2.3.4:5");
        assert_eq!(
            json["event"]["event"]["FeeFilter"]["feerate_sat_per_kvb"],
            1000
        );
        // Without an asmap the key is absent rather than null, so a page can
        // tell "no asmap" from "an address no asmap covers" by the hello.
        assert!(json["event"].get("ip").is_none());
    }

    #[test]
    fn test_hello_carries_the_clock() {
        let json = serde_json::to_value(Outgoing::Hello(Hello {
            server_time_ms: 1_700_000_000_000,
            asmap: false,
        }))
        .unwrap();
        assert_eq!(json["hello"]["server_time_ms"], 1_700_000_000_000u64);
        assert_eq!(json["hello"]["asmap"], false);
    }

    #[test]
    fn test_ip_info_without_an_asmap_and_for_unroutable_addresses() {
        let none = IpLookup::none();
        assert!(ip_info(&none, "1.2.3.4:8333").is_none());

        let lookup = IpLookup::from_bytes(include_bytes!("../tests/fixtures/asmap.raw").to_vec())
            .expect("the test asmap parses");
        // An onion address is not a socket address, and a private one is not
        // in any asmap: neither is a reason to fail.
        assert!(ip_info(&lookup, "abcdefg.onion:8333").is_none());
        assert!(ip_info(&lookup, "192.168.0.1:8333").is_none());
        assert!(ip_info(&lookup, "not an address").is_none());
    }
}
