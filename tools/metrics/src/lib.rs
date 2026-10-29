//! metrics: subscribes to p2p-observer events on NATS and serves Prometheus
//! metrics over HTTP.
//!
//! Two groups of series. The infrastructure ones are about the pipeline:
//! how many events of each kind arrive and how far behind the observer they
//! are read, what the observer dropped before its publisher, when it
//! restarted. The network ones are what the events say about the peers: how
//! attempts end, what peers claim in their handshakes, round trips, how
//! blocks spread, what the gossip carries.
//!
//! Every series is bounded. A label value the peer gets to choose -- a user
//! agent, a protocol version, a message command -- is normalised and then
//! capped, so the network cannot grow the registry. The tool keeps nothing
//! per connection: each event is a counter increment or a histogram sample
//! on its own. The only memory between events is per network, and small:
//! which observer run is sending, the best height announced, and the first
//! sighting of the last few blocks, from which propagation is measured.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};

use common::anyhow::{Context, Result};
use common::clap::Parser;
use common::events::connection_result::Result as AttemptResult;
use common::events::{
    AddressAnnouncement, BlockAnnouncement, ConnectionResult, DroppedEvents, Handshake, PeerEvent,
    PingRtt, SendCmpct, TcpStats, peer_event,
};
use common::futures_util::StreamExt;
use common::prost::Message;
use common::tokio::net::TcpListener;
use common::tokio::sync::{oneshot, watch};
use common::{async_nats, tokio, tracing};

pub mod labels;
pub mod metrics;
pub mod server;

use labels::{Bounded, OTHER};
pub use metrics::Metrics;

pub const TARGET: &str = "metrics";

/// How many blocks per network the first sighting is remembered for. A
/// propagation sample needs the first sighting of its block, and an
/// announcement of a block older than this many is a catch-up, not
/// propagation.
const RECENT_BLOCKS: usize = 64;

/// Serve Prometheus metrics computed from p2p-observer events
#[derive(Parser, Debug, Clone)]
#[command(version, about)]
pub struct Args {
    /// The NATS server to subscribe to
    #[arg(short = 'a', long, default_value = "nats://localhost:4222")]
    pub nats_url: String,

    /// Only events of this network; all networks by default
    #[arg(short, long)]
    pub network: Option<String>,

    /// The address the HTTP server listens on; the metrics are at /metrics
    #[arg(short, long, default_value = "127.0.0.1:8282")]
    pub listen: String,
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

/// The kind of an event as a label, the oneof's variant in the spelling of
/// the NATS subjects.
pub fn kind_of(event: &PeerEvent) -> &'static str {
    match &event.event {
        Some(peer_event::Event::PingRtt(_)) => "ping_rtt",
        Some(peer_event::Event::BlockAnnouncement(_)) => "block_announcement",
        Some(peer_event::Event::AddressAnnouncement(_)) => "address_announcement",
        Some(peer_event::Event::ConnectionResult(_)) => "connection_result",
        Some(peer_event::Event::Handshake(_)) => "handshake",
        Some(peer_event::Event::CompactBlockProbe(_)) => "compact_block_probe",
        Some(peer_event::Event::FeeFilter(_)) => "fee_filter",
        Some(peer_event::Event::SendCmpct(_)) => "send_cmpct",
        None => "none",
    }
}

/// The first sightings of the last [`RECENT_BLOCKS`] blocks.
#[derive(Debug, Default)]
struct RecentBlocks {
    first_seen_ms: HashMap<String, u64>,
    order: VecDeque<String>,
}

impl RecentBlocks {
    fn first_seen(&self, hash: &str) -> Option<u64> {
        self.first_seen_ms.get(hash).copied()
    }

    /// Records a first sighting. A hash already known keeps its earlier
    /// time, so a second `new_to_us` for the same block (two observers on
    /// one network, say) does not move it.
    fn record(&mut self, hash: &str, timestamp_ms: u64) {
        if let Some(existing) = self.first_seen_ms.get_mut(hash) {
            *existing = (*existing).min(timestamp_ms);
            return;
        }
        self.first_seen_ms.insert(hash.to_owned(), timestamp_ms);
        self.order.push_back(hash.to_owned());
        while self.order.len() > RECENT_BLOCKS {
            if let Some(old) = self.order.pop_front() {
                self.first_seen_ms.remove(&old);
            }
        }
    }
}

/// What is remembered about one network between events.
#[derive(Debug)]
struct NetworkState {
    /// The observer run the last event came from; a change is a restart.
    instance: Option<u64>,
    /// The highest height any announcement has carried.
    best_height: Option<u32>,
    blocks: RecentBlocks,
    user_agents: Bounded,
    protocol_versions: Bounded,
}

impl Default for NetworkState {
    fn default() -> Self {
        NetworkState {
            instance: None,
            best_height: None,
            blocks: RecentBlocks::default(),
            user_agents: Bounded::new(labels::USER_AGENT_CAP),
            protocol_versions: Bounded::new(labels::PROTOCOL_VERSION_CAP),
        }
    }
}

/// Everything the tool remembers between events, by network.
#[derive(Debug, Default)]
pub struct State {
    networks: HashMap<String, NetworkState>,
}

impl State {
    fn network(&mut self, network: &str) -> &mut NetworkState {
        if !self.networks.contains_key(network) {
            self.networks
                .insert(network.to_owned(), NetworkState::default());
        }
        self.networks.get_mut(network).expect("inserted just above")
    }
}

/// Runs the tool until `shutdown` turns true. `bound_addr` receives the
/// address the HTTP server listens on, for tests that bind port 0.
pub async fn run(
    args: Args,
    mut shutdown: watch::Receiver<bool>,
    bound_addr: Option<oneshot::Sender<SocketAddr>>,
) -> Result<()> {
    let metrics = Metrics::new()?;
    metrics
        .start_timestamp_seconds
        .set((now_ms() / 1000) as i64);

    let listener = TcpListener::bind(&args.listen)
        .await
        .with_context(|| format!("listening on {}", args.listen))?;
    let addr = listener.local_addr().context("reading the bound address")?;
    tracing::info!(target: TARGET, %addr, "serving metrics at /metrics");
    if let Some(tx) = bound_addr {
        let _ = tx.send(addr);
    }
    let server = tokio::spawn(server::serve(listener, metrics.registry.clone()));

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

    let mut state = State::default();
    let result = loop {
        tokio::select! {
            msg = sub.next() => {
                let Some(msg) = msg else {
                    break Err(common::anyhow::anyhow!("the NATS subscription ended"));
                };
                handle_message(&msg.subject, &msg.payload, &metrics, &mut state, now_ms());
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break Ok(());
                }
            }
        }
    };
    server.abort();
    result
}

/// One NATS message: decoded, counted, and handed to [`observe`].
pub fn handle_message(
    subject: &str,
    payload: &[u8],
    metrics: &Metrics,
    state: &mut State,
    now_ms: u64,
) {
    let Some(network) = network_of(subject) else {
        tracing::debug!(target: TARGET, subject, "ignoring subject");
        return;
    };
    let event = match PeerEvent::decode(payload) {
        Ok(event) => event,
        Err(e) => {
            tracing::warn!(target: TARGET, subject, error = %e, "failed to decode event");
            metrics
                .undecodable_events_total
                .with_label_values(&[network])
                .inc();
            return;
        }
    };
    let kind = kind_of(&event);
    metrics
        .events_total
        .with_label_values(&[network, kind])
        .inc();
    metrics
        .event_bytes_total
        .with_label_values(&[network, kind])
        .inc_by(payload.len() as u64);
    observe(network, &event, metrics, state, now_ms);
}

/// Turns one event into its samples and increments.
pub fn observe(
    network: &str,
    event: &PeerEvent,
    metrics: &Metrics,
    state: &mut State,
    now_ms: u64,
) {
    observe_pipeline(network, event, metrics, state, now_ms);
    match &event.event {
        Some(peer_event::Event::Handshake(hs)) => {
            observe_handshake(network, event, hs, metrics, state)
        }
        Some(peer_event::Event::PingRtt(ping)) => observe_ping(network, ping, metrics),
        Some(peer_event::Event::BlockAnnouncement(blk)) => {
            observe_block_announcement(network, event, blk, metrics, state)
        }
        Some(peer_event::Event::ConnectionResult(result)) => {
            observe_connection_result(network, result, metrics)
        }
        Some(peer_event::Event::AddressAnnouncement(ann)) => {
            observe_address_announcement(network, event, ann, metrics)
        }
        Some(peer_event::Event::CompactBlockProbe(probe)) => {
            let stage = labels::enum_label(probe.stage().as_str_name(), "PROBE_STAGE_");
            metrics
                .compact_block_probes_total
                .with_label_values(&[network, &stage])
                .inc();
        }
        Some(peer_event::Event::FeeFilter(f)) => {
            metrics
                .fee_filters_total
                .with_label_values(&[network])
                .inc();
            metrics
                .fee_filter_sat_per_kvb
                .with_label_values(&[network])
                .observe(f.feerate_sat_per_kvb as f64);
        }
        Some(peer_event::Event::SendCmpct(sc)) => observe_send_cmpct(network, sc, metrics),
        None => {}
    }
}

/// What every event says about the pipeline that delivered it.
fn observe_pipeline(
    network: &str,
    event: &PeerEvent,
    metrics: &Metrics,
    state: &mut State,
    now_ms: u64,
) {
    metrics
        .event_delay_seconds
        .with_label_values(&[network])
        .observe((now_ms as f64 - event.timestamp_ms as f64) / 1000.0);
    metrics
        .last_event_timestamp_seconds
        .with_label_values(&[network])
        .set((event.timestamp_ms / 1000) as i64);
    metrics
        .observer_dropped_events
        .with_label_values(&[network])
        .set(event.dropped_events as i64);
    if let Some(by_kind) = &event.dropped_by_kind {
        observe_dropped_by_kind(network, by_kind, metrics);
    }

    let net = state.network(network);
    match net.instance {
        Some(previous) if previous != event.instance_id => {
            tracing::info!(target: TARGET, network, previous, current = event.instance_id, "observer restarted");
            metrics
                .observer_restarts_total
                .with_label_values(&[network])
                .inc();
            // The old run's drops are gone with it.
            observe_dropped_by_kind(network, &DroppedEvents::default(), metrics);
        }
        _ => {}
    }
    net.instance = Some(event.instance_id);
}

fn observe_dropped_by_kind(network: &str, dropped: &DroppedEvents, metrics: &Metrics) {
    let counts = [
        ("ping_rtt", dropped.ping_rtt),
        ("block_announcement", dropped.block_announcement),
        ("address_announcement", dropped.address_announcement),
        ("connection_result", dropped.connection_result),
        ("handshake", dropped.handshake),
        ("compact_block_probe", dropped.compact_block_probe),
        ("fee_filter", dropped.fee_filter),
        ("send_cmpct", dropped.send_cmpct),
    ];
    for (kind, count) in counts {
        metrics
            .observer_dropped_events_by_kind
            .with_label_values(&[network, kind])
            .set(count as i64);
    }
}

fn observe_handshake(
    network: &str,
    event: &PeerEvent,
    hs: &Handshake,
    metrics: &Metrics,
    state: &mut State,
) {
    metrics
        .handshakes_total
        .with_label_values(&[network, labels::transport(event.transport_version)])
        .inc();

    let net = state.network(network);
    let user_agent = labels::user_agent(&hs.user_agent);
    metrics
        .handshake_user_agents_total
        .with_label_values(&[network, net.user_agents.label(&user_agent)])
        .inc();
    let version = hs.protocol_version.to_string();
    metrics
        .handshake_protocol_versions_total
        .with_label_values(&[network, net.protocol_versions.label(&version)])
        .inc();
    for bit in labels::service_bits(hs.services) {
        metrics
            .handshake_services_total
            .with_label_values(&[network, &bit])
            .inc();
    }

    let features = [
        ("relay", hs.relay),
        ("sendaddrv2", hs.sendaddrv2),
        ("wtxid_relay", hs.wtxid_relay),
        ("addr_recv", addr_recv_is_set(&hs.addr_recv)),
    ];
    for (feature, present) in features {
        if present {
            metrics
                .handshake_features_total
                .with_label_values(&[network, feature])
                .inc();
        }
    }

    metrics
        .handshake_clock_skew_seconds
        .with_label_values(&[network])
        .observe(hs.peer_timestamp as f64 - (event.timestamp_ms / 1000) as f64);
    if let Some(best) = net.best_height {
        metrics
            .handshake_height_delta
            .with_label_values(&[network])
            .observe(hs.start_height as f64 - best as f64);
    }
}

/// Whether a peer filled in the address it sees us at. `0.0.0.0:0` is what
/// a peer that did not bother looks like, and empty means the bytes were
/// not an address at all.
fn addr_recv_is_set(addr_recv: &str) -> bool {
    !addr_recv.is_empty() && !addr_recv.starts_with("0.0.0.0:") && addr_recv != "[::]:0"
}

fn observe_ping(network: &str, ping: &PingRtt, metrics: &Metrics) {
    metrics
        .ping_rtt_seconds
        .with_label_values(&[network])
        .observe(ping.rtt_ms as f64 / 1000.0);
    if let Some(tcp) = &ping.tcp_stats {
        observe_tcp(network, tcp, metrics);
    }
}

fn observe_tcp(network: &str, tcp: &TcpStats, metrics: &Metrics) {
    let labels = [network];
    metrics
        .ping_tcp_srtt_seconds
        .with_label_values(&labels)
        .observe(tcp.srtt_us as f64 / 1e6);
    metrics
        .ping_tcp_rttvar_seconds
        .with_label_values(&labels)
        .observe(tcp.rttvar_us as f64 / 1e6);
    metrics
        .ping_tcp_cwnd_segments
        .with_label_values(&labels)
        .observe(tcp.snd_cwnd as f64);
    metrics
        .ping_tcp_retransmits
        .with_label_values(&labels)
        .observe(tcp.total_retrans as f64);
    if let Some(min_rtt) = tcp.min_rtt_us {
        metrics
            .ping_tcp_min_rtt_seconds
            .with_label_values(&labels)
            .observe(min_rtt as f64 / 1e6);
    }
    if let Some(rate) = tcp.delivery_rate {
        metrics
            .ping_tcp_delivery_rate_bytes_per_second
            .with_label_values(&labels)
            .observe(rate as f64);
    }
}

fn observe_block_announcement(
    network: &str,
    event: &PeerEvent,
    blk: &BlockAnnouncement,
    metrics: &Metrics,
    state: &mut State,
) {
    let atype = labels::enum_label(blk.announcement_type().as_str_name(), "ANNOUNCEMENT_TYPE_");
    metrics
        .block_announcements_total
        .with_label_values(&[network, &atype])
        .inc();
    metrics
        .block_announcement_batch_size
        .with_label_values(&[network])
        .observe(blk.batch_size as f64);
    if let Some(shape) = &blk.compact_block {
        metrics
            .compact_block_short_ids
            .with_label_values(&[network])
            .observe(shape.short_ids as f64);
        metrics
            .compact_block_prefilled_txs
            .with_label_values(&[network])
            .observe(shape.prefilled_txs as f64);
    }

    let net = state.network(network);
    if let Some(height) = blk.height
        && net.best_height.is_none_or(|best| height > best)
    {
        net.best_height = Some(height);
        metrics
            .best_height
            .with_label_values(&[network])
            .set(height as i64);
    }

    if blk.new_to_us {
        metrics
            .blocks_total
            .with_label_values(&[network, &atype])
            .inc();
        net.blocks.record(&blk.block_hash, event.timestamp_ms);
        // The first sighting is the zero every other announcement of the
        // block is measured from, not a sample of how long one took.
        return;
    }
    if let Some(first_ms) = net.blocks.first_seen(&blk.block_hash) {
        let delay = (event.timestamp_ms as f64 - first_ms as f64).max(0.0) / 1000.0;
        metrics
            .block_propagation_seconds
            .with_label_values(&[network, &atype])
            .observe(delay);
    }
}

fn observe_connection_result(network: &str, result: &ConnectionResult, metrics: &Metrics) {
    let (outcome, reason, setup_ms) = match &result.result {
        Some(AttemptResult::Disconnected(d)) => {
            metrics
                .session_duration_seconds
                .with_label_values(&[network])
                .observe(d.uptime_ms as f64 / 1000.0);
            for (command, count) in &d.messages_by_command {
                metrics
                    .session_messages_total
                    .with_label_values(&[network, labels::command(command)])
                    .inc_by(*count as u64);
            }
            if d.messages_other > 0 {
                metrics
                    .session_messages_total
                    .with_label_values(&[network, OTHER])
                    .inc_by(d.messages_other as u64);
            }
            if d.unsolicited_pongs > 0 {
                metrics
                    .unsolicited_pongs_total
                    .with_label_values(&[network])
                    .inc_by(d.unsolicited_pongs as u64);
            }
            (
                "disconnected",
                labels::enum_label(d.reason().as_str_name(), "DISCONNECT_REASON_"),
                d.setup_ms,
            )
        }
        Some(AttemptResult::Failed(f)) => (
            "failed",
            labels::enum_label(f.reason().as_str_name(), "FAILURE_REASON_"),
            f.setup_ms,
        ),
        Some(AttemptResult::OurFault(o)) => (
            "our_fault",
            labels::enum_label(o.reason().as_str_name(), "OUR_FAULT_REASON_"),
            o.setup_ms,
        ),
        None => ("unknown", "unknown".to_owned(), 0),
    };
    metrics
        .connection_attempts_total
        .with_label_values(&[network, outcome, &reason])
        .inc();
    metrics
        .connection_setup_seconds
        .with_label_values(&[network, outcome])
        .observe(setup_ms as f64 / 1000.0);
}

fn observe_send_cmpct(network: &str, sc: &SendCmpct, metrics: &Metrics) {
    let mode = if sc.high_bandwidth { "high" } else { "low" };
    // BIP152 defines versions 1 and 2; anything else is a peer's invention.
    let version = match sc.version {
        1 => "1",
        2 => "2",
        _ => OTHER,
    };
    metrics
        .send_cmpct_total
        .with_label_values(&[network, mode, version])
        .inc();
}

fn observe_address_announcement(
    network: &str,
    event: &PeerEvent,
    ann: &AddressAnnouncement,
    metrics: &Metrics,
) {
    let message = labels::enum_label(ann.message().as_str_name(), "ADDR_MESSAGE_");
    metrics
        .address_announcements_total
        .with_label_values(&[network, &message])
        .inc();
    metrics
        .address_announcement_entries
        .with_label_values(&[network])
        .observe((ann.addresses.len() + ann.unparsed as usize) as f64);
    if ann.unparsed > 0 {
        metrics
            .unparsed_address_entries_total
            .with_label_values(&[network])
            .inc_by(ann.unparsed as u64);
    }
    if ann.rate_limited > 0 {
        metrics
            .rate_limited_address_entries_total
            .with_label_values(&[network])
            .inc_by(ann.rate_limited as u64);
    }
    if ann.solicited {
        metrics
            .solicited_address_announcements_total
            .with_label_values(&[network])
            .inc();
    }
    metrics
        .address_rate_limit_tokens
        .with_label_values(&[network])
        .set(ann.rate_limit_tokens);
    if ann.addresses.len() == 1
        && ann.unparsed == 0
        && labels::host(&ann.addresses[0].addr) == labels::host(&event.peer_addr)
    {
        metrics
            .self_announcements_total
            .with_label_values(&[network])
            .inc();
    }

    // A message carries up to a thousand entries; totals per label are
    // gathered first so each series is touched once per message.
    let mut by_net: HashMap<&'static str, u64> = HashMap::new();
    let mut by_service: HashMap<String, u64> = HashMap::new();
    let now_s = (event.timestamp_ms / 1000) as f64;
    let age = metrics
        .address_entry_age_seconds
        .with_label_values(&[network]);
    for entry in &ann.addresses {
        *by_net.entry(labels::address_net(&entry.addr)).or_default() += 1;
        for bit in labels::service_bits(entry.services) {
            *by_service.entry(bit).or_default() += 1;
        }
        age.observe(now_s - entry.ntime as f64);
    }
    for (net, count) in by_net {
        metrics
            .address_entries_total
            .with_label_values(&[network, net])
            .inc_by(count);
    }
    for (service, count) in by_service {
        metrics
            .address_entry_services_total
            .with_label_values(&[network, &service])
            .inc_by(count);
    }
}

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
    use common::events::connection_result::{Disconnected, Failed, OurFault};
    use common::events::{
        AddrMessage, AnnouncementType, CompactBlockShape, DisconnectReason, FailureReason,
        FeeFilter, GossipedAddress, OurFaultReason,
    };

    const NET: &str = "signet";

    fn event(connection_id: u64, timestamp_ms: u64, kind: peer_event::Event) -> PeerEvent {
        PeerEvent {
            connection_id,
            timestamp_ms,
            peer_addr: "1.2.3.4:38333".to_owned(),
            user_agent: "/Satoshi:28.1.0/".to_owned(),
            transport_version: Some(2),
            dropped_events: 0,
            instance_id: 7,
            dropped_by_kind: None,
            event: Some(kind),
        }
    }

    fn handshake() -> Handshake {
        Handshake {
            protocol_version: 70016,
            services: 0x40d,
            start_height: 150,
            relay: true,
            peer_timestamp: 1_000_010,
            addr_recv: "5.6.7.8:1234".to_owned(),
            sendaddrv2: true,
            wtxid_relay: false,
            user_agent: "/Satoshi:28.1.0(comment)/".to_owned(),
        }
    }

    fn announcement(hash: &str, new_to_us: bool, height: Option<u32>) -> BlockAnnouncement {
        BlockAnnouncement {
            block_hash: hash.to_owned(),
            announcement_type: AnnouncementType::Inv as i32,
            tcp_stats: None,
            batch_size: 1,
            height,
            new_to_us,
            compact_block: None,
        }
    }

    fn counter(m: &IntCounterVecRef, labels: &[&str]) -> u64 {
        m.with_label_values(labels).get()
    }
    type IntCounterVecRef = prometheus::IntCounterVec;

    fn histogram_count(m: &prometheus::HistogramVec, labels: &[&str]) -> u64 {
        m.with_label_values(labels).get_sample_count()
    }

    fn histogram_sum(m: &prometheus::HistogramVec, labels: &[&str]) -> f64 {
        m.with_label_values(labels).get_sample_sum()
    }

    #[test]
    fn test_subject_narrows_to_the_network() {
        let all = Args {
            nats_url: String::new(),
            network: None,
            listen: String::new(),
        };
        assert_eq!(all.subject(), "p2p-observer.*.*");
        let one = Args {
            network: Some("signet".to_owned()),
            ..all
        };
        assert_eq!(one.subject(), "p2p-observer.signet.*");
    }

    #[test]
    fn test_network_of_subject() {
        assert_eq!(network_of("p2p-observer.signet.handshake"), Some("signet"));
        assert_eq!(network_of("p2p-observer.signet.rpc.addresses"), None);
        assert_eq!(network_of("other.signet.handshake"), None);
        assert_eq!(network_of("p2p-observer.signet"), None);
    }

    #[test]
    fn test_events_are_counted_by_kind_and_size() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        let ev = event(
            1,
            1_000_000_000,
            peer_event::Event::FeeFilter(FeeFilter {
                feerate_sat_per_kvb: 1000,
            }),
        );
        let payload = ev.encode_to_vec();
        handle_message(
            "p2p-observer.signet.fee_filter",
            &payload,
            &m,
            &mut state,
            1_000_000_250,
        );
        assert_eq!(counter(&m.events_total, &[NET, "fee_filter"]), 1);
        assert_eq!(
            counter(&m.event_bytes_total, &[NET, "fee_filter"]),
            payload.len() as u64
        );
        assert_eq!(counter(&m.fee_filters_total, &[NET]), 1);
        assert_eq!(histogram_sum(&m.fee_filter_sat_per_kvb, &[NET]), 1000.0);
        assert!((histogram_sum(&m.event_delay_seconds, &[NET]) - 0.25).abs() < 1e-9);
        assert_eq!(
            m.last_event_timestamp_seconds
                .with_label_values(&[NET])
                .get(),
            1_000_000
        );
    }

    #[test]
    fn test_undecodable_and_foreign_subjects() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        handle_message(
            "p2p-observer.signet.handshake",
            b"\xff\xff\xff",
            &m,
            &mut state,
            0,
        );
        assert_eq!(counter(&m.undecodable_events_total, &[NET]), 1);
        let payload =
            event(1, 0, peer_event::Event::FeeFilter(FeeFilter::default())).encode_to_vec();
        handle_message(
            "p2p-observer.signet.rpc.addresses",
            &payload,
            &m,
            &mut state,
            0,
        );
        handle_message("unrelated", &payload, &m, &mut state, 0);
        assert_eq!(counter(&m.events_total, &[NET, "fee_filter"]), 0);
    }

    #[test]
    fn test_handshake_labels() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        observe(
            NET,
            &event(1, 1_000_000_000, peer_event::Event::Handshake(handshake())),
            &m,
            &mut state,
            0,
        );
        assert_eq!(counter(&m.handshakes_total, &[NET, "v2"]), 1);
        assert_eq!(
            counter(&m.handshake_user_agents_total, &[NET, "Satoshi:28.1.0"]),
            1
        );
        assert_eq!(
            counter(&m.handshake_protocol_versions_total, &[NET, "70016"]),
            1
        );
        for service in ["network", "bloom", "witness", "network_limited"] {
            assert_eq!(
                counter(&m.handshake_services_total, &[NET, service]),
                1,
                "{service}"
            );
        }
        assert_eq!(counter(&m.handshake_services_total, &[NET, "p2p_v2"]), 0);
        for feature in ["relay", "sendaddrv2", "addr_recv"] {
            assert_eq!(
                counter(&m.handshake_features_total, &[NET, feature]),
                1,
                "{feature}"
            );
        }
        assert_eq!(
            counter(&m.handshake_features_total, &[NET, "wtxid_relay"]),
            0
        );
        assert_eq!(histogram_sum(&m.handshake_clock_skew_seconds, &[NET]), 10.0);
        // No block announced yet, so the height has nothing to be compared to.
        assert_eq!(histogram_count(&m.handshake_height_delta, &[NET]), 0);
    }

    #[test]
    fn test_user_agents_past_the_cap_are_other() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        for i in 0..(labels::USER_AGENT_CAP + 5) {
            let hs = Handshake {
                user_agent: format!("/client{i}:1.0/"),
                ..handshake()
            };
            observe(
                NET,
                &event(i as u64, 0, peer_event::Event::Handshake(hs)),
                &m,
                &mut state,
                0,
            );
        }
        assert_eq!(
            counter(&m.handshake_user_agents_total, &[NET, "client0:1.0"]),
            1
        );
        assert_eq!(counter(&m.handshake_user_agents_total, &[NET, OTHER]), 5);
        assert_eq!(
            counter(&m.handshakes_total, &[NET, "v2"]),
            (labels::USER_AGENT_CAP + 5) as u64
        );
    }

    #[test]
    fn test_addr_recv_set() {
        assert!(addr_recv_is_set("1.2.3.4:8333"));
        assert!(!addr_recv_is_set("0.0.0.0:0"));
        assert!(!addr_recv_is_set("[::]:0"));
        assert!(!addr_recv_is_set(""));
    }

    #[test]
    fn test_height_delta_against_the_best_announced_height() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        observe(
            NET,
            &event(
                1,
                0,
                peer_event::Event::BlockAnnouncement(announcement("aa", true, Some(100))),
            ),
            &m,
            &mut state,
            0,
        );
        observe(
            NET,
            &event(
                2,
                0,
                peer_event::Event::BlockAnnouncement(announcement("bb", true, Some(90))),
            ),
            &m,
            &mut state,
            0,
        );
        assert_eq!(m.best_height.with_label_values(&[NET]).get(), 100);
        observe(
            NET,
            &event(3, 0, peer_event::Event::Handshake(handshake())),
            &m,
            &mut state,
            0,
        );
        assert_eq!(histogram_count(&m.handshake_height_delta, &[NET]), 1);
        assert_eq!(histogram_sum(&m.handshake_height_delta, &[NET]), 50.0);
    }

    #[test]
    fn test_block_propagation_is_measured_from_the_first_sighting() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        let hash = "00ab";
        observe(
            NET,
            &event(
                1,
                10_000,
                peer_event::Event::BlockAnnouncement(announcement(hash, true, Some(5))),
            ),
            &m,
            &mut state,
            0,
        );
        observe(
            NET,
            &event(
                2,
                12_500,
                peer_event::Event::BlockAnnouncement(announcement(hash, false, Some(5))),
            ),
            &m,
            &mut state,
            0,
        );
        observe(
            NET,
            &event(
                3,
                13_000,
                peer_event::Event::BlockAnnouncement(announcement(hash, false, Some(5))),
            ),
            &m,
            &mut state,
            0,
        );
        // A block whose first sighting this tool never saw has nothing to be
        // measured from.
        observe(
            NET,
            &event(
                4,
                13_000,
                peer_event::Event::BlockAnnouncement(announcement("unknown", false, None)),
            ),
            &m,
            &mut state,
            0,
        );
        assert_eq!(counter(&m.blocks_total, &[NET, "inv"]), 1);
        assert_eq!(counter(&m.block_announcements_total, &[NET, "inv"]), 4);
        assert_eq!(
            histogram_count(&m.block_propagation_seconds, &[NET, "inv"]),
            2
        );
        assert!((histogram_sum(&m.block_propagation_seconds, &[NET, "inv"]) - 5.5).abs() < 1e-9);
    }

    #[test]
    fn test_recent_blocks_forget_the_oldest() {
        let mut blocks = RecentBlocks::default();
        for i in 0..(RECENT_BLOCKS + 1) {
            blocks.record(&format!("block{i}"), i as u64);
        }
        assert_eq!(blocks.first_seen("block0"), None);
        assert_eq!(blocks.first_seen("block1"), Some(1));
        assert_eq!(blocks.first_seen_ms.len(), RECENT_BLOCKS);
        // A repeat sighting keeps the earlier time and does not grow the set.
        blocks.record("block1", 0);
        assert_eq!(blocks.first_seen("block1"), Some(0));
        assert_eq!(blocks.order.len(), RECENT_BLOCKS);
    }

    #[test]
    fn test_compact_block_shape() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        let mut blk = announcement("cc", true, Some(1));
        blk.announcement_type = AnnouncementType::CompactBlock as i32;
        blk.compact_block = Some(CompactBlockShape {
            short_ids: 2500,
            prefilled_txs: 1,
        });
        observe(
            NET,
            &event(1, 0, peer_event::Event::BlockAnnouncement(blk)),
            &m,
            &mut state,
            0,
        );
        assert_eq!(counter(&m.blocks_total, &[NET, "compact_block"]), 1);
        assert_eq!(histogram_sum(&m.compact_block_short_ids, &[NET]), 2500.0);
        assert_eq!(histogram_sum(&m.compact_block_prefilled_txs, &[NET]), 1.0);
    }

    #[test]
    fn test_connection_results() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        let disconnected = ConnectionResult {
            result: Some(AttemptResult::Disconnected(Disconnected {
                setup_ms: 500,
                uptime_ms: 90_000,
                reason: DisconnectReason::PeerClosed as i32,
                messages_by_command: [("ping".to_owned(), 3), ("weird".to_owned(), 2)].into(),
                messages_other: 4,
                unsolicited_pongs: 1,
            })),
        };
        let failed = ConnectionResult {
            result: Some(AttemptResult::Failed(Failed {
                reason: FailureReason::TcpConnectTimeout as i32,
                setup_ms: 10_000,
            })),
        };
        let our_fault = ConnectionResult {
            result: Some(AttemptResult::OurFault(OurFault {
                reason: OurFaultReason::ProxyUnreachable as i32,
                setup_ms: 1,
            })),
        };
        for (i, r) in [disconnected, failed, our_fault, ConnectionResult::default()]
            .into_iter()
            .enumerate()
        {
            observe(
                NET,
                &event(i as u64, 0, peer_event::Event::ConnectionResult(r)),
                &m,
                &mut state,
                0,
            );
        }
        assert_eq!(
            counter(
                &m.connection_attempts_total,
                &[NET, "disconnected", "peer_closed"]
            ),
            1
        );
        assert_eq!(
            counter(
                &m.connection_attempts_total,
                &[NET, "failed", "tcp_connect_timeout"]
            ),
            1
        );
        assert_eq!(
            counter(
                &m.connection_attempts_total,
                &[NET, "our_fault", "proxy_unreachable"]
            ),
            1
        );
        assert_eq!(
            counter(&m.connection_attempts_total, &[NET, "unknown", "unknown"]),
            1
        );
        assert_eq!(histogram_sum(&m.session_duration_seconds, &[NET]), 90.0);
        assert_eq!(
            histogram_sum(&m.connection_setup_seconds, &[NET, "failed"]),
            10.0
        );
        assert_eq!(counter(&m.session_messages_total, &[NET, "ping"]), 3);
        assert_eq!(counter(&m.session_messages_total, &[NET, OTHER]), 6);
        assert_eq!(counter(&m.unsolicited_pongs_total, &[NET]), 1);
    }

    #[test]
    fn test_send_cmpct() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        for (hb, v) in [(true, 2), (false, 2), (true, 1), (true, 9)] {
            let sc = SendCmpct {
                high_bandwidth: hb,
                version: v,
            };
            observe(
                NET,
                &event(1, 0, peer_event::Event::SendCmpct(sc)),
                &m,
                &mut state,
                0,
            );
        }
        assert_eq!(counter(&m.send_cmpct_total, &[NET, "high", "2"]), 1);
        assert_eq!(counter(&m.send_cmpct_total, &[NET, "low", "2"]), 1);
        assert_eq!(counter(&m.send_cmpct_total, &[NET, "high", "1"]), 1);
        assert_eq!(counter(&m.send_cmpct_total, &[NET, "high", OTHER]), 1);
    }

    #[test]
    fn test_address_announcement() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        let gossip = |addr: &str, services: u64, ntime: u32| GossipedAddress {
            addr: addr.to_owned(),
            services,
            ntime,
        };
        let ann = AddressAnnouncement {
            message: AddrMessage::Addrv2 as i32,
            unparsed: 2,
            addresses: vec![
                gossip("9.9.9.9:8333", 1, 900),
                gossip("[2001:db8::1]:8333", 1 | 8, 1000),
                gossip(&format!("{}.onion:8333", "a".repeat(56)), 0, 2000),
            ],
            solicited: true,
            rate_limited: 1,
            rate_limit_tokens: 3.5,
        };
        observe(
            NET,
            &event(1, 1_000_000, peer_event::Event::AddressAnnouncement(ann)),
            &m,
            &mut state,
            0,
        );
        assert_eq!(counter(&m.address_announcements_total, &[NET, "addrv2"]), 1);
        assert_eq!(histogram_sum(&m.address_announcement_entries, &[NET]), 5.0);
        assert_eq!(counter(&m.address_entries_total, &[NET, "ipv4"]), 1);
        assert_eq!(counter(&m.address_entries_total, &[NET, "ipv6"]), 1);
        assert_eq!(counter(&m.address_entries_total, &[NET, "onion"]), 1);
        assert_eq!(
            counter(&m.address_entry_services_total, &[NET, "network"]),
            2
        );
        assert_eq!(
            counter(&m.address_entry_services_total, &[NET, "witness"]),
            1
        );
        assert_eq!(counter(&m.address_entry_services_total, &[NET, "none"]), 1);
        assert_eq!(counter(&m.unparsed_address_entries_total, &[NET]), 2);
        assert_eq!(counter(&m.rate_limited_address_entries_total, &[NET]), 1);
        assert_eq!(counter(&m.solicited_address_announcements_total, &[NET]), 1);
        assert_eq!(
            m.address_rate_limit_tokens.with_label_values(&[NET]).get(),
            3.5
        );
        // Ages: 1000 - 900, 1000 - 1000, 1000 - 2000.
        assert_eq!(histogram_count(&m.address_entry_age_seconds, &[NET]), 3);
        assert_eq!(histogram_sum(&m.address_entry_age_seconds, &[NET]), -900.0);
        assert_eq!(counter(&m.self_announcements_total, &[NET]), 0);

        let own = AddressAnnouncement {
            message: AddrMessage::Addr as i32,
            addresses: vec![gossip("1.2.3.4:8333", 1, 1000)],
            ..Default::default()
        };
        observe(
            NET,
            &event(1, 1_000_000, peer_event::Event::AddressAnnouncement(own)),
            &m,
            &mut state,
            0,
        );
        assert_eq!(counter(&m.self_announcements_total, &[NET]), 1);
        assert_eq!(counter(&m.address_announcements_total, &[NET, "addr"]), 1);
    }

    #[test]
    fn test_ping_and_tcp_samples() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        let ping = PingRtt {
            rtt_ms: 150,
            tcp_stats: Some(TcpStats {
                srtt_us: 120_000,
                rttvar_us: 5_000,
                total_retrans: 3,
                snd_cwnd: 10,
                min_rtt_us: Some(100_000),
                lost: None,
                reordering: None,
                delivery_rate: Some(1_000_000),
                bytes_received: Some(42),
            }),
        };
        observe(
            NET,
            &event(1, 0, peer_event::Event::PingRtt(ping)),
            &m,
            &mut state,
            0,
        );
        assert_eq!(histogram_sum(&m.ping_rtt_seconds, &[NET]), 0.15);
        assert_eq!(histogram_sum(&m.ping_tcp_srtt_seconds, &[NET]), 0.12);
        assert_eq!(histogram_sum(&m.ping_tcp_min_rtt_seconds, &[NET]), 0.1);
        assert_eq!(histogram_sum(&m.ping_tcp_retransmits, &[NET]), 3.0);
        assert_eq!(
            histogram_sum(&m.ping_tcp_delivery_rate_bytes_per_second, &[NET]),
            1e6
        );
        let bare = PingRtt {
            rtt_ms: 50,
            tcp_stats: None,
        };
        observe(
            NET,
            &event(1, 0, peer_event::Event::PingRtt(bare)),
            &m,
            &mut state,
            0,
        );
        assert_eq!(histogram_count(&m.ping_rtt_seconds, &[NET]), 2);
        assert_eq!(histogram_count(&m.ping_tcp_srtt_seconds, &[NET]), 1);
    }

    #[test]
    fn test_observer_restart_and_drops() {
        let m = Metrics::new().unwrap();
        let mut state = State::default();
        let mut first = event(1, 0, peer_event::Event::FeeFilter(FeeFilter::default()));
        first.dropped_events = 12;
        first.dropped_by_kind = Some(DroppedEvents {
            address_announcement: 12,
            ..Default::default()
        });
        observe(NET, &first, &m, &mut state, 0);
        assert_eq!(
            m.observer_dropped_events.with_label_values(&[NET]).get(),
            12
        );
        assert_eq!(
            m.observer_dropped_events_by_kind
                .with_label_values(&[NET, "address_announcement"])
                .get(),
            12
        );
        assert_eq!(counter(&m.observer_restarts_total, &[NET]), 0);

        let mut second = event(1, 0, peer_event::Event::FeeFilter(FeeFilter::default()));
        second.instance_id = 8;
        observe(NET, &second, &m, &mut state, 0);
        assert_eq!(counter(&m.observer_restarts_total, &[NET]), 1);
        assert_eq!(m.observer_dropped_events.with_label_values(&[NET]).get(), 0);
        assert_eq!(
            m.observer_dropped_events_by_kind
                .with_label_values(&[NET, "address_announcement"])
                .get(),
            0
        );
        // The same run again is not another restart; another network is
        // its own observer.
        observe(NET, &second, &m, &mut state, 0);
        observe("mainnet", &first, &m, &mut state, 0);
        assert_eq!(counter(&m.observer_restarts_total, &[NET]), 1);
        assert_eq!(counter(&m.observer_restarts_total, &["mainnet"]), 0);
    }
}
