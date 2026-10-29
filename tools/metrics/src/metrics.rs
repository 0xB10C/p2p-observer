//! The registry: every series the tool serves, declared in one place with
//! its help text, so the `/metrics` output documents itself.
//!
//! Every metric carries a `network` label, the token of the NATS subject the
//! event arrived on; one tool can follow several observers. Durations are in
//! seconds, as Prometheus wants them, converted from the milliseconds and
//! microseconds of the events.

use common::anyhow::{Context, Result};
use prometheus::{
    GaugeVec, HistogramOpts, HistogramVec, IntCounterVec, IntGauge, IntGaugeVec, Opts, Registry,
};

pub const NAMESPACE: &str = "p2pobserver";

/// Buckets in seconds for a round trip on the network.
const RTT_BUCKETS: &[f64] = &[
    0.005, 0.01, 0.025, 0.05, 0.1, 0.15, 0.2, 0.3, 0.5, 0.75, 1.0, 2.0, 5.0,
];
/// Buckets in seconds for the way from the observer to this tool.
const DELAY_BUCKETS: &[f64] = &[
    0.0, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0, 10.0, 60.0,
];
/// Buckets in seconds for dial and handshake.
const SETUP_BUCKETS: &[f64] = &[0.05, 0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0];
/// Buckets in seconds for a session, from a glance to a week.
const SESSION_BUCKETS: &[f64] = &[
    1.0, 10.0, 60.0, 300.0, 900.0, 3600.0, 14_400.0, 86_400.0, 604_800.0,
];
/// Buckets in seconds for a peer's clock against ours, both ways.
const SKEW_BUCKETS: &[f64] = &[
    -3600.0, -600.0, -60.0, -10.0, -1.0, 0.0, 1.0, 10.0, 60.0, 600.0, 3600.0,
];
/// Buckets in blocks for a start height against the best height announced.
const HEIGHT_DELTA_BUCKETS: &[f64] = &[
    -1_000_000.0,
    -100_000.0,
    -10_000.0,
    -1000.0,
    -100.0,
    -10.0,
    -1.0,
    0.0,
    1.0,
    10.0,
    100.0,
    1000.0,
];
/// Buckets in seconds for how long after its first sighting a block is
/// announced.
const PROPAGATION_BUCKETS: &[f64] = &[
    0.1, 0.25, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 120.0, 300.0, 600.0,
];
/// Buckets for headers per HEADERS message; the observer caps it at 8.
const BATCH_BUCKETS: &[f64] = &[1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0];
/// Buckets for transactions in a compact block.
const SHORT_ID_BUCKETS: &[f64] = &[
    0.0, 100.0, 500.0, 1000.0, 2000.0, 3000.0, 4000.0, 5000.0, 7500.0, 10_000.0,
];
const PREFILLED_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 50.0, 100.0, 500.0, 1000.0];
/// Buckets in sat/kvB for a fee filter.
const FEE_FILTER_BUCKETS: &[f64] = &[
    0.0, 1.0, 10.0, 100.0, 250.0, 500.0, 1000.0, 1500.0, 2000.0, 3000.0, 5000.0, 10_000.0,
    50_000.0, 100_000.0,
];
/// Buckets for addresses per announcement; Bitcoin Core relays only
/// messages of ten or fewer, and sends up to a thousand to a GETADDR.
const ADDRESS_COUNT_BUCKETS: &[f64] = &[
    0.0, 1.0, 2.0, 3.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0,
];
/// Buckets in seconds for the age of a gossiped address, from the future
/// to past the 30 days after which Bitcoin Core calls an entry terrible.
const ADDRESS_AGE_BUCKETS: &[f64] = &[
    -600.0,
    0.0,
    60.0,
    600.0,
    3600.0,
    21_600.0,
    86_400.0,
    259_200.0,
    604_800.0,
    2_592_000.0,
];
/// Buckets in segments for a congestion window.
const CWND_BUCKETS: &[f64] = &[1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 200.0, 500.0, 1000.0];
/// Buckets for retransmitted segments over a connection's life.
const RETRANS_BUCKETS: &[f64] = &[0.0, 1.0, 2.0, 5.0, 10.0, 20.0, 50.0, 100.0, 500.0, 1000.0];
/// Buckets in bytes per second for the kernel's delivery rate estimate.
const RATE_BUCKETS: &[f64] = &[
    1e3, 1e4, 1e5, 2.5e5, 5e5, 1e6, 2.5e6, 5e6, 1e7, 2.5e7, 5e7, 1e8, 1e9,
];

#[derive(Debug, Clone)]
pub struct Metrics {
    pub registry: Registry,

    // The pipeline: what arrives here, and what the observer says about
    // itself on every event.
    pub start_timestamp_seconds: IntGauge,
    pub events_total: IntCounterVec,
    pub event_bytes_total: IntCounterVec,
    pub undecodable_events_total: IntCounterVec,
    pub event_delay_seconds: HistogramVec,
    pub last_event_timestamp_seconds: IntGaugeVec,
    pub observer_dropped_events: IntGaugeVec,
    pub observer_dropped_events_by_kind: IntGaugeVec,
    pub observer_restarts_total: IntCounterVec,

    // Attempts and sessions.
    pub connection_attempts_total: IntCounterVec,
    pub connection_setup_seconds: HistogramVec,
    pub session_duration_seconds: HistogramVec,
    pub session_messages_total: IntCounterVec,
    pub unsolicited_pongs_total: IntCounterVec,

    // What peers say about themselves.
    pub handshakes_total: IntCounterVec,
    pub handshake_user_agents_total: IntCounterVec,
    pub handshake_protocol_versions_total: IntCounterVec,
    pub handshake_services_total: IntCounterVec,
    pub handshake_features_total: IntCounterVec,
    pub handshake_clock_skew_seconds: HistogramVec,
    pub handshake_height_delta: HistogramVec,
    pub best_height: IntGaugeVec,

    // The path to a peer.
    pub ping_rtt_seconds: HistogramVec,
    pub ping_tcp_srtt_seconds: HistogramVec,
    pub ping_tcp_min_rtt_seconds: HistogramVec,
    pub ping_tcp_rttvar_seconds: HistogramVec,
    pub ping_tcp_cwnd_segments: HistogramVec,
    pub ping_tcp_retransmits: HistogramVec,
    pub ping_tcp_delivery_rate_bytes_per_second: HistogramVec,

    // Blocks.
    pub block_announcements_total: IntCounterVec,
    pub blocks_total: IntCounterVec,
    pub block_announcement_batch_size: HistogramVec,
    pub block_propagation_seconds: HistogramVec,
    pub compact_block_short_ids: HistogramVec,
    pub compact_block_prefilled_txs: HistogramVec,
    pub compact_block_probes_total: IntCounterVec,

    // Policy.
    pub fee_filters_total: IntCounterVec,
    pub fee_filter_sat_per_kvb: HistogramVec,
    pub send_cmpct_total: IntCounterVec,

    // Gossip.
    pub address_announcements_total: IntCounterVec,
    pub address_announcement_entries: HistogramVec,
    pub address_entries_total: IntCounterVec,
    pub address_entry_services_total: IntCounterVec,
    pub address_entry_age_seconds: HistogramVec,
    pub unparsed_address_entries_total: IntCounterVec,
    pub rate_limited_address_entries_total: IntCounterVec,
    pub solicited_address_announcements_total: IntCounterVec,
    pub self_announcements_total: IntCounterVec,
    pub address_rate_limit_tokens: GaugeVec,
}

fn counter(registry: &Registry, name: &str, help: &str, labels: &[&str]) -> Result<IntCounterVec> {
    let metric = IntCounterVec::new(Opts::new(name, help).namespace(NAMESPACE), labels)?;
    registry
        .register(Box::new(metric.clone()))
        .with_context(|| format!("registering {name}"))?;
    Ok(metric)
}

fn gauge(registry: &Registry, name: &str, help: &str, labels: &[&str]) -> Result<IntGaugeVec> {
    let metric = IntGaugeVec::new(Opts::new(name, help).namespace(NAMESPACE), labels)?;
    registry
        .register(Box::new(metric.clone()))
        .with_context(|| format!("registering {name}"))?;
    Ok(metric)
}

fn float_gauge(registry: &Registry, name: &str, help: &str, labels: &[&str]) -> Result<GaugeVec> {
    let metric = GaugeVec::new(Opts::new(name, help).namespace(NAMESPACE), labels)?;
    registry
        .register(Box::new(metric.clone()))
        .with_context(|| format!("registering {name}"))?;
    Ok(metric)
}

fn histogram(
    registry: &Registry,
    name: &str,
    help: &str,
    buckets: &[f64],
    labels: &[&str],
) -> Result<HistogramVec> {
    let opts = HistogramOpts::new(name, help)
        .namespace(NAMESPACE)
        .buckets(buckets.to_vec());
    let metric = HistogramVec::new(opts, labels)?;
    registry
        .register(Box::new(metric.clone()))
        .with_context(|| format!("registering {name}"))?;
    Ok(metric)
}

impl Metrics {
    pub fn new() -> Result<Self> {
        let r = Registry::new();
        let start_timestamp_seconds = IntGauge::with_opts(
            Opts::new(
                "start_timestamp_seconds",
                "Unix time this metrics tool started; every counter counts from then.",
            )
            .namespace(NAMESPACE),
        )?;
        r.register(Box::new(start_timestamp_seconds.clone()))
            .context("registering start_timestamp_seconds")?;

        Ok(Metrics {
            start_timestamp_seconds,
            events_total: counter(
                &r,
                "events_total",
                "Events received from the observer, by kind.",
                &["network", "kind"],
            )?,
            event_bytes_total: counter(
                &r,
                "event_bytes_total",
                "Bytes of encoded events received from the observer, by kind.",
                &["network", "kind"],
            )?,
            undecodable_events_total: counter(
                &r,
                "undecodable_events_total",
                "Payloads on an event subject that did not decode as a PeerEvent.",
                &["network"],
            )?,
            event_delay_seconds: histogram(
                &r,
                "event_delay_seconds",
                "Time from the event's timestamp to its arrival here. Queueing in the \
                 observer and NATS, plus any clock difference between the two hosts.",
                DELAY_BUCKETS,
                &["network"],
            )?,
            last_event_timestamp_seconds: gauge(
                &r,
                "last_event_timestamp_seconds",
                "Timestamp of the latest event received, in unix seconds.",
                &["network"],
            )?,
            observer_dropped_events: gauge(
                &r,
                "observer_dropped_events",
                "Events the observer could not hand to its publisher since it started, \
                 as reported on its latest event. Resets when the observer restarts.",
                &["network"],
            )?,
            observer_dropped_events_by_kind: gauge(
                &r,
                "observer_dropped_events_by_kind",
                "The same losses by the kind of event lost. Address announcements are \
                 shed first and are the expected entry; any other kind is a loss the \
                 drop policy did not intend.",
                &["network", "kind"],
            )?,
            observer_restarts_total: counter(
                &r,
                "observer_restarts_total",
                "Times the observer's instance id changed between two events.",
                &["network"],
            )?,

            connection_attempts_total: counter(
                &r,
                "connection_attempts_total",
                "Connection attempts by how they ended: a session that ran and then \
                 ended (reason is how it ended), an attempt that never reached a session \
                 (reason is where it failed), or one we could not make (reason is why).",
                &["network", "result", "reason"],
            )?,
            connection_setup_seconds: histogram(
                &r,
                "connection_setup_seconds",
                "Dial and handshake, up to the session or the failure.",
                SETUP_BUCKETS,
                &["network", "result"],
            )?,
            session_duration_seconds: histogram(
                &r,
                "session_duration_seconds",
                "How long a session ran, from after the handshake to its end.",
                SESSION_BUCKETS,
                &["network"],
            )?,
            session_messages_total: counter(
                &r,
                "session_messages_total",
                "Messages received over ended sessions, by command. Commands outside \
                 the known set count as other.",
                &["network", "command"],
            )?,
            unsolicited_pongs_total: counter(
                &r,
                "unsolicited_pongs_total",
                "Pongs over ended sessions whose nonce was never sent.",
                &["network"],
            )?,

            handshakes_total: counter(
                &r,
                "handshakes_total",
                "Connections that got through the version handshake, by transport.",
                &["network", "transport"],
            )?,
            handshake_user_agents_total: counter(
                &r,
                "handshake_user_agents_total",
                "Handshakes by user agent, with parenthesised comments removed. Past \
                 the first 128 distinct values a new one counts as other.",
                &["network", "user_agent"],
            )?,
            handshake_protocol_versions_total: counter(
                &r,
                "handshake_protocol_versions_total",
                "Handshakes by the peer's protocol version. Past the first 32 distinct \
                 values a new one counts as other.",
                &["network", "version"],
            )?,
            handshake_services_total: counter(
                &r,
                "handshake_services_total",
                "Service bits announced in handshakes, one count per bit set; none for \
                 no bits at all. A bit without a name is bit_<n>.",
                &["network", "service"],
            )?,
            handshake_features_total: counter(
                &r,
                "handshake_features_total",
                "Handshakes in which the peer asked for transaction relay (relay), \
                 offered addrv2 (sendaddrv2) or wtxid relay (wtxid_relay), or told us \
                 an address it sees us at (addr_recv).",
                &["network", "feature"],
            )?,
            handshake_clock_skew_seconds: histogram(
                &r,
                "handshake_clock_skew_seconds",
                "The peer's clock in its version message minus ours at receipt.",
                SKEW_BUCKETS,
                &["network"],
            )?,
            handshake_height_delta: histogram(
                &r,
                "handshake_height_delta",
                "The peer's claimed start height minus the best height announced so \
                 far. Not observed before a block with a height has been announced.",
                HEIGHT_DELTA_BUCKETS,
                &["network"],
            )?,
            best_height: gauge(
                &r,
                "best_height",
                "The highest block height any announcement has carried.",
                &["network"],
            )?,

            ping_rtt_seconds: histogram(
                &r,
                "ping_rtt_seconds",
                "Application-level round trip of a ping.",
                RTT_BUCKETS,
                &["network"],
            )?,
            ping_tcp_srtt_seconds: histogram(
                &r,
                "ping_tcp_srtt_seconds",
                "The kernel's smoothed round trip of the socket, sampled as the pong \
                 arrived.",
                RTT_BUCKETS,
                &["network"],
            )?,
            ping_tcp_min_rtt_seconds: histogram(
                &r,
                "ping_tcp_min_rtt_seconds",
                "The lowest round trip the kernel has seen on the socket, sampled as \
                 the pong arrived. Linux only.",
                RTT_BUCKETS,
                &["network"],
            )?,
            ping_tcp_rttvar_seconds: histogram(
                &r,
                "ping_tcp_rttvar_seconds",
                "The kernel's round trip variance of the socket, sampled as the pong \
                 arrived.",
                RTT_BUCKETS,
                &["network"],
            )?,
            ping_tcp_cwnd_segments: histogram(
                &r,
                "ping_tcp_cwnd_segments",
                "Congestion window of the socket, sampled as the pong arrived.",
                CWND_BUCKETS,
                &["network"],
            )?,
            ping_tcp_retransmits: histogram(
                &r,
                "ping_tcp_retransmits",
                "Segments retransmitted over the connection's life so far, sampled as \
                 the pong arrived.",
                RETRANS_BUCKETS,
                &["network"],
            )?,
            ping_tcp_delivery_rate_bytes_per_second: histogram(
                &r,
                "ping_tcp_delivery_rate_bytes_per_second",
                "The kernel's delivery rate estimate for the socket, sampled as the \
                 pong arrived. Linux only.",
                RATE_BUCKETS,
                &["network"],
            )?,

            block_announcements_total: counter(
                &r,
                "block_announcements_total",
                "Block announcements received, by the message that carried them.",
                &["network", "type"],
            )?,
            blocks_total: counter(
                &r,
                "blocks_total",
                "Blocks first heard of through an announcement, by the message that \
                 carried the first one.",
                &["network", "type"],
            )?,
            block_announcement_batch_size: histogram(
                &r,
                "block_announcement_batch_size",
                "Headers in the message carrying an announcement: one for an inv or a \
                 compact block, more when a HEADERS message was catching us up.",
                BATCH_BUCKETS,
                &["network"],
            )?,
            block_propagation_seconds: histogram(
                &r,
                "block_propagation_seconds",
                "How long after the first sighting of a block each further peer \
                 announced it. Only for blocks whose first sighting this tool saw.",
                PROPAGATION_BUCKETS,
                &["network", "type"],
            )?,
            compact_block_short_ids: histogram(
                &r,
                "compact_block_short_ids",
                "Transactions a compact block carried as short ids.",
                SHORT_ID_BUCKETS,
                &["network"],
            )?,
            compact_block_prefilled_txs: histogram(
                &r,
                "compact_block_prefilled_txs",
                "Transactions a compact block carried in full.",
                PREFILLED_BUCKETS,
                &["network"],
            )?,
            compact_block_probes_total: counter(
                &r,
                "compact_block_probes_total",
                "Steps of the compact block probe: coinbases requested from a peer that \
                 sent a compact block, and answers received.",
                &["network", "stage"],
            )?,

            fee_filters_total: counter(
                &r,
                "fee_filters_total",
                "Fee filter messages received.",
                &["network"],
            )?,
            fee_filter_sat_per_kvb: histogram(
                &r,
                "fee_filter_sat_per_kvb",
                "The fee rate a peer announced as its relay floor, in sat/kvB.",
                FEE_FILTER_BUCKETS,
                &["network"],
            )?,
            send_cmpct_total: counter(
                &r,
                "send_cmpct_total",
                "sendcmpct messages received, by the mode (high or low bandwidth) and \
                 compact block version the peer asked for.",
                &["network", "mode", "version"],
            )?,

            address_announcements_total: counter(
                &r,
                "address_announcements_total",
                "Address announcements received, by the message that carried them.",
                &["network", "message"],
            )?,
            address_announcement_entries: histogram(
                &r,
                "address_announcement_entries",
                "Addresses per announcement, as announced and before the rate limit.",
                ADDRESS_COUNT_BUCKETS,
                &["network"],
            )?,
            address_entries_total: counter(
                &r,
                "address_entries_total",
                "Addresses announced, by their network.",
                &["network", "net"],
            )?,
            address_entry_services_total: counter(
                &r,
                "address_entry_services_total",
                "Service bits on announced addresses, one count per bit set; none for \
                 no bits at all.",
                &["network", "service"],
            )?,
            address_entry_age_seconds: histogram(
                &r,
                "address_entry_age_seconds",
                "Our time at receipt minus the timestamp an announced address carried. \
                 Negative is a timestamp in the future.",
                ADDRESS_AGE_BUCKETS,
                &["network"],
            )?,
            unparsed_address_entries_total: counter(
                &r,
                "unparsed_address_entries_total",
                "Announced addresses the observer could not parse, almost always an \
                 addrv2 type it does not know.",
                &["network"],
            )?,
            rate_limited_address_entries_total: counter(
                &r,
                "rate_limited_address_entries_total",
                "Announced addresses the observer's per-connection rate limit discarded.",
                &["network"],
            )?,
            solicited_address_announcements_total: counter(
                &r,
                "solicited_address_announcements_total",
                "Address announcements that arrived while a GETADDR of ours was \
                 outstanding.",
                &["network"],
            )?,
            self_announcements_total: counter(
                &r,
                "self_announcements_total",
                "Announcements of a single address that is the announcing peer's own.",
                &["network"],
            )?,
            address_rate_limit_tokens: float_gauge(
                &r,
                "address_rate_limit_tokens",
                "The rate limiter's token level when the latest announcement was \
                 processed, before spending on it.",
                &["network"],
            )?,
            registry: r,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_every_metric_registers_and_encodes() {
        let metrics = Metrics::new().unwrap();
        // A vec without children is not gathered, so each is touched first.
        metrics
            .events_total
            .with_label_values(&["signet", "ping_rtt"])
            .inc();
        metrics
            .block_propagation_seconds
            .with_label_values(&["signet", "inv"])
            .observe(1.0);
        let families = metrics.registry.gather();
        let names: Vec<&str> = families.iter().map(|f| f.name()).collect();
        assert!(names.contains(&"p2pobserver_events_total"));
        assert!(names.contains(&"p2pobserver_block_propagation_seconds"));
        assert!(names.iter().all(|n| n.starts_with("p2pobserver_")));
    }

    #[test]
    fn test_a_second_registry_is_independent() {
        // Each `Metrics` owns its registry rather than the process-wide
        // default, so two can coexist in one process (as they do in tests).
        let a = Metrics::new().unwrap();
        let b = Metrics::new().unwrap();
        a.fee_filters_total.with_label_values(&["signet"]).inc();
        assert_eq!(b.fee_filters_total.with_label_values(&["signet"]).get(), 0);
    }
}
