//! Adding up what is in an archive.
//!
//! The replayer prints every event; this prints what a reader would otherwise
//! add up by hand before anything else can be said about an archive: how much
//! it covers, which hosts dominate it, how sessions end, what the peers claim
//! to be, and which blocks the observer could not place. Each table is one
//! that a pass over the mainnet archives needed, and each is small enough to
//! read in a terminal.
//!
//! Everything is keyed by host, not by connection or address: a host that
//! opens six thousand sessions is one row, which is the point. Memory grows
//! with hosts and block hashes, never with events.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::PathBuf;

use common::{
    anyhow::{Context, Result},
    clap::{self, Parser},
    events::{
        DisconnectReason, FailureReason, PeerEvent, connection_result::Result as Attempt,
        peer_event::Event,
    },
};

use crate::read::ArchiveReader;

#[derive(Parser, Debug)]
#[command(version, about = "Summarise p2p-observer archive files")]
pub struct Args {
    /// Archive files to read, either `.bin` or `.bin.zst`. Read in the order
    /// given, as one stream.
    #[arg(value_name = "FILE", required = true)]
    pub files: Vec<PathBuf>,
    /// Rows to show in the per-host and per-user-agent tables.
    #[arg(long, default_value_t = 20)]
    pub top: usize,
}

/// Reads every file into one [`Stats`] and prints it.
pub fn run(args: &Args) -> Result<()> {
    let mut stats = Stats::default();
    for path in &args.files {
        let archive = ArchiveReader::open(path)
            .with_context(|| format!("reading archive {}", path.display()))?;
        if stats.network.is_empty() {
            stats.network = archive.header.network.clone();
        }
        for (idx, event) in archive.enumerate() {
            let event = event
                .with_context(|| format!("at event {} in archive {}", idx + 1, path.display()))?;
            stats.observe(&event);
        }
    }
    print!("{}", stats.report(args.top));
    Ok(())
}

/// The host of a rendered peer address: everything before the port.
fn host_of(addr: &str) -> &str {
    addr.rsplit_once(':').map_or(addr, |(host, _)| host)
}

/// Leading zero hex digits of a block hash as rendered, which is a coarse
/// reading of how much work it took: mainnet hashes have about nineteen or
/// more, and a chain with a fraction of mainnet's hashrate shows up as a
/// second mode a few digits lower.
fn leading_zeros(hash: &str) -> usize {
    hash.bytes().take_while(|b| *b == b'0').count()
}

/// Everything remembered about one host.
#[derive(Debug, Default)]
struct Host {
    handshakes: u64,
    sessions: u64,
    /// Sessions in which the peer sent no message after the handshake.
    silent: u64,
    uptime_secs: u64,
    longest_secs: u64,
    decode_errors: u64,
    failed_attempts: u64,
    /// Announcements of blocks the observer's header tree could not place.
    unplaced: u64,
    /// Entries the rate limit discarded.
    rate_limited: u64,
    user_agents: BTreeMap<String, u64>,
}

impl Host {
    fn user_agent(&self) -> String {
        let mut agents: Vec<(&String, &u64)> = self.user_agents.iter().collect();
        agents.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
        let mut out: Vec<&str> = agents.iter().take(2).map(|(ua, _)| ua.as_str()).collect();
        if agents.len() > 2 {
            out.push("...");
        }
        out.join(" ")
    }
}

/// Bits set in service fields, with an all-ones field kept apart: it is a
/// filled-in field from a few sources, not sixty-four services, and split
/// into bits it drowns the real ones.
#[derive(Debug, Default)]
struct ServiceBits {
    fields: u64,
    all_ones: u64,
    bits: BTreeMap<u8, u64>,
}

impl ServiceBits {
    fn observe(&mut self, services: u64) {
        self.fields += 1;
        if services == u64::MAX {
            self.all_ones += 1;
            return;
        }
        for bit in 0..64 {
            if services & (1u64 << bit) != 0 {
                *self.bits.entry(bit).or_default() += 1;
            }
        }
    }
}

#[derive(Debug, Default)]
pub struct Stats {
    network: String,
    events: u64,
    first_ms: Option<u64>,
    last_ms: Option<u64>,
    instances: HashSet<u64>,
    /// The highest drop count seen per instance; the counter only grows
    /// within one run.
    dropped: HashMap<u64, u64>,
    hosts: HashMap<String, Host>,
    /// Hosts that completed a handshake under each user agent.
    hosts_by_user_agent: HashMap<String, HashSet<String>>,
    handshakes_by_user_agent: HashMap<String, u64>,
    session_ends: BTreeMap<String, u64>,
    failures: BTreeMap<String, u64>,
    our_faults: u64,
    /// Whether any announcement of the hash carried a height.
    blocks: HashMap<String, bool>,
    announcements: u64,
    handshake_services: ServiceBits,
    gossip_services: ServiceBits,
}

impl Stats {
    pub fn observe(&mut self, e: &PeerEvent) {
        self.events += 1;
        self.first_ms = Some(
            self.first_ms
                .map_or(e.timestamp_ms, |t| t.min(e.timestamp_ms)),
        );
        self.last_ms = Some(
            self.last_ms
                .map_or(e.timestamp_ms, |t| t.max(e.timestamp_ms)),
        );
        self.instances.insert(e.instance_id);
        let dropped = self.dropped.entry(e.instance_id).or_default();
        *dropped = (*dropped).max(e.dropped_events);

        let host = host_of(&e.peer_addr).to_owned();
        let Some(event) = &e.event else {
            return;
        };
        match event {
            Event::Handshake(hs) => {
                let h = self.hosts.entry(host.clone()).or_default();
                h.handshakes += 1;
                *h.user_agents.entry(hs.user_agent.clone()).or_default() += 1;
                self.hosts_by_user_agent
                    .entry(hs.user_agent.clone())
                    .or_default()
                    .insert(host);
                *self
                    .handshakes_by_user_agent
                    .entry(hs.user_agent.clone())
                    .or_default() += 1;
                self.handshake_services.observe(hs.services);
            }
            Event::ConnectionResult(r) => match &r.result {
                Some(Attempt::Disconnected(d)) => {
                    let h = self.hosts.entry(host).or_default();
                    h.sessions += 1;
                    let secs = d.uptime_ms / 1000;
                    h.uptime_secs += secs;
                    h.longest_secs = h.longest_secs.max(secs);
                    if d.messages_by_command.is_empty() && d.messages_other == 0 {
                        h.silent += 1;
                    }
                    let reason = d.reason();
                    if reason == DisconnectReason::DecodeError {
                        h.decode_errors += 1;
                    }
                    *self
                        .session_ends
                        .entry(enum_label(reason.as_str_name(), "DISCONNECT_REASON_"))
                        .or_default() += 1;
                }
                Some(Attempt::Failed(f)) => {
                    self.hosts.entry(host).or_default().failed_attempts += 1;
                    let reason = FailureReason::try_from(f.reason).unwrap_or_default();
                    *self
                        .failures
                        .entry(enum_label(reason.as_str_name(), "FAILURE_REASON_"))
                        .or_default() += 1;
                }
                Some(Attempt::OurFault(_)) => self.our_faults += 1,
                None => {}
            },
            Event::BlockAnnouncement(b) => {
                self.announcements += 1;
                let placed = self.blocks.entry(b.block_hash.clone()).or_default();
                *placed |= b.height.is_some();
                if b.height.is_none() {
                    self.hosts.entry(host).or_default().unplaced += 1;
                }
            }
            Event::AddressAnnouncement(a) => {
                self.hosts.entry(host).or_default().rate_limited += u64::from(a.rate_limited);
                for entry in &a.addresses {
                    self.gossip_services.observe(entry.services);
                }
            }
            Event::PingRtt(_)
            | Event::CompactBlockProbe(_)
            | Event::FeeFilter(_)
            | Event::SendCmpct(_) => {}
        }
    }

    /// The whole summary as text.
    pub fn report(&self, top: usize) -> String {
        let mut out = String::new();
        self.coverage(&mut out);
        self.sessions(&mut out);
        self.hosts(&mut out, top);
        self.user_agents(&mut out, top);
        self.blocks(&mut out);
        self.services(&mut out);
        out
    }

    fn coverage(&self, out: &mut String) {
        let span = match (self.first_ms, self.last_ms) {
            (Some(a), Some(b)) => format!("{} to {} ({})", unix(a), unix(b), duration(b - a)),
            _ => "nothing".to_owned(),
        };
        let handshook = self.hosts.values().filter(|h| h.handshakes > 0).count();
        let sessions: u64 = self.hosts.values().map(|h| h.sessions).sum();
        let dropped: u64 = self.dropped.values().sum();
        section(out, &format!("coverage ({})", self.network));
        table(
            out,
            &[
                row(["events", &n(self.events)]),
                row(["span", &span]),
                row(["observer instances", &n(self.instances.len() as u64)]),
                row(["events dropped by the observer", &n(dropped)]),
                row(["hosts seen", &n(self.hosts.len() as u64)]),
                row(["hosts that completed a handshake", &n(handshook as u64)]),
                row(["sessions ended", &n(sessions)]),
                row(["block announcements", &n(self.announcements)]),
                row(["distinct block hashes", &n(self.blocks.len() as u64)]),
            ],
        );
    }

    fn sessions(&self, out: &mut String) {
        let total: u64 = self.session_ends.values().sum();
        let silent: u64 = self.hosts.values().map(|h| h.silent).sum();
        section(out, "how sessions ended");
        let mut rows: Vec<Vec<String>> = self
            .session_ends
            .iter()
            .map(|(reason, count)| row([reason, &n(*count), &share(*count, total)]))
            .collect();
        rows.push(row([
            "(peer sent nothing)",
            &n(silent),
            &share(silent, total),
        ]));
        table(out, &rows);
        let failed: u64 = self.failures.values().sum();
        section(out, "attempts that never reached a session");
        let mut rows: Vec<Vec<String>> = self
            .failures
            .iter()
            .map(|(reason, count)| row([reason, &n(*count), &share(*count, failed)]))
            .collect();
        rows.push(row(["(our fault)", &n(self.our_faults), ""]));
        table(out, &rows);
    }

    fn hosts(&self, out: &mut String, top: usize) {
        let mut hosts: Vec<(&String, &Host)> = self.hosts.iter().collect();
        hosts.sort_by(|a, b| b.1.sessions.cmp(&a.1.sessions).then(a.0.cmp(b.0)));
        section(out, &format!("hosts by sessions (top {top})"));
        let mut rows = vec![row([
            "host",
            "sessions",
            "silent",
            "mean s",
            "longest s",
            "decode err",
            "failed",
            "unplaced",
            "rate limited",
            "user agent",
        ])];
        for (host, h) in hosts.iter().take(top) {
            // `checked_div` rather than a guarded division: a host with no
            // session has no mean uptime, and clippy reads the guard as this
            // call written out.
            let mean = h.uptime_secs.checked_div(h.sessions).unwrap_or(0);
            rows.push(row([
                host,
                &n(h.sessions),
                &n(h.silent),
                &n(mean),
                &n(h.longest_secs),
                &n(h.decode_errors),
                &n(h.failed_attempts),
                &n(h.unplaced),
                &n(h.rate_limited),
                &h.user_agent(),
            ]));
        }
        table(out, &rows);

        // The hosts the tree could not follow, which on mainnet is another
        // chain: these are where its blocks come from.
        let mut unplaced: Vec<(&String, &Host)> =
            self.hosts.iter().filter(|(_, h)| h.unplaced > 0).collect();
        if !unplaced.is_empty() {
            unplaced.sort_by(|a, b| b.1.unplaced.cmp(&a.1.unplaced).then(a.0.cmp(b.0)));
            section(
                out,
                &format!(
                    "hosts announcing blocks without a height ({} hosts, top {top})",
                    unplaced.len()
                ),
            );
            let mut rows = vec![row(["host", "unplaced", "sessions", "user agent"])];
            for (host, h) in unplaced.iter().take(top) {
                rows.push(row([host, &n(h.unplaced), &n(h.sessions), &h.user_agent()]));
            }
            table(out, &rows);
        }
    }

    fn user_agents(&self, out: &mut String, top: usize) {
        let mut agents: Vec<(&String, usize)> = self
            .hosts_by_user_agent
            .iter()
            .map(|(ua, hosts)| (ua, hosts.len()))
            .collect();
        agents.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
        section(out, &format!("user agents by hosts (top {top})"));
        let mut rows = vec![row(["user agent", "hosts", "handshakes"])];
        for (ua, hosts) in agents.iter().take(top) {
            let handshakes = self.handshakes_by_user_agent.get(*ua).copied().unwrap_or(0);
            rows.push(row([ua, &n(*hosts as u64), &n(handshakes)]));
        }
        table(out, &rows);
    }

    fn blocks(&self, out: &mut String) {
        let mut zeros: BTreeMap<usize, (u64, u64)> = BTreeMap::new();
        for (hash, placed) in &self.blocks {
            let entry = zeros.entry(leading_zeros(hash)).or_default();
            if *placed {
                entry.0 += 1;
            } else {
                entry.1 += 1;
            }
        }
        section(out, "distinct block hashes by leading zero hex digits");
        let mut rows = vec![row(["zeros", "with height", "without height"])];
        for (z, (placed, unplaced)) in &zeros {
            rows.push(row([&n(*z as u64), &n(*placed), &n(*unplaced)]));
        }
        table(out, &rows);
    }

    fn services(&self, out: &mut String) {
        for (what, bits) in [
            ("handshake service bits", &self.handshake_services),
            ("gossiped entry service bits", &self.gossip_services),
        ] {
            section(out, &format!("{what} ({} fields)", n(bits.fields)));
            let mut rows = vec![row(["bit", "name", "fields", "share"])];
            for (bit, count) in &bits.bits {
                rows.push(row([
                    &n(u64::from(*bit)),
                    service_name(*bit),
                    &n(*count),
                    &share(*count, bits.fields),
                ]));
            }
            rows.push(row([
                "all",
                "every bit set",
                &n(bits.all_ones),
                &share(bits.all_ones, bits.fields),
            ]));
            table(out, &rows);
        }
    }
}

fn service_name(bit: u8) -> &'static str {
    match bit {
        0 => "network",
        1 => "getutxo",
        2 => "bloom",
        3 => "witness",
        4 => "xthin",
        6 => "compact_filters",
        10 => "network_limited",
        11 => "p2p_v2",
        _ => "",
    }
}

/// `DISCONNECT_REASON_PEER_CLOSED` as `peer_closed`.
fn enum_label(name: &str, prefix: &str) -> String {
    name.strip_prefix(prefix)
        .unwrap_or(name)
        .to_ascii_lowercase()
}

fn n(v: u64) -> String {
    let digits = v.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn share(part: u64, whole: u64) -> String {
    if whole == 0 {
        return String::new();
    }
    format!("{:.1}%", part as f64 * 100.0 / whole as f64)
}

fn unix(ms: u64) -> String {
    use time::{OffsetDateTime, format_description::well_known::Rfc3339};
    OffsetDateTime::from_unix_timestamp((ms / 1000) as i64)
        .ok()
        .and_then(|t| t.format(&Rfc3339).ok())
        .unwrap_or_else(|| ms.to_string())
}

fn duration(ms: u64) -> String {
    let secs = ms / 1000;
    format!(
        "{}d {:02}h {:02}m",
        secs / 86_400,
        secs % 86_400 / 3_600,
        secs % 3_600 / 60
    )
}

fn section(out: &mut String, title: &str) {
    if !out.is_empty() {
        out.push('\n');
    }
    out.push_str("== ");
    out.push_str(title);
    out.push('\n');
}

fn row<const N: usize>(cells: [&str; N]) -> Vec<String> {
    cells.iter().map(|c| (*c).to_owned()).collect()
}

/// Pads each column to its widest cell. Numbers are not right-aligned: the
/// tables are read, not computed on, and a left edge is easier to scan.
fn table(out: &mut String, rows: &[Vec<String>]) {
    let columns = rows.iter().map(Vec::len).max().unwrap_or(0);
    let widths: Vec<usize> = (0..columns)
        .map(|c| {
            rows.iter()
                .filter_map(|r| r.get(c))
                .map(|cell| cell.chars().count())
                .max()
                .unwrap_or(0)
        })
        .collect();
    for r in rows {
        let line: Vec<String> = r
            .iter()
            .enumerate()
            .map(|(c, cell)| format!("{cell:<width$}", width = widths[c]))
            .collect();
        out.push_str("  ");
        out.push_str(line.join("  ").trim_end());
        out.push('\n');
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::events::{
        AddressAnnouncement, BlockAnnouncement, ConnectionResult, GossipedAddress, Handshake,
        connection_result::Disconnected,
    };

    fn event(addr: &str, at_ms: u64, event: Event) -> PeerEvent {
        PeerEvent {
            connection_id: 1,
            timestamp_ms: at_ms,
            peer_addr: addr.to_owned(),
            instance_id: 7,
            event: Some(event),
            ..Default::default()
        }
    }

    fn handshake(ua: &str, services: u64) -> Event {
        Event::Handshake(Handshake {
            user_agent: ua.to_owned(),
            services,
            ..Default::default()
        })
    }

    fn session(uptime_ms: u64, messages: &[(&str, u32)], reason: DisconnectReason) -> Event {
        Event::ConnectionResult(ConnectionResult {
            result: Some(Attempt::Disconnected(Disconnected {
                uptime_ms,
                reason: reason as i32,
                messages_by_command: messages
                    .iter()
                    .map(|(c, n)| ((*c).to_owned(), *n))
                    .collect(),
                ..Default::default()
            })),
        })
    }

    fn block(hash: &str, height: Option<u32>) -> Event {
        Event::BlockAnnouncement(BlockAnnouncement {
            block_hash: hash.to_owned(),
            height,
            ..Default::default()
        })
    }

    /// The stream the README's example output comes from.
    ///
    /// Invented: documentation addresses, made-up user agents and hashes with
    /// recognisable digits. An example taken from a real archive would print
    /// the peers it saw, which is not something to put in a README, and these
    /// tables are about shape rather than about any one capture.
    ///
    /// It is still shaped like what an archive holds: a node that stays for
    /// hours, a fleet of one-minute sessions that says nothing and announces a
    /// block the header tree cannot place, an implementation whose message we
    /// could not read, and an address that was never reached.
    fn demo() -> Stats {
        // 2026-10-25 12:00:00 UTC.
        const T0: u64 = 1_792_929_600_000;
        const HOUR: u64 = 3_600_000;
        let placed = |n: &str| format!("{}{}{}", "0".repeat(19), "dec0de", n.repeat(39));
        let fork = format!("{}{}{}", "0".repeat(16), "fa11", "b".repeat(44));

        // Built in one go: the network is the one field the header sets, and
        // clippy reads a default plus an assignment as this written out.
        let mut s = Stats {
            network: "mainnet".to_owned(),
            ..Default::default()
        };

        // A node that stays, announces blocks the tree places, and gossips --
        // including one field with every bit set.
        let core = "192.0.2.10:8333";
        s.observe(&event(core, T0, handshake("/Satoshi:30.0.0/", 0x40d)));
        for (i, hash) in ["1", "2", "3"].iter().enumerate() {
            let at = T0 + HOUR * i as u64 + 1_000;
            s.observe(&event(
                core,
                at,
                block(&placed(hash), Some(870_000 + i as u32)),
            ));
        }
        for (i, uptime) in [3_600_000u64, 7_200_000, 1_200_000].iter().enumerate() {
            let at = T0 + HOUR * (i as u64 + 1);
            s.observe(&event(
                core,
                at,
                session(
                    *uptime,
                    &[("inv", 4_210), ("addrv2", 3)],
                    DisconnectReason::PeerClosed,
                ),
            ));
        }
        s.observe(&event(
            core,
            T0 + HOUR,
            Event::AddressAnnouncement(AddressAnnouncement {
                addresses: vec![
                    GossipedAddress {
                        services: 0x409,
                        ..Default::default()
                    },
                    GossipedAddress {
                        services: u64::MAX,
                        ..Default::default()
                    },
                ],
                rate_limited: 3,
                ..Default::default()
            }),
        ));

        // Six sessions of exactly a minute, none of them carrying a message,
        // each announcing the same block no header tree will take.
        let fleet = "198.51.100.7:8333";
        for i in 0..6u64 {
            let at = T0 + HOUR * i + 120_000;
            s.observe(&event(fleet, at, handshake("/Satoshi:25.1.0/", 0)));
            s.observe(&event(fleet, at + 1_000, block(&fork, None)));
            s.observe(&event(
                fleet,
                at + 60_000,
                session(60_000, &[], DisconnectReason::PeerClosed),
            ));
        }

        // One session ended on a frame we could not read, and one attempt that
        // never reached a session at all.
        let other = "203.0.113.42:8333";
        s.observe(&event(
            other,
            T0 + HOUR,
            handshake("/btcwire:0.5.0/btcd:0.24.2/", 0x409),
        ));
        s.observe(&event(
            other,
            T0 + HOUR + 900_000,
            session(900_000, &[("inv", 61)], DisconnectReason::DecodeError),
        ));
        s.observe(&event(
            other,
            T0 + HOUR * 2,
            Event::ConnectionResult(ConnectionResult {
                result: Some(Attempt::Failed(common::events::connection_result::Failed {
                    reason: FailureReason::ConnectionRefused as i32,
                    setup_ms: 1_000,
                })),
            }),
        ));

        let v6 = "[2001:db8::1]:8333";
        s.observe(&event(
            v6,
            T0 + HOUR * 3,
            handshake("/Satoshi:29.0.0/", 0x409),
        ));
        s.observe(&event(
            v6,
            T0 + HOUR * 3 + 1_000,
            block(&placed("1"), Some(870_000)),
        ));
        s.observe(&event(
            v6,
            T0 + HOUR * 5,
            session(1_800_000, &[("inv", 902)], DisconnectReason::PeerClosed),
        ));

        // One event reporting the observer's own losses, so the coverage table
        // has something to say about them.
        let lossy = PeerEvent {
            dropped_events: 12,
            ..event(core, T0 + HOUR * 5, handshake("/Satoshi:30.0.0/", 0x40d))
        };
        s.observe(&lossy);

        s
    }

    /// The README prints what the tool prints. Regenerate with
    /// `cargo test -p archive readme_example -- --nocapture` and paste.
    #[test]
    fn test_the_readme_example_is_what_stats_prints() {
        let report = demo().report(10);
        println!("{report}");
        let flat = |s: &str| s.lines().map(str::trim_end).collect::<Vec<_>>().join("\n");
        assert!(
            flat(include_str!("../README.md")).contains(flat(&report).trim()),
            "the README example no longer matches what stats prints; \
             regenerate it from this:\n{report}"
        );
    }

    #[test]
    fn test_host_and_zeros() {
        assert_eq!(host_of("1.2.3.4:8333"), "1.2.3.4");
        assert_eq!(host_of("[2001:db8::1]:8333"), "[2001:db8::1]");
        assert_eq!(host_of("nonsense"), "nonsense");
        assert_eq!(leading_zeros("000abc"), 3);
        assert_eq!(leading_zeros("abc"), 0);
        assert_eq!(n(1_234_567), "1,234,567");
        assert_eq!(n(999), "999");
    }

    /// Two hosts, one of them silent and on another chain; the report says so
    /// in every table it has.
    #[test]
    fn test_report_adds_up_by_host() {
        let mut s = Stats::default();
        let good = "1.1.1.1:8333";
        let fleet = "2.2.2.2:8333";
        s.observe(&event(good, 1_000, handshake("/Satoshi:30.0.0/", 0x40d)));
        s.observe(&event(good, 2_000, block("0000000000000000000a", Some(10))));
        s.observe(&event(
            good,
            3_000,
            session(600_000, &[("ping", 3)], DisconnectReason::PeerClosed),
        ));
        s.observe(&event(
            good,
            3_500,
            Event::AddressAnnouncement(AddressAnnouncement {
                addresses: vec![
                    GossipedAddress {
                        services: u64::MAX,
                        ..Default::default()
                    },
                    GossipedAddress {
                        services: 1,
                        ..Default::default()
                    },
                ],
                rate_limited: 1,
                ..Default::default()
            }),
        ));
        for i in 0..3u64 {
            s.observe(&event(fleet, 10_000 + i, handshake("/Satoshi:25.1.0/", 0)));
            s.observe(&event(
                fleet,
                10_100 + i,
                block("0000000000000000bbbb", None),
            ));
            s.observe(&event(
                fleet,
                20_000 + i,
                session(60_000, &[], DisconnectReason::PeerClosed),
            ));
        }

        let report = s.report(10);
        println!("{report}");
        assert_eq!(s.hosts.len(), 2);
        let fleet_host = &s.hosts["2.2.2.2"];
        assert_eq!((fleet_host.sessions, fleet_host.silent), (3, 3));
        assert_eq!(fleet_host.unplaced, 3);
        assert_eq!(s.hosts["1.1.1.1"].rate_limited, 1);
        assert_eq!(s.gossip_services.all_ones, 1);
        assert_eq!(s.gossip_services.bits[&0], 1);
        assert_eq!(s.blocks.len(), 2);
        assert!(report.contains("sessions ended                    4"));
        assert!(report.contains("(peer sent nothing)  3  75.0%"));
        assert!(report.contains("/Satoshi:25.1.0/  1      3"));
        // The fork hash has fewer leading zeros and no height; the real one
        // the reverse.
        assert!(report.contains("16     0            1"));
        assert!(report.contains("19     1            0"));
        assert!(report.contains("hosts announcing blocks without a height (1 hosts"));
    }
}
