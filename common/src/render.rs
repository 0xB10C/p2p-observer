//! One-line rendering of an event, shared by the tools that print them.
//!
//! Lives here rather than in a tool so that live output and replayed output
//! cannot drift apart: adding a variant to the `event` oneof is a single edit,
//! and anything already printing events picks it up.
//!
//! The rendered line carries no prefix. Where an event came from differs by
//! caller — a NATS subject when listening, a position in the file when
//! replaying — so the caller supplies it.

use crate::events::{
    AddrMessage, AnnouncementType, DisconnectReason, PeerEvent, ProbeStage, TcpStats, Unplaced,
    peer_event,
};

/// A counter worth a word only when it is not zero, which for every counter
/// it is used on is the exception rather than the rule.
fn counted(name: &str, n: u32) -> String {
    if n == 0 {
        String::new()
    } else {
        format!(" {name}={n}")
    }
}

/// A field as one line.
///
/// Several of the strings below are printed as they came rather than through
/// `Debug`, because `peer=1.2.3.4:8333` reads better than its quoted form.
/// One of them is a peer's to choose: a v1 command string is twelve bytes of
/// whatever arrived, and nothing between the wire and here rejects a newline
/// in it -- rust-bitcoin's `CommandString` checks the length and nothing
/// else. A frame with an unknown command and a correct checksum is counted
/// under that name, and the name reaches this line.
///
/// A line that is secretly two is a forged record: whatever reads the log
/// splits on newlines, and the half after the break can be made to look like
/// a complete entry from somewhere else. So control characters are escaped
/// and everything else is left exactly as it arrived.
fn one_line(s: &str) -> std::borrow::Cow<'_, str> {
    if !s.chars().any(char::is_control) {
        return std::borrow::Cow::Borrowed(s);
    }
    std::borrow::Cow::Owned(
        s.chars()
            .flat_map(|c| {
                if c.is_control() {
                    c.escape_debug().collect::<Vec<char>>()
                } else {
                    vec![c]
                }
            })
            .collect(),
    )
}

/// An enum value as a name, or as the number it arrived as when this build
/// has no name for it.
///
/// `Unknown` is a real value of each of these enums -- zero, meaning the
/// sender did not set one -- so printing it for a number this build simply
/// does not know would say the wrong thing, and would throw away the only
/// thing that could identify the value. An archive outlives the binary that
/// wrote it, so a replayer is the normal place to meet a value from a later
/// one.
fn named<T: std::fmt::Debug, E>(raw: i32, parsed: Result<T, E>) -> String {
    match parsed {
        Ok(value) => format!("{value:?}"),
        Err(_) => format!("unknown({raw})"),
    }
}

/// Renders the transport version. Absent means the attempt failed while still
/// detecting, so no version was ever settled on.
fn transport(version: Option<u32>) -> String {
    match version {
        Some(v) => format!("v{v}"),
        None => "detecting".to_owned(),
    }
}

/// Renders the OS-level TCP samples, which are absent on platforms that do not
/// expose them. Leads with a space so it appends cleanly, and is empty when
/// there is nothing to show.
///
/// The per-field options are absent on a platform that has no equivalent, so
/// each is shown only when it was actually measured.
fn tcp(stats: Option<&TcpStats>) -> String {
    stats
        .map(|t| {
            let mut s = format!(
                " srtt={}µs rttvar={}µs retrans={} cwnd={}",
                t.srtt_us, t.rttvar_us, t.total_retrans, t.snd_cwnd
            );
            if let Some(v) = t.min_rtt_us {
                s.push_str(&format!(" minrtt={v}µs"));
            }
            if let Some(v) = t.lost {
                s.push_str(&format!(" lost={v}"));
            }
            if let Some(v) = t.reordering {
                s.push_str(&format!(" reorder={v}"));
            }
            if let Some(v) = t.delivery_rate {
                s.push_str(&format!(" rate={v}B/s"));
            }
            if let Some(v) = t.bytes_received {
                s.push_str(&format!(" rx={v}B"));
            }
            s
        })
        .unwrap_or_default()
}

/// Renders one event as a single unprefixed line.
pub fn event_line(event: &PeerEvent) -> String {
    let line = match &event.event {
        Some(peer_event::Event::Handshake(hs)) => {
            // Services as hex: the bits are the unit of meaning, and a decimal
            // bitfield has to be converted before it can be read.
            let addr_recv = if hs.addr_recv.is_empty() {
                String::new()
            } else {
                format!(" sees_us={}", one_line(&hs.addr_recv))
            };
            format!(
                "conn={} peer={} ua={:?} transport={} version={} services={:#x} height={} \
                 relay={} skew={}s addrv2={} wtxidrelay={}{addr_recv} ts={}",
                event.connection_id,
                one_line(&event.peer_addr),
                hs.user_agent,
                transport(event.transport_version),
                hs.protocol_version,
                hs.services,
                hs.start_height,
                hs.relay,
                // The peer's clock against ours, which is what anyone reading
                // the raw pair would work out first.
                // Saturating because the peer chose this number and nothing
                // checks it: a version carrying i64::MIN would otherwise
                // overflow here, and the archive would keep a line that
                // panics every reader of it from then on.
                hs.peer_timestamp
                    .saturating_sub((event.timestamp_ms / 1000) as i64),
                hs.sendaddrv2,
                hs.wtxid_relay,
                event.timestamp_ms,
            )
        }
        Some(peer_event::Event::PingRtt(ping)) => format!(
            "conn={} peer={} ua={:?} transport={} rtt={}ms{} ts={}",
            event.connection_id,
            one_line(&event.peer_addr),
            event.user_agent,
            transport(event.transport_version),
            ping.rtt_ms,
            tcp(ping.tcp_stats.as_ref()),
            event.timestamp_ms,
        ),
        Some(peer_event::Event::BlockAnnouncement(blk)) => {
            let atype = named(
                blk.announcement_type,
                AnnouncementType::try_from(blk.announcement_type),
            );
            // Shown only when it says something: a batch of one is the norm.
            let batch = if blk.batch_size > 1 {
                format!(" batch={}", blk.batch_size)
            } else {
                String::new()
            };
            let height = blk
                .height
                .map(|h| format!(" height={h}"))
                .unwrap_or_default();
            // Only on a block with no height: it is there to say why there is
            // none, and the difference it draws -- a tree that is behind, or a
            // peer announcing a chain that fails this network's rules -- is
            // not recoverable from anything else on the line.
            let unplaced = blk
                .unplaced
                .map(|u| format!(" unplaced={}", named(u, Unplaced::try_from(u))))
                .unwrap_or_default();
            let new = if blk.new_to_us { " new" } else { "" };
            let shape = blk
                .compact_block
                .as_ref()
                .map(|c| format!(" shortids={} prefilled={}", c.short_ids, c.prefilled_txs))
                .unwrap_or_default();
            format!(
                "conn={} peer={} block={} type={atype}{height}{unplaced}{new}{batch}{shape}{} ts={}",
                event.connection_id,
                one_line(&event.peer_addr),
                one_line(&blk.block_hash),
                tcp(blk.tcp_stats.as_ref()),
                event.timestamp_ms,
            )
        }
        Some(peer_event::Event::CompactBlockProbe(probe)) => {
            let stage = named(probe.stage, ProbeStage::try_from(probe.stage));
            format!(
                "conn={} peer={} block={} probe={stage}{} ts={}",
                event.connection_id,
                one_line(&event.peer_addr),
                one_line(&probe.block_hash),
                tcp(probe.tcp_stats.as_ref()),
                event.timestamp_ms,
            )
        }
        Some(peer_event::Event::FeeFilter(f)) => format!(
            "conn={} peer={} feefilter={}sat/kvB ts={}",
            event.connection_id,
            one_line(&event.peer_addr),
            f.feerate_sat_per_kvb,
            event.timestamp_ms,
        ),
        Some(peer_event::Event::SendCmpct(s)) => format!(
            "conn={} peer={} sendcmpct hb={} version={} ts={}",
            event.connection_id,
            one_line(&event.peer_addr),
            s.high_bandwidth,
            s.version,
            event.timestamp_ms,
        ),
        Some(peer_event::Event::AddressAnnouncement(ann)) => {
            // Shown only when non-zero, which is almost never.
            let unparsed = if ann.unparsed > 0 {
                format!(" unparsed={}", ann.unparsed)
            } else {
                String::new()
            };
            // Likewise: a rate-limited announcement is the interesting one.
            let limited = if ann.rate_limited > 0 {
                format!(" rate_limited={}", ann.rate_limited)
            } else {
                String::new()
            };
            let message = named(ann.message, AddrMessage::try_from(ann.message));
            format!(
                "conn={} peer={} message={message} addresses={} solicited={}{limited}{unparsed} \
                 tokens={:.1} ts={}",
                event.connection_id,
                one_line(&event.peer_addr),
                ann.addresses.len(),
                ann.solicited,
                ann.rate_limit_tokens,
                event.timestamp_ms,
            )
        }
        Some(peer_event::Event::ConnectionResult(res)) => {
            use crate::events::connection_result::Result as R;
            use crate::events::{FailureReason, OurFaultReason};
            // Each variant prints only what applies to it, which is the point
            // of the oneof: no duration that means two things, no failure
            // reason hanging off a success.
            let detail = match &res.result {
                Some(R::Disconnected(d)) => {
                    let reason = named(d.reason, DisconnectReason::try_from(d.reason));
                    // Ordered by count so the line opens with what the session
                    // was mostly doing; the full map is in the archive.
                    let mut by_command: Vec<_> = d.messages_by_command.iter().collect();
                    by_command.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                    let messages: Vec<String> = by_command
                        .iter()
                        .take(5)
                        .map(|(cmd, n)| format!("{}={n}", one_line(cmd)))
                        .collect();
                    // The session's own counters, each shown only when it has
                    // something to say -- which for all four is the exception.
                    // `undecodable` and `getheaders_ignored` in particular
                    // exist because nothing else in the stream reports them,
                    // so leaving them off the line defeated the point of
                    // recording them.
                    let counters = [
                        counted("unsolicited_pongs", d.unsolicited_pongs),
                        counted("undecodable", d.undecodable),
                        counted("getheaders_ignored", d.getheaders_ignored),
                        counted("msgs_other", d.messages_other),
                    ]
                    .concat();
                    format!(
                        "result=disconnected reason={reason} setup={}ms uptime={}ms{counters} msgs=[{}]",
                        d.setup_ms,
                        d.uptime_ms,
                        messages.join(" "),
                    )
                }
                Some(R::Failed(f)) => {
                    let reason = named(f.reason, FailureReason::try_from(f.reason));
                    format!("result=failed reason={reason} setup={}ms", f.setup_ms)
                }
                Some(R::OurFault(o)) => {
                    let reason = named(o.reason, OurFaultReason::try_from(o.reason));
                    format!("result=our_fault reason={reason} setup={}ms", o.setup_ms)
                }
                None => "result=unset".to_owned(),
            };
            format!(
                "conn={} peer={} ua={:?} {detail} transport={} ts={}",
                event.connection_id,
                one_line(&event.peer_addr),
                event.user_agent,
                transport(event.transport_version),
                event.timestamp_ms,
            )
        }
        // An event whose oneof is unset, or one carrying a variant this build
        // does not know about. Either way there is nothing to render but the
        // envelope.
        None => format!("unknown event from {}", one_line(&event.peer_addr)),
    };

    // Shown only when something has been lost, so the usual line is unchanged
    // -- but shown on every kind of event, because the loss it reports is not
    // confined to the kind that happens to be carrying the count.
    if event.dropped_events > 0 {
        // By kind too, naming only the kinds that lost anything.
        let by_kind = event
            .dropped_by_kind
            .as_ref()
            .map(|d| {
                [
                    ("ping_rtt", d.ping_rtt),
                    ("block_announcement", d.block_announcement),
                    ("address_announcement", d.address_announcement),
                    ("connection_result", d.connection_result),
                    ("handshake", d.handshake),
                    ("compact_block_probe", d.compact_block_probe),
                    ("fee_filter", d.fee_filter),
                    ("send_cmpct", d.send_cmpct),
                ]
                .into_iter()
                .filter(|(_, n)| *n > 0)
                .map(|(k, n)| format!("{k}={n}"))
                .collect::<Vec<_>>()
                .join(" ")
            })
            .filter(|s| !s.is_empty())
            .map(|s| format!(" [{s}]"))
            .unwrap_or_default();
        format!("{line} dropped={}{by_kind}", event.dropped_events)
    } else {
        line
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::events::connection_result::{Disconnected, Failed, OurFault, Result as R};
    use crate::events::{
        AddressAnnouncement, BlockAnnouncement, CompactBlockProbe, CompactBlockShape,
        ConnectionResult, DroppedEvents, FailureReason, FeeFilter, GossipedAddress, Handshake,
        OurFaultReason, PingRtt, SendCmpct,
    };
    use crate::prost::Message;
    use std::collections::BTreeMap;
    use testsupport::Rng;

    const NOW_MS: u64 = 1_700_000_000_000;

    /// The envelope every line starts from, so that a test says only what it
    /// is about.
    fn event(inner: peer_event::Event) -> PeerEvent {
        PeerEvent {
            peer_addr: "1.2.3.4:8333".to_owned(),
            connection_id: 42,
            user_agent: "/Satoshi:29.0.0/".to_owned(),
            transport_version: Some(2),
            timestamp_ms: NOW_MS,
            instance_id: 7,
            event: Some(inner),
            ..Default::default()
        }
    }

    fn tcp_stats() -> TcpStats {
        TcpStats {
            srtt_us: 12_000,
            rttvar_us: 3_000,
            total_retrans: 2,
            snd_cwnd: 10,
            min_rtt_us: Some(11_000),
            lost: Some(1),
            reordering: Some(3),
            delivery_rate: Some(1_250_000),
            bytes_received: Some(4_096),
        }
    }

    fn handshake() -> Handshake {
        Handshake {
            protocol_version: 70016,
            services: 0x409,
            start_height: 870_000,
            relay: true,
            peer_timestamp: 1_700_000_042,
            addr_recv: "5.6.7.8:1234".to_owned(),
            sendaddrv2: true,
            wtxid_relay: true,
            user_agent: "/Satoshi:29.0.0/".to_owned(),
            nonce: 99,
        }
    }

    fn announcement() -> BlockAnnouncement {
        BlockAnnouncement {
            block_hash: "00000000000000000001".to_owned(),
            announcement_type: AnnouncementType::CompactBlock as i32,
            tcp_stats: None,
            batch_size: 3,
            height: None,
            new_to_us: true,
            compact_block: Some(CompactBlockShape {
                short_ids: 2_500,
                prefilled_txs: 1,
            }),
            unplaced: Some(Unplaced::WeakerChain as i32),
        }
    }

    fn disconnected() -> Disconnected {
        Disconnected {
            setup_ms: 120,
            uptime_ms: 60_000,
            reason: DisconnectReason::PingTimeout as i32,
            messages_by_command: BTreeMap::from([("inv".to_owned(), 9), ("ping".to_owned(), 2)])
                .into_iter()
                .collect(),
            messages_other: 1,
            unsolicited_pongs: 3,
            undecodable: 1,
            getheaders_ignored: 4,
        }
    }

    fn line(inner: peer_event::Event) -> String {
        event_line(&event(inner))
    }

    #[test]
    fn test_a_handshake_line() {
        assert_eq!(
            line(peer_event::Event::Handshake(handshake())),
            "conn=42 peer=1.2.3.4:8333 ua=\"/Satoshi:29.0.0/\" transport=v2 version=70016 \
             services=0x409 height=870000 relay=true skew=42s addrv2=true wtxidrelay=true \
             sees_us=5.6.7.8:1234 ts=1700000000000"
        );
    }

    /// A peer chooses its own timestamp and nothing checks it, so the skew is
    /// worked out saturating: before it was, a version carrying `i64::MIN`
    /// overflowed here, and because the number was archived first, the line
    /// went on panicking every reader of that archive afterwards.
    #[test]
    fn test_a_peer_timestamp_at_the_edge_does_not_overflow() {
        for extreme in [i64::MIN, i64::MAX] {
            let hs = Handshake {
                peer_timestamp: extreme,
                ..handshake()
            };
            let rendered = line(peer_event::Event::Handshake(hs));
            let expected = extreme.saturating_sub((NOW_MS / 1000) as i64);
            assert!(
                rendered.contains(&format!("skew={expected}s")),
                "{rendered}"
            );
        }
    }

    #[test]
    fn test_a_ping_line_carries_the_tcp_samples() {
        assert_eq!(
            line(peer_event::Event::PingRtt(PingRtt {
                rtt_ms: 37,
                tcp_stats: Some(tcp_stats()),
            })),
            "conn=42 peer=1.2.3.4:8333 ua=\"/Satoshi:29.0.0/\" transport=v2 rtt=37ms \
             srtt=12000µs rttvar=3000µs retrans=2 cwnd=10 minrtt=11000µs lost=1 reorder=3 \
             rate=1250000B/s rx=4096B ts=1700000000000"
        );
    }

    /// Where the platform reports nothing, nothing is claimed: a zero srtt is
    /// a measurement and an absent one is not, which is why these are options
    /// and not defaults.
    #[test]
    fn test_a_ping_line_without_samples_claims_none() {
        assert_eq!(
            line(peer_event::Event::PingRtt(PingRtt {
                rtt_ms: 37,
                tcp_stats: None,
            })),
            "conn=42 peer=1.2.3.4:8333 ua=\"/Satoshi:29.0.0/\" transport=v2 rtt=37ms \
             ts=1700000000000"
        );
    }

    /// An announced block with no height says why it has none.
    ///
    /// Without it a tree that is merely behind and a peer announcing a chain
    /// that fails this network's rules render identically, which is the one
    /// distinction the field was added to draw.
    #[test]
    fn test_a_block_announcement_says_why_it_has_no_height() {
        assert_eq!(
            line(peer_event::Event::BlockAnnouncement(announcement())),
            "conn=42 peer=1.2.3.4:8333 block=00000000000000000001 type=CompactBlock \
             unplaced=WeakerChain new batch=3 shortids=2500 prefilled=1 ts=1700000000000"
        );
    }

    #[test]
    fn test_a_placed_block_says_nothing_about_being_unplaced() {
        let rendered = line(peer_event::Event::BlockAnnouncement(BlockAnnouncement {
            height: Some(870_001),
            unplaced: None,
            batch_size: 1,
            new_to_us: false,
            compact_block: None,
            ..announcement()
        }));
        assert_eq!(
            rendered,
            "conn=42 peer=1.2.3.4:8333 block=00000000000000000001 type=CompactBlock \
             height=870001 ts=1700000000000"
        );
    }

    #[test]
    fn test_the_short_lines() {
        assert_eq!(
            line(peer_event::Event::CompactBlockProbe(CompactBlockProbe {
                block_hash: "00000000000000000002".to_owned(),
                stage: ProbeStage::Answered as i32,
                tcp_stats: None,
            })),
            "conn=42 peer=1.2.3.4:8333 block=00000000000000000002 probe=Answered \
             ts=1700000000000"
        );
        assert_eq!(
            line(peer_event::Event::FeeFilter(FeeFilter {
                feerate_sat_per_kvb: 1_000,
            })),
            "conn=42 peer=1.2.3.4:8333 feefilter=1000sat/kvB ts=1700000000000"
        );
        assert_eq!(
            line(peer_event::Event::SendCmpct(SendCmpct {
                high_bandwidth: true,
                version: 2,
            })),
            "conn=42 peer=1.2.3.4:8333 sendcmpct hb=true version=2 ts=1700000000000"
        );
    }

    #[test]
    fn test_an_address_announcement_line() {
        assert_eq!(
            line(peer_event::Event::AddressAnnouncement(
                AddressAnnouncement {
                    message: AddrMessage::Addrv2 as i32,
                    unparsed: 2,
                    addresses: vec![GossipedAddress {
                        addr: "9.9.9.9:8333".to_owned(),
                        services: 1,
                        ntime: 1_700_000_000,
                    }],
                    solicited: true,
                    rate_limited: 5,
                    rate_limit_tokens: 0.25,
                }
            )),
            "conn=42 peer=1.2.3.4:8333 message=Addrv2 addresses=1 solicited=true \
             rate_limited=5 unparsed=2 tokens=0.2 ts=1700000000000"
        );
    }

    /// Every counter the session kept reaches the line.
    ///
    /// `undecodable` and `getheaders_ignored` especially: both exist because
    /// nothing else in the stream reports them -- a skipped frame and a reply
    /// that never went out leave no other trace -- and neither was printed.
    #[test]
    fn test_a_disconnected_line_carries_every_counter() {
        assert_eq!(
            line(peer_event::Event::ConnectionResult(ConnectionResult {
                result: Some(R::Disconnected(disconnected())),
            })),
            "conn=42 peer=1.2.3.4:8333 ua=\"/Satoshi:29.0.0/\" result=disconnected \
             reason=PingTimeout setup=120ms uptime=60000ms unsolicited_pongs=3 undecodable=1 \
             getheaders_ignored=4 msgs_other=1 msgs=[inv=9 ping=2] transport=v2 \
             ts=1700000000000"
        );
    }

    /// A session where none of that happened says none of it, which is the
    /// usual line.
    #[test]
    fn test_a_quiet_session_mentions_no_counters() {
        assert_eq!(
            line(peer_event::Event::ConnectionResult(ConnectionResult {
                result: Some(R::Disconnected(Disconnected {
                    messages_other: 0,
                    unsolicited_pongs: 0,
                    undecodable: 0,
                    getheaders_ignored: 0,
                    ..disconnected()
                })),
            })),
            "conn=42 peer=1.2.3.4:8333 ua=\"/Satoshi:29.0.0/\" result=disconnected \
             reason=PingTimeout setup=120ms uptime=60000ms msgs=[inv=9 ping=2] transport=v2 \
             ts=1700000000000"
        );
    }

    #[test]
    fn test_the_other_two_results() {
        assert_eq!(
            line(peer_event::Event::ConnectionResult(ConnectionResult {
                result: Some(R::Failed(Failed {
                    reason: FailureReason::ConnectionRefused as i32,
                    setup_ms: 10,
                })),
            })),
            "conn=42 peer=1.2.3.4:8333 ua=\"/Satoshi:29.0.0/\" result=failed \
             reason=ConnectionRefused setup=10ms transport=v2 ts=1700000000000"
        );
        assert_eq!(
            line(peer_event::Event::ConnectionResult(ConnectionResult {
                result: Some(R::OurFault(OurFault {
                    reason: OurFaultReason::NetworkUnreachable as i32,
                    setup_ms: 0,
                })),
            })),
            "conn=42 peer=1.2.3.4:8333 ua=\"/Satoshi:29.0.0/\" result=our_fault \
             reason=NetworkUnreachable setup=0ms transport=v2 ts=1700000000000"
        );
    }

    /// A value this build has no name for keeps its number.
    ///
    /// `Unknown` is a real value of each of these enums -- zero, the sender
    /// did not set one -- so printing it for a number from a later build said
    /// something false and threw away the only identifying thing about it. An
    /// archive outlives the binary that wrote it, which makes a replayer the
    /// ordinary place to meet one.
    #[test]
    fn test_an_enum_value_this_build_does_not_know_keeps_its_number() {
        let rendered = line(peer_event::Event::ConnectionResult(ConnectionResult {
            result: Some(R::Disconnected(Disconnected {
                reason: 999,
                ..disconnected()
            })),
        }));
        assert!(rendered.contains("reason=unknown(999)"), "{rendered}");

        let rendered = line(peer_event::Event::BlockAnnouncement(BlockAnnouncement {
            announcement_type: 998,
            unplaced: Some(997),
            ..announcement()
        }));
        assert!(rendered.contains("type=unknown(998)"), "{rendered}");
        assert!(rendered.contains("unplaced=unknown(997)"), "{rendered}");

        // And zero still reads as what it means.
        let rendered = line(peer_event::Event::ConnectionResult(ConnectionResult {
            result: Some(R::Disconnected(Disconnected {
                reason: 0,
                ..disconnected()
            })),
        }));
        assert!(rendered.contains("reason=Unknown"), "{rendered}");
    }

    /// The loss is reported on whatever event happens to be carrying the
    /// count, so it has to show on every kind of line.
    #[test]
    fn test_dropped_events_are_named_by_kind() {
        let mut dropped = event(peer_event::Event::FeeFilter(FeeFilter {
            feerate_sat_per_kvb: 1,
        }));
        dropped.dropped_events = 12;
        dropped.dropped_by_kind = Some(DroppedEvents {
            ping_rtt: 10,
            address_announcement: 2,
            ..Default::default()
        });
        assert_eq!(
            event_line(&dropped),
            "conn=42 peer=1.2.3.4:8333 feefilter=1sat/kvB ts=1700000000000 dropped=12 \
             [ping_rtt=10 address_announcement=2]"
        );
    }

    /// An event whose oneof is unset, or one carrying a variant this build
    /// does not know: there is nothing to render but the envelope, and
    /// saying so is better than an empty line.
    #[test]
    fn test_an_unset_event_renders_the_envelope() {
        let mut unset = event(peer_event::Event::FeeFilter(FeeFilter {
            feerate_sat_per_kvb: 1,
        }));
        unset.event = None;
        assert_eq!(event_line(&unset), "unknown event from 1.2.3.4:8333");
    }

    /// A transport that was never settled on, because the attempt failed
    /// while still detecting.
    #[test]
    fn test_an_undetected_transport() {
        let mut event = event(peer_event::Event::ConnectionResult(ConnectionResult {
            result: Some(R::Failed(Failed {
                reason: FailureReason::ConnectionRefused as i32,
                setup_ms: 10,
            })),
        }));
        event.transport_version = None;
        assert!(event_line(&event).contains("transport=detecting"));
    }

    // ── Arbitrary input ─────────────────────────────────────────────────────
    //
    // An event reaches this code off a NATS subject or out of an archive, and
    // in both cases it is bytes somebody else wrote. The cases above each fix
    // one shape; these say what has to hold for whatever arrives.

    fn edge_u64(rng: &mut Rng) -> u64 {
        *rng.pick(&[0, 1, 37, u64::MAX, u64::MAX / 2, 1_700_000_000_000])
    }

    fn edge_i64(rng: &mut Rng) -> i64 {
        *rng.pick(&[0, 1, -1, i64::MIN, i64::MAX, 1_700_000_000])
    }

    fn edge_u32(rng: &mut Rng) -> u32 {
        *rng.pick(&[0, 1, u32::MAX, u32::MAX / 2])
    }

    fn edge_i32(rng: &mut Rng) -> i32 {
        *rng.pick(&[0, 1, -1, i32::MIN, i32::MAX])
    }

    /// Strings of the kind that break whatever reads the line afterwards.
    fn edge_string(rng: &mut Rng) -> String {
        let choice: &&str = rng.pick(&[
            "",
            "/Satoshi:29.0.0/",
            "\"",
            "\\",
            "\r\n",
            "\n",
            "\0",
            "a,b",
            "👍",
        ]);
        if rng.one_in(8) {
            choice.repeat(40)
        } else {
            (*choice).to_owned()
        }
    }

    fn edge_tcp(rng: &mut Rng) -> Option<TcpStats> {
        if rng.one_in(3) {
            return None;
        }
        let maybe = |rng: &mut Rng| {
            if rng.one_in(2) {
                None
            } else {
                Some(edge_u32(rng))
            }
        };
        Some(TcpStats {
            srtt_us: edge_u32(rng),
            rttvar_us: edge_u32(rng),
            total_retrans: edge_u32(rng),
            snd_cwnd: edge_u32(rng),
            min_rtt_us: maybe(rng),
            lost: maybe(rng),
            reordering: maybe(rng),
            delivery_rate: if rng.one_in(2) {
                None
            } else {
                Some(edge_u64(rng))
            },
            bytes_received: if rng.one_in(2) {
                None
            } else {
                Some(edge_u64(rng))
            },
        })
    }

    /// An event of a random kind with every field at an edge.
    fn edge_event(rng: &mut Rng) -> PeerEvent {
        use crate::events::connection_result::{Disconnected, Failed, OurFault, Result as R};
        use crate::events::{
            AddressAnnouncement, BlockAnnouncement, CompactBlockProbe, CompactBlockShape,
            ConnectionResult, DroppedEvents, FeeFilter, GossipedAddress, Handshake, PingRtt,
            SendCmpct,
        };

        let inner = match rng.below(9) {
            0 => Some(peer_event::Event::Handshake(Handshake {
                protocol_version: edge_u32(rng),
                services: edge_u64(rng),
                start_height: edge_i32(rng),
                relay: rng.one_in(2),
                peer_timestamp: edge_i64(rng),
                addr_recv: edge_string(rng),
                sendaddrv2: rng.one_in(2),
                wtxid_relay: rng.one_in(2),
                user_agent: edge_string(rng),
                nonce: edge_u64(rng),
            })),
            1 => Some(peer_event::Event::PingRtt(PingRtt {
                rtt_ms: edge_u64(rng),
                tcp_stats: edge_tcp(rng),
            })),
            2 => Some(peer_event::Event::BlockAnnouncement(BlockAnnouncement {
                block_hash: edge_string(rng),
                announcement_type: edge_i32(rng),
                tcp_stats: edge_tcp(rng),
                batch_size: edge_u32(rng),
                height: if rng.one_in(2) {
                    None
                } else {
                    Some(edge_u32(rng))
                },
                new_to_us: rng.one_in(2),
                compact_block: if rng.one_in(2) {
                    None
                } else {
                    Some(CompactBlockShape {
                        short_ids: edge_u32(rng),
                        prefilled_txs: edge_u32(rng),
                    })
                },
                unplaced: if rng.one_in(2) {
                    None
                } else {
                    Some(edge_i32(rng))
                },
            })),
            3 => Some(peer_event::Event::CompactBlockProbe(CompactBlockProbe {
                block_hash: edge_string(rng),
                stage: edge_i32(rng),
                tcp_stats: edge_tcp(rng),
            })),
            4 => Some(peer_event::Event::FeeFilter(FeeFilter {
                feerate_sat_per_kvb: edge_u64(rng),
            })),
            5 => Some(peer_event::Event::SendCmpct(SendCmpct {
                high_bandwidth: rng.one_in(2),
                version: edge_u64(rng),
            })),
            6 => Some(peer_event::Event::AddressAnnouncement(
                AddressAnnouncement {
                    message: edge_i32(rng),
                    unparsed: edge_u32(rng),
                    addresses: (0..rng.below(4))
                        .map(|_| GossipedAddress {
                            addr: edge_string(rng),
                            services: edge_u64(rng),
                            ntime: edge_u32(rng),
                        })
                        .collect(),
                    solicited: rng.one_in(2),
                    rate_limited: edge_u32(rng),
                    rate_limit_tokens: *rng.pick(&[0.0, -1.0, f64::MAX, f64::NAN, 0.25]),
                },
            )),
            7 => Some(peer_event::Event::ConnectionResult(ConnectionResult {
                result: match rng.below(4) {
                    0 => Some(R::Disconnected(Disconnected {
                        setup_ms: edge_u64(rng),
                        uptime_ms: edge_u64(rng),
                        reason: edge_i32(rng),
                        messages_by_command: (0..rng.below(3))
                            .map(|_| (edge_string(rng), edge_u32(rng)))
                            .collect(),
                        messages_other: edge_u32(rng),
                        unsolicited_pongs: edge_u32(rng),
                        undecodable: edge_u32(rng),
                        getheaders_ignored: edge_u32(rng),
                    })),
                    1 => Some(R::Failed(Failed {
                        reason: edge_i32(rng),
                        setup_ms: edge_u64(rng),
                    })),
                    2 => Some(R::OurFault(OurFault {
                        reason: edge_i32(rng),
                        setup_ms: edge_u64(rng),
                    })),
                    _ => None,
                },
            })),
            _ => None,
        };

        PeerEvent {
            peer_addr: edge_string(rng),
            connection_id: edge_u64(rng),
            user_agent: edge_string(rng),
            transport_version: if rng.one_in(3) {
                None
            } else {
                Some(edge_u32(rng))
            },
            timestamp_ms: edge_u64(rng),
            instance_id: edge_u64(rng),
            dropped_events: edge_u64(rng),
            dropped_by_kind: if rng.one_in(2) {
                None
            } else {
                Some(DroppedEvents {
                    ping_rtt: edge_u64(rng),
                    block_announcement: edge_u64(rng),
                    address_announcement: edge_u64(rng),
                    connection_result: edge_u64(rng),
                    handshake: edge_u64(rng),
                    compact_block_probe: edge_u64(rng),
                    fee_filter: edge_u64(rng),
                    send_cmpct: edge_u64(rng),
                })
            },
            event: inner,
        }
    }

    /// Every field at an edge, in every kind of event, rendered.
    ///
    /// These numbers are a peer's to choose and the line does arithmetic on
    /// them -- which is how the handshake line came to overflow a subtraction
    /// on a version message carrying `i64::MIN`. One case of that was found by
    /// reading; this is the shape of test that finds the next one.
    #[test]
    fn test_every_field_at_an_edge_still_renders() {
        for seed in 0..20_000u64 {
            let mut rng = Rng::new(seed);
            let event = edge_event(&mut rng);
            let line = event_line(&event);
            assert!(!line.is_empty(), "seed {seed} rendered nothing");
        }
    }

    /// A rendered line is one line.
    ///
    /// The caller prefixes it and writes it out, and whatever reads the log
    /// afterwards splits on newlines: a line that is secretly two is a forged
    /// record. Several fields are printed raw rather than through `Debug`,
    /// and while the observer is the one that formats them today, an archive
    /// or a NATS subject is not something this code gets to vouch for.
    #[test]
    fn test_a_rendered_line_is_one_line() {
        for seed in 0..20_000u64 {
            let mut rng = Rng::new(seed);
            let event = edge_event(&mut rng);
            let line = event_line(&event);
            assert!(
                !line.contains('\n') && !line.contains('\r'),
                "seed {seed} rendered {} lines: {line:?}",
                line.split(['\n', '\r']).count()
            );
        }
    }

    /// Bytes nobody wrote on purpose, decoded as an event and rendered.
    ///
    /// Most are refused by the decoder; protobuf is permissive enough that
    /// plenty are not, and those carry whatever the encoding allowed.
    #[test]
    fn test_arbitrary_bytes_that_decode_as_an_event_render() {
        let mut rng = Rng::new(99);
        let mut decoded = 0;
        for _ in 0..20_000 {
            let len = rng.below(64);
            let bytes = rng.bytes(len);
            if let Ok(event) = PeerEvent::decode(&bytes[..]) {
                decoded += 1;
                assert!(!event_line(&event).is_empty());
            }
        }
        // Or the assertion above is about nothing. Most random bytes are not a
        // protobuf message; a couple of hundred that are is plenty to be
        // rendering something.
        assert!(
            decoded > 200,
            "only {decoded} of 20000 inputs decoded as an event"
        );
    }
}
