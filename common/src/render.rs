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
    AddrMessage, AnnouncementType, DisconnectReason, PeerEvent, TcpStats, peer_event,
};

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
fn tcp(stats: Option<&TcpStats>) -> String {
    stats
        .map(|t| {
            format!(
                " srtt={}µs rttvar={}µs retrans={} cwnd={}",
                t.srtt_us, t.rttvar_us, t.total_retrans, t.snd_cwnd
            )
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
                format!(" sees_us={}", hs.addr_recv)
            };
            format!(
                "conn={} peer={} ua={:?} transport={} version={} services={:#x} height={} \
                 relay={} skew={}s addrv2={} wtxidrelay={}{addr_recv} ts={}",
                event.connection_id,
                event.peer_addr,
                hs.user_agent,
                transport(event.transport_version),
                hs.protocol_version,
                hs.services,
                hs.start_height,
                hs.relay,
                // The peer's clock against ours, which is what anyone reading
                // the raw pair would work out first.
                hs.peer_timestamp - (event.timestamp_ms / 1000) as i64,
                hs.sendaddrv2,
                hs.wtxid_relay,
                event.timestamp_ms,
            )
        }
        Some(peer_event::Event::PingRtt(ping)) => format!(
            "conn={} peer={} ua={:?} transport={} rtt={}ms{} ts={}",
            event.connection_id,
            event.peer_addr,
            event.user_agent,
            transport(event.transport_version),
            ping.rtt_ms,
            tcp(ping.tcp_stats.as_ref()),
            event.timestamp_ms,
        ),
        Some(peer_event::Event::BlockAnnouncement(blk)) => {
            let atype = AnnouncementType::try_from(blk.announcement_type)
                .unwrap_or(AnnouncementType::Unknown);
            let rtt = blk
                .rtt_ms
                .map(|r| format!(" rtt={r}ms"))
                .unwrap_or_default();
            format!(
                "conn={} peer={} block={} type={:?}{rtt}{} ts={}",
                event.connection_id,
                event.peer_addr,
                blk.block_hash,
                atype,
                tcp(blk.tcp_stats.as_ref()),
                event.timestamp_ms,
            )
        }
        Some(peer_event::Event::AddressAnnouncement(ann)) => {
            // Shown only when non-zero, which is almost never.
            let unparsed = if ann.unparsed > 0 {
                format!(" unparsed={}", ann.unparsed)
            } else {
                String::new()
            };
            let message = AddrMessage::try_from(ann.message).unwrap_or(AddrMessage::Unknown);
            format!(
                "conn={} peer={} message={message:?} addresses={}{unparsed} ts={}",
                event.connection_id,
                event.peer_addr,
                ann.addresses.len(),
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
                    let reason =
                        DisconnectReason::try_from(d.reason).unwrap_or(DisconnectReason::Unknown);
                    // Ordered by count so the line opens with what the session
                    // was mostly doing; the full map is in the archive.
                    let mut by_command: Vec<_> = d.messages_by_command.iter().collect();
                    by_command.sort_by(|a, b| b.1.cmp(a.1).then(a.0.cmp(b.0)));
                    let messages: Vec<String> = by_command
                        .iter()
                        .take(5)
                        .map(|(cmd, n)| format!("{cmd}={n}"))
                        .collect();
                    let unsolicited = if d.unsolicited_pongs > 0 {
                        format!(" unsolicited_pongs={}", d.unsolicited_pongs)
                    } else {
                        String::new()
                    };
                    format!(
                        "result=disconnected reason={reason:?} setup={}ms uptime={}ms{unsolicited} msgs=[{}]",
                        d.setup_ms,
                        d.uptime_ms,
                        messages.join(" "),
                    )
                }
                Some(R::Failed(f)) => {
                    let reason =
                        FailureReason::try_from(f.reason).unwrap_or(FailureReason::Unknown);
                    format!("result=failed reason={reason:?} setup={}ms", f.setup_ms)
                }
                Some(R::OurFault(o)) => {
                    let reason =
                        OurFaultReason::try_from(o.reason).unwrap_or(OurFaultReason::Unknown);
                    format!("result=our_fault reason={reason:?} setup={}ms", o.setup_ms)
                }
                None => "result=unset".to_owned(),
            };
            format!(
                "conn={} peer={} ua={:?} {detail} transport={} ts={}",
                event.connection_id,
                event.peer_addr,
                event.user_agent,
                transport(event.transport_version),
                event.timestamp_ms,
            )
        }
        // An event whose oneof is unset, or one carrying a variant this build
        // does not know about. Either way there is nothing to render but the
        // envelope.
        None => format!("unknown event from {}", event.peer_addr),
    };

    // Shown only when something has been lost, so the usual line is unchanged
    // -- but shown on every kind of event, because the loss it reports is not
    // confined to the kind that happens to be carrying the count.
    if event.dropped_events > 0 {
        format!("{line} dropped={}", event.dropped_events)
    } else {
        line
    }
}
