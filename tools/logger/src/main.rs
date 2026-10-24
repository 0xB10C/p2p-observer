use common::{
    async_nats,
    events::{PeerEvent, peer_event},
    futures_util::StreamExt,
    prost::Message,
};

#[tokio::main]
async fn main() {
    let url = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "nats://localhost:4222".to_owned());

    let nats = async_nats::connect(&url)
        .await
        .expect("failed to connect to NATS");
    let mut sub = nats
        .subscribe("p2p-observer.>")
        .await
        .expect("failed to subscribe");

    println!("connected to {url}, listening on p2p-observer.>");

    while let Some(msg) = sub.next().await {
        match PeerEvent::decode(msg.payload.as_ref()) {
            Ok(event) => print_event(&msg.subject, &event),
            Err(e) => eprintln!("[{}] failed to decode: {e}", msg.subject),
        }
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

fn print_event(subject: &str, event: &PeerEvent) {
    match &event.event {
        Some(peer_event::Event::PingRtt(ping)) => {
            let tcp = ping
                .tcp_stats
                .as_ref()
                .map(|t| {
                    format!(
                        " srtt={}µs rttvar={}µs retrans={} cwnd={}",
                        t.srtt_us, t.rttvar_us, t.total_retrans, t.snd_cwnd
                    )
                })
                .unwrap_or_default();
            println!(
                "[{subject}] conn={} peer={} ua={:?} transport={} rtt={}ms{tcp} ts={}",
                event.connection_id,
                event.peer_addr,
                event.user_agent,
                transport(event.transport_version),
                ping.rtt_ms,
                event.timestamp_ms,
            );
        }
        Some(peer_event::Event::BlockAnnouncement(blk)) => {
            let atype = common::events::AnnouncementType::try_from(blk.announcement_type)
                .unwrap_or(common::events::AnnouncementType::Unknown);
            let rtt = blk
                .rtt_ms
                .map(|r| format!(" rtt={r}ms"))
                .unwrap_or_default();
            let tcp = blk
                .tcp_stats
                .as_ref()
                .map(|t| {
                    format!(
                        " srtt={}µs rttvar={}µs retrans={} cwnd={}",
                        t.srtt_us, t.rttvar_us, t.total_retrans, t.snd_cwnd
                    )
                })
                .unwrap_or_default();
            println!(
                "[{subject}] conn={} peer={} block={} type={:?}{rtt}{tcp} ts={}",
                event.connection_id, event.peer_addr, blk.block_hash, atype, event.timestamp_ms,
            );
        }
        Some(peer_event::Event::AddressAnnouncement(ann)) => {
            // Shown only when non-zero, which is almost never.
            let unparsed = if ann.unparsed > 0 {
                format!(" unparsed={}", ann.unparsed)
            } else {
                String::new()
            };
            let message = common::events::AddrMessage::try_from(ann.message)
                .unwrap_or(common::events::AddrMessage::Unknown);
            println!(
                "[{subject}] conn={} peer={} message={message:?} addresses={}{unparsed} ts={}",
                event.connection_id,
                event.peer_addr,
                ann.addresses.len(),
                event.timestamp_ms,
            );
        }
        Some(peer_event::Event::ConnectionResult(res)) => {
            use common::events::connection_result::Result as R;
            // Each variant prints only what applies to it, which is the point
            // of the oneof: no duration that means two things, no failure
            // reason hanging off a success.
            let detail = match &res.result {
                Some(R::Disconnected(d)) => format!(
                    "result=disconnected setup={}ms uptime={}ms",
                    d.setup_ms, d.uptime_ms
                ),
                Some(R::Failed(f)) => {
                    let reason = common::events::FailureReason::try_from(f.reason)
                        .unwrap_or(common::events::FailureReason::Unknown);
                    format!("result=failed reason={reason:?} setup={}ms", f.setup_ms)
                }
                Some(R::OurFault(o)) => {
                    let reason = common::events::OurFaultReason::try_from(o.reason)
                        .unwrap_or(common::events::OurFaultReason::Unknown);
                    format!("result=our_fault reason={reason:?} setup={}ms", o.setup_ms)
                }
                None => "result=unset".to_owned(),
            };
            println!(
                "[{subject}] conn={} peer={} {detail} transport={} ts={}",
                event.connection_id,
                event.peer_addr,
                transport(event.transport_version),
                event.timestamp_ms,
            );
        }
        None => {
            println!("[{subject}] unknown event from {}", event.peer_addr);
        }
    }
}
