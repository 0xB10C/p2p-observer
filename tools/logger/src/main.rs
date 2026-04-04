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

fn print_event(subject: &str, event: &PeerEvent) {
    match &event.event {
        Some(peer_event::Event::PingRtt(ping)) => {
            println!(
                "[{subject}] conn={} peer={} ua={:?} transport=v{} rtt={}ms ts={}",
                event.connection_id,
                event.peer_addr,
                event.user_agent,
                event.transport_version,
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
            println!(
                "[{subject}] conn={} peer={} block={} type={:?}{rtt} ts={}",
                event.connection_id, event.peer_addr, blk.block_hash, atype, event.timestamp_ms,
            );
        }
        None => {
            println!("[{subject}] unknown event from {}", event.peer_addr);
        }
    }
}
