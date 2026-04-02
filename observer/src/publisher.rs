use common::{
    async_nats,
    events::{PeerEvent, peer_event},
    prost::Message,
    tokio::sync::mpsc,
    tracing,
};

use crate::TARGET_PUBLISHER as TARGET;

pub(crate) async fn run(
    nats: async_nats::Client,
    network: String,
    mut rx: mpsc::Receiver<PeerEvent>,
) {
    while let Some(event) = rx.recv().await {
        let subject = format!("p2p-observer.{}.{}", network, subject_for(&event));
        let payload = event.encode_to_vec();
        if let Err(e) = nats.publish(subject, payload.into()).await {
            tracing::warn!(target: TARGET, "nats publish failed: {e}");
        }
    }
}

fn subject_for(event: &PeerEvent) -> &'static str {
    match &event.event {
        Some(peer_event::Event::PingRtt(_)) => "ping_rtt",
        None => "unknown",
    }
}
