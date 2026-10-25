use common::{async_nats, events::PeerEvent, futures_util::StreamExt, prost::Message, render};

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
            Ok(event) => println!("[{}] {}", msg.subject, render::event_line(&event)),
            Err(e) => eprintln!("[{}] failed to decode: {e}", msg.subject),
        }
    }
}
