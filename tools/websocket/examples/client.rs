//! Connects to a running websocket tool, subscribes, and prints what
//! arrives: a way to look at the JSON without a browser.
//!
//! ```sh
//! cargo run -p websocket --example client -- ws://127.0.0.1:47484 '{"handshakes": true}' 3
//! ```

use common::futures_util::{SinkExt, StreamExt};
use common::tokio;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::Message;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let url = args
        .next()
        .unwrap_or_else(|| "ws://127.0.0.1:47484".to_owned());
    let subscriptions = args
        .next()
        .unwrap_or_else(|| r#"{"handshakes": true}"#.to_owned());
    let count: usize = args.next().and_then(|n| n.parse().ok()).unwrap_or(1);

    let (mut ws, _) = connect_async(&url).await.expect("connecting");
    ws.send(Message::text(subscriptions))
        .await
        .expect("sending subscriptions");
    let mut printed = 0;
    while printed < count {
        match ws.next().await {
            Some(Ok(Message::Text(text))) => {
                println!("{text}");
                printed += 1;
            }
            Some(Ok(_)) => {}
            Some(Err(e)) => {
                eprintln!("error: {e}");
                break;
            }
            None => break,
        }
    }
}
