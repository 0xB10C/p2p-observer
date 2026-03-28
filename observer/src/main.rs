use common::{tokio, tracing, tracing_subscriber};

mod connection;
mod peer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::DEBUG)
        .init();

    let peers = [
        "95.217.75.216:8333",
        "37.205.15.108:8333",
        "95.217.75.216:8333",
    ];

    let handles: Vec<_> = peers
        .iter()
        .map(|&addr| {
            tokio::spawn(async move {
                connection::connect_with_retry(addr).await;
            })
        })
        .collect();

    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl+c");
    tracing::info!("shutting down");

    for h in handles {
        h.abort();
    }
}
