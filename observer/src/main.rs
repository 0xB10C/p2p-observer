use common::{tokio, tracing, tracing_subscriber};

mod connection;
mod peer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let peers = ["95.217.75.216:8333"];

    let handles: Vec<_> = peers
        .iter()
        .map(|&addr| {
            tokio::spawn(async move {
                if let Err(e) = connection::connect(addr).await {
                    tracing::error!(addr, "connection failed: {e:#}");
                }
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
