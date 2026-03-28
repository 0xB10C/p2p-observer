use common::{tokio, tracing, tracing_subscriber};

mod connection;
mod peer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::TRACE)
        .init();

    let content = std::fs::read_to_string("addresses.txt").expect("failed to read addresses.txt");
    let peers: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect();

    let handles: Vec<_> = peers
        .into_iter()
        .map(|addr| {
            tokio::spawn(async move {
                connection::connect_with_retry(&addr).await;
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
