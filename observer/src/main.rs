use common::{tokio, tracing, tracing_subscriber};
use std::path::Path;
use std::sync::{Arc, Mutex};

mod addresses;
mod connection;
mod peer;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(false)
        .with_max_level(tracing::Level::TRACE)
        .init();

    let store_path = Path::new("addresses.json");
    let store = Arc::new(Mutex::new(
        addresses::AddrStore::load(store_path).expect("failed to load address store"),
    ));

    {
        let content =
            std::fs::read_to_string("addresses.txt").expect("failed to read addresses.txt");
        let mut s = store.lock().unwrap();
        for line in content.lines().map(str::trim).filter(|l| !l.is_empty()) {
            if let Some(addr) = addresses::parse_addr(line) {
                s.insert(addr);
            }
        }
    }

    let (status_tx, status_rx) = tokio::sync::mpsc::channel(256);
    let (new_addr_tx, new_addr_rx) = tokio::sync::mpsc::channel(256);

    tokio::spawn(addresses::run(store.clone(), status_rx, new_addr_rx));

    let mut connect_timer = tokio::time::interval(tokio::time::Duration::from_secs(10));
    let mut task_handles = Vec::new();

    loop {
        tokio::select! {
            _ = connect_timer.tick() => {
                let batch = store.lock().unwrap().get_batch(10);
                for addr in batch {
                    store.lock().unwrap().mark_task_started(&addr);
                    let status_tx = status_tx.clone();
                    let new_addr_tx = new_addr_tx.clone();
                    task_handles.push(tokio::spawn(async move {
                        connection::connect_with_retry(addr, status_tx, new_addr_tx).await;
                    }));
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    for h in task_handles {
        h.abort();
    }
}
