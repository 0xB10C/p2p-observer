use common::{p2p::Magic, tokio, tracing, tracing_subscriber};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

const MAGIC: Magic = Magic::SIGNET;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Number of connection tasks currently running (connecting, retrying, or in message loop).
pub(crate) static ACTIVE_TASKS: AtomicUsize = AtomicUsize::new(0);
/// Number of connections that have completed the handshake and are in the main message loop.
pub(crate) static IN_MESSAGE_LOOP: AtomicUsize = AtomicUsize::new(0);

mod addresses;
mod connection;
mod protocol;
mod transport;

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
    let mut active_addrs: HashSet<addresses::NetAddr> = HashSet::new();
    let mut task_handles: Vec<(addresses::NetAddr, tokio::task::JoinHandle<()>)> = Vec::new();

    loop {
        tokio::select! {
            _ = connect_timer.tick() => {
                // Reap finished tasks.
                task_handles.retain(|(addr, handle)| {
                    if handle.is_finished() {
                        active_addrs.remove(addr);
                        false
                    } else {
                        true
                    }
                });

                let active = ACTIVE_TASKS.load(Ordering::Relaxed);
                let connected = IN_MESSAGE_LOOP.load(Ordering::Relaxed);
                let s = store.lock().unwrap();
                tracing::error!(
                    unknown = s.unknown_len(),
                    good = s.good_len(),
                    bad = s.bad_len(),
                    active,
                    connected,
                    "stats"
                );
                let opening = active - connected;
                let max_new = 100usize.saturating_sub(opening);
                let batch = s.get_batch(max_new, &active_addrs);
                drop(s);

                for addr in batch {
                    active_addrs.insert(addr.clone());
                    let status_tx = status_tx.clone();
                    let new_addr_tx = new_addr_tx.clone();
                    let a = addr.clone();
                    task_handles.push((addr, tokio::spawn(async move {
                        connection::connect_with_retry(a, MAGIC, status_tx, new_addr_tx).await;
                    })));
                }
            }
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("shutting down");
                break;
            }
        }
    }

    for (_, h) in task_handles {
        h.abort();
    }
}
