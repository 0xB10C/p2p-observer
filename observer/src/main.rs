use common::{p2p::Magic, tokio, tracing, tracing_subscriber};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

const MAGIC: Magic = Magic::SIGNET;

pub(crate) const TARGET_CONNECTION: &str = "connection";
pub(crate) const TARGET_PROTOCOL: &str = "protocol";
pub(crate) const TARGET_ADDRESSES: &str = "addresses";
pub(crate) const TARGET_MAIN: &str = "main";

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
    let filter = tracing_subscriber::EnvFilter::new(format!(
        "{TARGET_MAIN}=debug,{TARGET_CONNECTION}=info,{TARGET_PROTOCOL}=debug,{TARGET_ADDRESSES}=debug"
    ));
    tracing_subscriber::fmt()
        .with_target(true)
        .with_ansi(false)
        .with_env_filter(filter)
        .init();

    let store_path = Path::new("addresses.json");
    let store = Arc::new(Mutex::new(
        addresses::AddrStore::load(store_path).expect("failed to load address store"),
    ));

    {
        let content =
            std::fs::read_to_string("addresses.txt").expect("failed to read addresses.txt");
        let addrs: Vec<_> = content
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .filter_map(addresses::parse_addr)
            .collect();
        store.lock().unwrap().insert_batch(addrs);
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
                tracing::info!(target: TARGET_MAIN,
                    unknown = s.unknown_len(),
                    good = s.good_len(),
                    bad = s.bad_len(),
                    active,
                    connected,
                    "stats"
                );
                let opening = active.saturating_sub(connected);
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
                tracing::info!(target: TARGET_MAIN, "shutting down");
                break;
            }
        }
    }

    for (_, h) in task_handles {
        h.abort();
    }

    if let Err(e) = store.lock().unwrap().save() {
        tracing::warn!(target: TARGET_MAIN, "failed to persist address store on shutdown: {e}");
    }
}
