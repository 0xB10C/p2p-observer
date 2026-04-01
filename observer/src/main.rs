use common::{tokio, tracing, tracing_subscriber};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

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
mod logging;
mod protocol;
mod settings;
mod transport;

#[tokio::main]
async fn main() {
    let cfg = settings::Config::load().expect("failed to load config");
    let magic = cfg.magic().expect("invalid network in config");
    let session_cfg = protocol::SessionConfig {
        ping_interval: common::tokio::time::Duration::from_secs(cfg.ping_interval_secs),
        user_agent: cfg.user_agent.clone(),
    };

    let filter = tracing_subscriber::EnvFilter::new(cfg.log_levels.to_filter_string());
    tracing_subscriber::fmt()
        .with_target(true)
        .fmt_fields(logging::PlainFields)
        .with_env_filter(filter)
        .init();

    let store = init_store(&cfg);

    let (status_tx, status_rx) = tokio::sync::mpsc::channel(256);
    let (new_addr_tx, new_addr_rx) = tokio::sync::mpsc::channel(256);

    tokio::spawn(addresses::run(store.clone(), status_rx, new_addr_rx));

    run_loop(&store, magic, session_cfg, status_tx, new_addr_tx).await;

    if let Err(e) = store.lock().unwrap().save() {
        tracing::warn!(target: TARGET_MAIN, "failed to persist address store on shutdown: {e}");
    }
}

fn init_store(cfg: &settings::Config) -> Arc<Mutex<addresses::AddrStore>> {
    let store_path = Path::new("addresses.json");
    let store = Arc::new(Mutex::new(
        addresses::AddrStore::load(store_path).expect("failed to load address store"),
    ));
    let addrs: Vec<_> = cfg
        .bootstrap_addrs
        .iter()
        .filter_map(|s| addresses::parse_addr(s))
        .collect();
    store.lock().unwrap().insert_batch(addrs);
    store
}

async fn run_loop(
    store: &Arc<Mutex<addresses::AddrStore>>,
    magic: common::p2p::Magic,
    session_cfg: protocol::SessionConfig,
    status_tx: tokio::sync::mpsc::Sender<addresses::StatusUpdate>,
    new_addr_tx: tokio::sync::mpsc::Sender<Vec<addresses::NetAddr>>,
) {
    let mut connect_timer = tokio::time::interval(tokio::time::Duration::from_secs(1));
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
                    let cfg = session_cfg.clone();
                    task_handles.push((addr, tokio::spawn(async move {
                        connection::connect_with_retry(a, magic, cfg, status_tx, new_addr_tx).await;
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
}
