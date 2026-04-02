use common::{tokio, tracing, tracing_subscriber};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) const TARGET_CONNECTION: &str = "connection";
pub(crate) const TARGET_PROTOCOL: &str = "protocol";
pub(crate) const TARGET_ADDRESSES: &str = "addresses";
pub(crate) const TARGET_MAIN: &str = "main";
pub(crate) const TARGET_PUBLISHER: &str = "publisher";

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
mod publisher;
mod settings;
mod transport;

#[tokio::main]
async fn main() {
    let cfg = settings::Config::load().expect("failed to load config");
    let magic = cfg.magic().expect("invalid network in config");

    let filter = tracing_subscriber::EnvFilter::new(cfg.log_levels.to_filter_string());
    tracing_subscriber::fmt()
        .with_target(true)
        .fmt_fields(logging::PlainFields)
        .with_env_filter(filter)
        .init();

    cfg.log_settings();

    let store = init_store(&cfg);

    let (status_tx, status_rx) = tokio::sync::mpsc::channel(256);
    let (new_addr_tx, new_addr_rx) = tokio::sync::mpsc::channel(256);

    tokio::spawn(addresses::run(store.clone(), status_rx, new_addr_rx));

    let nats = common::async_nats::connect(&cfg.nats_url)
        .await
        .expect("failed to connect to NATS");
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<common::events::PeerEvent>(1024);
    tokio::spawn(publisher::run(nats, cfg.network.clone(), event_rx));

    let proto_cfg = protocol::Config {
        magic,
        ping_interval: common::tokio::time::Duration::from_secs(cfg.ping_interval_secs),
        user_agent: cfg.user_agent.clone(),
        event_tx,
    };

    run_loop(&store, cfg, proto_cfg, status_tx, new_addr_tx).await;

    if let Err(e) = store.lock().unwrap().save() {
        tracing::warn!(target: TARGET_MAIN, "failed to persist address store on shutdown: {e}");
    }
}

fn init_store(cfg: &settings::Config) -> Arc<Mutex<addresses::AddrStore>> {
    let filename = format!("addresses-{}.json", cfg.network);
    let store_path = Path::new(&filename);
    let store = Arc::new(Mutex::new(
        addresses::AddrStore::load(store_path).expect("failed to load address store"),
    ));
    let addrs: Vec<_> = cfg
        .bootstrap_addrs
        .iter()
        .filter_map(|s| addresses::parse_addr(s))
        .collect();
    // allow bootstrapping via local addresses
    store.lock().unwrap().insert_batch(addrs, true);
    store
}

async fn run_loop(
    store: &Arc<Mutex<addresses::AddrStore>>,
    cfg: settings::Config,
    proto_cfg: protocol::Config,
    status_tx: tokio::sync::mpsc::Sender<addresses::StatusUpdate>,
    new_addr_tx: tokio::sync::mpsc::Sender<Vec<addresses::PeerAddr>>,
) {
    let mut connect_timer = tokio::time::interval(tokio::time::Duration::from_secs(1));
    let mut active_addrs: HashSet<addresses::PeerAddr> = HashSet::new();
    let mut task_handles: Vec<(addresses::PeerAddr, tokio::task::JoinHandle<()>)> = Vec::new();

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

                let batch = s.get_batch(cfg.connections_per_second as usize, &active_addrs);
                drop(s);

                for addr in batch {
                    active_addrs.insert(addr.clone());
                    let conn = connection::Connection::new(
                        proto_cfg.clone(),
                        status_tx.clone(),
                        new_addr_tx.clone(),
                        addr.clone(),
                    );
                    task_handles.push((addr, tokio::spawn(conn.run())));
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
