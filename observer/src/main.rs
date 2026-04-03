use common::{tokio, tracing, tracing_subscriber};
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) const TARGET_CONNECTION: &str = "connection";
pub(crate) const TARGET_PROTOCOL: &str = "protocol";
pub(crate) const TARGET_ADDRESSES: &str = "addresses";
pub(crate) const TARGET_MAIN: &str = "main";
pub(crate) const TARGET_PUBLISHER: &str = "publisher";
pub(crate) const TARGET_RPC: &str = "rpc";
pub(crate) const TARGET_HEADERTREE: &str = "headertree";

use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};

/// Number of connection tasks currently running (connecting, retrying, or in message loop).
pub(crate) static ACTIVE_TASKS: AtomicUsize = AtomicUsize::new(0);
/// Number of connections that have completed the handshake and are in the main message loop.
pub(crate) static IN_MESSAGE_LOOP: AtomicUsize = AtomicUsize::new(0);

mod addresses;
mod connection;
mod headertree;
mod logging;
mod protocol;
mod publisher;
mod rpc;
mod settings;
mod transport;

#[tokio::main]
async fn main() {
    let cfg = settings::Config::load().expect("failed to load config");
    let magic = cfg.magic().expect("invalid network in config");
    let params = common::bitcoin::network::Params::new(
        common::bitcoin::Network::try_from(magic).expect("invalid magic for network params"),
    );

    let filter = tracing_subscriber::EnvFilter::new(cfg.log_levels.to_filter_string());
    tracing_subscriber::fmt()
        .with_target(true)
        .fmt_fields(logging::PlainFields)
        .with_env_filter(filter)
        .init();

    cfg.log_settings();

    let store = init_store(&cfg);

    let header_path = format!("headers-{}.bin", cfg.network);
    let header_tree = Arc::new(RwLock::new(
        headertree::HeaderTree::load(Path::new(&header_path), params)
            .expect("failed to load header tree"),
    ));

    let (status_tx, status_rx) = tokio::sync::mpsc::channel(256);
    let (new_addr_tx, new_addr_rx) = tokio::sync::mpsc::channel(256);

    tokio::spawn(addresses::run(store.clone(), status_rx, new_addr_rx));

    let nats = common::async_nats::connect(&cfg.nats_url)
        .await
        .expect("failed to connect to NATS");
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<common::events::PeerEvent>(1024);
    tokio::spawn(publisher::run(nats.clone(), cfg.network.clone(), event_rx));
    tokio::spawn(rpc::Rpc::new(nats, &cfg.network, store.clone()).run());
    tokio::spawn(headertree::persist_task(
        header_tree.clone(),
        header_path.clone().into(),
    ));

    // Bootstrap sync: connect to bootstrap peers sequentially to sync headers first.
    let bootstrap_addrs: Vec<_> = cfg
        .bootstrap_addrs
        .iter()
        .filter_map(|s| addresses::parse_addr(s))
        .collect();

    bootstrap_sync(
        &bootstrap_addrs,
        magic,
        &cfg,
        &header_tree,
        &event_tx,
        &status_tx,
        &new_addr_tx,
    )
    .await;

    let proto_cfg = protocol::Config {
        magic,
        ping_interval: common::tokio::time::Duration::from_secs(cfg.ping_interval_secs),
        user_agent: cfg.user_agent.clone(),
        event_tx,
        header_tree: header_tree.clone(),
        sync_headers: false,
    };

    run_loop(&store, cfg, proto_cfg, status_tx, new_addr_tx).await;

    if let Err(e) = header_tree.write().unwrap().save(Path::new(&header_path)) {
        tracing::warn!(target: TARGET_MAIN, "failed to persist header tree on shutdown: {e}");
    }
    if let Err(e) = store.lock().unwrap().save() {
        tracing::warn!(target: TARGET_MAIN, "failed to persist address store on shutdown: {e}");
    }
}

async fn bootstrap_sync(
    bootstrap_addrs: &[addresses::PeerAddr],
    magic: common::p2p::Magic,
    cfg: &settings::Config,
    header_tree: &Arc<RwLock<headertree::HeaderTree>>,
    event_tx: &tokio::sync::mpsc::Sender<common::events::PeerEvent>,
    status_tx: &tokio::sync::mpsc::Sender<addresses::StatusUpdate>,
    new_addr_tx: &tokio::sync::mpsc::Sender<Vec<addresses::PeerAddr>>,
) {
    if bootstrap_addrs.is_empty() {
        tracing::warn!(target: TARGET_MAIN, "no bootstrap peers configured, skipping header sync");
        return;
    }

    let sync_cfg = protocol::Config {
        magic,
        ping_interval: common::tokio::time::Duration::from_secs(cfg.ping_interval_secs),
        user_agent: cfg.user_agent.clone(),
        event_tx: event_tx.clone(),
        header_tree: header_tree.clone(),
        sync_headers: true,
    };

    loop {
        for peer in bootstrap_addrs {
            tracing::info!(target: TARGET_MAIN, addr = %peer.addr, "bootstrap sync: trying peer");
            let mut conn = connection::Connection::new(
                sync_cfg.clone(),
                status_tx.clone(),
                new_addr_tx.clone(),
                peer.clone(),
            );
            match conn.try_connect().await {
                Ok(_) => {
                    tracing::info!(target: TARGET_MAIN, "bootstrap header sync complete");
                    return;
                }
                Err(e) => {
                    if e.is::<protocol::SyncComplete>() {
                        tracing::info!(target: TARGET_MAIN, "bootstrap header sync complete");
                        return;
                    }
                    tracing::warn!(target: TARGET_MAIN, addr = %peer.addr, "bootstrap sync failed: {e:#}");
                }
            }
        }
        tracing::warn!(target: TARGET_MAIN, "all bootstrap peers failed, retrying in 10s");
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
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
                    manual = s.manual_len(),
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
