//! The observer, as a library.
//!
//! The binary is a few lines over [`run`], which is what lets the whole thing
//! be started inside a test: the wiring between the address manager, the
//! connection tasks, the header tree and the publisher is only ever exercised
//! by starting it, and a unit test of any one of those parts cannot see a
//! channel plugged into the wrong end.

use common::{tokio, tracing, tracing_subscriber};
use std::future::Future;
use std::sync::{Arc, RwLock};

pub(crate) const TARGET_CONNECTION: &str = "connection";
pub(crate) const TARGET_PROTOCOL: &str = "protocol";
pub(crate) const TARGET_MAIN: &str = "main";
pub(crate) const TARGET_PUBLISHER: &str = "publisher";
pub(crate) const TARGET_RPC: &str = "rpc";
pub(crate) const TARGET_HEADERTREE: &str = "headertree";
pub(crate) const TARGET_ADDRMAN: &str = "addrman";

mod addresses;
mod connection;
mod connections;
mod emit;
mod fdlimit;
mod headertree;
mod logging;
#[cfg(test)]
mod misbehaving;
mod protocol;
mod publisher;
mod rpc;
pub mod settings;
mod tcp;
mod transport;

use addresses::book::EnabledNets;
use addresses::peer_addr::PeerAddr;

pub use settings::Config;

/// The internals the benchmarks in `benches/` measure.
///
/// A benchmark is a separate crate and can only see what is public, and the
/// things worth measuring here -- the address book at the size it reaches, the
/// header tree at the height mainnet is at -- are deliberately not. Behind a
/// feature rather than simply public, so that an ordinary build exposes
/// nothing it does not have to.
#[cfg(feature = "bench")]
pub mod bench_api {
    pub use crate::addresses::banlist::Banlist;
    pub use crate::addresses::book::{Book, EnabledNets, Gossiped};
    pub use crate::addresses::peer_addr::PeerAddr;
    pub use crate::addresses::policy::{Outcome, Reason};
    pub use crate::headertree::{HeaderTree, testing};
}

/// Installs the log subscriber the configuration asks for.
///
/// Separate from [`run`] because a subscriber is process-wide and can only be
/// installed once: the binary does it at startup, and a test either does it
/// itself or does without.
pub fn init_logging(cfg: &Config) {
    let filter = tracing_subscriber::EnvFilter::new(cfg.log_levels.to_filter_string());
    tracing_subscriber::fmt()
        .with_target(true)
        .fmt_fields(logging::PlainFields)
        .with_env_filter(filter)
        .init();
}

/// Runs the observer until `shutdown` resolves, then writes its state out.
///
/// Returning is part of what this promises: the address book and the header
/// tree are on disk by the time it does, which is the only reason the caller
/// is handed a future to stop it with rather than the process being killed.
pub async fn run(cfg: Config, shutdown: impl Future<Output = ()>) {
    let magic = cfg.magic().expect("invalid network in config");
    let network =
        common::bitcoin::Network::try_from(magic).expect("invalid magic for network params");
    let params = common::bitcoin::network::Params::new(network);
    let checkpoints = headertree::merge_checkpoints(
        headertree::builtin_checkpoints(network),
        cfg.checkpoints().expect("invalid checkpoint in config"),
    );

    cfg.log_settings();

    // Before anything opens a socket: the descriptor limit is what bounds how
    // many peers we can hold, see [`fdlimit`].
    fdlimit::prepare(cfg.addrman.max_dialing).expect("not enough file descriptors");

    // One directory per network, created up front. Every loader below reads a
    // missing file as "no state yet" and starts empty, so the directory is the
    // only thing that has to be there.
    let datadir = cfg.network_dir();
    std::fs::create_dir_all(&datadir).expect("failed to create the data directory");

    let header_path = datadir.join("headers.bin");
    let checkpoint_heights: Vec<u32> = checkpoints.iter().map(|c| c.height).collect();
    let header_tree = Arc::new(RwLock::new(
        headertree::HeaderTree::load(&header_path, params, checkpoints)
            .expect("failed to load header tree"),
    ));
    tracing::info!(target: TARGET_MAIN,
        checkpoints = ?checkpoint_heights,
        reached = ?header_tree.read().unwrap().reached_checkpoint(),
        "checkpoints"
    );

    let nats = common::async_nats::connect(&cfg.nats_url)
        .await
        .expect("failed to connect to NATS");
    let (event_tx, event_rx) =
        tokio::sync::mpsc::channel::<common::events::PeerEvent>(emit::EVENT_QUEUE);
    let publisher = tokio::spawn(publisher::run(nats.clone(), cfg.network.clone(), event_rx));
    let persist = tokio::spawn(headertree::persist_task(
        header_tree.clone(),
        header_path.clone(),
    ));

    // The handle has to exist before the dialer, which needs one for every
    // connection task, and the manager needs the dialer.
    let (addrman, gossip_rx, life_rx, cmd_rx) = addresses::channels();

    // Not persisted and not published: what is connected right now, for the
    // RPC to answer, since no event can say it after the fact. Made here
    // because both the RPC below and every connection task need it, the
    // bootstrap sync included.
    let connections = connections::Registry::new();

    let rpc_task = tokio::spawn(
        rpc::Rpc::new(
            nats,
            &cfg.network,
            addrman.clone(),
            header_tree.clone(),
            connections.clone(),
        )
        .run(),
    );

    let bootstrap: Vec<PeerAddr> = cfg
        .bootstrap_addrs
        .iter()
        .filter_map(|s| match PeerAddr::parse_ip(s) {
            Some(addr) => Some(addr),
            None => {
                tracing::warn!(target: TARGET_MAIN, addr = %s, "ignoring unparseable bootstrap address");
                None
            }
        })
        .collect();

    // Sync headers from the bootstrap peers before the manager starts
    // dialling, so block announcements can be placed against a known chain
    // from the first connection. This path deliberately bypasses the manager:
    // it is sequential, it must see its own errors, and it has no business
    // influencing retry scheduling.
    bootstrap_sync(
        &bootstrap,
        magic,
        &cfg,
        &header_tree,
        &event_tx,
        &addrman,
        &connections,
    )
    .await;

    let proto_cfg = protocol::Config {
        magic,
        ping_interval: common::tokio::time::Duration::from_secs(cfg.ping_interval_secs),
        probe_compact_blocks: cfg.probe_compact_blocks,
        user_agent: cfg.user_agent.clone(),
        event_tx,
        header_tree: header_tree.clone(),
        connections: connections.clone(),
        sync_headers: false,
        networks: cfg.networks.clone(),
    };

    let dialer = connection::TaskDialer {
        cfg: proto_cfg,
        addrman: addrman.clone(),
    };

    let mut manager = addresses::Manager::new(
        addresses::Config {
            dials_per_tick: cfg.connections_per_second as usize,
            max_dialing: cfg.addrman.max_dialing,
            capacity: cfg.addrman.capacity,
            nets: enabled_nets(&cfg.networks),
            snapshot_path: datadir.join("addresses.bin"),
            banlist_path: datadir.join("banlist.json"),
        },
        dialer,
    )
    // A bad ban list is fatal on purpose: it is operator intent, and quietly
    // dialling addresses we were told never to dial is worse than not
    // starting. A bad address snapshot is not fatal -- see addresses::persist.
    .expect("failed to start the address manager");

    let seeded = manager.add_manual(addresses::unix_now(), &bootstrap);
    tracing::info!(target: TARGET_MAIN, seeded, "seeded bootstrap addresses");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let manager_task = tokio::spawn(manager.run(gossip_rx, life_rx, cmd_rx, shutdown_rx));

    // SIGINT or SIGTERM: either way the address book and the header tree get
    // written before the process goes.
    shutdown.await;
    tracing::info!(target: TARGET_MAIN, "shutting down");

    // Let the manager write its snapshot before the process goes away.
    let _ = shutdown_tx.send(());
    if let Err(e) = manager_task.await {
        tracing::warn!(target: TARGET_MAIN, "the address manager did not shut down cleanly: {e}");
    }

    // Nothing else may be writing the file while the final save runs.
    persist.abort();
    if let Err(e) = header_tree.write().unwrap().save(&header_path) {
        tracing::warn!(target: TARGET_MAIN, "failed to persist the header tree on shutdown: {e}");
    }

    // Returning has to mean the observer has stopped serving, not just that
    // its state is safe: whoever called this may start another one, and two
    // RPC tasks answering on the same subject answer differently. The
    // publisher cannot be waited out instead -- the connection tasks still
    // hold senders on its channel, and a quiet peer holds one for as long as
    // it stays quiet.
    rpc_task.abort();
    publisher.abort();
}

fn enabled_nets(nets: &settings::NetworksConfig) -> EnabledNets {
    EnabledNets {
        ipv4: nets.ipv4.enabled,
        ipv6: nets.ipv6.enabled,
        tor: nets.tor.enabled,
        cjdns: nets.cjdns.enabled,
        i2p: nets.i2p.enabled,
    }
}

async fn bootstrap_sync(
    bootstrap: &[PeerAddr],
    magic: common::p2p::Magic,
    cfg: &settings::Config,
    header_tree: &Arc<RwLock<headertree::HeaderTree>>,
    event_tx: &tokio::sync::mpsc::Sender<common::events::PeerEvent>,
    addrman: &addresses::Handle,
    connections: &Arc<connections::Registry>,
) {
    if bootstrap.is_empty() {
        tracing::warn!(target: TARGET_MAIN, "no bootstrap peers configured, skipping header sync");
        return;
    }

    let sync_cfg = protocol::Config {
        magic,
        ping_interval: common::tokio::time::Duration::from_secs(cfg.ping_interval_secs),
        probe_compact_blocks: cfg.probe_compact_blocks,
        user_agent: cfg.user_agent.clone(),
        event_tx: event_tx.clone(),
        header_tree: header_tree.clone(),
        connections: connections.clone(),
        sync_headers: true,
        networks: cfg.networks.clone(),
    };

    loop {
        for addr in bootstrap {
            tracing::info!(target: TARGET_MAIN, %addr, "bootstrap sync: trying peer");
            match connection::bootstrap_attempt(*addr, &sync_cfg, addrman).await {
                Ok(_) => {
                    tracing::info!(target: TARGET_MAIN, "bootstrap header sync complete");
                    return;
                }
                Err(e) => {
                    // The session signals a finished sync by erroring with
                    // SyncComplete, which is a success for our purposes.
                    if e.is::<protocol::SyncComplete>()
                        || e.chain().any(|c| c.is::<protocol::SyncComplete>())
                    {
                        tracing::info!(target: TARGET_MAIN, "bootstrap header sync complete");
                        return;
                    }
                    tracing::warn!(target: TARGET_MAIN, %addr, "bootstrap sync failed: {e:#}");
                }
            }
        }
        tracing::warn!(target: TARGET_MAIN, "all bootstrap peers failed, retrying in 10s");
        tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;
    }
}
