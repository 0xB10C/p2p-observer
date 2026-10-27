use common::{tokio, tracing, tracing_subscriber};
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
mod emit;
mod headertree;
mod logging;
mod protocol;
mod publisher;
mod rpc;
mod settings;
mod tcp;
mod transport;

use addresses::book::EnabledNets;
use addresses::peer_addr::PeerAddr;

#[tokio::main]
async fn main() {
    let cfg = settings::Config::load().expect("failed to load config");
    let magic = cfg.magic().expect("invalid network in config");
    let network =
        common::bitcoin::Network::try_from(magic).expect("invalid magic for network params");
    let params = common::bitcoin::network::Params::new(network);
    let checkpoints = headertree::merge_checkpoints(
        headertree::builtin_checkpoints(network),
        cfg.checkpoints().expect("invalid checkpoint in config"),
    );

    let filter = tracing_subscriber::EnvFilter::new(cfg.log_levels.to_filter_string());
    tracing_subscriber::fmt()
        .with_target(true)
        .fmt_fields(logging::PlainFields)
        .with_env_filter(filter)
        .init();

    cfg.log_settings();

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
    tokio::spawn(publisher::run(nats.clone(), cfg.network.clone(), event_rx));
    tokio::spawn(headertree::persist_task(
        header_tree.clone(),
        header_path.clone(),
    ));

    // The handle has to exist before the dialer, which needs one for every
    // connection task, and the manager needs the dialer.
    let (addrman, gossip_rx, life_rx, cmd_rx) = addresses::channels();

    tokio::spawn(rpc::Rpc::new(nats, &cfg.network, addrman.clone(), header_tree.clone()).run());

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
    bootstrap_sync(&bootstrap, magic, &cfg, &header_tree, &event_tx, &addrman).await;

    let proto_cfg = protocol::Config {
        magic,
        ping_interval: common::tokio::time::Duration::from_secs(cfg.ping_interval_secs),
        probe_compact_blocks: cfg.probe_compact_blocks,
        user_agent: cfg.user_agent.clone(),
        event_tx,
        header_tree: header_tree.clone(),
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
    common::shutdown::signal().await;
    tracing::info!(target: TARGET_MAIN, "shutting down");

    // Let the manager write its snapshot before the process goes away.
    let _ = shutdown_tx.send(());
    if let Err(e) = manager_task.await {
        tracing::warn!(target: TARGET_MAIN, "the address manager did not shut down cleanly: {e}");
    }

    if let Err(e) = header_tree.write().unwrap().save(&header_path) {
        tracing::warn!(target: TARGET_MAIN, "failed to persist the header tree on shutdown: {e}");
    }
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
