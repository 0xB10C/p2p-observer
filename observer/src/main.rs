use common::{tokio, tracing, tracing_subscriber};
use std::path::{Path, PathBuf};
use std::sync::{Arc, RwLock};

pub(crate) const TARGET_CONNECTION: &str = "connection";
pub(crate) const TARGET_PROTOCOL: &str = "protocol";
pub(crate) const TARGET_MAIN: &str = "main";
pub(crate) const TARGET_PUBLISHER: &str = "publisher";
pub(crate) const TARGET_RPC: &str = "rpc";
pub(crate) const TARGET_HEADERTREE: &str = "headertree";
pub(crate) const TARGET_ADDRMAN: &str = "addrman";

mod addrman;
mod connection;
mod headertree;
mod logging;
mod protocol;
mod publisher;
mod rpc;
mod settings;
mod tcp;
mod transport;

use addrman::book::EnabledNets;
use addrman::peer_addr::PeerAddr;

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

    let header_path = format!("headers-{}.bin", cfg.network);
    let header_tree = Arc::new(RwLock::new(
        headertree::HeaderTree::load(Path::new(&header_path), params)
            .expect("failed to load header tree"),
    ));

    let nats = common::async_nats::connect(&cfg.nats_url)
        .await
        .expect("failed to connect to NATS");
    let (event_tx, event_rx) = tokio::sync::mpsc::channel::<common::events::PeerEvent>(1024);
    tokio::spawn(publisher::run(nats.clone(), cfg.network.clone(), event_rx));
    tokio::spawn(headertree::persist_task(
        header_tree.clone(),
        header_path.clone().into(),
    ));

    // The handle has to exist before the dialer, which needs one for every
    // connection task, and the manager needs the dialer.
    let (addrman, gossip_rx, life_rx, cmd_rx) = addrman::channels();

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

    let mut manager = addrman::Manager::new(
        addrman::Config {
            dials_per_tick: cfg.connections_per_second as usize,
            max_dialing: cfg.addrman.max_dialing,
            capacity: cfg.addrman.capacity,
            nets: enabled_nets(&cfg.networks),
            snapshot_path: PathBuf::from(format!("addresses-{}.bin", cfg.network)),
            banlist_path: PathBuf::from(format!("banlist-{}.json", cfg.network)),
        },
        dialer,
    )
    // A bad ban list is fatal on purpose: it is operator intent, and quietly
    // dialling addresses we were told never to dial is worse than not
    // starting. A bad address snapshot is not fatal -- see addrman::persist.
    .expect("failed to start the address manager");

    let seeded = manager.add_manual(addrman::unix_now(), &bootstrap);
    tracing::info!(target: TARGET_MAIN, seeded, "seeded bootstrap addresses");

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let manager_task = tokio::spawn(manager.run(gossip_rx, life_rx, cmd_rx, shutdown_rx));

    match tokio::signal::ctrl_c().await {
        Ok(()) => tracing::info!(target: TARGET_MAIN, "shutting down"),
        Err(e) => tracing::warn!(target: TARGET_MAIN, "could not listen for ctrl-c: {e}"),
    }

    // Let the manager write its snapshot before the process goes away.
    let _ = shutdown_tx.send(());
    if let Err(e) = manager_task.await {
        tracing::warn!(target: TARGET_MAIN, "the address manager did not shut down cleanly: {e}");
    }

    if let Err(e) = header_tree.write().unwrap().save(Path::new(&header_path)) {
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
    addrman: &addrman::Handle,
) {
    if bootstrap.is_empty() {
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
