use common::{tokio, tracing, tracing_subscriber};
use std::sync::atomic::{AtomicUsize, Ordering};

pub(crate) const TARGET_CONNECTION: &str = "connection";
pub(crate) const TARGET_PROTOCOL: &str = "protocol";
pub(crate) const TARGET_ADDRESSES: &str = "addresses";
pub(crate) const TARGET_MAIN: &str = "main";
pub(crate) const TARGET_PUBLISHER: &str = "publisher";
pub(crate) const TARGET_RPC: &str = "rpc";
pub(crate) const TARGET_HEADERTREE: &str = "headertree";

/// Number of connection tasks currently running.
pub(crate) static ACTIVE_TASKS: AtomicUsize = AtomicUsize::new(0);
/// Number of connections in the main message loop.
pub(crate) static IN_MESSAGE_LOOP: AtomicUsize = AtomicUsize::new(0);

mod addresses;
mod connection;
mod headertree;
mod logging;
mod protocol;
mod publisher;
mod rpc;
mod settings;
mod tcp;
mod transport;

use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Result of probing a single peer for inbound connection slots.
struct ProbeResult {
    peer_addr: String,
    max_concurrent: usize,
    total_opened: usize,
}

/// Maximum consecutive TCP failures before we skip a peer.
const MAX_TCP_FAILURES: usize = 5;
/// Number of short-lived connections (<2s) that trigger eviction detection.
const EVICTION_COUNT: usize = 3;
/// Connection shorter than this is considered eviction.
const EVICTION_THRESHOLD: Duration = Duration::from_secs(2);
/// Number of peers to probe in parallel.
const PARALLEL_PROBES: usize = 20;
/// Don't spawn new connections if this many are already in-flight.
const MAX_INFLIGHT: usize = 3000;
/// Give up on a peer after this long, even if no eviction detected.
const PROBE_TIMEOUT: Duration = Duration::from_secs(120);

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

    // Collect all good peers to probe.
    let peers: Vec<addresses::PeerAddr> = {
        let s = store.lock().unwrap();
        // get_batch with a huge n and empty active set returns all good peers (after manual).
        let empty = std::collections::HashSet::new();
        s.get_batch(s.good_len() + s.manual_len(), &empty, &cfg.networks)
    };

    tracing::info!(target: TARGET_MAIN, count = peers.len(), "starting inbound slot probe");

    // Open CSV file for results.
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let csv_path = format!("inbound_slots_{}.csv", timestamp);
    let csv_file = File::create(&csv_path).expect("failed to create CSV file");
    let csv_writer = Arc::new(Mutex::new(BufWriter::new(csv_file)));
    {
        let mut w = csv_writer.lock().unwrap();
        writeln!(w, "peer_addr,max_concurrent_connections,total_opened,timestamp").unwrap();
        w.flush().unwrap();
    }
    tracing::info!(target: TARGET_MAIN, path = %csv_path, "CSV file created");

    let proto_cfg = protocol::Config {
        magic,
        ping_interval: common::tokio::time::Duration::from_secs(cfg.ping_interval_secs),
        user_agent: cfg.user_agent.clone(),
        event_tx: event_tx.clone(),
        header_tree: header_tree.clone(),
        sync_headers: false,
        networks: cfg.networks.clone(),
        concurrent_gauge: None,
        peak_gauge: None,
    };

    // Process peers in chunks of PARALLEL_PROBES.
    for chunk in peers.chunks(PARALLEL_PROBES) {
        let mut handles = Vec::new();
        for peer in chunk {
            let proto_cfg = proto_cfg.clone();
            let status_tx = status_tx.clone();
            let new_addr_tx = new_addr_tx.clone();
            let csv_writer = csv_writer.clone();
            let event_tx = event_tx.clone();
            let peer = peer.clone();

            handles.push(tokio::spawn(async move {
                let result = probe_peer(peer, proto_cfg, status_tx, new_addr_tx).await;

                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                // Emit NATS event.
                let _ = event_tx
                    .send(common::events::PeerEvent {
                        connection_id: 0,
                        timestamp_ms: ts,
                        peer_addr: result.peer_addr.clone(),
                        user_agent: String::new(),
                        transport_version: 0,
                        event: Some(
                            common::events::peer_event::Event::InboundSlotCount(
                                common::events::InboundSlotCount {
                                    max_concurrent_connections: result.max_concurrent as u32,
                                    total_opened: result.total_opened as u32,
                                },
                            ),
                        ),
                    })
                    .await;

                // Write CSV row.
                {
                    let mut w = csv_writer.lock().unwrap();
                    let _ = writeln!(
                        w,
                        "{},{},{},{}",
                        result.peer_addr, result.max_concurrent, result.total_opened, ts
                    );
                    let _ = w.flush();
                }

                tracing::info!(target: TARGET_MAIN,
                    peer = %result.peer_addr,
                    max_concurrent = result.max_concurrent,
                    total_opened = result.total_opened,
                    "probe complete"
                );
            }));
        }

        // Wait for all probes in this chunk.
        for h in handles {
            let _ = h.await;
        }
    }

    tracing::info!(target: TARGET_MAIN, "all probes complete");

    if let Err(e) = store.lock().unwrap().save() {
        tracing::warn!(target: TARGET_MAIN, "failed to persist address store on shutdown: {e}");
    }
}

/// Probe a single peer: open 5 connections/sec, detect eviction, return peak concurrent.
async fn probe_peer(
    peer: addresses::PeerAddr,
    base_cfg: protocol::Config,
    status_tx: tokio::sync::mpsc::Sender<addresses::StatusUpdate>,
    new_addr_tx: tokio::sync::mpsc::Sender<Vec<addresses::PeerAddr>>,
) -> ProbeResult {
    let peer_addr_str = peer.addr.to_string();
    tracing::info!(target: TARGET_MAIN, peer = %peer_addr_str, "probing peer");

    let concurrent_gauge = Arc::new(AtomicUsize::new(0));
    let peak_gauge = Arc::new(AtomicUsize::new(0));

    // Build a Config with the gauges attached.
    let probe_cfg = protocol::Config {
        concurrent_gauge: Some(concurrent_gauge.clone()),
        peak_gauge: Some(peak_gauge.clone()),
        ..base_cfg
    };

    // First, try a single connection to see if the peer is reachable.
    // We use a timeout: if the connection stays alive for 3s, the peer is reachable.
    // If it fails before that, the peer is unreachable.
    {
        tracing::info!(target: TARGET_MAIN, peer = %peer_addr_str, "testing reachability");
        let mut conn = connection::Connection::new(
            probe_cfg.clone(),
            status_tx.clone(),
            new_addr_tx.clone(),
            peer.clone(),
        );
        match tokio::time::timeout(
            tokio::time::Duration::from_secs(3),
            conn.try_connect(),
        ).await {
            Ok(Ok(_)) => {
                // Connection completed (peer closed it) within 3s — still reachable.
                tracing::info!(target: TARGET_MAIN, peer = %peer_addr_str, "peer is reachable (connection closed quickly), starting probe");
            }
            Ok(Err(e)) => {
                // Connection failed within 3s.
                tracing::warn!(target: TARGET_MAIN, peer = %peer_addr_str, error = %e, "peer unreachable, skipping");
                concurrent_gauge.store(0, Ordering::Relaxed);
                peak_gauge.store(0, Ordering::Relaxed);
                return ProbeResult {
                    peer_addr: peer_addr_str,
                    max_concurrent: 0,
                    total_opened: 0,
                };
            }
            Err(_) => {
                // Timeout = connection stayed alive for 3s = peer is reachable.
                tracing::info!(target: TARGET_MAIN, peer = %peer_addr_str, "peer is reachable, starting probe");
                // The timed-out connection task is dropped here, which cancels it.
            }
        }
    }
    // Reset gauges after the reachability test.
    concurrent_gauge.store(0, Ordering::Relaxed);
    peak_gauge.store(0, Ordering::Relaxed);

    let mut task_handles: Vec<tokio::task::JoinHandle<Option<Duration>>> = Vec::new();
    let mut total_opened: usize = 0;
    let mut total_connected: usize = 0;
    let mut consecutive_tcp_failures: usize = 0;
    let mut short_lived_count: usize = 0;
    let probe_start = std::time::Instant::now();

    // 200ms interval = 5 connections per second, one at a time.
    let mut ticker = tokio::time::interval(tokio::time::Duration::from_millis(200));
    let mut last_log = std::time::Instant::now();
    let mut last_log_state = (0usize, 0usize, 0usize, 0usize); // concurrent, inflight, opened, connected

    'outer: loop {
        ticker.tick().await;

        // Overall timeout.
        if probe_start.elapsed() > PROBE_TIMEOUT {
            tracing::warn!(target: TARGET_MAIN,
                peer = %peer_addr_str,
                "probe timeout reached, stopping"
            );
            break;
        }

        // Check completed tasks for eviction signals.
        let mut new_handles = Vec::with_capacity(task_handles.len());
        for handle in task_handles.drain(..) {
            if handle.is_finished() {
                match handle.await {
                    Ok(Some(duration)) => {
                        // Connection succeeded then closed. Check duration.
                        total_connected += 1;
                        if duration < EVICTION_THRESHOLD {
                            short_lived_count += 1;
                            tracing::info!(target: TARGET_MAIN,
                                peer = %peer_addr_str,
                                duration_ms = duration.as_millis() as u64,
                                short_lived_count,
                                "short-lived connection detected"
                            );
                            if short_lived_count >= EVICTION_COUNT {
                                tracing::info!(target: TARGET_MAIN,
                                    peer = %peer_addr_str,
                                    "eviction detected, stopping probe"
                                );
                                break 'outer;
                            }
                        } else {
                            // Long-lived connection closed — not eviction, reset counter.
                            short_lived_count = 0;
                        }
                        // Reset TCP failure counter on any successful connection.
                        consecutive_tcp_failures = 0;
                    }
                    Ok(None) => {
                        // TCP/handshake failure.
                        consecutive_tcp_failures += 1;
                        tracing::debug!(target: TARGET_MAIN,
                            peer = %peer_addr_str,
                            consecutive_tcp_failures,
                            "TCP/handshake failure"
                        );
                        if consecutive_tcp_failures >= MAX_TCP_FAILURES {
                            tracing::warn!(target: TARGET_MAIN,
                                peer = %peer_addr_str,
                                "too many TCP failures, skipping peer"
                            );
                            break 'outer;
                        }
                    }
                    Err(_) => {} // JoinError (panic/cancel) — ignore
                }
            } else {
                new_handles.push(handle);
            }
        }
        task_handles = new_handles;

        // Spawn one connection per tick (200ms), respecting the in-flight cap.
        if task_handles.len() < MAX_INFLIGHT {
            let cfg = probe_cfg.clone();
            let stx = status_tx.clone();
            let natx = new_addr_tx.clone();
            let peer = peer.clone();

            task_handles.push(tokio::spawn(async move {
                let mut conn = connection::Connection::new(cfg, stx, natx, peer);
                match conn.try_connect().await {
                    Ok(connected_at) => Some(connected_at.elapsed()),
                    Err(_) => None,
                }
            }));
            total_opened += 1;
        }

        // Log every ~1s, or immediately when state changes.
        let current = concurrent_gauge.load(Ordering::Relaxed);
        let state = (current, task_handles.len(), total_opened, total_connected);
        if state != last_log_state || last_log.elapsed() >= Duration::from_secs(5) {
            let peak = peak_gauge.load(Ordering::Relaxed);
            tracing::info!(target: TARGET_MAIN,
                peer = %peer_addr_str,
                concurrent = current,
                peak,
                inflight = task_handles.len(),
                total_opened,
                total_connected,
                tcp_failures = consecutive_tcp_failures,
                "probe tick"
            );
            last_log_state = state;
            last_log = std::time::Instant::now();
        }
    }

    // Cancel all remaining connection tasks.
    for handle in &task_handles {
        handle.abort();
    }
    for handle in task_handles {
        let _ = handle.await;
    }

    let peak = peak_gauge.load(Ordering::Relaxed);
    ProbeResult {
        peer_addr: peer_addr_str,
        max_concurrent: peak,
        total_opened,
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
