use common::{
    anyhow::{Context, Result},
    p2p::{
        self, Magic, ProtocolVersion, ServiceFlags, address,
        message::NetworkMessage,
        message_network::{self, UserAgent},
    },
    tokio::{
        self,
        io::{AsyncReadExt, AsyncWriteExt, BufReader},
        net::TcpStream,
        time::{Duration, timeout},
    },
    tracing, tracing_subscriber,
};
use std::fs::File;
use std::io::{BufRead, BufWriter, Write};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

const USER_AGENT: &str = "/slot-probe/";
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const EVICTION_THRESHOLD: Duration = Duration::from_secs(2);
const EVICTION_COUNT: usize = 3;
const MAX_TCP_FAILURES: usize = 5;
const MAX_INFLIGHT: usize = 3500;
const PROBE_TIMEOUT: Duration = Duration::from_secs(300);
const PARALLEL_PROBES: usize = 20;

const TARGET: &str = "slot-probe";

struct ProbeResult {
    peer_addr: String,
    max_concurrent: usize,
    total_opened: usize,
    user_agent: String,
}

struct ConnectResult {
    connected_at: Instant,
    user_agent: String,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_target(true)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .init();

    check_fd_limit();

    let addr_file = std::env::args().nth(1).unwrap_or_else(|| "addrs.txt".to_string());
    let addrs = read_addresses(&addr_file);
    if addrs.is_empty() {
        tracing::error!(target: TARGET, file = %addr_file, "no addresses found");
        std::process::exit(1);
    }
    tracing::info!(target: TARGET, count = addrs.len(), file = %addr_file, "loaded addresses");

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let csv_path = format!("inbound_slots_{}.csv", timestamp);
    let csv_file = File::create(&csv_path).expect("failed to create CSV file");
    let csv_writer = Arc::new(std::sync::Mutex::new(BufWriter::new(csv_file)));
    {
        let mut w = csv_writer.lock().unwrap();
        writeln!(w, "peer_addr,max_concurrent_connections,total_opened,user_agent,timestamp").unwrap();
        w.flush().unwrap();
    }
    tracing::info!(target: TARGET, path = %csv_path, "CSV file created");

    let semaphore = Arc::new(tokio::sync::Semaphore::new(PARALLEL_PROBES));
    let mut handles = Vec::new();

    for &addr in &addrs {
        let permit = semaphore.clone().acquire_owned().await.unwrap();
        let csv_writer = csv_writer.clone();
        handles.push(tokio::spawn(async move {
            let result = probe_peer(addr).await;
            let ts = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            {
                let mut w = csv_writer.lock().unwrap();
                let ua = if result.user_agent.contains(',') || result.user_agent.contains('"') {
                    format!("\"{}\"", result.user_agent.replace('"', "\"\""))
                } else {
                    result.user_agent.clone()
                };
                let _ = writeln!(
                    w, "{},{},{},{},{}",
                    result.peer_addr, result.max_concurrent, result.total_opened, ua, ts
                );
                let _ = w.flush();
            }
            tracing::info!(target: TARGET,
                peer = %result.peer_addr,
                max_concurrent = result.max_concurrent,
                total_opened = result.total_opened,
                "probe complete"
            );
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    tracing::info!(target: TARGET, "all probes complete");
}

fn read_addresses(path: &str) -> Vec<SocketAddr> {
    let file = match File::open(path) {
        Ok(f) => f,
        Err(e) => {
            tracing::error!(target: TARGET, path, error = %e, "failed to open address file");
            return Vec::new();
        }
    };
    std::io::BufReader::new(file)
        .lines()
        .filter_map(|line| {
            let line = line.ok()?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                return None;
            }
            trimmed.parse::<SocketAddr>().ok()
        })
        .collect()
}

async fn probe_peer(addr: SocketAddr) -> ProbeResult {
    let peer_str = addr.to_string();
    tracing::info!(target: TARGET, peer = %peer_str, "testing reachability");

    let concurrent = Arc::new(AtomicUsize::new(0));
    let peak = Arc::new(AtomicUsize::new(0));

    // Try a single handshake first. Only proceed with bulk probing if it succeeds.
    let mut user_agent = match do_handshake(addr).await {
        Ok(ua) => {
            tracing::info!(target: TARGET, peer = %peer_str, ua = %ua, "first connection succeeded");
            ua
        }
        Err(e) => {
            tracing::warn!(target: TARGET, peer = %peer_str, error = format!("{e:#}"), "first connection failed, skipping");
            return ProbeResult { peer_addr: peer_str, max_concurrent: 0, total_opened: 0, user_agent: String::new() };
        }
    };

    // Main probe: one connection every 200ms.
    // Each task returns Ok((duration, user_agent)) on success, Err(error_string) on failure.
    let mut task_handles: Vec<tokio::task::JoinHandle<std::result::Result<(Duration, String), String>>> = Vec::new();
    let mut total_opened: usize = 0;
    let mut total_connected: usize = 0;
    let mut consecutive_tcp_failures: usize = 0;
    let mut short_lived_count: usize = 0;
    let probe_start = Instant::now();
    let mut ticker = tokio::time::interval(Duration::from_millis(200));
    let mut last_log_state = (0usize, 0usize, 0usize, 0usize);
    let mut last_log = Instant::now();

    'outer: loop {
        ticker.tick().await;

        if probe_start.elapsed() > PROBE_TIMEOUT {
            tracing::warn!(target: TARGET, peer = %peer_str, "probe timeout");
            break;
        }

        // Reap finished tasks.
        let mut new_handles = Vec::with_capacity(task_handles.len());
        for handle in task_handles.drain(..) {
            if handle.is_finished() {
                match handle.await {
                    Ok(Ok((duration, ua))) => {
                        total_connected += 1;
                        if user_agent.is_empty() && !ua.is_empty() {
                            user_agent = ua;
                        }
                        if duration < EVICTION_THRESHOLD {
                            short_lived_count += 1;
                            tracing::info!(target: TARGET,
                                peer = %peer_str,
                                duration_ms = duration.as_millis() as u64,
                                short_lived_count,
                                "short-lived connection"
                            );
                            if short_lived_count >= EVICTION_COUNT {
                                tracing::info!(target: TARGET, peer = %peer_str, "eviction detected");
                                break 'outer;
                            }
                        } else {
                            short_lived_count = 0;
                        }
                        consecutive_tcp_failures = 0;
                    }
                    Ok(Err(e)) => {
                        consecutive_tcp_failures += 1;
                        tracing::debug!(target: TARGET,
                            peer = %peer_str, consecutive_tcp_failures, error = %e, "TCP failure"
                        );
                        if consecutive_tcp_failures >= MAX_TCP_FAILURES {
                            tracing::warn!(target: TARGET, peer = %peer_str, error = %e, "too many TCP failures");
                            break 'outer;
                        }
                    }
                    Err(_) => {}
                }
            } else {
                new_handles.push(handle);
            }
        }
        task_handles = new_handles;

        // Spawn 3 connections per tick.
        for _ in 0..3 {
            if task_handles.len() >= MAX_INFLIGHT {
                break;
            }
            let c = concurrent.clone();
            let p = peak.clone();
            task_handles.push(tokio::spawn(async move {
                do_connect(addr, c, p).await
                    .map(|r| (r.connected_at.elapsed(), r.user_agent))
                    .map_err(|e| format!("{e:#}"))
            }));
            total_opened += 1;
        }

        // Log on state change or every 5s.
        let cur = concurrent.load(Ordering::Relaxed);
        let state = (cur, task_handles.len(), total_opened, total_connected);
        if state != last_log_state || last_log.elapsed() >= Duration::from_secs(5) {
            tracing::info!(target: TARGET,
                peer = %peer_str,
                concurrent = cur,
                peak = peak.load(Ordering::Relaxed),
                inflight = task_handles.len(),
                total_opened,
                total_connected,
                "probe"
            );
            last_log_state = state;
            last_log = Instant::now();
        }
    }

    for h in &task_handles { h.abort(); }
    for h in task_handles { let _ = h.await; }

    ProbeResult {
        peer_addr: peer_str,
        max_concurrent: peak.load(Ordering::Relaxed),
        total_opened,
        user_agent,
    }
}

/// Connect via v1, complete the handshake, then immediately drop the connection.
/// Returns the peer's user agent string.
async fn do_handshake(addr: SocketAddr) -> Result<String> {
    let stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("TCP connect timeout")?
        .context("TCP connect")?;
    stream.set_nodelay(true).ok();

    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    send_msg(&mut writer, Magic::BITCOIN, build_version()).await?;

    let mut got_version = false;
    let mut got_verack = false;
    let mut user_agent = String::new();
    while !(got_version && got_verack) {
        let msg = recv_msg(&mut reader).await?;
        match msg {
            NetworkMessage::Version(v) => {
                user_agent = v.user_agent.to_string();
                send_msg(&mut writer, Magic::BITCOIN, NetworkMessage::Verack).await?;
                got_version = true;
            }
            NetworkMessage::Verack => got_verack = true,
            _ => {}
        }
    }
    Ok(user_agent)
}

/// Connect via v1, handshake, then hold the connection open (respond to pings).
/// Returns ConnectResult with handshake time and user_agent.
async fn do_connect(
    addr: SocketAddr,
    concurrent: Arc<AtomicUsize>,
    peak: Arc<AtomicUsize>,
) -> Result<ConnectResult> {
    let stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("TCP connect timeout")?
        .context("TCP connect")?;
    stream.set_nodelay(true).ok();

    let (read_half, write_half) = stream.into_split();
    let mut reader = BufReader::new(read_half);
    let mut writer = write_half;

    // Send version.
    send_msg(&mut writer, Magic::BITCOIN, build_version()).await?;

    // Handshake loop.
    let mut got_version = false;
    let mut got_verack = false;
    let mut user_agent = String::new();
    while !(got_version && got_verack) {
        let msg = recv_msg(&mut reader).await?;
        match msg {
            NetworkMessage::Version(v) => {
                user_agent = v.user_agent.to_string();
                send_msg(&mut writer, Magic::BITCOIN, NetworkMessage::Verack).await?;
                got_version = true;
            }
            NetworkMessage::Verack => got_verack = true,
            _ => {}
        }
    }

    let connected_at = Instant::now();
    let cur = concurrent.fetch_add(1, Ordering::Relaxed) + 1;
    peak.fetch_max(cur, Ordering::Relaxed);

    // Idle loop: respond to pings until disconnected.
    loop {
        match recv_msg(&mut reader).await {
            Ok(NetworkMessage::Ping(nonce)) => {
                if send_msg(&mut writer, Magic::BITCOIN, NetworkMessage::Pong(nonce)).await.is_err() {
                    break;
                }
            }
            Ok(_) => {}
            Err(_) => break,
        }
    }

    concurrent.fetch_sub(1, Ordering::Relaxed);
    Ok(ConnectResult { connected_at, user_agent })
}

fn check_fd_limit() {
    let mut rlim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut rlim) };
    let soft = rlim.rlim_cur;
    let hard = rlim.rlim_max;
    // We need: PARALLEL_PROBES * MAX_INFLIGHT file descriptors in the worst case,
    // but realistically a few thousand should be fine.
    let recommended = (PARALLEL_PROBES * MAX_INFLIGHT / 10).max(65536) as u64;
    tracing::info!(target: TARGET, soft, hard, "file descriptor limits");
    if soft < recommended {
        tracing::warn!(target: TARGET,
            soft, recommended,
            "soft fd limit is low, try: ulimit -n {recommended}"
        );
        // Try to raise it.
        let new_soft = hard.min(recommended);
        rlim.rlim_cur = new_soft;
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) };
        if ret == 0 {
            tracing::info!(target: TARGET, new_soft, "raised soft fd limit");
        } else {
            tracing::warn!(target: TARGET, "failed to raise fd limit, expect 'Too many open files' errors");
        }
    }
}

// ── Minimal v1 wire protocol ──────────────────────────────────────────────────

async fn send_msg(
    writer: &mut tokio::net::tcp::OwnedWriteHalf,
    magic: Magic,
    msg: NetworkMessage,
) -> Result<()> {
    use common::bitcoin::consensus::Encodable;
    let raw = p2p::message::RawNetworkMessage::new(magic, msg);
    let mut buf = Vec::new();
    raw.consensus_encode(&mut buf)?;
    writer.write_all(&buf).await?;
    Ok(())
}

async fn recv_msg(reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>) -> Result<NetworkMessage> {
    use common::bitcoin::consensus::Decodable;
    // Header: 24 bytes (magic 4 + command 12 + length 4 + checksum 4)
    let mut header = [0u8; 24];
    reader.read_exact(&mut header).await.context("read header")?;
    let payload_len = u32::from_le_bytes([header[16], header[17], header[18], header[19]]) as usize;
    let mut payload = vec![0u8; payload_len];
    reader.read_exact(&mut payload).await.context("read payload")?;

    let mut full = Vec::with_capacity(24 + payload_len);
    full.extend_from_slice(&header);
    full.extend_from_slice(&payload);
    let raw = p2p::message::RawNetworkMessage::consensus_decode(&mut full.as_slice())
        .context("decode message")?;
    Ok(raw.payload().clone())
}

fn build_version() -> NetworkMessage {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64;

    NetworkMessage::Version(message_network::VersionMessage {
        version: ProtocolVersion::WTXID_RELAY_VERSION,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp,
        receiver: address::Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            ServiceFlags::NONE,
        ),
        sender: address::Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            ServiceFlags::NONE,
        ),
        nonce: 0,
        user_agent: UserAgent::from_nonstandard(USER_AGENT),
        start_height: 0,
        relay: false,
    })
}
