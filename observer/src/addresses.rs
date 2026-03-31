use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use common::{
    anyhow::{Context, Result},
    p2p::address::{AddrV2, AddrV2Message, Address},
    serde::{Deserialize, Serialize},
    serde_json,
    tokio::{
        self,
        sync::mpsc,
        time::{Duration, interval},
    },
    tracing,
};

// ── Address types ────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Hash, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "common::serde")]
pub enum NetAddr {
    Ipv4(Ipv4Addr, u16),
    Ipv6(Ipv6Addr, u16),
    TorV3([u8; 32], u16),
    I2p([u8; 32], u16),
    Cjdns(Ipv6Addr, u16),
}

impl NetAddr {
    /// Returns `true` if the address is globally routable and worth storing.
    pub fn is_routable(&self) -> bool {
        match self {
            NetAddr::Ipv4(ip, port) => {
                *port != 0
                    && !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_private()
                    && !ip.is_link_local()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
            }
            NetAddr::Ipv6(ip, port) => {
                *port != 0
                    && !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    // fe80::/10 link-local
                    && (ip.segments()[0] & 0xffc0) != 0xfe80
                    // fd00::/8 unique local (fc00::/8 is CJDNS and has its own variant)
                    && ip.octets()[0] != 0xfd
            }
            NetAddr::TorV3(key, port) => *port != 0 && key != &[0u8; 32],
            NetAddr::I2p(hash, port) => *port != 0 && hash != &[0u8; 32],
            NetAddr::Cjdns(ip, port) => *port != 0 && !ip.is_unspecified(),
        }
    }

    /// Returns a TCP socket address for address types that support direct TCP connections.
    /// Returns `None` for Tor and I2P addresses.
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match self {
            NetAddr::Ipv4(ip, port) => Some(SocketAddr::new(IpAddr::V4(*ip), *port)),
            NetAddr::Ipv6(ip, port) => Some(SocketAddr::new(IpAddr::V6(*ip), *port)),
            NetAddr::Cjdns(ip, port) => Some(SocketAddr::new(IpAddr::V6(*ip), *port)),
            NetAddr::TorV3(_, _) | NetAddr::I2p(_, _) => None,
        }
    }
}

impl std::fmt::Display for NetAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetAddr::Ipv4(ip, port) => write!(f, "{}:{}", ip, port),
            NetAddr::Ipv6(ip, port) => write!(f, "[{}]:{}", ip, port),
            NetAddr::TorV3(key, port) => write!(
                f,
                "torv3:{:02x}{:02x}{:02x}{:02x}:{}",
                key[0], key[1], key[2], key[3], port
            ),
            NetAddr::I2p(hash, port) => write!(
                f,
                "i2p:{:02x}{:02x}{:02x}{:02x}:{}",
                hash[0], hash[1], hash[2], hash[3], port
            ),
            NetAddr::Cjdns(ip, port) => write!(f, "cjdns:[{}]:{}", ip, port),
        }
    }
}

impl TryFrom<&AddrV2Message> for NetAddr {
    type Error = ();

    fn try_from(msg: &AddrV2Message) -> std::result::Result<Self, ()> {
        match &msg.addr {
            AddrV2::Ipv4(ip) => Ok(NetAddr::Ipv4(*ip, msg.port)),
            AddrV2::Ipv6(ip) => Ok(NetAddr::Ipv6(*ip, msg.port)),
            AddrV2::TorV3(key) => Ok(NetAddr::TorV3(*key, msg.port)),
            AddrV2::I2p(hash) => Ok(NetAddr::I2p(*hash, msg.port)),
            AddrV2::Cjdns(ip) => Ok(NetAddr::Cjdns(*ip, msg.port)),
            AddrV2::Unknown(_, _) => Err(()),
        }
    }
}

impl TryFrom<&Address> for NetAddr {
    type Error = ();

    fn try_from(addr: &Address) -> std::result::Result<Self, ()> {
        let sa = addr.socket_addr().map_err(|_| ())?;
        match sa {
            SocketAddr::V4(v4) => Ok(NetAddr::Ipv4(*v4.ip(), v4.port())),
            SocketAddr::V6(v6) => {
                let ip = *v6.ip();
                // CJDNS uses the fc00::/8 prefix
                if ip.octets()[0] == 0xfc {
                    Ok(NetAddr::Cjdns(ip, v6.port()))
                } else {
                    Ok(NetAddr::Ipv6(ip, v6.port()))
                }
            }
        }
    }
}

/// Parse an "ip:port" or "[ipv6]:port" string into a `NetAddr`.
pub fn parse_addr(s: &str) -> Option<NetAddr> {
    let sa: SocketAddr = s.parse().ok()?;
    match sa.ip() {
        IpAddr::V4(ip) => Some(NetAddr::Ipv4(ip, sa.port())),
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                Some(NetAddr::Ipv4(ipv4, sa.port()))
            } else if ip.octets()[0] == 0xfc {
                Some(NetAddr::Cjdns(ip, sa.port()))
            } else {
                Some(NetAddr::Ipv6(ip, sa.port()))
            }
        }
    }
}

// ── Store types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "common::serde")]
pub enum AddrStatus {
    Unknown,
    /// Unix timestamp (seconds) of the last successful connection.
    LastSeen(u64),
    Offline,
    /// The host is reachable but the port is closed (TCP RST). The Bitcoin
    /// node is likely not running or not listening on this port.
    ConnectionRefused,
    /// The host is not reachable.
    HostUnreachable,
    /// The network for this address is unreachable (e.g. no IPv6 connectivity).
    NetworkUnreachable,
    /// TCP connection timed out — the node may be firewalled or the IP unoccupied.
    TimedOut,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(crate = "common::serde")]
pub struct AddrEntry {
    pub addr: NetAddr,
    pub status: AddrStatus,
    /// True while a tokio task is active for this address. Not persisted.
    #[serde(skip)]
    pub active_task: bool,
}

pub enum StatusUpdate {
    LastSeen {
        addr: NetAddr,
        at: u64,
    },
    Offline(NetAddr),
    /// The host is reachable but the port is closed (TCP RST).
    ConnectionRefused(NetAddr),
    /// The host is not reachable.
    HostUnreachable(NetAddr),
    /// The network for this address is unreachable (e.g. no IPv6 connectivity).
    NetworkUnreachable(NetAddr),
    /// TCP connection timed out — the node may be firewalled or the IP unoccupied.
    TimedOut(NetAddr),
    /// Sent when the task for an address exits; clears `active_task`.
    TaskDone(NetAddr),
}

pub struct AddrStore {
    entries: HashMap<NetAddr, AddrEntry>,
    max_size: usize,
    persist_path: PathBuf,
}

impl AddrStore {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let entries: Vec<AddrEntry> =
                    serde_json::from_str(&s).context("parse address store")?;
                Ok(Self {
                    entries: entries.into_iter().map(|e| (e.addr.clone(), e)).collect(),
                    max_size: 10_000,
                    persist_path: path.to_owned(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::empty(path)),
            Err(e) => Err(e).context("read address store"),
        }
    }

    pub fn empty(path: &Path) -> Self {
        Self {
            entries: HashMap::new(),
            max_size: 10_000,
            persist_path: path.to_owned(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let entries: Vec<&AddrEntry> = self.entries.values().collect();
        let json = serde_json::to_string(&entries).context("serialize address store")?;
        std::fs::write(&self.persist_path, json).context("write address store")
    }

    /// Insert a new address. Returns `false` if already present, not routable, or the store is at capacity.
    pub fn insert(&mut self, addr: NetAddr) -> bool {
        if !addr.is_routable() {
            return false;
        }
        if self.entries.contains_key(&addr) {
            return false;
        }
        if self.entries.len() >= self.max_size {
            // TODO: evict oldest Offline entry
            return false;
        }
        self.entries.insert(
            addr.clone(),
            AddrEntry {
                addr: addr.clone(),
                status: AddrStatus::Unknown,
                active_task: false,
            },
        );
        let active = self.entries.values().filter(|e| e.active_task).count();
        tracing::debug!(%addr, total = self.entries.len(), active, "new address");
        true
    }

    /// Returns up to `n` addresses to connect to.
    ///
    /// Three buckets in priority order:
    ///   1. `Unknown`   — never attempted, preferred over all others (up to half the batch)
    ///   2. `LastSeen`  — previously connected, oldest first (up to half the batch)
    ///   3. Known-bad   — `Offline`, `ConnectionRefused`, `HostUnreachable`, `TimedOut` —
    ///      only fills slots left over after the first two buckets are exhausted
    ///
    /// Only addresses with a TCP socket address and no active task are returned.
    pub fn get_batch(&self, n: usize) -> Vec<NetAddr> {
        let half = n / 2;

        let base_filter = |e: &&AddrEntry| !e.active_task && e.addr.to_socket_addr().is_some();

        let fresh: Vec<&AddrEntry> = self
            .entries
            .values()
            .filter(|e| base_filter(e) && matches!(e.status, AddrStatus::Unknown))
            .collect();

        let mut seen: Vec<&AddrEntry> = self
            .entries
            .values()
            .filter(|e| base_filter(e) && matches!(e.status, AddrStatus::LastSeen(_)))
            .collect();

        let stale: Vec<&AddrEntry> = self
            .entries
            .values()
            .filter(|e| {
                base_filter(e)
                    && matches!(
                        e.status,
                        AddrStatus::Offline
                            | AddrStatus::ConnectionRefused
                            | AddrStatus::HostUnreachable
                            | AddrStatus::TimedOut
                    )
            })
            .collect();

        // Oldest first
        seen.sort_by_key(|e| match e.status {
            AddrStatus::LastSeen(t) => t,
            _ => 0,
        });

        // Fill Unknown and LastSeen with a 50/50 split, overflowing to each other.
        let from_seen_initial = seen.len().min(half);
        let from_fresh = fresh.len().min(n - from_seen_initial);
        let from_seen = seen.len().min(n - from_fresh);
        // Known-bad only fills slots left over once Unknown and LastSeen are exhausted.
        let from_stale = stale.len().min(n - from_fresh - from_seen);

        let mut result = Vec::with_capacity(from_fresh + from_seen + from_stale);
        result.extend(fresh[..from_fresh].iter().map(|e| e.addr.clone()));
        result.extend(seen[..from_seen].iter().map(|e| e.addr.clone()));
        result.extend(stale[..from_stale].iter().map(|e| e.addr.clone()));
        result
    }

    pub fn entries_len(&self) -> usize {
        self.entries.len()
    }

    pub fn mark_task_started(&mut self, addr: &NetAddr) {
        if let Some(entry) = self.entries.get_mut(addr) {
            entry.active_task = true;
        }
    }

    pub fn apply_update(&mut self, update: StatusUpdate) {
        match update {
            StatusUpdate::LastSeen { addr, at } => {
                if let Some(entry) = self.entries.get_mut(&addr) {
                    entry.status = AddrStatus::LastSeen(at);
                }
            }
            StatusUpdate::Offline(addr) => {
                if let Some(entry) = self.entries.get_mut(&addr) {
                    entry.status = AddrStatus::Offline;
                }
            }
            StatusUpdate::ConnectionRefused(addr) => {
                if let Some(entry) = self.entries.get_mut(&addr) {
                    entry.status = AddrStatus::ConnectionRefused;
                }
            }
            StatusUpdate::HostUnreachable(addr) => {
                if let Some(entry) = self.entries.get_mut(&addr) {
                    entry.status = AddrStatus::HostUnreachable;
                }
            }
            StatusUpdate::NetworkUnreachable(addr) => {
                if let Some(entry) = self.entries.get_mut(&addr) {
                    entry.status = AddrStatus::NetworkUnreachable;
                }
            }
            StatusUpdate::TimedOut(addr) => {
                if let Some(entry) = self.entries.get_mut(&addr) {
                    entry.status = AddrStatus::TimedOut;
                }
            }
            StatusUpdate::TaskDone(addr) => {
                if let Some(entry) = self.entries.get_mut(&addr) {
                    entry.active_task = false;
                }
            }
        }
    }
}

// ── Background task ──────────────────────────────────────────────────────────

/// Drives the address store: applies status updates, ingests new addresses from peers,
/// and persists state to disk every 60 seconds.
pub async fn run(
    store: Arc<Mutex<AddrStore>>,
    mut status_rx: mpsc::Receiver<StatusUpdate>,
    mut new_addr_rx: mpsc::Receiver<Vec<NetAddr>>,
) {
    let mut persist_timer = interval(Duration::from_secs(60));
    persist_timer.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            _ = persist_timer.tick() => {
                if let Err(e) = store.lock().unwrap().save() {
                    tracing::warn!("failed to persist address store: {e}");
                }
            }
            Some(update) = status_rx.recv() => {
                store.lock().unwrap().apply_update(update);
            }
            Some(addrs) = new_addr_rx.recv() => {
                let mut s = store.lock().unwrap();
                for addr in addrs {
                    s.insert(addr);
                }
            }
        }
    }
}
