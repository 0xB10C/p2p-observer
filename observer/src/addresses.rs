use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use crate::TARGET_ADDRESSES as TARGET;
use common::{
    anyhow::{Context, Result},
    p2p::{
        ServiceFlags,
        address::{AddrV2, AddrV2Message, Address},
    },
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

/// A network address bundled with the service flags advertised by the peer.
///
/// `Hash` and `Eq` are based on the `addr` field only — the same IP:port with
/// different services is still the same peer.
pub struct PeerAddr {
    pub addr: NetAddr,
    services: ServiceFlags,
}

impl PeerAddr {
    pub fn new(addr: NetAddr, services: ServiceFlags) -> Self {
        Self { addr, services }
    }

    pub fn services(&self) -> ServiceFlags {
        self.services
    }
}

impl std::fmt::Debug for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerAddr")
            .field("addr", &self.addr)
            .field("services", &self.services)
            .finish()
    }
}

impl Clone for PeerAddr {
    fn clone(&self) -> Self {
        Self::new(self.addr.clone(), self.services)
    }
}

impl std::hash::Hash for PeerAddr {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.addr.hash(state);
    }
}

impl PartialEq for PeerAddr {
    fn eq(&self, other: &Self) -> bool {
        self.addr == other.addr
    }
}

impl Eq for PeerAddr {}

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.addr.fmt(f)
    }
}

impl TryFrom<&AddrV2Message> for PeerAddr {
    type Error = ();

    fn try_from(msg: &AddrV2Message) -> std::result::Result<Self, ()> {
        let addr = NetAddr::try_from(msg)?;
        Ok(PeerAddr::new(addr, msg.services))
    }
}

impl TryFrom<&Address> for PeerAddr {
    type Error = ();

    fn try_from(a: &Address) -> std::result::Result<Self, ()> {
        let addr = NetAddr::try_from(a)?;
        Ok(PeerAddr::new(addr, a.services))
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

/// Parse an "ip:port" or "[ipv6]:port" string into a `PeerAddr` with no known services.
pub fn parse_addr(s: &str) -> Option<PeerAddr> {
    let sa: SocketAddr = s.parse().ok()?;
    let addr = match sa.ip() {
        IpAddr::V4(ip) => NetAddr::Ipv4(ip, sa.port()),
        IpAddr::V6(ip) => {
            if let Some(ipv4) = ip.to_ipv4_mapped() {
                NetAddr::Ipv4(ipv4, sa.port())
            } else if ip.octets()[0] == 0xfc {
                NetAddr::Cjdns(ip, sa.port())
            } else {
                NetAddr::Ipv6(ip, sa.port())
            }
        }
    };
    Some(PeerAddr::new(addr, ServiceFlags::NONE))
}

// ── Store types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(crate = "common::serde")]
pub enum BadReason {
    ConnectionRefused,
    /// The host is not reachable.
    HostUnreachable,
    /// The network for this address is unreachable (e.g. no IPv6 connectivity).
    NetworkUnreachable,
    /// TCP connection timed out — the node may be firewalled or the IP unoccupied.
    TimedOut,
}

pub enum StatusUpdate {
    Good {
        addr: NetAddr,
        at: u64,
    },
    Bad {
        addr: NetAddr,
        at: u64,
        reason: BadReason,
    },
}

const MAX_UNKNOWN: usize = 100_000;
const MAX_GOOD: usize = 500_000;
const MAX_BAD: usize = 100_000;

pub struct AddrStore {
    unknown: HashSet<PeerAddr>,
    good: HashMap<PeerAddr, u64>,
    bad: HashMap<PeerAddr, (u64, BadReason)>,
    persist_path: PathBuf,
}

/// On-disk representation — uses Vecs since NetAddr can't be a JSON object key.
/// Services are stored as u64 since ServiceFlags doesn't impl Serialize.
#[derive(Serialize, Deserialize)]
#[serde(crate = "common::serde")]
struct StoreDisk {
    unknown: Vec<(NetAddr, u64)>,
    good: Vec<(NetAddr, u64, u64)>,
    bad: Vec<(NetAddr, u64, BadReason, u64)>,
}

impl AddrStore {
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let disk: StoreDisk = serde_json::from_str(&s).context("parse address store")?;
                Ok(Self {
                    unknown: disk
                        .unknown
                        .into_iter()
                        .map(|(a, svc)| PeerAddr::new(a, ServiceFlags::from(svc)))
                        .collect(),
                    good: disk
                        .good
                        .into_iter()
                        .map(|(a, ts, svc)| (PeerAddr::new(a, ServiceFlags::from(svc)), ts))
                        .collect(),
                    bad: disk
                        .bad
                        .into_iter()
                        .map(|(a, ts, r, svc)| (PeerAddr::new(a, ServiceFlags::from(svc)), (ts, r)))
                        .collect(),
                    persist_path: path.to_owned(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::empty(path)),
            Err(e) => Err(e).context("read address store"),
        }
    }

    pub fn empty(path: &Path) -> Self {
        Self {
            unknown: HashSet::new(),
            good: HashMap::new(),
            bad: HashMap::new(),
            persist_path: path.to_owned(),
        }
    }

    pub fn save(&self) -> Result<()> {
        let disk = StoreDisk {
            unknown: self
                .unknown
                .iter()
                .map(|p| (p.addr.clone(), p.services().to_u64()))
                .collect(),
            good: self
                .good
                .iter()
                .map(|(p, &ts)| (p.addr.clone(), ts, p.services().to_u64()))
                .collect(),
            bad: self
                .bad
                .iter()
                .map(|(p, (ts, r))| (p.addr.clone(), *ts, *r, p.services().to_u64()))
                .collect(),
        };
        let json = serde_json::to_string(&disk).context("serialize address store")?;
        std::fs::write(&self.persist_path, json).context("write address store")?;
        tracing::info!(target: TARGET,
            unknown = self.unknown.len(),
            good = self.good.len(),
            bad = self.bad.len(),
            "address store saved"
        );
        Ok(())
    }

    /// Insert new addresses as Unknown. Returns the number of addresses inserted.
    pub fn insert_batch(&mut self, addrs: Vec<PeerAddr>, allow_local: bool) -> usize {
        let mut inserted = 0;
        for peer in addrs {
            if !allow_local && !peer.addr.is_routable() {
                continue;
            }
            if self.good.contains_key(&peer) || self.bad.contains_key(&peer) {
                continue;
            }
            if self.unknown.len() >= MAX_UNKNOWN {
                break;
            }
            self.unknown.insert(peer);
            inserted += 1;
        }
        inserted
    }

    /// Returns up to `n` addresses to connect to, excluding those in `active`.
    ///
    /// Priority order:
    ///   1. Good — oldest-seen first. Then:
    ///   2. Unknown. Then:
    ///   3. Bad — fill remaining slots.
    ///
    /// Only addresses with a TCP socket address are returned.
    pub fn get_batch(&self, n: usize, active: &HashSet<PeerAddr>) -> Vec<PeerAddr> {
        let mut batch = Vec::with_capacity(n);

        let base =
            |peer: &PeerAddr| !active.contains(&peer) && peer.addr.to_socket_addr().is_some();

        let mut good: Vec<(&PeerAddr, u64)> = self
            .good
            .iter()
            .filter(|(a, _)| base(a))
            .map(|(a, &ts)| (a, ts))
            .collect();
        good.sort_by_key(|(_, ts)| *ts);

        // first, fill up with good ones
        let good_fill = std::cmp::min(n, good.len());
        batch.extend(good[..good_fill].iter().map(|(peer, _)| (*peer).clone()));
        if batch.len() == n {
            tracing::debug!(target: TARGET,
                good=good_fill,
                "returned batch with only good addresses:"
            );
            return batch;
        }
        assert!(
            batch.len() <= n,
            "batch has {} entries while {} are allowed",
            batch.len(),
            n
        );

        // then, fill up with unknown
        let unknown: Vec<&PeerAddr> = self.unknown.iter().filter(|a| base(a)).collect();
        let unknown_fill = std::cmp::min(n - batch.len(), unknown.len());
        batch.extend(unknown[..unknown_fill].iter().map(|a| (*a).clone()));
        if batch.len() == n {
            tracing::debug!(target: TARGET,
                good=good_fill,
                unknown=unknown_fill,
                "returned batch with good and unknown addresses:"
            );
            return batch;
        }
        assert!(batch.len() <= n);

        // then, fill up with bad ones
        let bad: Vec<&PeerAddr> = self.bad.keys().filter(|a| base(a)).collect();
        let bad_fill = std::cmp::min(n - batch.len(), bad.len());
        batch.extend(bad[..bad_fill].iter().map(|a| (*a).clone()));
        tracing::debug!(target: TARGET,
            good=good_fill,
            unknown=unknown_fill,
            bad=bad_fill,
            "returned batch with good, unknown, and bad addresses:"
        );
        assert!(batch.len() <= n);

        batch
    }

    pub fn unknown_len(&self) -> usize {
        self.unknown.len()
    }

    pub fn good_len(&self) -> usize {
        self.good.len()
    }

    pub fn bad_len(&self) -> usize {
        self.bad.len()
    }

    /// Look up the `PeerAddr` for a `NetAddr` in any table, preserving its services.
    fn take(&mut self, addr: &NetAddr) -> Option<PeerAddr> {
        let key = PeerAddr::new(addr.clone(), ServiceFlags::NONE);
        if let Some(peer) = self.unknown.take(&key) {
            return Some(peer);
        }
        if let Some((peer, _)) = self.good.remove_entry(&key) {
            return Some(peer);
        }
        if let Some((peer, _)) = self.bad.remove_entry(&key) {
            return Some(peer);
        }
        None
    }

    pub fn apply_update(&mut self, update: StatusUpdate) {
        match update {
            StatusUpdate::Good { addr, at } => {
                let peer = self
                    .take(&addr)
                    .unwrap_or_else(|| PeerAddr::new(addr, ServiceFlags::NONE));
                if self.good.len() < MAX_GOOD {
                    self.good.insert(peer, at);
                }
            }
            StatusUpdate::Bad { addr, at, reason } => {
                let peer = self
                    .take(&addr)
                    .unwrap_or_else(|| PeerAddr::new(addr, ServiceFlags::NONE));
                if self.bad.len() < MAX_BAD {
                    self.bad.insert(peer, (at, reason));
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
    mut new_addr_rx: mpsc::Receiver<Vec<PeerAddr>>,
) {
    let mut persist_timer = interval(Duration::from_secs(60));
    persist_timer.tick().await; // skip the immediate first tick

    loop {
        tokio::select! {
            _ = persist_timer.tick() => {
                if let Err(e) = store.lock().unwrap().save() {
                    tracing::warn!(target: TARGET, "failed to persist address store: {e}");
                }
            }
            Some(update) = status_rx.recv() => {
                store.lock().unwrap().apply_update(update);
            }
            Some(addrs) = new_addr_rx.recv() => {
                store.lock().unwrap().insert_batch(addrs, false);
            }
        }
    }
}
