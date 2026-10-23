//! Addresses the operator never wants dialled.
//!
//! Kept in its own small file rather than inside the address snapshot. The
//! snapshot is deliberately disposable — it can be dropped on a format change
//! or cleared after corruption — and a hand-curated ban list is the one thing
//! in the old combined file that must survive that. Keeping it separate also
//! makes it editable by hand.

use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use common::{
    anyhow::{Context, Result},
    serde::{Deserialize, Serialize},
    serde_json,
};

use super::key::AddrKey;

/// A CIDR network. Serialises as a string, e.g. "10.0.0.0/8" or "1.2.3.4/32".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix_len: u8,
}

impl IpNet {
    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let shift = 32u8.saturating_sub(self.prefix_len);
                let mask: u32 = if shift >= 32 { 0 } else { !0u32 << shift };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let shift = 128u8.saturating_sub(self.prefix_len);
                let mask: u128 = if shift >= 128 { 0 } else { !0u128 << shift };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            // Never match across families.
            _ => false,
        }
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix_len)
    }
}

impl FromStr for IpNet {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (addr_str, prefix_str) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };

        let addr: IpAddr = addr_str
            .parse()
            .map_err(|_| format!("invalid IP address: {addr_str}"))?;

        // A bare address means that host alone.
        let max_prefix = match addr {
            IpAddr::V4(_) => 32u8,
            IpAddr::V6(_) => 128u8,
        };
        let prefix_len = match prefix_str {
            Some(p) => p
                .parse::<u8>()
                .map_err(|_| format!("invalid prefix length: {p}"))?,
            None => max_prefix,
        };
        if prefix_len > max_prefix {
            return Err(format!(
                "prefix length {prefix_len} exceeds maximum {max_prefix} for {addr}"
            ));
        }

        Ok(IpNet { addr, prefix_len })
    }
}

impl Serialize for IpNet {
    fn serialize<S: common::serde::Serializer>(
        &self,
        s: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for IpNet {
    fn deserialize<D: common::serde::Deserializer<'de>>(
        d: D,
    ) -> std::result::Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        IpNet::from_str(&s).map_err(common::serde::de::Error::custom)
    }
}

/// One ban, with an optional note saying why.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(crate = "common::serde")]
pub struct BanEntry {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,
    /// CIDR networks, for the IP-based networks.
    #[serde(default)]
    pub nets: Vec<IpNet>,
    /// Exact addresses, as rendered by `AddrKey::Display`. Used for Tor and
    /// I2P, which have no notion of a prefix to ban.
    #[serde(default)]
    pub hosts: Vec<String>,
}

/// The ban list, and the file it came from.
#[derive(Debug, Default)]
pub struct Banlist {
    entries: Vec<BanEntry>,
    path: PathBuf,
}

impl Banlist {
    /// Load the ban list. A missing file is an empty list, not an error.
    ///
    /// A malformed file *is* an error: unlike the address snapshot, this is
    /// hand-maintained operator intent. Silently starting with no bans would
    /// mean dialling addresses we were told never to dial, so the caller is
    /// expected to surface this rather than carry on.
    pub fn load(path: &Path) -> Result<Self> {
        match std::fs::read_to_string(path) {
            Ok(s) => {
                let entries: Vec<BanEntry> = serde_json::from_str(&s).context("parse ban list")?;
                Ok(Self {
                    entries,
                    path: path.to_owned(),
                })
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                entries: Vec::new(),
                path: path.to_owned(),
            }),
            Err(e) => Err(e).context("read ban list"),
        }
    }

    #[cfg(test)]
    pub fn from_entries(entries: Vec<BanEntry>) -> Self {
        Self {
            entries,
            path: PathBuf::from("/dev/null"),
        }
    }

    /// Write the list back out, atomically, so an RPC ban survives a crash.
    pub fn save(&self) -> Result<()> {
        use std::io::Write;

        let json = serde_json::to_string_pretty(&self.entries).context("serialize ban list")?;
        let tmp = self.path.with_extension("json.tmp");
        let mut file = std::fs::File::create(&tmp).context("create temporary ban list")?;
        file.write_all(json.as_bytes())
            .context("write temporary ban list")?;
        file.sync_all().context("flush temporary ban list")?;
        drop(file);
        std::fs::rename(&tmp, &self.path).context("rename ban list")?;
        Ok(())
    }

    pub fn entries(&self) -> &[BanEntry] {
        &self.entries
    }

    /// Total number of banned networks and hosts.
    pub fn len(&self) -> usize {
        self.entries
            .iter()
            .map(|e| e.nets.len() + e.hosts.len())
            .sum()
    }

    /// Kept alongside `len` because clippy's `len_without_is_empty` asks for
    /// it; the manager only ever reports the count.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether this address is banned.
    pub fn contains(&self, key: &AddrKey) -> bool {
        match key.ip() {
            Some(ip) => self
                .entries
                .iter()
                .any(|e| e.nets.iter().any(|net| net.contains(ip))),
            // Tor and I2P have no IP to match a prefix against, so they are
            // banned by exact host instead.
            None => {
                let host = key.to_string();
                self.entries.iter().any(|e| e.hosts.contains(&host))
            }
        }
    }

    /// Add an entry, skipping networks and hosts already covered. Returns how
    /// many new ones were added.
    pub fn add(&mut self, entry: BanEntry) -> usize {
        let nets: Vec<IpNet> = entry
            .nets
            .into_iter()
            .filter(|n| !self.entries.iter().any(|e| e.nets.contains(n)))
            .collect();
        let hosts: Vec<String> = entry
            .hosts
            .into_iter()
            .filter(|h| !self.entries.iter().any(|e| e.hosts.contains(h)))
            .collect();

        let added = nets.len() + hosts.len();
        if added > 0 {
            self.entries.push(BanEntry {
                comment: entry.comment,
                nets,
                hosts,
            });
        }
        added
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ban(nets: &[&str]) -> BanEntry {
        BanEntry {
            comment: None,
            nets: nets.iter().map(|s| s.parse().unwrap()).collect(),
            hosts: Vec::new(),
        }
    }

    #[test]
    fn test_bare_address_bans_one_host() {
        let net: IpNet = "1.2.3.4".parse().unwrap();
        assert_eq!(net.to_string(), "1.2.3.4/32");
        assert!(net.contains("1.2.3.4".parse().unwrap()));
        assert!(!net.contains("1.2.3.5".parse().unwrap()));

        let net: IpNet = "2001:db8::1".parse().unwrap();
        assert_eq!(net.to_string(), "2001:db8::1/128");
    }

    #[test]
    fn test_prefix_matching() {
        let net: IpNet = "10.0.0.0/8".parse().unwrap();
        assert!(net.contains("10.1.2.3".parse().unwrap()));
        assert!(net.contains("10.255.255.255".parse().unwrap()));
        assert!(!net.contains("11.0.0.1".parse().unwrap()));

        // /0 matches everything in its own family, and nothing outside it.
        let all: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("8.8.8.8".parse().unwrap()));
        assert!(!all.contains("2001:db8::1".parse().unwrap()));
    }

    #[test]
    fn test_families_never_cross() {
        let v4: IpNet = "0.0.0.0/0".parse().unwrap();
        let v6: IpNet = "::/0".parse().unwrap();
        assert!(!v4.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("1.2.3.4".parse().unwrap()));
    }

    #[test]
    fn test_rejects_bad_input() {
        assert!("not-an-ip".parse::<IpNet>().is_err());
        assert!("1.2.3.4/33".parse::<IpNet>().is_err());
        assert!("2001:db8::1/129".parse::<IpNet>().is_err());
        assert!("1.2.3.4/abc".parse::<IpNet>().is_err());
    }

    #[test]
    fn test_contains_address() {
        let list = Banlist::from_entries(vec![ban(&["10.0.0.0/8", "2001:db8::/32"])]);
        assert!(list.contains(&AddrKey::parse_ip("10.1.1.1:8333").unwrap()));
        assert!(list.contains(&AddrKey::parse_ip("[2001:db8::5]:8333").unwrap()));
        assert!(!list.contains(&AddrKey::parse_ip("1.2.3.4:8333").unwrap()));
    }

    #[test]
    fn test_onion_banned_by_exact_host() {
        let onion = AddrKey::TorV3([3u8; 32], 8333);
        let other = AddrKey::TorV3([4u8; 32], 8333);

        let list = Banlist::from_entries(vec![BanEntry {
            comment: Some("spam".to_owned()),
            nets: Vec::new(),
            hosts: vec![onion.to_string()],
        }]);
        assert!(list.contains(&onion));
        assert!(!list.contains(&other));

        // A CIDR ban must never catch an onion address, which has no IP.
        let cidr = Banlist::from_entries(vec![ban(&["0.0.0.0/0", "::/0"])]);
        assert!(!cidr.contains(&onion));
    }

    #[test]
    fn test_add_skips_duplicates() {
        let mut list = Banlist::from_entries(vec![]);
        assert_eq!(list.add(ban(&["10.0.0.0/8", "1.2.3.4/32"])), 2);
        assert_eq!(list.len(), 2);
        // Both already present: nothing added, and no empty entry appended.
        assert_eq!(list.add(ban(&["10.0.0.0/8"])), 0);
        assert_eq!(list.entries().len(), 1);
        // Partial overlap adds only what is new.
        assert_eq!(list.add(ban(&["10.0.0.0/8", "9.9.9.9/32"])), 1);
        assert_eq!(list.len(), 3);
    }

    #[test]
    fn test_save_load_round_trip() {
        let dir = std::env::temp_dir().join(format!("p2p-observer-ban-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("banlist.json");

        let mut list = Banlist::load(&path).unwrap();
        assert!(list.is_empty(), "a missing file is an empty list");
        list.add(BanEntry {
            comment: Some("bad ASN".to_owned()),
            nets: vec!["10.0.0.0/8".parse().unwrap()],
            hosts: vec![AddrKey::TorV3([9u8; 32], 8333).to_string()],
        });
        list.save().unwrap();
        assert!(!path.with_extension("json.tmp").exists());

        let reloaded = Banlist::load(&path).unwrap();
        assert_eq!(reloaded.len(), 2);
        assert_eq!(reloaded.entries()[0].comment.as_deref(), Some("bad ASN"));
        assert!(reloaded.contains(&AddrKey::parse_ip("10.1.1.1:8333").unwrap()));
        assert!(reloaded.contains(&AddrKey::TorV3([9u8; 32], 8333)));

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Operator intent must not be silently discarded.
    #[test]
    fn test_malformed_file_is_an_error() {
        let dir = std::env::temp_dir().join(format!("p2p-observer-ban-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("banlist.json");
        std::fs::write(&path, "{ not a list }").unwrap();

        assert!(Banlist::load(&path).is_err());

        std::fs::remove_dir_all(&dir).ok();
    }
}
