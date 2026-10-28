//! IP address metadata: the autonomous system an address belongs to, looked
//! up in a Bitcoin Core asmap file, and the AS's name and country from the
//! dataset embedded in the `asinfo` crate. The same lookup spytrap's
//! websocket tool does.

use std::net::IpAddr;
use std::path::Path;

use common::anyhow::{Context, Result};
use common::serde::Serialize;

/// What we know about the network an IP address belongs to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(crate = "common::serde")]
pub struct IpInfo {
    /// Autonomous system number; 0 when the asmap has no mapping.
    pub asn: u32,
    /// Short AS handle, e.g. `AMAZON-02`; empty when unknown.
    pub handle: String,
    /// AS description, e.g. `Amazon.com, Inc.`; empty when unknown.
    pub description: String,
    /// ISO 3166-1 alpha-2 country code of the AS registration; empty when unknown.
    pub country: String,
}

/// Resolves addresses with an optional asmap file.
#[derive(Debug, Default)]
pub struct IpLookup {
    asmap: Option<asmap::Asmap>,
}

impl IpLookup {
    /// A lookup without an asmap: every address resolves to `None`.
    pub fn none() -> Self {
        Self::default()
    }

    /// Loads and validates an asmap file (e.g. `latest_asmap.dat` from
    /// bitcoin-core/asmap-data).
    pub fn from_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let asmap = asmap::Asmap::from_file(path)
            .with_context(|| format!("loading asmap from {}", path.display()))?;
        Ok(IpLookup { asmap: Some(asmap) })
    }

    /// Builds a lookup from raw asmap bytes.
    pub fn from_bytes(data: Vec<u8>) -> Result<Self> {
        let asmap = asmap::Asmap::from_bytes(data).context("validating asmap data")?;
        Ok(IpLookup { asmap: Some(asmap) })
    }

    /// Whether an asmap is loaded.
    pub fn available(&self) -> bool {
        self.asmap.is_some()
    }

    /// AS information for an address, `None` without an asmap. Addresses that
    /// are not globally routable report ASN 0 even if the asmap has a mapping
    /// for them (asmap files cover such space with whatever BGP announces).
    pub fn lookup(&self, ip: IpAddr) -> Option<IpInfo> {
        let asmap = self.asmap.as_ref()?;
        let asn = if is_routable(ip) { asmap.lookup(ip) } else { 0 };
        Some(describe(asn))
    }
}

/// Rough "globally routable" check: loopback, private, link-local,
/// unique-local and unspecified addresses are not.
pub fn is_routable(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast())
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return is_routable(IpAddr::V4(v4));
            }
            !(v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_unique_local()
                || v6.is_unicast_link_local())
        }
    }
}

/// AS metadata for an ASN; the name fields stay empty for unknown ASNs.
pub fn describe(asn: u32) -> IpInfo {
    match (asn != 0).then(|| asinfo::lookup(asn)).flatten() {
        Some(info) => IpInfo {
            asn,
            handle: info.handle.to_string(),
            description: info.description.to_string(),
            country: info.country.as_str().to_string(),
        },
        None => IpInfo {
            asn,
            handle: String::new(),
            description: String::new(),
            country: String::new(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE: &[u8] = include_bytes!("../tests/fixtures/asmap.raw");

    #[test]
    fn test_without_asmap_nothing_resolves() {
        let lookup = IpLookup::none();
        assert!(!lookup.available());
        assert_eq!(lookup.lookup("8.8.8.8".parse().unwrap()), None);
    }

    #[test]
    fn test_fixture_maps_prefixes() {
        let lookup = IpLookup::from_bytes(FIXTURE.to_vec()).unwrap();
        assert!(lookup.available());
        // 250.0.0.0/8 -> AS1000 and 101.5.0.0/16 -> AS5 in the fixture.
        assert_eq!(
            lookup.lookup("250.1.2.3".parse().unwrap()).unwrap().asn,
            1000
        );
        assert_eq!(lookup.lookup("101.5.42.7".parse().unwrap()).unwrap().asn, 5);
        assert_eq!(
            lookup
                .lookup("::ffff:250.0.0.1".parse().unwrap())
                .unwrap()
                .asn,
            1000
        );
        let unmapped = lookup.lookup("127.0.0.1".parse().unwrap()).unwrap();
        assert_eq!(unmapped.asn, 0);
        assert!(unmapped.description.is_empty());
    }

    #[test]
    fn test_routability() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "192.168.0.1",
            "169.254.1.1",
            "::1",
            "fd00::1",
            "fe80::1",
            "::ffff:10.0.0.1",
        ] {
            assert!(!is_routable(ip.parse().unwrap()), "{ip}");
        }
        for ip in [
            "8.8.8.8",
            "143.20.137.5",
            "2001:4860:4860::8888",
            "::ffff:8.8.8.8",
        ] {
            assert!(is_routable(ip.parse().unwrap()), "{ip}");
        }
    }

    #[test]
    fn test_garbage_asmap_is_rejected() {
        assert!(IpLookup::from_bytes(vec![0xff; 64]).is_err());
    }

    #[test]
    fn test_known_asn_has_metadata() {
        // AS13335 (Cloudflare) is stable across dataset updates.
        let info = describe(13335);
        assert_eq!(info.asn, 13335);
        assert!(!info.handle.is_empty());
        assert!(!info.description.is_empty());
        assert_eq!(info.country.len(), 2);
    }

    #[test]
    fn test_unknown_asn_has_empty_metadata() {
        let info = describe(u32::MAX);
        assert_eq!(info.asn, u32::MAX);
        assert!(info.handle.is_empty());
    }
}
