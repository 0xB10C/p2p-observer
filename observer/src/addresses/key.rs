//! Compact address keys.
//!
//! The runtime table is keyed by [`AddrKey`]: a network tag plus the raw
//! address bytes and port. Onion and I2P addresses are held as their 32-byte
//! keys rather than their text form, so an entry costs the same regardless of
//! network and the human-readable encoding is computed only for display.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use common::{
    p2p::address::{AddrV2, AddrV2Message, Address},
    serde::{Deserialize, Serialize},
};

/// A peer address, stored in its most compact form.
///
/// Sized by its largest variant (a 32-byte Tor or I2P key), so an enum costs
/// exactly what a flat tagged byte array would while keeping each network's
/// address length in the type instead of in a comment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(crate = "common::serde")]
pub enum AddrKey {
    Ipv4([u8; 4], u16),
    Ipv6([u8; 16], u16),
    /// Tor v3 onion service, as the raw 32-byte ed25519 public key.
    TorV3([u8; 32], u16),
    /// I2P destination, as the raw 32-byte hash.
    I2p([u8; 32], u16),
    /// CJDNS uses the fc00::/8 range and needs its own tag: the same bytes
    /// reached over CJDNS and over plain IPv6 are different peers to us,
    /// because reaching them requires a different network to be enabled.
    Cjdns([u8; 16], u16),
}

/// Which network an address belongs to. Used to check the address against the
/// operator's enabled-networks configuration without matching on the key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Net {
    Ipv4,
    Ipv6,
    TorV3,
    I2p,
    Cjdns,
}

impl AddrKey {
    pub fn net(&self) -> Net {
        match self {
            AddrKey::Ipv4(..) => Net::Ipv4,
            AddrKey::Ipv6(..) => Net::Ipv6,
            AddrKey::TorV3(..) => Net::TorV3,
            AddrKey::I2p(..) => Net::I2p,
            AddrKey::Cjdns(..) => Net::Cjdns,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            AddrKey::Ipv4(_, p)
            | AddrKey::Ipv6(_, p)
            | AddrKey::TorV3(_, p)
            | AddrKey::I2p(_, p)
            | AddrKey::Cjdns(_, p) => *p,
        }
    }

    /// The IP address, for the networks that have one. `None` for Tor and I2P,
    /// which are not reachable by IP and cannot be matched against CIDR bans.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            AddrKey::Ipv4(b, _) => Some(IpAddr::V4(Ipv4Addr::from(*b))),
            AddrKey::Ipv6(b, _) | AddrKey::Cjdns(b, _) => Some(IpAddr::V6(Ipv6Addr::from(*b))),
            AddrKey::TorV3(..) | AddrKey::I2p(..) => None,
        }
    }

    /// A socket address for the networks that can be dialled directly.
    /// `None` for Tor and I2P, which go through a proxy by name.
    pub fn socket_addr(&self) -> Option<SocketAddr> {
        self.ip().map(|ip| SocketAddr::new(ip, self.port()))
    }

    /// `true` if the address is globally routable and worth storing at all.
    pub fn is_routable(&self) -> bool {
        if self.port() == 0 {
            return false;
        }
        match self {
            AddrKey::Ipv4(b, _) => {
                let ip = Ipv4Addr::from(*b);
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_private()
                    && !ip.is_link_local()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
            }
            AddrKey::Ipv6(b, _) => {
                let ip = Ipv6Addr::from(*b);
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_multicast()
                    // fe80::/10 link-local
                    && (ip.segments()[0] & 0xffc0) != 0xfe80
                    // fd00::/8 unique local. fc00::/8 is CJDNS and has its own
                    // variant, so it is not excluded here.
                    && ip.octets()[0] != 0xfd
            }
            AddrKey::TorV3(key, _) => key != &[0u8; 32],
            AddrKey::I2p(hash, _) => hash != &[0u8; 32],
            AddrKey::Cjdns(b, _) => !Ipv6Addr::from(*b).is_unspecified(),
        }
    }

    /// Parse an `ip:port` or `[ipv6]:port` string. Used for bootstrap and
    /// operator-supplied addresses, which are always given by IP.
    pub fn parse_ip(s: &str) -> Option<Self> {
        let sa: SocketAddr = s.parse().ok()?;
        Some(Self::from_socket_addr(sa))
    }

    pub fn from_socket_addr(sa: SocketAddr) -> Self {
        match sa.ip() {
            IpAddr::V4(ip) => AddrKey::Ipv4(ip.octets(), sa.port()),
            IpAddr::V6(ip) => {
                // An IPv4-mapped address is an IPv4 peer, not an IPv6 one.
                if let Some(v4) = ip.to_ipv4_mapped() {
                    AddrKey::Ipv4(v4.octets(), sa.port())
                } else if ip.octets()[0] == 0xfc {
                    AddrKey::Cjdns(ip.octets(), sa.port())
                } else {
                    AddrKey::Ipv6(ip.octets(), sa.port())
                }
            }
        }
    }
}

impl TryFrom<&AddrV2Message> for AddrKey {
    type Error = ();

    fn try_from(msg: &AddrV2Message) -> Result<Self, ()> {
        match &msg.addr {
            AddrV2::Ipv4(ip) => Ok(AddrKey::Ipv4(ip.octets(), msg.port)),
            AddrV2::Ipv6(ip) => Ok(AddrKey::Ipv6(ip.octets(), msg.port)),
            AddrV2::TorV3(key) => Ok(AddrKey::TorV3(*key, msg.port)),
            AddrV2::I2p(hash) => Ok(AddrKey::I2p(*hash, msg.port)),
            AddrV2::Cjdns(ip) => Ok(AddrKey::Cjdns(ip.octets(), msg.port)),
            // An address type we don't understand. We can't dial it and we
            // can't meaningfully store it, so drop it.
            AddrV2::Unknown(..) => Err(()),
        }
    }
}

impl TryFrom<&Address> for AddrKey {
    type Error = ();

    fn try_from(addr: &Address) -> Result<Self, ()> {
        addr.socket_addr()
            .map(Self::from_socket_addr)
            .map_err(|_| ())
    }
}

/// Lowercase RFC 4648 base32, no padding. Used for onion addresses.
fn base32_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz234567";
    let mut out = String::with_capacity((bytes.len() * 8).div_ceil(5));
    let mut bits = 0u64;
    let mut n = 0;

    for &byte in bytes {
        bits = (bits << 8) | u64::from(byte);
        n += 8;
        while n >= 5 {
            n -= 5;
            out.push(ALPHABET[((bits >> n) & 0x1f) as usize] as char);
        }
    }
    if n > 0 {
        out.push(ALPHABET[((bits << (5 - n)) & 0x1f) as usize] as char);
    }
    out
}

/// Render a Tor v3 public key as its `.onion` hostname.
///
/// The hostname is base32(pubkey || checksum || version) where the checksum is
/// the first two bytes of SHA3-256(".onion checksum" || pubkey || version) and
/// version is 3. Always 56 base32 characters plus the suffix.
fn onion_host(key: &[u8; 32]) -> String {
    use sha3::Digest;
    const VERSION: u8 = 0x03;

    let hash = sha3::Sha3_256::new()
        .chain_update(b".onion checksum")
        .chain_update(key)
        .chain_update([VERSION])
        .finalize();

    let mut bytes = [0u8; 35];
    bytes[..32].copy_from_slice(key);
    bytes[32..34].copy_from_slice(&hash[..2]);
    bytes[34] = VERSION;

    format!("{}.onion", base32_encode(&bytes))
}

impl std::fmt::Display for AddrKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AddrKey::Ipv4(b, p) => write!(f, "{}:{}", Ipv4Addr::from(*b), p),
            AddrKey::Ipv6(b, p) => write!(f, "[{}]:{}", Ipv6Addr::from(*b), p),
            AddrKey::TorV3(key, p) => write!(f, "{}:{}", onion_host(key), p),
            AddrKey::I2p(hash, p) => write!(f, "{}.b32.i2p:{}", base32_encode(hash), p),
            AddrKey::Cjdns(b, p) => write!(f, "cjdns:[{}]:{}", Ipv6Addr::from(*b), p),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_base32_rfc4648_vectors() {
        assert_eq!(base32_encode(b""), "");
        assert_eq!(base32_encode(b"f"), "my");
        assert_eq!(base32_encode(b"fo"), "mzxq");
        assert_eq!(base32_encode(b"foo"), "mzxw6");
        assert_eq!(base32_encode(b"foob"), "mzxw6yq");
        assert_eq!(base32_encode(b"fooba"), "mzxw6ytb");
        assert_eq!(base32_encode(b"foobar"), "mzxw6ytboi");
    }

    #[test]
    fn test_onion_host_shape() {
        let host = onion_host(&[0u8; 32]);
        assert!(host.ends_with(".onion"));
        let label = host.strip_suffix(".onion").unwrap();
        assert_eq!(label.len(), 56);
        assert!(
            label
                .chars()
                .all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c))
        );
        assert_ne!(onion_host(&[0u8; 32]), onion_host(&[1u8; 32]));
    }

    #[test]
    fn test_ipv4_mapped_is_stored_as_ipv4() {
        // ::ffff:1.2.3.4 is the same peer as 1.2.3.4, and must not occupy a
        // second entry under the IPv6 tag.
        let mapped = AddrKey::parse_ip("[::ffff:1.2.3.4]:8333").unwrap();
        assert_eq!(mapped, AddrKey::Ipv4([1, 2, 3, 4], 8333));
        assert_eq!(mapped, AddrKey::parse_ip("1.2.3.4:8333").unwrap());
    }

    #[test]
    fn test_cjdns_range_gets_its_own_tag() {
        let key = AddrKey::parse_ip("[fc00::1]:8333").unwrap();
        assert_eq!(key.net(), Net::Cjdns);
        // Same bytes, different network: distinct entries, because dialling
        // them requires different networks to be enabled.
        let bytes = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(key, AddrKey::Cjdns(bytes, 8333));
        assert_ne!(key, AddrKey::Ipv6(bytes, 8333));
    }

    #[test]
    fn test_routability() {
        assert!(AddrKey::parse_ip("1.2.3.4:8333").unwrap().is_routable());
        // Port 0 is never dialable.
        assert!(!AddrKey::parse_ip("1.2.3.4:0").unwrap().is_routable());
        assert!(!AddrKey::parse_ip("127.0.0.1:8333").unwrap().is_routable());
        assert!(!AddrKey::parse_ip("10.0.0.1:8333").unwrap().is_routable());
        assert!(!AddrKey::parse_ip("169.254.0.1:8333").unwrap().is_routable());
        assert!(!AddrKey::parse_ip("[::1]:8333").unwrap().is_routable());
        assert!(!AddrKey::parse_ip("[fe80::1]:8333").unwrap().is_routable());
        assert!(!AddrKey::parse_ip("[fd00::1]:8333").unwrap().is_routable());
        assert!(
            AddrKey::parse_ip("[2001:db8::1]:8333")
                .unwrap()
                .is_routable()
        );
        // CJDNS lives in fc00::/8, which the IPv6 arm rejects as unique-local.
        // Its own variant must not inherit that rejection.
        assert!(AddrKey::parse_ip("[fc00::1]:8333").unwrap().is_routable());
        assert!(!AddrKey::TorV3([0u8; 32], 8333).is_routable());
        assert!(AddrKey::TorV3([7u8; 32], 8333).is_routable());
    }

    #[test]
    fn test_display_round_trips_for_ip_networks() {
        for s in ["1.2.3.4:8333", "[2001:db8::1]:8333"] {
            assert_eq!(AddrKey::parse_ip(s).unwrap().to_string(), s);
        }
    }

    /// The whole point of the compact key: every network costs the same, and
    /// onion addresses are 32 bytes rather than a 62-character string.
    #[test]
    fn test_key_is_compact() {
        assert!(
            std::mem::size_of::<AddrKey>() <= 40,
            "AddrKey grew to {} bytes",
            std::mem::size_of::<AddrKey>()
        );
    }
}
