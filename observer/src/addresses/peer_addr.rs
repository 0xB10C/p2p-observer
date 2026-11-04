//! Compact peer addresses.
//!
//! The runtime book is keyed by [`PeerAddr`]: a network tag plus the raw
//! address bytes and port. Onion and I2P addresses are held as their 32-byte
//! form rather than their text form, so an entry costs the same regardless of
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
pub enum PeerAddr {
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
/// operator's enabled-networks configuration without matching on the variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Net {
    Ipv4,
    Ipv6,
    TorV3,
    I2p,
    Cjdns,
}

impl PeerAddr {
    pub fn net(&self) -> Net {
        match self {
            PeerAddr::Ipv4(..) => Net::Ipv4,
            PeerAddr::Ipv6(..) => Net::Ipv6,
            PeerAddr::TorV3(..) => Net::TorV3,
            PeerAddr::I2p(..) => Net::I2p,
            PeerAddr::Cjdns(..) => Net::Cjdns,
        }
    }

    pub fn port(&self) -> u16 {
        match self {
            PeerAddr::Ipv4(_, p)
            | PeerAddr::Ipv6(_, p)
            | PeerAddr::TorV3(_, p)
            | PeerAddr::I2p(_, p)
            | PeerAddr::Cjdns(_, p) => *p,
        }
    }

    /// The IP address, for the networks that have one. `None` for Tor and I2P,
    /// which are not reachable by IP and cannot be matched against CIDR bans.
    pub fn ip(&self) -> Option<IpAddr> {
        match self {
            PeerAddr::Ipv4(b, _) => Some(IpAddr::V4(Ipv4Addr::from(*b))),
            PeerAddr::Ipv6(b, _) | PeerAddr::Cjdns(b, _) => Some(IpAddr::V6(Ipv6Addr::from(*b))),
            PeerAddr::TorV3(..) | PeerAddr::I2p(..) => None,
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
            PeerAddr::Ipv4(b, _) => {
                let ip = Ipv4Addr::from(*b);
                !ip.is_unspecified()
                    && !ip.is_loopback()
                    && !ip.is_private()
                    && !ip.is_link_local()
                    && !ip.is_multicast()
                    && !ip.is_broadcast()
            }
            PeerAddr::Ipv6(b, _) => {
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
            PeerAddr::TorV3(key, _) => key != &[0u8; 32],
            PeerAddr::I2p(hash, _) => hash != &[0u8; 32],
            PeerAddr::Cjdns(b, _) => !Ipv6Addr::from(*b).is_unspecified(),
        }
    }

    /// Parse any address this tool prints, which is the contract: whatever
    /// [`Display`](std::fmt::Display) renders, this reads back.
    ///
    /// Used for bootstrap addresses and for the ones an operator hands to the
    /// RPC. It used to take IPs only, so the two RPC methods that take an
    /// address -- `addresses.add` and `addresses.inspect` -- refused the onion,
    /// I2P and CJDNS addresses the tool had just finished printing in the
    /// answer to `addresses.list`.
    ///
    /// Validity is not this function's business: `fc00::/8` is what makes an
    /// address reachable over CJDNS and a non-zero key is what makes an onion
    /// service a service, and both are [`Self::is_routable`]'s question. This
    /// one only has to be the inverse of the renderer, so that the set of
    /// things it accepts and the set of things we print are the same set.
    pub fn parse(s: &str) -> Option<Self> {
        // Base32 is case-insensitive, and an operator pasting an address from
        // somewhere else should not have to care which case it arrived in.
        // Hex IPv6 and the two prefixes are no different, so the whole string
        // is lowered once here and nothing below looks at the original.
        let lower = s.to_ascii_lowercase();

        // The prefix is the only thing separating a CJDNS peer from the same
        // bytes reached over plain IPv6, which is why the renderer prints it.
        if let Some(rest) = lower.strip_prefix("cjdns:") {
            let sa: SocketAddr = rest.parse().ok()?;
            let IpAddr::V6(ip) = sa.ip() else {
                return None;
            };
            return Some(PeerAddr::Cjdns(ip.octets(), sa.port()));
        }

        if let Some((host, port)) = lower.rsplit_once(':')
            && let Ok(port) = port.parse::<u16>()
        {
            if let Some(b32) = host.strip_suffix(".b32.i2p") {
                let hash: [u8; 32] = base32_decode(b32)?.try_into().ok()?;
                return Some(PeerAddr::I2p(hash, port));
            }
            if host.ends_with(".onion") {
                return Some(PeerAddr::TorV3(onion_key(host)?, port));
            }
        }

        // Not prefixed, not suffixed: a socket address in its own right.
        let sa: SocketAddr = lower.parse().ok()?;
        Some(Self::from_socket_addr(sa))
    }

    pub fn from_socket_addr(sa: SocketAddr) -> Self {
        match sa.ip() {
            IpAddr::V4(ip) => PeerAddr::Ipv4(ip.octets(), sa.port()),
            IpAddr::V6(ip) => {
                // An IPv4-mapped address is an IPv4 peer, not an IPv6 one.
                if let Some(v4) = ip.to_ipv4_mapped() {
                    PeerAddr::Ipv4(v4.octets(), sa.port())
                } else if ip.octets()[0] == 0xfc {
                    PeerAddr::Cjdns(ip.octets(), sa.port())
                } else {
                    PeerAddr::Ipv6(ip.octets(), sa.port())
                }
            }
        }
    }
}

impl TryFrom<&AddrV2Message> for PeerAddr {
    type Error = ();

    fn try_from(msg: &AddrV2Message) -> Result<Self, ()> {
        match &msg.addr {
            AddrV2::Ipv4(ip) => Ok(PeerAddr::Ipv4(ip.octets(), msg.port)),
            // Through `from_socket_addr` rather than straight into the Ipv6
            // variant, so that the two things it normalises are normalised
            // here too. A peer is free to put an fc00::/8 address or an
            // IPv4-mapped one in this field, and an `Ipv6` variant holding
            // either is a peer this tool cannot reach and cannot look up:
            // `is_routable` lets fc00::/8 through on the grounds that CJDNS
            // has its own variant, and the renderer prints no `cjdns:`
            // prefix for an `Ipv6`, so the address an operator reads in
            // `addresses.list` names a different entry in
            // `addresses.inspect`. An IPv4-mapped one is the same peer as the
            // plain IPv4 address under a second key.
            AddrV2::Ipv6(ip) => Ok(Self::from_socket_addr(SocketAddr::new(
                IpAddr::V6(*ip),
                msg.port,
            ))),
            AddrV2::TorV3(key) => Ok(PeerAddr::TorV3(*key, msg.port)),
            AddrV2::I2p(hash) => Ok(PeerAddr::I2p(*hash, msg.port)),
            AddrV2::Cjdns(ip) => Ok(PeerAddr::Cjdns(ip.octets(), msg.port)),
            // An address type we don't understand. We can't dial it and we
            // can't meaningfully store it, so drop it.
            AddrV2::Unknown(..) => Err(()),
        }
    }
}

impl TryFrom<&Address> for PeerAddr {
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

/// The inverse of [`base32_encode`].
///
/// Refuses a character outside the alphabet, and refuses trailing bits that
/// are not zero. The second one is what keeps the mapping one to one: the
/// encoder pads the last group with zeros, so a group padded with anything
/// else is a string the encoder would never have produced, and accepting it
/// would give two spellings of one address.
fn base32_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 5 / 8);
    let mut bits: u32 = 0;
    let mut n = 0;

    for byte in s.bytes() {
        let value = match byte {
            b'a'..=b'z' => byte - b'a',
            b'2'..=b'7' => byte - b'2' + 26,
            _ => return None,
        };
        bits = (bits << 5) | u32::from(value);
        n += 5;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    if n > 0 && bits & ((1 << n) - 1) != 0 {
        return None;
    }
    Some(out)
}

/// The key a `.onion` hostname names, if it is a well-formed v3 one.
///
/// Checked by re-rendering rather than by picking the checksum and version
/// out of the decoded bytes: both are derived from the key, so the hostname
/// the encoder would print for the key it decoded to is the only thing they
/// can agree with. That also means this cannot drift from the renderer.
///
/// The check matters because the checksum is the only thing between a typo
/// and a different service: the bytes of a mistyped onion address are a
/// perfectly good 32-byte key, just nobody's.
fn onion_key(host: &str) -> Option<[u8; 32]> {
    let raw = base32_decode(host.strip_suffix(".onion")?)?;
    let key: [u8; 32] = raw.get(..32)?.try_into().ok()?;
    (raw.len() == 35 && onion_host(&key) == host).then_some(key)
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

impl std::fmt::Display for PeerAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PeerAddr::Ipv4(b, p) => write!(f, "{}:{}", Ipv4Addr::from(*b), p),
            PeerAddr::Ipv6(b, p) => write!(f, "[{}]:{}", Ipv6Addr::from(*b), p),
            PeerAddr::TorV3(key, p) => write!(f, "{}:{}", onion_host(key), p),
            PeerAddr::I2p(hash, p) => write!(f, "{}.b32.i2p:{}", base32_encode(hash), p),
            PeerAddr::Cjdns(b, p) => write!(f, "cjdns:[{}]:{}", Ipv6Addr::from(*b), p),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;

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
        let mapped = PeerAddr::parse("[::ffff:1.2.3.4]:8333").unwrap();
        assert_eq!(mapped, PeerAddr::Ipv4([1, 2, 3, 4], 8333));
        assert_eq!(mapped, PeerAddr::parse("1.2.3.4:8333").unwrap());
    }

    #[test]
    fn test_cjdns_range_gets_its_own_tag() {
        let addr = PeerAddr::parse("[fc00::1]:8333").unwrap();
        assert_eq!(addr.net(), Net::Cjdns);
        // Same bytes, different network: distinct entries, because dialling
        // them requires different networks to be enabled.
        let bytes = Ipv6Addr::new(0xfc00, 0, 0, 0, 0, 0, 0, 1).octets();
        assert_eq!(addr, PeerAddr::Cjdns(bytes, 8333));
        assert_ne!(addr, PeerAddr::Ipv6(bytes, 8333));
    }

    #[test]
    fn test_routability() {
        assert!(PeerAddr::parse("1.2.3.4:8333").unwrap().is_routable());
        // Port 0 is never dialable.
        assert!(!PeerAddr::parse("1.2.3.4:0").unwrap().is_routable());
        assert!(!PeerAddr::parse("127.0.0.1:8333").unwrap().is_routable());
        assert!(!PeerAddr::parse("10.0.0.1:8333").unwrap().is_routable());
        assert!(!PeerAddr::parse("169.254.0.1:8333").unwrap().is_routable());
        assert!(!PeerAddr::parse("[::1]:8333").unwrap().is_routable());
        assert!(!PeerAddr::parse("[fe80::1]:8333").unwrap().is_routable());
        assert!(!PeerAddr::parse("[fd00::1]:8333").unwrap().is_routable());
        assert!(PeerAddr::parse("[2001:db8::1]:8333").unwrap().is_routable());
        // CJDNS lives in fc00::/8, which the IPv6 arm rejects as unique-local.
        // Its own variant must not inherit that rejection.
        assert!(PeerAddr::parse("[fc00::1]:8333").unwrap().is_routable());
        assert!(!PeerAddr::TorV3([0u8; 32], 8333).is_routable());
        assert!(PeerAddr::TorV3([7u8; 32], 8333).is_routable());
    }

    #[test]
    fn test_display_round_trips_for_ip_networks() {
        for s in ["1.2.3.4:8333", "[2001:db8::1]:8333"] {
            assert_eq!(PeerAddr::parse(s).unwrap().to_string(), s);
        }
    }

    /// Everything the renderer prints, the parser reads back -- for every
    /// network, not only the two that are socket addresses.
    ///
    /// This is the property the RPC rests on: `addresses.list` prints these
    /// and `addresses.add` and `addresses.inspect` take them, so a rendering
    /// the parser refuses is an address an operator can see in one answer and
    /// cannot ask about in the next. Which is exactly what onion, I2P and
    /// CJDNS addresses were.
    ///
    /// Driven by a counter rather than a generator so that a failure names the
    /// case that failed and the next run fails the same way.
    #[test]
    fn test_every_rendering_parses_back_to_the_address_it_came_from() {
        for i in 0..512u32 {
            let four = i.to_le_bytes();
            let port = 8333u16.wrapping_add(i as u16);

            let mut key = [0u8; 32];
            for (j, slot) in key.iter_mut().enumerate() {
                *slot = (i as u8).wrapping_mul(j as u8 + 1).wrapping_add(j as u8);
            }
            // Global unicast: an `Ipv6` variant never holds an fc00::/8 or an
            // IPv4-mapped address, because the two conversions that build one
            // send both of those somewhere else.
            let mut sixteen = [0u8; 16];
            sixteen[0] = 0x20;
            sixteen[1..5].copy_from_slice(&four);
            sixteen[15] = i as u8;
            let mut cjdns = sixteen;
            cjdns[0] = 0xfc;
            cjdns[1] = 0x00;

            for addr in [
                PeerAddr::Ipv4(four, port),
                PeerAddr::Ipv6(sixteen, port),
                PeerAddr::TorV3(key, port),
                PeerAddr::I2p(key, port),
                PeerAddr::Cjdns(cjdns, port),
            ] {
                let text = addr.to_string();
                assert_eq!(PeerAddr::parse(&text), Some(addr), "{text}");
                // And in the case it was pasted in, which for an onion address
                // copied out of a directory is often not the one we print.
                assert_eq!(
                    PeerAddr::parse(&text.to_uppercase()),
                    Some(addr),
                    "{}",
                    text.to_uppercase()
                );
            }
        }
    }

    /// A mistyped onion address names nobody, and is refused rather than
    /// resolved to whoever it happens to spell.
    ///
    /// The bytes of a mistyped onion address are a perfectly good 32-byte
    /// key -- just nobody's -- so the checksum is the only thing between a
    /// typo and dialling a stranger. Everything else here is the same
    /// question for a different field.
    #[test]
    fn test_an_address_that_cannot_have_been_printed_is_refused() {
        let onion = PeerAddr::TorV3([7u8; 32], 8333).to_string();
        assert!(PeerAddr::parse(&onion).is_some(), "{onion}");
        let typo = format!(
            "{}{}",
            if onion.starts_with('a') { 'b' } else { 'a' },
            &onion[1..]
        );
        assert_eq!(PeerAddr::parse(&typo), None, "{typo}");

        // The right shape and the wrong length: 56 base32 characters for an
        // onion address, 52 for an I2P hash, and nothing else.
        assert_eq!(PeerAddr::parse("aaaa.onion:8333"), None);
        assert_eq!(PeerAddr::parse("aaaa.b32.i2p:8333"), None);
        // Characters outside the alphabet. 0, 1, 8 and 9 are not in it.
        assert_eq!(PeerAddr::parse("0.b32.i2p:8333"), None);
        // A port that is not one, and no port at all.
        assert_eq!(PeerAddr::parse(&onion.replace(":8333", ":70000")), None);
        assert_eq!(PeerAddr::parse(&onion.replace(":8333", "")), None);
        // `cjdns:` names an IPv6 address and nothing else.
        assert_eq!(PeerAddr::parse("cjdns:1.2.3.4:8333"), None);
        assert_eq!(PeerAddr::parse("cjdns:nonsense"), None);

        // And the padding rule. The last base32 character of a 32-byte hash
        // carries one real bit and four zeros; a character that sets any of
        // those four is a string the renderer would never have produced, and
        // taking it would give two spellings of one address.
        let i2p = PeerAddr::I2p([0u8; 32], 8333).to_string();
        let (b32, rest) = i2p.split_at(52);
        let repadded = format!("{}b{}", &b32[..51], rest);
        assert_eq!(PeerAddr::parse(&repadded), None, "{repadded}");
    }

    /// An address gossiped in the addrv2 IPv6 field gets the same treatment a
    /// socket address does.
    ///
    /// A peer chooses which field it puts an address in, and nothing stops it
    /// putting an fc00::/8 or an IPv4-mapped address in this one. Both used to
    /// land in the `Ipv6` variant, and an `Ipv6` holding either is a peer this
    /// tool cannot reach and cannot look up: `is_routable` lets fc00::/8
    /// through on the grounds that CJDNS has its own variant, the renderer
    /// prints no `cjdns:` prefix for an `Ipv6`, so what an operator reads out
    /// of `addresses.list` names a different entry in `addresses.inspect`.
    /// The IPv4-mapped one is the same peer as the plain address under a
    /// second key, dialled twice and counted twice.
    #[test]
    fn test_a_gossiped_ipv6_is_normalised_like_any_other() {
        use common::p2p::ServiceFlags;

        let gossiped = |ip: Ipv6Addr| {
            PeerAddr::try_from(&AddrV2Message {
                time: 1_700_000_000,
                services: ServiceFlags::NETWORK,
                addr: AddrV2::Ipv6(ip),
                port: 8333,
            })
            .expect("an ipv6 address is not an address type we refuse")
        };

        // CJDNS, which reaching requires a network of its own to be enabled.
        assert_eq!(
            gossiped("fc00::1".parse().unwrap()),
            PeerAddr::Cjdns(Ipv6Addr::from_str("fc00::1").unwrap().octets(), 8333)
        );
        // An IPv4 peer, spelled the long way.
        assert_eq!(
            gossiped("::ffff:1.2.3.4".parse().unwrap()),
            PeerAddr::Ipv4([1, 2, 3, 4], 8333)
        );
        // And an ordinary one, which is left alone.
        assert_eq!(
            gossiped("2001:db8::1".parse().unwrap()),
            PeerAddr::Ipv6(Ipv6Addr::from_str("2001:db8::1").unwrap().octets(), 8333)
        );
    }

    /// The whole point of the compact form: every network costs the same, and
    /// onion addresses are 32 bytes rather than a 62-character string.
    #[test]
    fn test_peer_addr_is_compact() {
        assert!(
            std::mem::size_of::<PeerAddr>() <= 40,
            "PeerAddr grew to {} bytes",
            std::mem::size_of::<PeerAddr>()
        );
    }
}
