//! Label values, and the rule that every one of them is bounded.
//!
//! A Prometheus series is kept for every distinct label combination ever
//! seen, so a label a peer gets to choose -- its user agent, its protocol
//! version, the commands it sends -- is a label the network gets to grow.
//! Nothing here reaches a metric unnormalised, and the values that still
//! come from the peer afterwards go through [`Bounded`], which caps how many
//! distinct values one label can take.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr};

/// The label value anything past a cap, or outside an allowlist, counts as.
pub const OTHER: &str = "other";

/// How many distinct user agents get a series of their own.
pub const USER_AGENT_CAP: usize = 128;
/// How many distinct protocol versions get a series of their own.
pub const PROTOCOL_VERSION_CAP: usize = 32;
/// Longest user agent label kept after normalising.
const USER_AGENT_MAX_CHARS: usize = 64;

/// A label whose distinct values are capped. The first `cap` values seen
/// are themselves; every later new value is [`OTHER`]. Which values make the
/// cut depends on what arrived first, which is good enough for the common
/// clients and keeps the long tail to one series.
#[derive(Debug)]
pub struct Bounded {
    cap: usize,
    seen: HashSet<String>,
}

impl Bounded {
    pub fn new(cap: usize) -> Self {
        Bounded {
            cap,
            seen: HashSet::new(),
        }
    }

    pub fn label<'a>(&'a mut self, value: &'a str) -> &'a str {
        if self.seen.contains(value) {
            return value;
        }
        if self.seen.len() < self.cap {
            self.seen.insert(value.to_owned());
            return value;
        }
        OTHER
    }
}

/// A prost enum name as a label: the message prefix off, lowercase.
/// `DISCONNECT_REASON_PEER_CLOSED` with prefix `DISCONNECT_REASON_` is
/// `peer_closed`.
pub fn enum_label(name: &str, prefix: &str) -> String {
    name.strip_prefix(prefix)
        .unwrap_or(name)
        .to_ascii_lowercase()
}

/// The transport version as announced: `v1`, `v2`, or `unknown` when none
/// was settled on.
pub fn transport(version: Option<u32>) -> &'static str {
    match version {
        Some(1) => "v1",
        Some(2) => "v2",
        _ => "unknown",
    }
}

/// The client behind a user agent, without what makes user agents many.
///
/// Comments in parentheses go -- that is where distributions, forks and
/// hand-edited strings put their marks -- and so do the enclosing slashes,
/// leaving the chain of `name:version` segments: `/Satoshi:28.1.0(foo)/` is
/// `Satoshi:28.1.0` and `/Satoshi:28.1.0/Knots:20250305/` is
/// `Satoshi:28.1.0/Knots:20250305`. The result is cut at
/// [`USER_AGENT_MAX_CHARS`], and an empty one is `unknown`.
pub fn user_agent(raw: &str) -> String {
    let mut without_comments = String::with_capacity(raw.len());
    let mut depth = 0usize;
    for c in raw.chars() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            _ if depth == 0 => without_comments.push(c),
            _ => {}
        }
    }
    let joined: String = without_comments
        .split('/')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join("/");
    if joined.is_empty() {
        return "unknown".to_owned();
    }
    joined.chars().take(USER_AGENT_MAX_CHARS).collect()
}

/// P2P commands a peer can send, as a label. Anything not on the list is
/// [`OTHER`]: the command string is whatever the peer put on the wire.
pub fn command(raw: &str) -> &str {
    const KNOWN: &[&str] = &[
        "addr",
        "addrv2",
        "alert",
        "block",
        "blocktxn",
        "cfcheckpt",
        "cfheaders",
        "cfilter",
        "cmpctblock",
        "feefilter",
        "filteradd",
        "filterclear",
        "filterload",
        "getaddr",
        "getblocks",
        "getblocktxn",
        "getcfcheckpt",
        "getcfheaders",
        "getcfilters",
        "getdata",
        "getheaders",
        "headers",
        "inv",
        "mempool",
        "merkleblock",
        "notfound",
        "ping",
        "pong",
        "reject",
        "sendaddrv2",
        "sendcmpct",
        "sendheaders",
        "sendtxrcncl",
        "tx",
        "verack",
        "version",
        "wtxidrelay",
    ];
    if KNOWN.contains(&raw) { raw } else { OTHER }
}

/// Service bits by name, as Bitcoin Core knows them. A bit without a name
/// is `bit_<n>`, which is precisely the bit worth noticing.
pub fn service_bits(services: u64) -> Vec<String> {
    const NAMED: &[(u64, &str)] = &[
        (1, "network"),
        (2, "getutxo"),
        (4, "bloom"),
        (8, "witness"),
        (16, "xthin"),
        (64, "compact_filters"),
        (1 << 10, "network_limited"),
        (1 << 11, "p2p_v2"),
    ];
    if services == 0 {
        return vec!["none".to_owned()];
    }
    (0..64)
        .filter(|bit| services & (1u64 << bit) != 0)
        .map(|bit| {
            NAMED
                .iter()
                .find(|(mask, _)| *mask == 1u64 << bit)
                .map(|(_, name)| (*name).to_owned())
                .unwrap_or_else(|| format!("bit_{bit}"))
        })
        .collect()
}

/// The network of an address as the observer renders it: `1.2.3.4:8333`,
/// `[2001:db8::1]:8333`, `<56 chars>.onion:8333`, `<52 chars>.b32.i2p:8333`,
/// and CJDNS as an IPv6 address in fc00::/8.
pub fn address_net(addr: &str) -> &'static str {
    let Some((host, _port)) = addr.rsplit_once(':') else {
        return OTHER;
    };
    if host.ends_with(".onion") {
        return "onion";
    }
    if host.ends_with(".b32.i2p") {
        return "i2p";
    }
    if let Some(inner) = host.strip_prefix('[').and_then(|h| h.strip_suffix(']')) {
        return match inner.parse::<Ipv6Addr>() {
            Ok(v6) if v6.octets()[0] == 0xfc => "cjdns",
            Ok(_) => "ipv6",
            Err(_) => OTHER,
        };
    }
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => "ipv4",
        // Not how the observer renders IPv6, but a bare one is still one.
        Ok(IpAddr::V6(v6)) if v6.octets()[0] == 0xfc => "cjdns",
        Ok(IpAddr::V6(_)) => "ipv6",
        Err(_) => OTHER,
    }
}

/// The host of a rendered address, so two renderings of one peer compare
/// without their ports.
pub fn host(addr: &str) -> &str {
    addr.rsplit_once(':').map(|(host, _)| host).unwrap_or(addr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_user_agent_drops_comments_and_slashes() {
        assert_eq!(user_agent("/Satoshi:28.1.0/"), "Satoshi:28.1.0");
        assert_eq!(user_agent("/Satoshi:28.1.0(foo; bar)/"), "Satoshi:28.1.0");
        assert_eq!(
            user_agent("/Satoshi:28.1.0/Knots:20250305/"),
            "Satoshi:28.1.0/Knots:20250305"
        );
        assert_eq!(
            user_agent("/Satoshi:27.0.0(nested (deep))/"),
            "Satoshi:27.0.0"
        );
        assert_eq!(user_agent(""), "unknown");
        assert_eq!(user_agent("/(only a comment)/"), "unknown");
        assert_eq!(user_agent("()("), "unknown");
    }

    #[test]
    fn test_user_agent_is_cut() {
        let long = format!("/{}/", "x".repeat(500));
        assert_eq!(user_agent(&long).chars().count(), USER_AGENT_MAX_CHARS);
    }

    #[test]
    fn test_bounded_keeps_the_first_values_and_folds_the_rest() {
        let mut bounded = Bounded::new(2);
        assert_eq!(bounded.label("a"), "a");
        assert_eq!(bounded.label("b"), "b");
        assert_eq!(bounded.label("c"), OTHER);
        assert_eq!(bounded.label("a"), "a");
        assert_eq!(bounded.label("d"), OTHER);
    }

    #[test]
    fn test_enum_label_strips_the_prefix() {
        assert_eq!(
            enum_label("DISCONNECT_REASON_PEER_CLOSED", "DISCONNECT_REASON_"),
            "peer_closed"
        );
        assert_eq!(enum_label("UNRELATED", "DISCONNECT_REASON_"), "unrelated");
    }

    #[test]
    fn test_commands_outside_the_list_are_other() {
        assert_eq!(command("ping"), "ping");
        assert_eq!(command("wtxidrelay"), "wtxidrelay");
        assert_eq!(command("evil\u{0}cmd"), OTHER);
        assert_eq!(command("PING"), OTHER);
    }

    #[test]
    fn test_service_bits_are_named() {
        assert_eq!(service_bits(0), vec!["none"]);
        assert_eq!(
            service_bits(0x40d),
            vec!["network", "bloom", "witness", "network_limited"]
        );
        assert_eq!(service_bits(1 << 40), vec!["bit_40"]);
    }

    #[test]
    fn test_address_net() {
        assert_eq!(address_net("1.2.3.4:8333"), "ipv4");
        assert_eq!(address_net("[2001:db8::1]:8333"), "ipv6");
        assert_eq!(address_net("[fc00::1]:8333"), "cjdns");
        assert_eq!(address_net("[fd00::1]:8333"), "ipv6");
        assert_eq!(address_net("2001:db8::1:8333"), "ipv6");
        assert_eq!(address_net("fc00::1:8333"), "cjdns");
        assert_eq!(
            address_net(&format!("{}.onion:8333", "a".repeat(56))),
            "onion"
        );
        assert_eq!(address_net(&format!("{}.b32.i2p:0", "a".repeat(52))), "i2p");
        assert_eq!(address_net("nonsense"), OTHER);
        assert_eq!(address_net("[nonsense]:1"), OTHER);
        assert_eq!(address_net("host.example:8333"), OTHER);
    }

    #[test]
    fn test_host() {
        assert_eq!(host("1.2.3.4:8333"), "1.2.3.4");
        assert_eq!(host("[::1]:8333"), "[::1]");
        assert_eq!(host("bare"), "bare");
    }

    #[test]
    fn test_transport() {
        assert_eq!(transport(Some(1)), "v1");
        assert_eq!(transport(Some(2)), "v2");
        assert_eq!(transport(Some(3)), "unknown");
        assert_eq!(transport(None), "unknown");
    }
}
