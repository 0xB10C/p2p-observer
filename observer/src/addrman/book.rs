//! The address book and the pick.
//!
//! Everything here is synchronous and takes an explicit `now`, so the whole
//! thing can be driven from tests with a fake clock. The only state that is
//! not persisted is `active`, which exists purely so we never dial an address
//! we already have a task for.

use std::collections::HashMap;

use common::serde::{Deserialize, Serialize};

use super::banlist::Banlist;
use super::peer_addr::{Net, PeerAddr};
use super::policy::{self, Class, Origin, Outcome};

/// Hard ceiling on stored entries. Fake addresses are cheap to broadcast, so
/// the book needs a bound that does not depend on peers behaving.
/// At roughly 70 bytes of payload plus hashmap overhead, 2M entries is a few
/// hundred megabytes.
pub const DEFAULT_CAPACITY: usize = 2_000_000;

/// Upper bound on carried-over per-class credit.
///
/// Credit is a class's unspent share of earlier dial budgets. Every tick each
/// class earns `weight / total * budget`, and starting a dial costs it one
/// whole unit, so a class with no candidates banks its share instead of
/// wasting it — which is what lets a 70/20/10 split hold even at one dial per
/// tick, where no single batch can express it. The cap stops a class that has
/// had nothing to dial for a long stretch from releasing all of it at once the
/// moment a candidate turns up. Spent in `allocate`.
const CREDIT_CAP: f32 = 4.0;

/// What we have learned about which transport a peer speaks.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "common::serde")]
pub enum TransportHint {
    /// Nothing known yet. Try v2, and fall back to v1 inside the same attempt.
    #[default]
    Unknown,
    /// Has spoken v2. Never downgraded by a failure: a failed v2 attempt is a
    /// failed attempt, not evidence the peer dropped support.
    V2,
    /// v2 did not work but v1 did. Dial v1 directly until the peer starts
    /// advertising `NODE_P2P_V2`, which is the only evidence we get that it
    /// has been upgraded.
    V1Only,
}

/// Whether a set of service flags advertises BIP324 support.
fn advertises_v2(services: u64) -> bool {
    const P2P_V2: u64 = 1 << 11;
    services & P2P_V2 != 0
}

/// Whether we currently have a task for an address. Memory only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Phase {
    Dialing,
    Connected,
}

/// What we know about one address.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(crate = "common::serde")]
pub struct Entry {
    /// Service flags, from gossip or from the peer's own version message.
    pub services: u64,
    /// When we last saw this address in gossip. Keeps a failing address alive
    /// while the network still believes in it.
    pub last_announced: u32,
    /// When we last started a dial. 0 means never attempted.
    pub last_attempt: u32,
    /// When we last completed a handshake. 0 means never.
    pub last_success: u32,
    /// Earliest time we may dial this again.
    pub next_attempt: u32,
    /// Consecutive failures since the last success.
    pub failures: u8,
    /// Consecutive sessions that ended suspiciously early.
    pub short_sessions: u8,
    /// Whether the most recent attempt failed. This is the one thing that
    /// separates `Good` from `WasGood`; both have connected at some point.
    pub last_attempt_failed: bool,
    pub origin: Origin,
    pub transport: TransportHint,
}

impl Entry {
    pub(super) fn new(now: u32, services: u64, origin: Origin) -> Self {
        Self {
            services,
            last_announced: now,
            last_attempt: 0,
            last_success: 0,
            // Dialable immediately.
            next_attempt: 0,
            failures: 0,
            short_sessions: 0,
            last_attempt_failed: false,
            origin,
            transport: TransportHint::Unknown,
        }
    }

    pub fn class(&self) -> Class {
        // Keyed on `failures`, not on `last_attempt`. A dial that has started
        // but not reported back has a `last_attempt` and no result, and using
        // that as "has been tried" would classify every address as bad the
        // moment it was first picked -- which also skewed the class weights,
        // because the unknown pool drained into the bad pool as it was dialled.
        // `failures` only moves when a real failure is recorded.
        policy::classify(
            self.failures > 0,
            self.last_success,
            self.last_attempt_failed,
        )
    }

    fn connected_before(&self) -> bool {
        self.last_success > 0
    }
}

/// An address learned from a peer's gossip.
#[derive(Clone, Copy, Debug)]
pub struct Gossiped {
    pub addr: PeerAddr,
    pub services: u64,
    /// The nTime the peer announced, exactly as announced. Carried for the
    /// published event only: no decision here reads a timestamp a peer chose.
    pub ntime: u32,
}

/// An address to dial, with what we know about its transport.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Dial {
    pub addr: PeerAddr,
    pub transport: TransportHint,
}

/// Which networks the operator has enabled.
#[derive(Clone, Copy, Debug)]
pub struct EnabledNets {
    pub ipv4: bool,
    pub ipv6: bool,
    pub tor: bool,
    pub cjdns: bool,
    pub i2p: bool,
}

impl EnabledNets {
    pub fn allows(&self, net: Net) -> bool {
        match net {
            Net::Ipv4 => self.ipv4,
            Net::Ipv6 => self.ipv6,
            Net::TorV3 => self.tor,
            Net::Cjdns => self.cjdns,
            Net::I2p => self.i2p,
        }
    }

    #[cfg(test)]
    pub fn all() -> Self {
        Self {
            ipv4: true,
            ipv6: true,
            tor: true,
            cjdns: true,
            i2p: true,
        }
    }
}

/// A snapshot of book sizes, for logging and the stats RPC.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub total: usize,
    pub unknown: usize,
    pub good: usize,
    pub was_good: usize,
    pub bad: usize,
    pub dialing: usize,
    pub connected: usize,
}

/// xorshift64*. We need spread, not cryptographic quality, and we do not want
/// a dependency for it.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // A zero state is a fixed point for xorshift.
        Self(seed | 1)
    }

    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Uniform in `[0, 1)`.
    fn next_f32(&mut self) -> f32 {
        // Top 24 bits give a float with no rounding to exactly 1.0.
        ((self.next_u64() >> 40) as f32) / (1u32 << 24) as f32
    }

    /// Uniform in `[0, n)`. Returns 0 for n == 0.
    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }
}

/// Reservoir sampler: keeps up to `k` items uniformly at random from a stream
/// of unknown length, so the pick never has to collect or sort the whole book.
struct Reservoir {
    items: Vec<Dial>,
    seen: usize,
    k: usize,
}

impl Reservoir {
    fn new(k: usize) -> Self {
        Self {
            items: Vec::with_capacity(k),
            seen: 0,
            k,
        }
    }

    fn offer(&mut self, rng: &mut Rng, item: Dial) {
        if self.k == 0 {
            return;
        }
        self.seen += 1;
        if self.items.len() < self.k {
            self.items.push(item);
        } else {
            let j = rng.below(self.seen);
            if j < self.k {
                self.items[j] = item;
            }
        }
    }
}

/// Index into the per-class credit and weight arrays. Good is absent on
/// purpose: reconnects are taken ahead of the budget, not out of it.
const CLASS_UNKNOWN: usize = 0;
const CLASS_WAS_GOOD: usize = 1;
const CLASS_BAD: usize = 2;

pub struct Book {
    entries: HashMap<PeerAddr, Entry>,
    active: HashMap<PeerAddr, Phase>,
    /// Carried-over fractional dial budget for unknown / was_good / bad.
    credit: [f32; 3],
    capacity: usize,
    rng: Rng,
}

impl Book {
    pub fn new(capacity: usize, seed: u64) -> Self {
        Self {
            entries: HashMap::new(),
            active: HashMap::new(),
            credit: [0.0; 3],
            capacity,
            rng: Rng::new(seed),
        }
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Kept alongside `len` because clippy's `len_without_is_empty` asks for
    /// it; the manager only ever reports the count.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn entry(&self, addr: &PeerAddr) -> Option<&Entry> {
        self.entries.get(addr)
    }

    /// Replace the whole entry set, as when loading a snapshot.
    pub fn restore(&mut self, entries: HashMap<PeerAddr, Entry>) {
        self.entries = entries;
        self.active.clear();
    }

    pub fn iter(&self) -> impl Iterator<Item = (&PeerAddr, &Entry)> {
        self.entries.iter()
    }

    pub fn stats(&self) -> Stats {
        let mut s = Stats {
            total: self.entries.len(),
            dialing: 0,
            connected: 0,
            ..Default::default()
        };
        for entry in self.entries.values() {
            match entry.class() {
                Class::Unknown => s.unknown += 1,
                Class::Good => s.good += 1,
                Class::WasGood => s.was_good += 1,
                Class::Bad => s.bad += 1,
            }
        }
        for phase in self.active.values() {
            match phase {
                Phase::Dialing => s.dialing += 1,
                Phase::Connected => s.connected += 1,
            }
        }
        s
    }

    pub fn dialing_count(&self) -> usize {
        self.active
            .values()
            .filter(|p| matches!(p, Phase::Dialing))
            .count()
    }

    // ── Ingest ───────────────────────────────────────────────────────────────

    /// Take addresses learned from gossip. Returns how many were newly added.
    ///
    /// Existing entries have their services and announcement time refreshed:
    /// a peer's service flags do change, so freezing them at whatever the first
    /// announcement happened to say would leave them stale.
    ///
    /// The announced nTime is deliberately not stored. It is a number the peer
    /// chose, and we have our own clock: `last_announced` records when we
    /// heard the address, which is the same fact without the trust.
    pub fn ingest(&mut self, now: u32, addrs: &[Gossiped], banlist: &Banlist) -> usize {
        let mut added = 0;
        for g in addrs {
            if !g.addr.is_routable() || banlist.contains(&g.addr) {
                continue;
            }
            if let Some(entry) = self.entries.get_mut(&g.addr) {
                entry.last_announced = now;
                // A peer that now advertises v2 is worth another v2 attempt
                // even if we previously filed it as v1-only.
                if g.services != entry.services {
                    if advertises_v2(g.services) && entry.transport == TransportHint::V1Only {
                        entry.transport = TransportHint::Unknown;
                    }
                    entry.services = g.services;
                }
                continue;
            }

            if self.entries.len() >= self.capacity && !self.evict_one(now) {
                // Nothing evictable: the book is full of addresses we have
                // reason to keep. Drop the new one rather than grow.
                continue;
            }
            self.entries
                .insert(g.addr, Entry::new(now, g.services, Origin::Gossip));
            added += 1;
        }
        added
    }

    /// Add operator-supplied or bootstrap addresses. These are never forgotten
    /// and never evicted, and they are dialled ahead of everything else.
    pub fn insert_manual(&mut self, now: u32, addrs: &[PeerAddr]) -> usize {
        let mut added = 0;
        for addr in addrs {
            match self.entries.get_mut(addr) {
                Some(entry) => {
                    // Promote: the operator asked for this one explicitly.
                    if entry.origin != Origin::Manual {
                        entry.origin = Origin::Manual;
                        added += 1;
                    }
                }
                None => {
                    self.entries
                        .insert(*addr, Entry::new(now, 0, Origin::Manual));
                    added += 1;
                }
            }
        }
        added
    }

    /// Drop one entry to make room. Prefers an entry already past its forget
    /// rule; failing that, a random unknown.
    ///
    /// Entries that have connected before are never evicted to make room for a new
    /// unknown one, which is what stops a flood of invented addresses from
    /// displacing peers we have actually reached. Manual entries are never
    /// evicted at all.
    fn evict_one(&mut self, now: u32) -> bool {
        let mut forgettable: Option<PeerAddr> = None;
        let mut unknown = Reservoir::new(1);

        for (addr, entry) in &self.entries {
            if entry.origin == Origin::Manual || self.active.contains_key(addr) {
                continue;
            }
            if policy::should_forget(
                now,
                entry.origin,
                entry.last_success,
                entry.last_announced,
                entry.failures,
            ) {
                forgettable = Some(*addr);
                break;
            }
            if entry.class() == Class::Unknown {
                unknown.offer(
                    &mut self.rng,
                    Dial {
                        addr: *addr,
                        transport: TransportHint::Unknown,
                    },
                );
            }
        }

        let victim = forgettable.or_else(|| unknown.items.first().map(|d| d.addr));
        match victim {
            Some(addr) => {
                self.entries.remove(&addr);
                true
            }
            None => false,
        }
    }

    /// Drop every entry matching a newly added ban.
    pub fn purge_banned(&mut self, banlist: &Banlist) -> usize {
        let before = self.entries.len();
        self.entries.retain(|addr, _| !banlist.contains(addr));
        before - self.entries.len()
    }

    // ── Outcomes ─────────────────────────────────────────────────────────────

    /// Note that a dial has been handed to a connection task.
    pub fn record_dialing(&mut self, addr: PeerAddr, now: u32) {
        self.active.insert(addr, Phase::Dialing);
        if let Some(entry) = self.entries.get_mut(&addr) {
            entry.last_attempt = now;
        }
    }

    /// Note a completed handshake.
    pub fn record_connected(
        &mut self,
        addr: PeerAddr,
        now: u32,
        services: u64,
        transport_version: u8,
    ) {
        self.active.insert(addr, Phase::Connected);
        let Some(entry) = self.entries.get_mut(&addr) else {
            return;
        };
        entry.last_success = now;
        entry.last_attempt_failed = false;
        entry.failures = 0;
        // The peer's own version message is more trustworthy than gossip, and a
        // change in what it advertises is the only thing that revises a
        // standing v1-only verdict.
        let upgraded = advertises_v2(services) && !advertises_v2(entry.services);
        entry.services = services;
        entry.transport = match transport_version {
            // Spoke v2. Never downgraded later: a failed v2 attempt is a
            // failed attempt, not evidence the peer dropped support.
            2 => TransportHint::V2,
            // v1 carried the session. With no verdict yet that means we tried
            // v2 first in this same attempt and it did not work, so file it —
            // direct evidence outranks whatever the peer advertises.
            _ if entry.transport == TransportHint::Unknown => TransportHint::V1Only,
            // A standing verdict is revisited only when the peer has started
            // advertising v2 since we last looked. Retrying v2 on every
            // reconnect instead would just repeat a handshake we know fails.
            _ if entry.transport == TransportHint::V1Only && upgraded => TransportHint::Unknown,
            _ => entry.transport,
        };
    }

    /// Note that an attempt or session has ended, and schedule the retry.
    ///
    /// This is the only place retry timing is decided. Connection tasks are
    /// single-shot and hold no backoff state of their own.
    pub fn record_ended(&mut self, addr: PeerAddr, now: u32, outcome: Outcome) {
        self.active.remove(&addr);
        let r = self.rng.next_f32();

        let Some(entry) = self.entries.get_mut(&addr) else {
            return;
        };

        match outcome {
            // Our own fault: no route, proxy down. Says nothing about the
            // peer, so no counter moves and the class does not change.
            Outcome::OurFault(_) => {}
            Outcome::Disconnected { .. } => {
                entry.last_attempt_failed = false;
                entry.failures = 0;
                if outcome.is_short_session() {
                    entry.short_sessions = entry.short_sessions.saturating_add(1);
                } else {
                    entry.short_sessions = 0;
                }
            }
            Outcome::Failed(_) => {
                entry.last_attempt_failed = true;
                entry.failures = entry.failures.saturating_add(1);
            }
        }

        let base = policy::retry_delay_secs(
            &outcome,
            entry.origin,
            entry.connected_before(),
            entry.failures,
            entry.short_sessions,
        );
        entry.next_attempt = now.saturating_add(policy::jitter(base, r));

        let forget = policy::should_forget(
            now,
            entry.origin,
            entry.last_success,
            entry.last_announced,
            entry.failures,
        );
        if forget {
            self.entries.remove(&addr);
        }
    }

    /// Record that v2 did not work for this address but v1 did, so later
    /// attempts can skip straight to v1.
    pub fn record_v1_only(&mut self, addr: PeerAddr) {
        if let Some(entry) = self.entries.get_mut(&addr)
            && entry.transport == TransportHint::Unknown
        {
            entry.transport = TransportHint::V1Only;
        }
    }

    // ── Pick ─────────────────────────────────────────────────────────────────

    /// Choose addresses to dial.
    ///
    /// One pass over the book. Due reconnects to good addresses are taken
    /// first, outside `budget` but capped by MAX_RECONNECTS_PER_TICK; the
    /// remaining classes share `budget` by weight, with fractional shares
    /// carried between ticks as credit. Picked addresses are marked Dialing
    /// here, so the same address cannot be handed out twice.
    pub fn pick(
        &mut self,
        now: u32,
        budget: usize,
        nets: &EnabledNets,
        banlist: &Banlist,
    ) -> Vec<Dial> {
        let mut manual = Reservoir::new(budget);
        let mut reconnect = Reservoir::new(policy::MAX_RECONNECTS_PER_TICK);
        let mut by_class = [
            Reservoir::new(budget),
            Reservoir::new(budget),
            Reservoir::new(budget),
        ];

        for (addr, entry) in &self.entries {
            // Never dial an address we already have a task for. This is the
            // one invariant here that must never be approximate.
            if self.active.contains_key(addr) {
                continue;
            }
            if entry.next_attempt > now {
                continue;
            }
            if !nets.allows(addr.net()) || banlist.contains(addr) {
                continue;
            }

            let dial = Dial {
                addr: *addr,
                transport: entry.transport,
            };

            if entry.origin == Origin::Manual {
                manual.offer(&mut self.rng, dial);
                continue;
            }

            match entry.class() {
                Class::Good => reconnect.offer(&mut self.rng, dial),
                Class::Unknown => by_class[CLASS_UNKNOWN].offer(&mut self.rng, dial),
                Class::WasGood => by_class[CLASS_WAS_GOOD].offer(&mut self.rng, dial),
                Class::Bad => by_class[CLASS_BAD].offer(&mut self.rng, dial),
            }
        }

        let available = [
            by_class[CLASS_UNKNOWN].items.len(),
            by_class[CLASS_WAS_GOOD].items.len(),
            by_class[CLASS_BAD].items.len(),
        ];
        let take = self.allocate(budget, available);

        let mut out = Vec::with_capacity(budget + reconnect.items.len() + manual.items.len());
        out.extend(manual.items);
        out.extend(reconnect.items);
        for (i, res) in by_class.into_iter().enumerate() {
            out.extend(res.items.into_iter().take(take[i]));
        }

        for dial in &out {
            self.record_dialing(dial.addr, now);
        }
        out
    }

    /// Split `budget` between unknown / was_good / bad by weight.
    ///
    /// Shares are accumulated as credit rather than applied per batch: at one
    /// dial per tick a 70/20/10 split cannot be expressed in a single batch,
    /// but it comes out right over a few dozen ticks.
    fn allocate(&mut self, budget: usize, available: [usize; 3]) -> [usize; 3] {
        const W: [f32; 3] = [
            policy::WEIGHT_UNKNOWN,
            policy::WEIGHT_WAS_GOOD,
            policy::WEIGHT_BAD,
        ];
        let total: f32 = W[0] + W[1] + W[2];

        // Each class earns its share of this tick's budget as credit.
        for (credit, weight) in self.credit.iter_mut().zip(W) {
            *credit = (*credit + weight / total * budget as f32).min(CREDIT_CAP);
        }

        // Hand out slots one at a time to whichever class is owed most and
        // still has a candidate, debiting a whole dial from its credit.
        //
        // Deliberately not floor(credit) per class with the leftover shared
        // out: at a budget of one dial per tick every class floors to zero, so
        // the leftover decides every pick, and whichever class the loop
        // happens to visit first wins every time without being charged for
        // it. Assigning each slot to the most-owed class instead makes the
        // weights hold at any budget, down to one.
        //
        // A class with no candidates is skipped, so its share flows to the
        // others rather than being wasted -- but it keeps its credit and gets
        // the share back as soon as it has candidates again.
        let mut take = [0usize; 3];
        for _ in 0..budget {
            let mut best: Option<usize> = None;
            for i in 0..3 {
                if take[i] >= available[i] {
                    continue;
                }
                if best.is_none_or(|b| self.credit[i] > self.credit[b]) {
                    best = Some(i);
                }
            }
            match best {
                Some(i) => {
                    take[i] += 1;
                    // Bounded below as well as above, so a long run where only
                    // one class has candidates cannot leave it with an
                    // unpayable deficit.
                    self.credit[i] = (self.credit[i] - 1.0).max(-CREDIT_CAP);
                }
                // Nothing dialable left in any class.
                None => break,
            }
        }
        take
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addrman::banlist::BanEntry;
    use crate::addrman::policy::{OurFault, Reason};

    const DAY: u32 = 24 * 60 * 60;
    const NOW: u32 = 1_000_000;

    fn empty_banlist() -> Banlist {
        Banlist::from_entries(vec![])
    }

    fn ip(a: u8, b: u8, c: u8, d: u8) -> PeerAddr {
        PeerAddr::Ipv4([a, b, c, d], 8333)
    }

    /// Insert an entry already in a given class, so pick/eviction can be
    /// exercised without replaying a history of outcomes.
    fn insert(book: &mut Book, addr: PeerAddr, class: Class) {
        let mut e = Entry::new(NOW, 0, Origin::Gossip);
        match class {
            Class::Unknown => {}
            Class::Good => {
                e.last_attempt = NOW;
                e.last_success = NOW;
                e.last_attempt_failed = false;
            }
            Class::WasGood => {
                e.last_attempt = NOW;
                e.last_success = NOW - DAY;
                e.last_attempt_failed = true;
                e.failures = 1;
            }
            Class::Bad => {
                e.last_attempt = NOW;
                e.last_success = 0;
                e.last_attempt_failed = true;
                e.failures = 1;
            }
        }
        assert_eq!(e.class(), class);
        book.entries.insert(addr, e);
    }

    /// Clear the active set and make every entry due again, so a test can run
    /// many ticks of pick() without modelling connection outcomes.
    fn release_all(book: &mut Book) {
        book.active.clear();
        for e in book.entries.values_mut() {
            e.next_attempt = 0;
        }
    }

    // ── The invariants that must never be approximate ────────────────────────

    #[test]
    fn test_active_addresses_are_never_picked() {
        let mut t = Book::new(100, 1);
        let bl = empty_banlist();
        let addr = ip(1, 2, 3, 4);
        insert(&mut t, addr, Class::Unknown);

        // First pick hands it out and marks it active.
        let first = t.pick(NOW, 10, &EnabledNets::all(), &bl);
        assert_eq!(first.len(), 1);
        assert_eq!(first[0].addr, addr);

        // While it is active it must not be handed out again, however many
        // ticks pass and even once it would otherwise be due.
        for tick in 0..5 {
            release_all(&mut t);
            t.active.insert(addr, Phase::Dialing);
            let again = t.pick(NOW + tick, 10, &EnabledNets::all(), &bl);
            assert!(
                again.is_empty(),
                "active address picked again on tick {tick}"
            );
        }

        // Once the attempt ends it becomes eligible again.
        t.record_ended(addr, NOW, Outcome::OurFault(OurFault::NetworkUnreachable));
        release_all(&mut t);
        assert_eq!(t.pick(NOW, 10, &EnabledNets::all(), &bl).len(), 1);
    }

    #[test]
    fn test_banned_addresses_are_never_picked() {
        let mut t = Book::new(100, 1);
        insert(&mut t, ip(10, 0, 0, 1), Class::Unknown);
        insert(&mut t, ip(1, 2, 3, 4), Class::Unknown);

        let bl = Banlist::from_entries(vec![BanEntry {
            comment: None,
            nets: vec!["10.0.0.0/8".parse().unwrap()],
            hosts: Vec::new(),
        }]);

        let picked = t.pick(NOW, 10, &EnabledNets::all(), &bl);
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].addr, ip(1, 2, 3, 4));
    }

    #[test]
    fn test_disabled_networks_are_never_picked() {
        let mut t = Book::new(100, 1);
        insert(&mut t, ip(1, 2, 3, 4), Class::Unknown);
        insert(&mut t, PeerAddr::TorV3([7u8; 32], 8333), Class::Unknown);

        let nets = EnabledNets {
            ipv4: true,
            ipv6: false,
            tor: false,
            cjdns: false,
            i2p: false,
        };
        let picked = t.pick(NOW, 10, &nets, &empty_banlist());
        assert_eq!(picked.len(), 1);
        assert_eq!(picked[0].addr.net(), Net::Ipv4);
    }

    #[test]
    fn test_entries_not_yet_due_are_not_picked() {
        let mut t = Book::new(100, 1);
        let addr = ip(1, 2, 3, 4);
        insert(&mut t, addr, Class::Unknown);
        t.entries.get_mut(&addr).unwrap().next_attempt = NOW + 100;

        assert!(
            t.pick(NOW, 10, &EnabledNets::all(), &empty_banlist())
                .is_empty()
        );
        assert_eq!(
            t.pick(NOW + 100, 10, &EnabledNets::all(), &empty_banlist())
                .len(),
            1
        );
    }

    #[test]
    fn test_banning_purges_matching_entries() {
        let mut t = Book::new(100, 1);
        insert(&mut t, ip(10, 0, 0, 1), Class::Good);
        insert(&mut t, ip(10, 5, 5, 5), Class::Unknown);
        insert(&mut t, ip(1, 2, 3, 4), Class::Good);

        let bl = Banlist::from_entries(vec![BanEntry {
            comment: None,
            nets: vec!["10.0.0.0/8".parse().unwrap()],
            hosts: Vec::new(),
        }]);
        // Banning removes what is already stored, whatever its class.
        assert_eq!(t.purge_banned(&bl), 2);
        assert_eq!(t.len(), 1);
        assert!(t.entry(&ip(1, 2, 3, 4)).is_some());
    }

    // ── Growth ───────────────────────────────────────────────────────────────

    #[test]
    fn test_flood_cannot_grow_the_table_past_capacity() {
        let cap = 1_000;
        let mut t = Book::new(cap, 1);
        let bl = empty_banlist();

        // 20k invented addresses arriving in batches, as a flooding peer
        // would send them.
        for chunk in 0..20u8 {
            let batch: Vec<Gossiped> = (0..1000u32)
                .map(|i| Gossiped {
                    addr: PeerAddr::Ipv4([100, chunk, (i / 256) as u8, (i % 256) as u8], 8333),
                    services: 0,
                    ntime: NOW,
                })
                .collect();
            t.ingest(NOW, &batch, &bl);
            assert!(t.len() <= cap, "capacity exceeded mid-flood: {}", t.len());
        }
        assert!(t.len() <= cap);
    }

    #[test]
    fn test_flood_does_not_evict_addresses_we_have_reached() {
        let cap = 100;
        let mut t = Book::new(cap, 1);
        let bl = empty_banlist();

        // Addresses we have actually connected to, plus one the operator
        // added by hand.
        let good = ip(1, 2, 3, 4);
        let was_good = ip(5, 6, 7, 8);
        insert(&mut t, good, Class::Good);
        insert(&mut t, was_good, Class::WasGood);
        t.insert_manual(NOW, &[ip(9, 9, 9, 9)]);

        let batch: Vec<Gossiped> = (0..5000u32)
            .map(|i| Gossiped {
                addr: PeerAddr::Ipv4(
                    [100, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                    8333,
                ),
                services: 0,
                ntime: NOW,
            })
            .collect();
        t.ingest(NOW, &batch, &bl);

        assert!(t.len() <= cap);
        // Eviction only ever takes unknowns, so everything we had evidence
        // for is still here.
        assert!(t.entry(&good).is_some(), "good address was evicted");
        assert!(t.entry(&was_good).is_some(), "was_good address was evicted");
        assert!(
            t.entry(&ip(9, 9, 9, 9)).is_some(),
            "manual address was evicted"
        );
    }

    #[test]
    fn test_unroutable_and_banned_addresses_are_not_ingested() {
        let mut t = Book::new(100, 1);
        let bl = Banlist::from_entries(vec![BanEntry {
            comment: None,
            nets: vec!["8.8.8.0/24".parse().unwrap()],
            hosts: Vec::new(),
        }]);

        let batch = [
            // Loopback, private, port 0: not worth storing.
            Gossiped {
                addr: ip(127, 0, 0, 1),
                services: 0,
                ntime: NOW,
            },
            Gossiped {
                addr: ip(10, 0, 0, 1),
                services: 0,
                ntime: NOW,
            },
            Gossiped {
                addr: PeerAddr::Ipv4([1, 2, 3, 4], 0),
                services: 0,
                ntime: NOW,
            },
            // Banned.
            Gossiped {
                addr: ip(8, 8, 8, 8),
                services: 0,
                ntime: NOW,
            },
            // The one good one.
            Gossiped {
                addr: ip(1, 2, 3, 4),
                services: 0,
                ntime: NOW,
            },
        ];
        assert_eq!(t.ingest(NOW, &batch, &bl), 1);
        assert_eq!(t.len(), 1);
    }

    // ── Ingest refreshes what gossip tells us ────────────────────────────────

    #[test]
    fn test_reannouncement_refreshes_services() {
        let mut t = Book::new(100, 1);
        let bl = empty_banlist();
        let addr = ip(1, 2, 3, 4);

        t.ingest(
            NOW,
            &[Gossiped {
                addr,
                services: 0b1,
                ntime: NOW - 500,
            }],
            &bl,
        );
        assert_eq!(t.entry(&addr).unwrap().services, 0b1);

        // Service flags do change, so a re-announcement must refresh them.
        t.ingest(
            NOW + 10,
            &[Gossiped {
                addr,
                services: 0b1001,
                ntime: NOW,
            }],
            &bl,
        );
        let e = t.entry(&addr).unwrap();
        assert_eq!(e.services, 0b1001);
        assert_eq!(e.last_announced, NOW + 10);
        // Re-announcing must not create a duplicate entry.
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn test_advertised_v2_clears_a_v1only_verdict() {
        let mut t = Book::new(100, 1);
        let bl = empty_banlist();
        let addr = ip(1, 2, 3, 4);
        const P2P_V2: u64 = 1 << 11;

        t.ingest(
            NOW,
            &[Gossiped {
                addr,
                services: 0,
                ntime: NOW,
            }],
            &bl,
        );
        t.record_v1_only(addr);
        assert_eq!(t.entry(&addr).unwrap().transport, TransportHint::V1Only);

        // The node was upgraded and now advertises v2: worth trying again.
        t.ingest(
            NOW,
            &[Gossiped {
                addr,
                services: P2P_V2,
                ntime: NOW,
            }],
            &bl,
        );
        assert_eq!(t.entry(&addr).unwrap().transport, TransportHint::Unknown);
    }

    /// The version message is the most trustworthy source of service flags we
    /// get, so it is also what revises the transport verdict.
    #[test]
    fn test_version_message_advertising_v2_clears_a_v1only_verdict() {
        const P2P_V2: u64 = 1 << 11;
        let mut t = Book::new(100, 1);
        let addr = ip(1, 2, 3, 4);
        insert(&mut t, addr, Class::Unknown);

        // A v1 session with no v2 advertised: the verdict stands, and a second
        // v1 session does not disturb it.
        t.record_connected(addr, NOW, 0, 1);
        assert_eq!(t.entry(&addr).unwrap().transport, TransportHint::V1Only);
        t.record_connected(addr, NOW + 10, 0, 1);
        assert_eq!(t.entry(&addr).unwrap().transport, TransportHint::V1Only);

        // Now it advertises v2 in its version message: worth v2 again.
        t.record_connected(addr, NOW + 20, P2P_V2, 1);
        assert_eq!(t.entry(&addr).unwrap().transport, TransportHint::Unknown);
    }

    #[test]
    fn test_connecting_over_v2_is_never_downgraded() {
        let mut t = Book::new(100, 1);
        let addr = ip(1, 2, 3, 4);
        insert(&mut t, addr, Class::Unknown);

        t.record_connected(addr, NOW, 0, 2);
        assert_eq!(t.entry(&addr).unwrap().transport, TransportHint::V2);

        // A later failure is a failed attempt, not evidence the peer dropped
        // v2 support.
        t.record_ended(addr, NOW, Outcome::Failed(Reason::TcpConnectTimeout));
        assert_eq!(t.entry(&addr).unwrap().transport, TransportHint::V2);
        t.record_v1_only(addr);
        assert_eq!(t.entry(&addr).unwrap().transport, TransportHint::V2);
    }

    // ── Outcomes and retry scheduling ────────────────────────────────────────

    #[test]
    fn test_success_then_failure_moves_good_to_was_good() {
        let mut t = Book::new(100, 1);
        let addr = ip(1, 2, 3, 4);
        insert(&mut t, addr, Class::Unknown);

        t.record_connected(addr, NOW, 0b1101, 1);
        assert_eq!(t.entry(&addr).unwrap().class(), Class::Good);
        // The peer's own version message outranks gossip.
        assert_eq!(t.entry(&addr).unwrap().services, 0b1101);

        t.record_ended(addr, NOW + 10, Outcome::Failed(Reason::ConnectionRefused));
        assert_eq!(t.entry(&addr).unwrap().class(), Class::WasGood);
        assert_eq!(t.entry(&addr).unwrap().failures, 1);
    }

    #[test]
    fn test_our_fault_does_not_count_against_the_address() {
        let mut t = Book::new(100, 1);
        let addr = ip(1, 2, 3, 4);
        insert(&mut t, addr, Class::Unknown);

        // No IPv6 route, Tor proxy down, and so on: nothing to do with the
        // peer, so the class and counters must not move. Marking these bad
        // would poison the book with perfectly good addresses whenever a
        // network was unavailable.
        for i in 0..5 {
            t.record_dialing(addr, NOW + i);
            t.record_ended(
                addr,
                NOW + i,
                Outcome::OurFault(OurFault::NetworkUnreachable),
            );
        }
        let e = t.entry(&addr).unwrap();
        assert_eq!(e.failures, 0);
        assert!(!e.last_attempt_failed);
        assert_eq!(
            e.class(),
            Class::Unknown,
            "our own fault must not make an address look bad"
        );
    }

    #[test]
    fn test_short_sessions_back_off_but_a_stable_one_resets() {
        let mut t = Book::new(100, 1);
        let addr = ip(1, 2, 3, 4);
        insert(&mut t, addr, Class::Unknown);
        t.record_connected(addr, NOW, 0, 1);

        // Repeated evictions accumulate and the retry grows.
        let mut last = 0;
        for i in 1..=3u32 {
            t.record_ended(addr, NOW, Outcome::Disconnected { uptime_secs: 2 });
            let e = t.entry(&addr).unwrap();
            assert_eq!(u32::from(e.short_sessions), i);
            let delay = e.next_attempt - NOW;
            assert!(delay > last, "delay did not grow: {delay} after {last}");
            last = delay;
        }

        // A session that ran properly clears the suspicion.
        t.record_ended(addr, NOW, Outcome::Disconnected { uptime_secs: 600 });
        let e = t.entry(&addr).unwrap();
        assert_eq!(e.short_sessions, 0);
        assert!(
            e.next_attempt - NOW <= 6,
            "a stable peer should be retried fast"
        );
    }

    #[test]
    fn test_forgotten_entry_is_removed() {
        let mut t = Book::new(100, 1);
        let addr = ip(1, 2, 3, 4);
        insert(&mut t, addr, Class::Bad);
        t.entries.get_mut(&addr).unwrap().failures = 4;

        // Fifth failure on an address that has never once connected: dropped
        // regardless of how recently it was announced.
        t.record_ended(addr, NOW, Outcome::Failed(Reason::TcpConnectTimeout));
        assert!(t.entry(&addr).is_none(), "entry should have been forgotten");
        assert!(t.active.is_empty(), "active slot should have been released");
    }

    #[test]
    fn test_manual_entries_are_never_forgotten() {
        let mut t = Book::new(100, 1);
        let addr = ip(1, 2, 3, 4);
        t.insert_manual(NOW, &[addr]);

        for _ in 0..20 {
            t.record_ended(addr, NOW, Outcome::Failed(Reason::TcpConnectTimeout));
        }
        let e = t.entry(&addr).expect("manual entry was forgotten");
        // And it keeps a short retry rather than backing off to days.
        assert!(e.next_attempt - NOW < 120);
    }

    #[test]
    fn test_outcome_for_an_unknown_key_is_ignored() {
        let mut t = Book::new(100, 1);
        let addr = ip(1, 2, 3, 4);
        // An outcome can arrive after the entry was forgotten or banned away.
        t.active.insert(addr, Phase::Dialing);
        t.record_ended(addr, NOW, Outcome::Failed(Reason::Other));
        assert!(t.active.is_empty(), "active slot must still be released");
        assert!(t.is_empty());
    }

    // ── The pick ─────────────────────────────────────────────────────────────

    #[test]
    fn test_manual_and_reconnects_come_before_the_budget() {
        let mut t = Book::new(1000, 1);
        let bl = empty_banlist();

        t.insert_manual(NOW, &[ip(9, 9, 9, 9)]);
        for i in 0..10u8 {
            insert(&mut t, ip(1, 1, 1, i), Class::Good);
        }
        for i in 0..50u8 {
            insert(&mut t, ip(2, 2, 2, i), Class::Unknown);
        }

        // A budget of 2 still gets the manual address and the due reconnects
        // on top, because staying connected is the point.
        let picked = t.pick(NOW, 2, &EnabledNets::all(), &bl);
        assert!(picked.len() > 2, "reconnects were squeezed into the budget");
        assert!(picked.iter().any(|d| d.addr == ip(9, 9, 9, 9)));
        let goods = picked
            .iter()
            .filter(|d| d.addr.to_string().starts_with("1.1.1."))
            .count();
        assert_eq!(goods, 10, "all due reconnects should be taken");
    }

    /// The flaw found reviewing the design notes: reconnects are taken outside
    /// the budget, which is unbounded unless it has a ceiling of its own.
    /// After downtime every good entry is due at once.
    #[test]
    fn test_reconnect_burst_is_capped() {
        let mut t = Book::new(10_000, 1);
        let bl = empty_banlist();

        // 5000 peers we have connected to, every one of them overdue, as
        // happens after the process has been stopped for a while.
        for i in 0..5000u32 {
            let addr = PeerAddr::Ipv4(
                [3, (i / 65536) as u8, (i / 256) as u8, (i % 256) as u8],
                8333,
            );
            insert(&mut t, addr, Class::Good);
        }

        let picked = t.pick(NOW + 30 * DAY, 1, &EnabledNets::all(), &bl);
        assert!(
            picked.len() <= policy::MAX_RECONNECTS_PER_TICK + 1,
            "unbounded reconnect burst: {} dials in one tick",
            picked.len()
        );
    }

    #[test]
    fn test_class_shares_follow_the_weights() {
        let mut t = Book::new(10_000, 42);
        let bl = empty_banlist();

        // Plenty of candidates in each class, so availability never decides.
        for i in 0..100u8 {
            insert(&mut t, ip(10, 0, 0, i), Class::Unknown);
            insert(&mut t, ip(10, 1, 0, i), Class::WasGood);
            insert(&mut t, ip(10, 2, 0, i), Class::Bad);
        }

        let mut counts = [0usize; 3];
        // One dial per tick: the case a per-batch percentage cannot express.
        for _ in 0..1000 {
            release_all(&mut t);
            for dial in t.pick(NOW, 1, &EnabledNets::all(), &bl) {
                match dial.addr {
                    PeerAddr::Ipv4([10, 0, ..], _) => counts[CLASS_UNKNOWN] += 1,
                    PeerAddr::Ipv4([10, 1, ..], _) => counts[CLASS_WAS_GOOD] += 1,
                    PeerAddr::Ipv4([10, 2, ..], _) => counts[CLASS_BAD] += 1,
                    other => panic!("unexpected pick: {other}"),
                }
            }
        }

        let total: usize = counts.iter().sum();
        assert_eq!(total, 1000, "every tick should have spent its budget");
        // 70 / 20 / 10, within a couple of points.
        for (i, expected) in [
            (CLASS_UNKNOWN, 700.0),
            (CLASS_WAS_GOOD, 200.0),
            (CLASS_BAD, 100.0),
        ] {
            let got = counts[i] as f32;
            assert!(
                (got - expected).abs() < 25.0,
                "class {i}: expected ~{expected}, got {got} (all: {counts:?})"
            );
        }
    }

    #[test]
    fn test_a_classs_unused_share_goes_to_the_others() {
        let mut t = Book::new(1000, 7);
        let bl = empty_banlist();

        // Only unknowns exist. The budget must still be spent in full rather
        // than 30% of it going nowhere.
        for i in 0..100u8 {
            insert(&mut t, ip(10, 0, 0, i), Class::Unknown);
        }
        for _ in 0..20 {
            release_all(&mut t);
            assert_eq!(t.pick(NOW, 10, &EnabledNets::all(), &bl).len(), 10);
        }
    }

    #[test]
    fn test_pick_respects_the_budget_and_marks_dialing() {
        let mut t = Book::new(1000, 1);
        let bl = empty_banlist();
        for i in 0..100u8 {
            insert(&mut t, ip(10, 0, 0, i), Class::Unknown);
        }

        let picked = t.pick(NOW, 7, &EnabledNets::all(), &bl);
        assert_eq!(picked.len(), 7);
        // Being dialled is not a result: these are still unknown until one
        // arrives, which is also what keeps the class weights honest.
        for dial in &picked {
            assert_eq!(t.entry(&dial.addr).unwrap().class(), Class::Unknown);
        }
        assert_eq!(t.dialing_count(), 7);
        assert_eq!(t.stats().dialing, 7);
        // Every pick records an attempt time, so classification advances.
        for dial in &picked {
            assert_eq!(t.entry(&dial.addr).unwrap().last_attempt, NOW);
        }
    }

    #[test]
    fn test_empty_table_and_zero_budget_are_fine() {
        let mut t = Book::new(100, 1);
        let bl = empty_banlist();
        assert!(t.pick(NOW, 10, &EnabledNets::all(), &bl).is_empty());

        insert(&mut t, ip(1, 2, 3, 4), Class::Unknown);
        assert!(t.pick(NOW, 0, &EnabledNets::all(), &bl).is_empty());
    }

    #[test]
    fn test_stats_counts_each_class() {
        let mut t = Book::new(100, 1);
        insert(&mut t, ip(1, 0, 0, 1), Class::Unknown);
        insert(&mut t, ip(1, 0, 0, 2), Class::Unknown);
        insert(&mut t, ip(1, 0, 0, 3), Class::Good);
        insert(&mut t, ip(1, 0, 0, 4), Class::WasGood);
        insert(&mut t, ip(1, 0, 0, 5), Class::Bad);

        let s = t.stats();
        assert_eq!(s.total, 5);
        assert_eq!(s.unknown, 2);
        assert_eq!(s.good, 1);
        assert_eq!(s.was_good, 1);
        assert_eq!(s.bad, 1);
    }

    #[test]
    fn test_rng_is_in_range() {
        let mut rng = Rng::new(12345);
        for _ in 0..10_000 {
            let f = rng.next_f32();
            assert!((0.0..1.0).contains(&f), "next_f32 out of range: {f}");
            assert!(rng.below(7) < 7);
        }
        assert_eq!(rng.below(0), 0, "below(0) must not divide by zero");
    }

    #[test]
    fn test_reservoir_keeps_k_items() {
        let mut rng = Rng::new(9);
        let mut r = Reservoir::new(3);
        for i in 0..100u8 {
            r.offer(
                &mut rng,
                Dial {
                    addr: ip(1, 2, 3, i),
                    transport: TransportHint::Unknown,
                },
            );
        }
        assert_eq!(r.items.len(), 3);
        assert_eq!(r.seen, 100);

        // A zero-size reservoir accepts nothing and must not panic.
        let mut z = Reservoir::new(0);
        z.offer(
            &mut rng,
            Dial {
                addr: ip(1, 2, 3, 4),
                transport: TransportHint::Unknown,
            },
        );
        assert!(z.items.is_empty());
    }
}
