//! Retry delays, class weights and forget rules.
//!
//! Everything here is a pure function of its arguments and an explicit `now`,
//! with no clock, no randomness and no state. That is deliberate: the policy is
//! the part most likely to need tuning, and it should be possible to check a
//! change against a table of expected values rather than by running a crawler
//! for a day.

use common::serde::{Deserialize, Serialize};

/// A session shorter than this is read as an eviction rather than an ordinary
/// disconnect: the peer accepted us and then dropped us almost immediately,
/// most likely because its inbound slots are full.
pub const SHORT_SESSION_SECS: u32 = 31;

/// Relative share of each class in the dial budget. Good addresses are not in
/// this list: reconnects are taken separately, ahead of the budget.
pub const WEIGHT_UNKNOWN: f32 = 70.0;
pub const WEIGHT_WAS_GOOD: f32 = 20.0;
pub const WEIGHT_BAD: f32 = 10.0;

/// Maximum reconnects to good addresses started in a single tick.
///
/// Due reconnects are taken outside the normal dial budget, so that peers we
/// want to stay connected to are not starved by the flow of newly gossiped
/// addresses. That exemption needs a ceiling of its own: after any downtime
/// every good entry's `next_attempt` is already in the past, so an uncapped
/// pass would dial the entire good book in one tick — thousands of sockets at
/// once and a thundering herd at the peers. Jitter does not help, because
/// those delays have already elapsed.
pub const MAX_RECONNECTS_PER_TICK: usize = 25;

/// Addresses accepted from a peer per second, and the burst it may spend at
/// once, mirroring Bitcoin Core. At 0.1/s a single peer can teach us about
/// ~8.6k addresses a day, which is the most effective single bound on how
/// fast the book grows. Our own GETADDR reply is exempt — we asked for it.
pub const ADDR_RATE_PER_SEC: f64 = 0.1;
pub const ADDR_BURST: f64 = 1000.0;

/// Fixed retry interval for operator-supplied and bootstrap addresses.
const MANUAL_RETRY_SECS: u32 = 60;

/// How long a peer that is on another chain is left alone.
///
/// Long, because the answer does not change quickly: a node following a fork
/// of this network's rules is running software that has to be replaced to
/// follow ours, and until then every connection to it ends the same way. A
/// day is short enough that a node which switches back is picked up again
/// without an operator doing anything, and long enough that five hundred such
/// peers cost one handshake each a day instead of one every five seconds.
///
/// It applies to operator-supplied addresses too, which otherwise keep a
/// short fixed retry: an operator asked for a peer on this network, and
/// reconnecting every minute to be told the same thing is not what they
/// asked for.
const OTHER_CHAIN_SECS: u32 = 24 * 60 * 60;

/// How long a peer that broke the protocol is left alone.
///
/// A violation says the peer sent something the protocol forbids -- a message
/// declaring a length above the limit, an INV above the item limit -- which
/// until now was treated as an ordinary disconnect and redialled in five
/// seconds. It is not an ordinary disconnect: whatever produced it is a build
/// or an operator doing it on purpose, and both repeat.
///
/// Flat rather than doubling, unlike the eviction and failure backoffs. Those
/// counters exist to tell a flaky address from a gone one, which is a question
/// of degree; this is categorical, and a second violation tells us nothing the
/// first did not. An hour is where the eviction backoff tops out, which is the
/// same statement -- we have stopped expecting this peer to behave -- and it
/// still picks up a node that was restarted into a fixed build the same day.
///
/// Operator-supplied addresses keep their short interval even so: an operator
/// who points us at their own node is often pointing us at the build that is
/// misbehaving, and a backoff would quietly stop honouring that.
const VIOLATION_SECS: u32 = 60 * 60;

/// Wait after a session that ended having run for a healthy length of time.
/// Short, because we want to be connected to this peer.
const STABLE_RECONNECT_SECS: u32 = 5;

// Wait after our own side could not make the attempt at all. None of these is
// a backoff: the address did nothing wrong and its counters do not move. They
// differ only in how long the obstacle is likely to last, which is the one
// thing we do know.

/// The Tor proxy is not answering. Local to this host and often a restart away
/// from working, so keep checking.
const PROXY_UNREACHABLE_SECS: u32 = 30;
/// No route from here to that network. Nothing about that changes until the
/// host's own connectivity does, and an observer with no IPv6 route holds
/// thousands of IPv6 addresses — retrying each one every 30 seconds would
/// spend the dial budget on attempts that cannot succeed.
const NETWORK_UNREACHABLE_SECS: u32 = 60 * 60;
/// Configured not to dial this network. The pick already filters these out, so
/// an address only reaches here if the configuration changed under an attempt
/// that was already in flight.
const NETWORK_DISABLED_SECS: u32 = 24 * 60 * 60;

// Each pair below is one exponential backoff: `BASE` is the delay after the
// first occurrence, and every consecutive one multiplies it until it is
// clamped at `CAP`. The multiplier lives with the call in `retry_delay_secs`,
// because it is the one part that differs between the three.

/// After a session that ended early enough to look like an eviction, or in
/// which the peer never sent a message. Doubles per consecutive such session.
const EVICTION_BASE_SECS: u32 = 60;
const EVICTION_CAP_SECS: u32 = 60 * 60;

/// After a failed attempt on an address that has connected before. Doubles per
/// consecutive failure, and stays keen: it worked once, so it is likely to
/// work again.
const WAS_GOOD_BASE_SECS: u32 = 60;
const WAS_GOOD_CAP_SECS: u32 = 6 * 60 * 60;

/// After a failed attempt on an address that has never once connected.
/// Quadruples per consecutive failure. Far harsher than the two above, because
/// addresses are free to invent and most that have never connected never
/// will.
const BAD_BASE_SECS: u32 = 60 * 60;
const BAD_CAP_SECS: u32 = 7 * 24 * 60 * 60;

/// Forget an address that has connected before once it has been unreachable
/// for this long.
const WAS_GOOD_FORGET_AFTER_SECS: u32 = 30 * 24 * 60 * 60;

// When to give up on an address that has never once connected.
//
// Two thresholds rather than one, because a re-announcement is weak evidence
// that somebody out there can still reach it. At `IF_STALE` failures we drop
// the address only if nobody has announced it within `ANNOUNCE_GRACE`; at
// `ALWAYS` failures we drop it however often it is announced, which is what
// stops a peer keeping dead entries alive by re-gossiping them.
//
// Note what the chosen values do: the grace window is far wider than the
// backoff needed to reach `IF_STALE`, so in practice that threshold only
// catches addresses that have dropped out of gossip altogether, and anything
// still being announced survives to `ALWAYS`.
const BAD_FORGET_FAILURES_IF_STALE: u8 = 3;
const BAD_FORGET_FAILURES_ALWAYS: u8 = 5;
const BAD_ANNOUNCE_GRACE_SECS: u32 = 30 * 24 * 60 * 60;

/// How we came to know an address, which decides how patient we are with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(crate = "common::serde")]
pub enum Origin {
    /// Configured as a bootstrap peer or added by the operator over RPC.
    /// Retried on a short fixed interval and never forgotten.
    Manual,
    /// Learned from a peer's addr/addrv2 gossip.
    Gossip,
}

/// Why a dial attempt did not produce a session.
///
/// Timeouts are split by where they fired: a peer that never answers the TCP
/// connect and one that completes the transport handshake and then goes silent
/// are different behaviours, and only the second is worth being surprised by.
/// Nothing in this module branches on the reason — it is carried so the
/// attempt can be reported faithfully.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    ConnectionRefused,
    HostUnreachable,
    TcpConnectTimeout,
    V2TransportTimeout,
    VersionHandshakeTimeout,
    V2TransportHandshake,
    VersionHandshake,
    UnexpectedEof,
    Other,
}

/// Why we could not make an attempt at all. Never counted against the address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OurFault {
    /// No route from here to that network.
    NetworkUnreachable,
    /// The Tor SOCKS5 proxy is not answering.
    ProxyUnreachable,
    /// Configured not to dial this network, or no transport for it.
    NetworkDisabled,
}

/// What became of a dial attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Never reached a working session.
    Failed(Reason),
    /// A session ran and then ended. `silent` when the peer sent no message
    /// at all after the handshake.
    Disconnected { uptime_secs: u32, silent: bool },
    /// The peer is on a chain we refuse, and said so. Not a failure of the
    /// address -- it answered, handshook and told us something true about
    /// itself -- so nothing is counted against it; it is simply not a peer on
    /// this network, and a day is how long we take its word for it.
    OtherChain,
    /// The peer sent something the protocol forbids and we hung up. Like
    /// `OtherChain` this is a verdict on the peer rather than on the address
    /// -- it answered and handshook, so it is as reachable as any good
    /// address -- so no failure is counted and the delay carries the whole
    /// judgement. See VIOLATION_SECS.
    Violated,
    /// We could not even make the attempt: no route to that network, the Tor
    /// proxy is down, and so on. Never counted against the address, because it
    /// says nothing about the peer.
    OurFault(OurFault),
}

impl Outcome {
    /// Whether this outcome counts as a failure of the address itself.
    pub fn counts_as_failure(&self) -> bool {
        matches!(self, Outcome::Failed(_))
    }

    /// Whether this outcome is a session that gave us nothing: one that ended
    /// suspiciously early, or one the peer sat through without sending a
    /// message. Both are backed off the same way.
    pub fn is_short_session(&self) -> bool {
        matches!(
            self,
            Outcome::Disconnected { uptime_secs, silent }
                if *silent || *uptime_secs < SHORT_SESSION_SECS
        )
    }
}

/// Which bucket an address falls into, derived from its history rather than
/// stored. `Good` and `WasGood` both mean "has connected at least once"; they
/// differ only in whether the most recent attempt worked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Never attempted.
    Unknown,
    /// The most recent attempt succeeded.
    Good,
    /// Has connected before, but the most recent attempt failed.
    WasGood,
    /// Attempted at least once and never once connected.
    Bad,
}

/// Classify an address from its history. `last_success` of 0 means never.
///
/// `tried` means we hold at least one real *result* for this address, not that
/// a dial was started. An address handed to a dial task that has not reported
/// back yet is still Unknown: nothing has failed, so calling it bad would be a
/// lie, and it cannot be picked again while the attempt is in flight.
pub fn classify(tried: bool, last_success: u32, last_attempt_failed: bool) -> Class {
    // A success implies the address was tried, whatever `tried` says.
    if last_success > 0 {
        return if last_attempt_failed {
            Class::WasGood
        } else {
            Class::Good
        };
    }
    if tried { Class::Bad } else { Class::Unknown }
}

/// Seconds to wait before dialling this address again, before jitter.
///
/// `failures` and `short_sessions` are the entry's counters *after* this
/// outcome has been applied, so the first failure arrives here as 1.
pub fn retry_delay_secs(
    outcome: &Outcome,
    origin: Origin,
    connected_before: bool,
    failures: u8,
    short_sessions: u8,
) -> u32 {
    // A chain verdict outranks everything below, the operator's own addresses
    // included: see OTHER_CHAIN_SECS.
    if matches!(outcome, Outcome::OtherChain) {
        return OTHER_CHAIN_SECS;
    }

    // Operator-supplied addresses keep a short fixed interval whatever
    // happens: the operator asked for this address specifically, and backing
    // off to days would quietly stop honouring that.
    if origin == Origin::Manual {
        return MANUAL_RETRY_SECS;
    }

    match outcome {
        // Handled above, before the origin check.
        Outcome::OtherChain => OTHER_CHAIN_SECS,

        Outcome::Violated => VIOLATION_SECS,

        Outcome::OurFault(reason) => match reason {
            OurFault::ProxyUnreachable => PROXY_UNREACHABLE_SECS,
            OurFault::NetworkUnreachable => NETWORK_UNREACHABLE_SECS,
            OurFault::NetworkDisabled => NETWORK_DISABLED_SECS,
        },

        Outcome::Disconnected { .. } => {
            if outcome.is_short_session() {
                // Probably being evicted, or a peer that completes the
                // handshake, says nothing, and hangs up on a timer -- a fleet
                // of those closing at exactly a minute was two thirds of all
                // sessions, redialled five seconds after each. Back off so we
                // stop hammering either.
                exp_backoff(EVICTION_BASE_SECS, 2, short_sessions, EVICTION_CAP_SECS)
            } else {
                STABLE_RECONNECT_SECS
            }
        }

        Outcome::Failed(_) if connected_before => {
            // It worked before, so it is probably coming back. Stay keen.
            exp_backoff(WAS_GOOD_BASE_SECS, 2, failures, WAS_GOOD_CAP_SECS)
        }

        Outcome::Failed(_) => {
            // Never once reachable. Most of these are addresses that were
            // cheap to invent, so back off aggressively.
            exp_backoff(BAD_BASE_SECS, 4, failures, BAD_CAP_SECS)
        }
    }
}

/// `base * factor^(n-1)`, clamped to `cap` and saturating rather than
/// overflowing. `n` of 0 or 1 both give `base`.
fn exp_backoff(base: u32, factor: u32, n: u8, cap: u32) -> u32 {
    let exp = u32::from(n.saturating_sub(1));
    base.saturating_mul(factor.saturating_pow(exp)).min(cap)
}

/// Spread a delay by +/-10% so that a batch of entries that failed together
/// does not come due together. `r` is a uniform random value in `[0, 1)`.
pub fn jitter(delay_secs: u32, r: f32) -> u32 {
    debug_assert!((0.0..1.0).contains(&r), "jitter factor out of range: {r}");
    let spread = delay_secs as f32 * 0.1;
    let offset = spread * (r * 2.0 - 1.0);
    (delay_secs as f32 + offset).round().max(1.0) as u32
}

/// Whether to drop an address from the book entirely.
///
/// `last_success` and `last_announced` are unix seconds, 0 meaning never.
pub fn should_forget(
    now: u32,
    origin: Origin,
    last_success: u32,
    last_announced: u32,
    failures: u8,
) -> bool {
    // The operator asked for this one. It is not ours to forget.
    if origin == Origin::Manual {
        return false;
    }

    if last_success > 0 {
        // Connected before. Keep it as long as that success is recent enough
        // to be worth retrying.
        return now.saturating_sub(last_success) > WAS_GOOD_FORGET_AFTER_SECS;
    }

    // Never connected.
    if failures >= BAD_FORGET_FAILURES_ALWAYS {
        return true;
    }
    if failures >= BAD_FORGET_FAILURES_IF_STALE {
        return now.saturating_sub(last_announced) > BAD_ANNOUNCE_GRACE_SECS;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY: u32 = 24 * 60 * 60;

    fn failed() -> Outcome {
        Outcome::Failed(Reason::TcpConnectTimeout)
    }

    #[test]
    fn test_classify() {
        assert_eq!(classify(false, 0, false), Class::Unknown);
        assert_eq!(classify(true, 0, true), Class::Bad);
        assert_eq!(classify(true, 1000, false), Class::Good);
        assert_eq!(classify(true, 1000, true), Class::WasGood);
        // A recorded success outranks the `tried` flag, so the two can never
        // disagree into a nonsensical class.
        assert_eq!(classify(false, 1000, false), Class::Good);
        assert_eq!(classify(false, 1000, true), Class::WasGood);
    }

    #[test]
    fn test_stable_session_retries_quickly() {
        let out = Outcome::Disconnected {
            uptime_secs: 600,
            silent: false,
        };
        assert_eq!(
            retry_delay_secs(&out, Origin::Gossip, true, 0, 0),
            STABLE_RECONNECT_SECS
        );
    }

    /// A peer that holds the session open for a while but never sends a
    /// message is backed off like an eviction, however long it stayed.
    #[test]
    fn test_silent_session_backs_off_like_an_eviction() {
        let silent = Outcome::Disconnected {
            uptime_secs: 60,
            silent: true,
        };
        assert!(silent.is_short_session());
        for (short_sessions, expected) in [(1, 60), (2, 120), (3, 240)] {
            assert_eq!(
                retry_delay_secs(&silent, Origin::Gossip, true, 0, short_sessions),
                expected
            );
        }
        // The same uptime with something said is a stable session.
        let spoke = Outcome::Disconnected {
            uptime_secs: 60,
            silent: false,
        };
        assert!(!spoke.is_short_session());
        assert_eq!(
            retry_delay_secs(&spoke, Origin::Gossip, true, 0, 3),
            STABLE_RECONNECT_SECS
        );
    }

    #[test]
    fn test_eviction_backs_off_and_caps() {
        let out = Outcome::Disconnected {
            uptime_secs: 5,
            silent: false,
        };
        assert!(out.is_short_session());
        // 60s doubling per consecutive short session.
        for (short_sessions, expected) in [(1, 60), (2, 120), (3, 240), (4, 480)] {
            assert_eq!(
                retry_delay_secs(&out, Origin::Gossip, true, 0, short_sessions),
                expected,
                "short_sessions={short_sessions}"
            );
        }
        // Capped at an hour, and never overflows however high the counter goes.
        assert_eq!(
            retry_delay_secs(&out, Origin::Gossip, true, 0, 200),
            EVICTION_CAP_SECS
        );
    }

    #[test]
    fn test_was_good_backs_off_and_caps() {
        for (failures, expected) in [(1, 60), (2, 120), (3, 240)] {
            assert_eq!(
                retry_delay_secs(&failed(), Origin::Gossip, true, failures, 0),
                expected,
                "failures={failures}"
            );
        }
        assert_eq!(
            retry_delay_secs(&failed(), Origin::Gossip, true, 255, 0),
            WAS_GOOD_CAP_SECS
        );
    }

    #[test]
    fn test_bad_backs_off_harder_than_was_good() {
        // Quadrupling from an hour.
        for (failures, expected) in [(1, 3600), (2, 14400), (3, 57600)] {
            assert_eq!(
                retry_delay_secs(&failed(), Origin::Gossip, false, failures, 0),
                expected,
                "failures={failures}"
            );
        }
        assert_eq!(
            retry_delay_secs(&failed(), Origin::Gossip, false, 255, 0),
            BAD_CAP_SECS
        );

        // An address that has worked before is always retried sooner than one
        // that never has.
        for failures in 1..=5 {
            assert!(
                retry_delay_secs(&failed(), Origin::Gossip, true, failures, 0)
                    < retry_delay_secs(&failed(), Origin::Gossip, false, failures, 0),
                "failures={failures}"
            );
        }
    }

    #[test]
    fn test_our_fault_waits_on_the_obstacle_and_is_not_a_failure() {
        let delay =
            |reason| retry_delay_secs(&Outcome::OurFault(reason), Origin::Gossip, false, 0, 0);
        // A missing route lasts until the host is reconfigured; a dead proxy
        // may be back in a moment.
        assert_eq!(delay(OurFault::ProxyUnreachable), PROXY_UNREACHABLE_SECS);
        assert_eq!(
            delay(OurFault::NetworkUnreachable),
            NETWORK_UNREACHABLE_SECS
        );
        assert_eq!(delay(OurFault::NetworkDisabled), NETWORK_DISABLED_SECS);
        assert!(delay(OurFault::NetworkUnreachable) > delay(OurFault::ProxyUnreachable));

        // Whichever it was, it says nothing about the address.
        assert!(!Outcome::OurFault(OurFault::NetworkUnreachable).counts_as_failure());
        assert!(failed().counts_as_failure());
    }

    #[test]
    fn test_manual_keeps_a_short_fixed_retry() {
        // However bad its history, and whatever the outcome.
        for outcome in [
            failed(),
            Outcome::OurFault(OurFault::NetworkUnreachable),
            Outcome::Disconnected {
                uptime_secs: 0,
                silent: false,
            },
        ] {
            assert_eq!(
                retry_delay_secs(&outcome, Origin::Manual, false, 200, 200),
                MANUAL_RETRY_SECS
            );
        }
        // With one exception: an operator asked for a peer on this network,
        // and a minute's retry on a peer that is not would just repeat the
        // same handshake and the same answer all day.
        assert_eq!(
            retry_delay_secs(&Outcome::OtherChain, Origin::Manual, true, 0, 0),
            OTHER_CHAIN_SECS
        );
    }

    /// A peer on a chain we refuse is left for a day, and nothing is held
    /// against the address: it answered and told us the truth about itself.
    #[test]
    fn test_another_chain_waits_a_day_and_is_not_a_failure() {
        for origin in [Origin::Gossip, Origin::Manual] {
            assert_eq!(
                retry_delay_secs(&Outcome::OtherChain, origin, true, 0, 0),
                24 * 60 * 60
            );
        }
        // However many times it has happened: the delay is the verdict, not
        // a backoff that doubles.
        assert_eq!(
            retry_delay_secs(&Outcome::OtherChain, Origin::Gossip, true, 9, 9),
            OTHER_CHAIN_SECS
        );
        assert!(!Outcome::OtherChain.counts_as_failure());
        // Not an eviction either. We hung up, so the length says nothing.
        assert!(!Outcome::OtherChain.is_short_session());
    }

    /// A peer that broke a protocol limit waits an hour, which is the whole
    /// of the judgement: nothing is counted against the address, because the
    /// address answered and handshook.
    #[test]
    fn test_a_violation_waits_an_hour_and_is_not_a_failure() {
        assert_eq!(
            retry_delay_secs(&Outcome::Violated, Origin::Gossip, true, 0, 0),
            60 * 60
        );
        // Flat, not doubling: a second violation says nothing the first did
        // not, so neither counter moves the delay.
        assert_eq!(
            retry_delay_secs(&Outcome::Violated, Origin::Gossip, true, 9, 9),
            VIOLATION_SECS
        );
        // An operator who points us at a misbehaving node is usually pointing
        // us at the build that misbehaves, so their addresses keep the short
        // interval -- unlike the chain verdict, which outranks it.
        assert_eq!(
            retry_delay_secs(&Outcome::Violated, Origin::Manual, true, 0, 0),
            MANUAL_RETRY_SECS
        );

        assert!(!Outcome::Violated.counts_as_failure());
        // Not an eviction either: we hung up, so the length says nothing.
        assert!(!Outcome::Violated.is_short_session());

        // Far enough from an ordinary disconnect to be worth asserting: that
        // is the behaviour this replaces.
        let ordinary = Outcome::Disconnected {
            uptime_secs: 3600,
            silent: false,
        };
        assert!(
            retry_delay_secs(&Outcome::Violated, Origin::Gossip, true, 0, 0)
                > retry_delay_secs(&ordinary, Origin::Gossip, true, 0, 0) * 100
        );
    }

    #[test]
    fn test_jitter_stays_within_ten_percent() {
        for r in [0.0, 0.25, 0.5, 0.75, 0.999] {
            let got = jitter(1000, r);
            assert!((900..=1100).contains(&got), "r={r} gave {got}");
        }
        // Extremes land on the bounds, and the midpoint is unchanged.
        assert_eq!(jitter(1000, 0.0), 900);
        assert_eq!(jitter(1000, 0.5), 1000);
        // Never returns 0, which would mean an immediate redial.
        assert!(jitter(0, 0.0) >= 1);
        assert!(jitter(1, 0.0) >= 1);
    }

    #[test]
    fn test_manual_is_never_forgotten() {
        assert!(!should_forget(100 * DAY, Origin::Manual, 0, 0, 255));
    }

    #[test]
    fn test_was_good_forgotten_once_success_is_old() {
        let now = 100 * DAY;
        // Succeeded a week ago: keep.
        assert!(!should_forget(now, Origin::Gossip, now - 7 * DAY, 0, 50));
        // Succeeded 31 days ago: drop.
        assert!(should_forget(now, Origin::Gossip, now - 31 * DAY, 0, 1));
    }

    #[test]
    fn test_bad_forget_rules() {
        let now = 100 * DAY;

        // Too few failures to forget, however stale.
        assert!(!should_forget(now, Origin::Gossip, 0, 0, 2));

        // Three failures and no recent announcement: drop.
        assert!(should_forget(now, Origin::Gossip, 0, now - 31 * DAY, 3));
        // Three failures but recently re-announced: keep for now.
        assert!(!should_forget(now, Origin::Gossip, 0, now - DAY, 3));

        // Five failures: drop regardless of announcements, so that an attacker
        // cannot keep dead entries resident by re-gossiping them.
        assert!(should_forget(now, Origin::Gossip, 0, now, 5));
    }
}
