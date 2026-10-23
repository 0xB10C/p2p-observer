//! Retry delays, class weights and forget rules.
//!
//! Everything here is a pure function of its arguments and an explicit `now`,
//! with no clock, no randomness and no state. That is deliberate: the policy is
//! the part most likely to need tuning, and it should be possible to check a
//! change against a table of expected values rather than by running a crawler
//! for a day.

/// A session shorter than this is read as an eviction rather than an ordinary
/// disconnect: the peer accepted us and then dropped us almost immediately,
/// most likely because its inbound slots are full.
pub const SHORT_SESSION_SECS: u32 = 31;

/// Relative share of each class in the dial budget. Good addresses are not in
/// this list: reconnects are taken separately, ahead of the budget.
pub const WEIGHT_UNKNOWN: f32 = 70.0;
pub const WEIGHT_LAPSED: f32 = 20.0;
pub const WEIGHT_BAD: f32 = 10.0;

/// Maximum reconnects to good addresses started in a single tick.
///
/// Due reconnects are taken outside the normal dial budget, so that peers we
/// want to stay connected to are not starved by the flow of newly gossiped
/// addresses. That exemption needs a ceiling of its own: after any downtime
/// every good entry's `next_attempt` is already in the past, so an uncapped
/// pass would dial the entire good table in one tick — thousands of sockets at
/// once and a thundering herd at the peers. Jitter does not help, because
/// those delays have already elapsed.
pub const MAX_RECONNECTS_PER_TICK: usize = 25;

/// Gossiped timestamps are clamped to this far past `now`. A peer can claim
/// any nTime it likes, and a far-future value would otherwise make an address
/// look permanently fresher than every honest one.
pub const NTIME_MAX_SKEW_SECS: u32 = 600;

/// Addresses accepted from a peer per second, and the burst it may spend at
/// once, mirroring Bitcoin Core. At 0.1/s a single peer can teach us about
/// ~8.6k addresses a day, which is the most effective single bound on table
/// growth. Our own GETADDR reply is exempt — we asked for it.
pub const ADDR_RATE_PER_SEC: f64 = 0.1;
pub const ADDR_BURST: f64 = 1000.0;

/// Fixed retry interval for operator-supplied and bootstrap addresses.
const MANUAL_RETRY_SECS: u32 = 60;

/// Wait after a session that ended having run for a healthy length of time.
/// Short, because we want to be connected to this peer.
const STABLE_RECONNECT_SECS: u32 = 5;

/// Wait after our own side failed (no route, proxy down). Not the address's
/// fault, so it is a short pause rather than a backoff.
const OUR_FAULT_SECS: u32 = 30;

const EVICTION_BASE_SECS: u32 = 60;
const EVICTION_CAP_SECS: u32 = 60 * 60;

const LAPSED_BASE_SECS: u32 = 60;
const LAPSED_CAP_SECS: u32 = 6 * 60 * 60;

const BAD_BASE_SECS: u32 = 60 * 60;
const BAD_CAP_SECS: u32 = 7 * 24 * 60 * 60;

/// Forget a lapsed address once it has been unreachable for this long.
const LAPSED_FORGET_AFTER_SECS: u32 = 30 * 24 * 60 * 60;
/// Forget a never-reachable address after this many failures, provided nobody
/// has re-announced it recently.
const BAD_FORGET_FAILURES_IF_STALE: u8 = 3;
/// Forget a never-reachable address after this many failures regardless of
/// how often it is announced. Stops an attacker keeping dead entries alive by
/// re-gossiping them.
const BAD_FORGET_FAILURES_ALWAYS: u8 = 5;
/// How long an announcement keeps a failing address from being forgotten.
const BAD_ANNOUNCE_GRACE_SECS: u32 = 30 * 24 * 60 * 60;

/// How we came to know an address, which decides how patient we are with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    /// Configured as a bootstrap peer or added by the operator over RPC.
    /// Retried on a short fixed interval and never forgotten.
    Manual,
    /// Learned from a peer's addr/addrv2 gossip.
    Gossip,
}

/// Why a dial attempt did not produce a session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    ConnectionRefused,
    HostUnreachable,
    TimedOut,
    UnexpectedEof,
    HandshakeFailed,
    Other,
}

/// What became of a dial attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Never reached a working session.
    Failed(Reason),
    /// A session ran and then ended.
    Disconnected { uptime_secs: u32 },
    /// We could not even make the attempt: no route to that network, the Tor
    /// proxy is down, and so on. Never counted against the address, because it
    /// says nothing about the peer.
    OurFault,
}

impl Outcome {
    /// Whether this outcome counts as a failure of the address itself.
    pub fn counts_as_failure(&self) -> bool {
        matches!(self, Outcome::Failed(_))
    }

    /// Whether this outcome is a session that ended suspiciously early.
    pub fn is_short_session(&self) -> bool {
        matches!(self, Outcome::Disconnected { uptime_secs } if *uptime_secs < SHORT_SESSION_SECS)
    }
}

/// Which bucket an address falls into, derived from its history rather than
/// stored. `Good` and `Lapsed` both mean "has connected at least once"; they
/// differ only in whether the most recent attempt worked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Class {
    /// Never attempted.
    Unknown,
    /// The most recent attempt succeeded.
    Good,
    /// Has connected before, but the most recent attempt failed.
    Lapsed,
    /// Attempted at least once and never once connected.
    Bad,
}

/// Classify an address from its history. `last_success` of 0 means never.
pub fn classify(attempted: bool, last_success: u32, last_attempt_failed: bool) -> Class {
    match (attempted, last_success > 0) {
        (false, _) => Class::Unknown,
        (true, false) => Class::Bad,
        (true, true) if last_attempt_failed => Class::Lapsed,
        (true, true) => Class::Good,
    }
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
    // Operator-supplied addresses keep a short fixed interval whatever
    // happens: the operator asked for this address specifically, and backing
    // off to days would quietly stop honouring that.
    if origin == Origin::Manual {
        return MANUAL_RETRY_SECS;
    }

    match outcome {
        Outcome::OurFault => OUR_FAULT_SECS,

        Outcome::Disconnected { uptime_secs } => {
            if *uptime_secs >= SHORT_SESSION_SECS {
                STABLE_RECONNECT_SECS
            } else {
                // Probably being evicted. Back off so we stop hammering a peer
                // whose inbound slots are full.
                exp_backoff(EVICTION_BASE_SECS, 2, short_sessions, EVICTION_CAP_SECS)
            }
        }

        Outcome::Failed(_) if connected_before => {
            // It worked before, so it is probably coming back. Stay keen.
            exp_backoff(LAPSED_BASE_SECS, 2, failures, LAPSED_CAP_SECS)
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

/// Clamp a gossiped timestamp so a peer cannot claim an address is from the
/// future.
pub fn clamp_ntime(ntime: u32, now: u32) -> u32 {
    ntime.min(now.saturating_add(NTIME_MAX_SKEW_SECS))
}

/// Whether to drop an address from the table entirely.
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
        return now.saturating_sub(last_success) > LAPSED_FORGET_AFTER_SECS;
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
        Outcome::Failed(Reason::TimedOut)
    }

    #[test]
    fn test_classify() {
        assert_eq!(classify(false, 0, false), Class::Unknown);
        assert_eq!(classify(true, 0, true), Class::Bad);
        assert_eq!(classify(true, 1000, false), Class::Good);
        assert_eq!(classify(true, 1000, true), Class::Lapsed);
    }

    #[test]
    fn test_stable_session_retries_quickly() {
        let out = Outcome::Disconnected { uptime_secs: 600 };
        assert_eq!(
            retry_delay_secs(&out, Origin::Gossip, true, 0, 0),
            STABLE_RECONNECT_SECS
        );
    }

    #[test]
    fn test_eviction_backs_off_and_caps() {
        let out = Outcome::Disconnected { uptime_secs: 5 };
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
    fn test_lapsed_backs_off_and_caps() {
        for (failures, expected) in [(1, 60), (2, 120), (3, 240)] {
            assert_eq!(
                retry_delay_secs(&failed(), Origin::Gossip, true, failures, 0),
                expected,
                "failures={failures}"
            );
        }
        assert_eq!(
            retry_delay_secs(&failed(), Origin::Gossip, true, 255, 0),
            LAPSED_CAP_SECS
        );
    }

    #[test]
    fn test_bad_backs_off_harder_than_lapsed() {
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
    fn test_our_fault_is_a_short_pause_and_not_a_failure() {
        assert_eq!(
            retry_delay_secs(&Outcome::OurFault, Origin::Gossip, false, 0, 0),
            OUR_FAULT_SECS
        );
        assert!(!Outcome::OurFault.counts_as_failure());
        assert!(failed().counts_as_failure());
    }

    #[test]
    fn test_manual_keeps_a_short_fixed_retry() {
        // However bad its history, and whatever the outcome.
        for outcome in [
            failed(),
            Outcome::OurFault,
            Outcome::Disconnected { uptime_secs: 0 },
        ] {
            assert_eq!(
                retry_delay_secs(&outcome, Origin::Manual, false, 200, 200),
                MANUAL_RETRY_SECS
            );
        }
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
    fn test_clamp_ntime() {
        let now = 1_000_000;
        // A plausible timestamp is left alone.
        assert_eq!(clamp_ntime(now - 50, now), now - 50);
        // A far-future claim is pulled back to the allowed skew.
        assert_eq!(clamp_ntime(now + 86_400, now), now + NTIME_MAX_SKEW_SECS);
        // Within the skew is fine; clocks disagree.
        assert_eq!(clamp_ntime(now + 60, now), now + 60);
        assert_eq!(clamp_ntime(u32::MAX, now), now + NTIME_MAX_SKEW_SECS);
    }

    #[test]
    fn test_manual_is_never_forgotten() {
        assert!(!should_forget(100 * DAY, Origin::Manual, 0, 0, 255));
    }

    #[test]
    fn test_lapsed_forgotten_once_success_is_old() {
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
