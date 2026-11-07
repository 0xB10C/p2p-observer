//! The open file limit, which is the ceiling on how many peers we watch.
//!
//! Nothing caps the number of established connections. `max_dialing` bounds
//! the dials in flight, and an address leaves that count the moment its
//! handshake completes, so sessions accumulate for as long as peers stay up.
//! That is deliberate: the tool exists to watch as much of the network as it
//! can reach, and a ceiling on connections is a decision to stop watching part
//! of it.
//!
//! What follows is that the descriptor limit is the real ceiling, and the
//! operator should learn it at startup rather than from the first socket that
//! fails to open -- by which time the log line is competing with every other
//! connection failing the same way. So: raise the soft limit as far as the OS
//! allows, refuse to start if what is left cannot cover even the dials in
//! flight, and report the headroom either way.
//!
//! Bitcoin Core does the same thing in `RaiseFileDescriptorLimit`, and for the
//! same reason -- its connection count is bounded, but the limit still decides
//! whether the bound is reachable.

use crate::TARGET_MAIN;
use common::tracing;

/// Descriptors reserved for everything that is not a peer connection.
///
/// The NATS connection, the RPC listener and whatever clients it has, the
/// state files as they are rewritten, stdout, and what the runtime keeps for
/// itself. Generous on purpose: overestimating costs a line at startup,
/// underestimating costs an unexplained failure hours in.
const RESERVE: u64 = 64;

/// The limit we need before a single peer is connected.
fn floor(max_dialing: u64) -> u64 {
    max_dialing.saturating_add(RESERVE)
}

/// What to do about the limit we found.
///
/// `RLIM_INFINITY` arrives as `u64::MAX`, which needs no special case here: it
/// is above every floor and is a legitimate thing to raise the soft limit to.
#[derive(Debug, PartialEq, Eq)]
enum Plan {
    /// The soft limit is already everything we can have.
    Keep { limit: u64 },
    /// Raise the soft limit to the hard one.
    Raise { to: u64 },
    /// Not even the hard limit covers the floor. Nothing to do but say so.
    TooLow { hard: u64, floor: u64 },
}

fn plan(soft: u64, hard: u64, floor: u64) -> Plan {
    if hard < floor {
        Plan::TooLow { hard, floor }
    } else if soft < hard {
        // Taken whether or not the soft limit already clears the floor: no
        // ceiling on connections means every descriptor the OS will part with
        // is another peer we can watch.
        Plan::Raise { to: hard }
    } else {
        Plan::Keep { limit: soft }
    }
}

/// Raise the open file limit as far as the OS allows, and report what it
/// leaves for peer connections.
///
/// Fails only when the hard limit cannot cover [`floor`] -- that is a
/// misconfigured host rather than a busy one, and it will not get better by
/// running.
#[cfg(unix)]
pub(crate) fn prepare(max_dialing: usize) -> Result<(), String> {
    let floor = floor(max_dialing as u64);
    let (soft, hard) = current().map_err(|e| format!("cannot read the open file limit: {e}"))?;

    let mut limit = match plan(soft, hard, floor) {
        Plan::TooLow { hard, floor } => {
            return Err(format!(
                "the open file limit allows at most {hard} descriptors, \
                 and {floor} are needed for {max_dialing} dials in flight \
                 plus {RESERVE} reserved -- raise it or lower max_dialing"
            ));
        }
        Plan::Keep { limit } => limit,
        Plan::Raise { to } => match raise(to, hard) {
            Ok(()) => to,
            // Not fatal in itself: macOS refuses a raise to an unlimited hard
            // limit, and a sandbox may refuse one outright. What matters is
            // whether the limit we are left with clears the floor, which the
            // check below does.
            Err(e) => {
                tracing::warn!(target: TARGET_MAIN,
                    soft, hard, wanted = to, error = %e,
                    "could not raise the open file limit"
                );
                soft
            }
        },
    };
    if limit < floor {
        return Err(format!(
            "the open file limit is {limit} descriptors and {floor} are needed \
             for {max_dialing} dials in flight plus {RESERVE} reserved"
        ));
    }

    // Re-read rather than trust the raise: the kernel is free to clamp, and a
    // number we only believe is worse than no number at all here.
    if let Ok((soft, _)) = current() {
        limit = soft;
    }
    let headroom = limit.saturating_sub(floor);
    if limit == u64::MAX {
        tracing::info!(target: TARGET_MAIN,
            "the open file limit is unlimited: nothing but the host bounds how \
             many peers we connect to"
        );
    } else {
        tracing::info!(target: TARGET_MAIN,
            limit, reserved = RESERVE, max_dialing, headroom,
            "open file limit, leaving headroom for established connections"
        );
    }
    Ok(())
}

/// Nothing to raise and nothing to check: a platform without the limit has no
/// ceiling for us to report.
#[cfg(not(unix))]
pub(crate) fn prepare(_max_dialing: usize) -> Result<(), String> {
    Ok(())
}

#[cfg(unix)]
// `rlim_t` is u64 here and on macOS but i64 on the BSDs, so the casts are
// portability and not redundancy, whatever the lint says on this platform.
#[allow(clippy::unnecessary_cast)]
fn current() -> std::io::Result<(u64, u64)> {
    let mut lim = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `lim` is initialised and lives across the call, which only
    // writes the two fields it is given.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok((lim.rlim_cur as u64, lim.rlim_max as u64))
}

#[cfg(unix)]
// `rlim_t` is u64 here and on macOS but i64 on the BSDs, so the casts are
// portability and not redundancy, whatever the lint says on this platform.
#[allow(clippy::unnecessary_cast)]
fn raise(to: u64, hard: u64) -> std::io::Result<()> {
    let lim = libc::rlimit {
        rlim_cur: to as libc::rlim_t,
        rlim_max: hard as libc::rlim_t,
    };
    // SAFETY: `lim` is initialised and lives across the call, which only
    // reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &lim) } != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The floor covers the dials that can be in flight at once, which is the
    /// one part of our descriptor use that is actually bounded.
    #[test]
    fn test_the_floor_covers_the_dials_in_flight() {
        assert_eq!(floor(200), 200 + RESERVE);
        assert_eq!(floor(0), RESERVE);
        // A configured number large enough to overflow is still a number.
        assert_eq!(floor(u64::MAX), u64::MAX);
    }

    /// The soft limit is raised whenever the hard one is higher, even when the
    /// soft limit would already do: connections are unbounded, so the spare
    /// descriptors are peers we would otherwise not see.
    #[test]
    fn test_a_higher_hard_limit_is_always_taken() {
        assert_eq!(plan(1024, 1_048_576, 264), Plan::Raise { to: 1_048_576 });
        assert_eq!(plan(128, 4096, 264), Plan::Raise { to: 4096 });
        assert_eq!(
            plan(4096, u64::MAX, 264),
            Plan::Raise { to: u64::MAX },
            "an unlimited hard limit is a target like any other"
        );
    }

    /// Nothing to do when the soft limit is already the hard one.
    #[test]
    fn test_an_exhausted_hard_limit_is_kept() {
        assert_eq!(plan(4096, 4096, 264), Plan::Keep { limit: 4096 });
    }

    /// A hard limit under the floor cannot be fixed by raising anything, and
    /// is reported with both numbers so the operator can act on it.
    #[test]
    fn test_a_hard_limit_under_the_floor_is_refused() {
        assert_eq!(
            plan(64, 200, 264),
            Plan::TooLow {
                hard: 200,
                floor: 264
            }
        );
        // Refused on the hard limit even where the soft one happens to clear
        // the floor, which the OS does not allow but the arithmetic should
        // not depend on.
        assert_eq!(
            plan(300, 200, 264),
            Plan::TooLow {
                hard: 200,
                floor: 264
            }
        );
    }

    /// `prepare` reads the real limit, raises it, and leaves the process able
    /// to open what it promised.
    ///
    /// Everything above this was the decision in the abstract. This is the
    /// part that calls `getrlimit` and `setrlimit` -- the part that either
    /// lets the observer hold its peers or refuses to start -- and it was
    /// covered only by two runs against the binary at the time it was
    /// written, which is not something a later edit can repeat.
    ///
    /// Raising the soft limit to the hard one is the only side effect, and it
    /// is the one the binary has anyway: more descriptors, no fewer.
    #[cfg(unix)]
    #[test]
    fn test_prepare_raises_the_soft_limit_to_the_hard_one() {
        let (soft, hard) = current().expect("the kernel reports RLIMIT_NOFILE");
        // Make the precondition rather than inherit it. Where the soft limit
        // is already the hard one -- this dev shell, and any systemd unit
        // whose LimitNOFILE= sets both -- `plan` returns `Keep`, `raise` is
        // never called, and every assertion below holds before `prepare` is
        // even entered. Lowering our own soft limit first, with the module's
        // own `raise`, is the one way to leave the raise somewhere to go.
        if soft == hard {
            let lowered = floor(200).max(soft / 2);
            assert!(
                lowered < hard,
                "a host whose whole limit is {hard} cannot show a raise"
            );
            raise(lowered, hard).expect("lowering our own soft limit");
        }

        let (soft_before, hard_before) = current().expect("the kernel reports RLIMIT_NOFILE");
        assert!(
            soft_before < hard_before,
            "the raise has nowhere to go, so nothing below is a test of it"
        );
        prepare(200).expect("200 dials plus a reserve fits in any usable limit");

        let (soft, hard) = current().expect("the kernel reports RLIMIT_NOFILE");
        assert_eq!(hard, hard_before, "the hard limit is not ours to move");
        // What `prepare` promises: it returned Ok, so the limit it left us
        // covers the dials, and it never went down to get there.
        assert!(
            soft >= floor(200),
            "{soft} descriptors is under the {} needed",
            floor(200)
        );
        assert!(
            soft >= soft_before,
            "{soft} descriptors is fewer than the {soft_before} we started with"
        );
        // A refused raise is tolerated on purpose -- macOS refuses one to an
        // unlimited hard limit and a sandbox may refuse one outright, and
        // `prepare` warns and carries on -- so the equality is asserted only
        // where the kernel is expected to grant it.
        #[cfg(target_os = "linux")]
        assert_eq!(
            soft, hard,
            "the soft limit should have been raised to the hard one"
        );
    }

    /// And it refuses, by name, when the limit cannot cover what was asked.
    ///
    /// The refusal is deliberate -- starting and then failing to dial halfway
    /// through is worse than not starting -- so the message is what an
    /// operator has to act on, and it has to name both numbers. Asked for
    /// more dials than any host could have descriptors for, which exercises
    /// the real syscalls without moving the process's own limit anywhere.
    #[cfg(unix)]
    #[test]
    fn test_prepare_refuses_a_limit_that_cannot_cover_the_dials() {
        let (_, hard) = current().expect("the kernel reports RLIMIT_NOFILE");
        if hard == u64::MAX {
            // An unlimited hard limit covers anything, and saying so is the
            // other branch's job.
            return;
        }
        let too_many = usize::try_from(hard).unwrap_or(usize::MAX);
        let err = prepare(too_many).expect_err("more dials than descriptors");
        assert!(
            err.contains(&hard.to_string()),
            "{err}: the message should name the limit it found"
        );
        assert!(
            err.contains("max_dialing") || err.contains("needed"),
            "{err}: the message should say what to do about it"
        );
    }
}
