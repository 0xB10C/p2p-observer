//! What the observer is connected to right now.
//!
//! Every other fact about a connection is published as an event and kept by
//! whoever cares; this is the one thing an event stream cannot answer. A
//! consumer that attaches at noon has no way to learn about a session that
//! began at nine, because the handshake that described it is in the past: it
//! sees the connection only when something happens on it, and a quiet peer
//! takes a ping interval to appear with its handshake columns empty for good.
//! So the set of live sessions is held here and answered over RPC, and a page
//! or a script can ask what is connected instead of waiting to find out.
//!
//! It is deliberately small. The identity of a session goes in, which is
//! fixed once the handshake is done, plus a few totals refreshed on the
//! connection's own ping timer -- about one write per connection per two
//! minutes, so the lock is never contended and never held across an await.
//! Anything that moves faster than that is on the event stream, where it
//! belongs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use crate::addresses::peer_addr::PeerAddr;

/// One live session.
///
/// The peer's claims are recorded as made, the same as on the handshake
/// event: that it said so is the observation.
#[derive(Clone, Debug)]
pub(crate) struct Live {
    pub(crate) addr: PeerAddr,
    pub(crate) transport_version: u8,
    /// Unix milliseconds at which the handshake completed, so a reader can
    /// work out the uptime against its own clock as well as ours.
    pub(crate) connected_ms: u64,
    pub(crate) user_agent: String,
    pub(crate) protocol_version: u32,
    pub(crate) services: u64,
    pub(crate) start_height: i32,
    pub(crate) relay: bool,
    pub(crate) sendaddrv2: bool,
    pub(crate) wtxid_relay: bool,
    pub(crate) addr_recv: String,
    pub(crate) peer_timestamp: i64,
    /// Everything below is refreshed on the ping timer.
    pub(crate) counters: Counters,
    /// When that last happened, so a reader can see how stale the counters
    /// are rather than assuming they are current.
    pub(crate) updated_ms: u64,
}

/// The totals a session has accumulated, as of its last ping.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct Counters {
    /// Messages received from the peer, all commands together.
    pub(crate) messages: u64,
    pub(crate) unsolicited_pongs: u32,
    /// The most recent round trip, and the lowest of the samples kept.
    pub(crate) rtt_ms: Option<u32>,
    pub(crate) min_rtt_ms: Option<u32>,
}

/// The live sessions of this observer, by connection id.
#[derive(Debug, Default)]
pub(crate) struct Registry {
    live: Mutex<HashMap<u64, Live>>,
}

impl Registry {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// The map, whether or not a panic somewhere else has poisoned the lock.
    ///
    /// Nothing in here holds an invariant a half-finished write could break:
    /// entries go in and come out whole. So a poisoned lock says only that
    /// some other thread died nearby, and panicking on it would turn that
    /// into a second failure -- in [`Registered::drop`] into an abort, since
    /// a drop runs during the unwinding from the first panic and a panic
    /// while unwinding ends the process. The worst a recovered lock can hold
    /// is an entry for a session that has finished, which the RPC would
    /// report for as long as the process ran.
    fn map(&self) -> MutexGuard<'_, HashMap<u64, Live>> {
        self.live.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// Note a session that has just finished its handshake. The returned
    /// guard removes it again, so a task that is dropped or cancelled cannot
    /// leave a session in here that is no longer running.
    pub(crate) fn register(self: &Arc<Self>, id: u64, live: Live) -> Registered {
        self.map().insert(id, live);
        Registered {
            registry: Arc::clone(self),
            id,
        }
    }

    /// Refresh the counters of a live session; does nothing once it is gone.
    pub(crate) fn refresh(&self, id: u64, counters: Counters, now_ms: u64) {
        if let Some(live) = self.map().get_mut(&id) {
            live.counters = counters;
            live.updated_ms = now_ms;
        }
    }

    /// Every live session, oldest connection id first, so two snapshots read
    /// in the same order.
    pub(crate) fn snapshot(&self) -> Vec<(u64, Live)> {
        let mut all: Vec<(u64, Live)> = self
            .map()
            .iter()
            .map(|(id, live)| (*id, live.clone()))
            .collect();
        all.sort_by_key(|(id, _)| *id);
        all
    }
}

/// Removes a session from the registry when it ends, however it ends.
#[derive(Debug)]
pub(crate) struct Registered {
    registry: Arc<Registry>,
    id: u64,
}

impl Drop for Registered {
    fn drop(&mut self) {
        self.registry.map().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn live(height: i32) -> Live {
        Live {
            addr: PeerAddr::Ipv4([10, 0, 0, 1], 8333),
            transport_version: 2,
            connected_ms: 1_700_000_000_000,
            user_agent: "/Satoshi:30.0.0/".to_owned(),
            protocol_version: 70016,
            services: 1033,
            start_height: height,
            relay: true,
            sendaddrv2: true,
            wtxid_relay: true,
            addr_recv: "0.0.0.0:0".to_owned(),
            peer_timestamp: 1_700_000_000,
            counters: Counters::default(),
            updated_ms: 0,
        }
    }

    #[test]
    fn test_a_session_lives_as_long_as_its_guard() {
        let registry = Registry::new();
        let first = registry.register(1, live(1));
        let _second = registry.register(2, live(2));
        assert_eq!(registry.snapshot().len(), 2);
        // Oldest id first, whatever order they were registered in.
        assert_eq!(
            registry
                .snapshot()
                .iter()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            vec![1, 2]
        );

        drop(first);
        assert_eq!(registry.snapshot().len(), 1);
        assert_eq!(registry.snapshot()[0].0, 2);
    }

    #[test]
    fn test_counters_are_refreshed_in_place() {
        let registry = Registry::new();
        let _guard = registry.register(7, live(1));
        registry.refresh(
            7,
            Counters {
                messages: 42,
                unsolicited_pongs: 1,
                rtt_ms: Some(37),
                min_rtt_ms: Some(35),
            },
            1_700_000_060_000,
        );
        let (_, live) = registry.snapshot().remove(0);
        assert_eq!(live.counters.messages, 42);
        assert_eq!(live.counters.rtt_ms, Some(37));
        assert_eq!(live.updated_ms, 1_700_000_060_000);
        // The handshake is untouched by a refresh.
        assert_eq!(live.start_height, 1);

        // A session that has ended is not resurrected by a late refresh.
        drop(_guard);
        registry.refresh(7, Counters::default(), 0);
        assert!(registry.snapshot().is_empty());
    }

    /// Dropping a registration must not panic, whatever state the lock is in.
    ///
    /// A `Drop` that can panic is a process abort waiting for a bad moment:
    /// it runs during unwinding from some other panic, and a panic while
    /// unwinding aborts. In a test binary that eats the summary -- the run
    /// ends mid-list with no failure named, which is exactly as much as it
    /// tells you in production.
    ///
    /// The lock is poisoned here the way any panic holding it would poison
    /// it. A poisoned map of live sessions is not corrupted state worth
    /// ending the process over: the worst it can hold is an entry for a
    /// session that has finished, which the RPC would report for as long as
    /// the process ran.
    #[test]
    fn test_dropping_a_registration_survives_a_poisoned_lock() {
        let registry = Registry::new();
        let registered = registry.register(1, live(100));

        let poisoner = Arc::clone(&registry);
        let _ = std::thread::spawn(move || {
            let _held = poisoner.live.lock().expect("registry lock");
            panic!("poisoning the registry lock the way a panic in here would");
        })
        .join();
        assert!(registry.live.is_poisoned());

        drop(registered);
        // And the entry is gone, so the guard did its job rather than merely
        // surviving.
        assert!(
            registry.snapshot().is_empty(),
            "the registration outlived its guard"
        );
    }
}
