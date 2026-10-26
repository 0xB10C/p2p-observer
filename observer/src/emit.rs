//! Handing research events to the publisher.

use common::{
    events::{PeerEvent, peer_event::Event},
    tokio::sync::mpsc,
};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};

/// Depth of the event queue between the connection tasks and the publisher.
///
/// Sized for the startup burst: every connection handshakes at once and each
/// answers a GETADDR, which at 160 peers is ~160 announcements of up to 1000
/// addresses -- around 9 MB -- inside a couple of seconds, while the publisher
/// awaits each NATS publish in turn. 1024 slots lost 61 events to that burst.
/// The cost is memory in the worst case: an announcement with 1000 entries is
/// about 50 KB, so a queue full of them would be ~400 MB.
pub(crate) const EVENT_QUEUE: usize = 8192;

/// Slots kept free of address announcements.
///
/// Gossip is the bulk of the stream and the least costly thing to lose: an
/// address that was dropped will be announced again. A handshake or a
/// disconnect will not. So when the queue runs short it is announcements that
/// are shed, and everything else still has this much room.
pub(crate) const GOSSIP_SHED_BELOW: usize = 1024;

/// Events that could not be handed to the publisher since the process started.
static DROPPED: AtomicU64 = AtomicU64::new(0);

/// This run of the observer, as every event names it.
static INSTANCE: OnceLock<u64> = OnceLock::new();

/// A value that differs between runs of the observer.
///
/// `RandomState` is seeded from the OS once per process, so hashing anything
/// with it yields a per-process random number without taking a dependency on
/// a random crate for one value at startup. It only has to differ between
/// runs; nothing is secured by it.
fn fresh_instance_id() -> u64 {
    use std::hash::{BuildHasher, Hasher, RandomState};
    let mut hasher = RandomState::new().build_hasher();
    hasher.write_u64(u64::from(std::process::id()));
    hasher.finish()
}

/// Queue one event, dropping it rather than blocking a connection task.
///
/// Stamps the running drop count on the way out, which is the only way a
/// reader can tell a quiet stretch of the stream from a lossy one. The count
/// is read before the send, so an event reports the losses that came before it
/// and never its own.
///
/// Every event goes through here so that no emit site can forget the stamp,
/// and so there is one place where the decision to drop is made.
pub(crate) fn send(tx: &mpsc::Sender<PeerEvent>, mut event: PeerEvent) {
    event.dropped_events = DROPPED.load(Ordering::Relaxed);
    event.instance_id = *INSTANCE.get_or_init(fresh_instance_id);
    let is_gossip = matches!(event.event, Some(Event::AddressAnnouncement(_)));
    if (is_gossip && tx.capacity() <= GOSSIP_SHED_BELOW) || tx.try_send(event).is_err() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::events::{AddressAnnouncement, PingRtt};
    use std::sync::Mutex;

    /// The drop counter is process-wide, so tests that read it must not
    /// interleave.
    static SERIAL: Mutex<()> = Mutex::new(());

    fn ping() -> PeerEvent {
        PeerEvent {
            event: Some(Event::PingRtt(PingRtt::default())),
            ..Default::default()
        }
    }

    fn gossip() -> PeerEvent {
        PeerEvent {
            event: Some(Event::AddressAnnouncement(AddressAnnouncement::default())),
            ..Default::default()
        }
    }

    #[test]
    fn test_stamps_the_drop_count_and_counts_a_full_channel() {
        let _serial = SERIAL.lock().unwrap();
        let (tx, mut rx) = mpsc::channel(1);

        // The first event fits. Whatever other tests have dropped, this is the
        // baseline the second event has to exceed.
        send(&tx, ping());
        let baseline = rx.try_recv().unwrap().dropped_events;

        // Fill the channel, then drop one.
        send(&tx, ping());
        send(&tx, ping());

        // The event that fit was stamped before the drop happened.
        assert_eq!(rx.try_recv().unwrap().dropped_events, baseline);
        assert!(rx.try_recv().is_err());

        // The next one to get through reports the loss.
        send(&tx, ping());
        assert_eq!(rx.try_recv().unwrap().dropped_events, baseline + 1);
    }

    #[test]
    fn test_every_event_names_the_same_run() {
        let (tx, mut rx) = mpsc::channel(4);
        send(&tx, ping());
        send(&tx, ping());
        let a = rx.try_recv().unwrap().instance_id;
        let b = rx.try_recv().unwrap().instance_id;
        assert_ne!(a, 0, "an id of zero would look like an old archive");
        assert_eq!(a, b);
    }

    #[test]
    fn test_gossip_is_shed_while_other_events_still_fit() {
        let _serial = SERIAL.lock().unwrap();
        // One slot more than the reserve: a single announcement fits, and then
        // the queue is down to exactly the room gossip must leave alone.
        let (tx, mut rx) = mpsc::channel(GOSSIP_SHED_BELOW + 1);

        send(&tx, gossip());
        assert_eq!(tx.capacity(), GOSSIP_SHED_BELOW);

        // Refused, with the reserve untouched...
        send(&tx, gossip());
        assert_eq!(tx.capacity(), GOSSIP_SHED_BELOW);

        // ...while a ping goes straight in, and reports the shed announcement.
        send(&tx, ping());
        assert_eq!(tx.capacity(), GOSSIP_SHED_BELOW - 1);
        let first = rx.try_recv().unwrap();
        let second = rx.try_recv().unwrap();
        assert!(matches!(first.event, Some(Event::AddressAnnouncement(_))));
        assert!(matches!(second.event, Some(Event::PingRtt(_))));
        assert_eq!(second.dropped_events, first.dropped_events + 1);
    }
}
