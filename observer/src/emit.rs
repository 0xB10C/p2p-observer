//! Handing research events to the publisher.

use common::{
    events::{DroppedEvents, PeerEvent, peer_event::Event},
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

/// The same losses by kind, indexed by [`Kind`].
static DROPPED_BY_KIND: [AtomicU64; Kind::COUNT] = [const { AtomicU64::new(0) }; Kind::COUNT];

/// This run of the observer, as every event names it.
static INSTANCE: OnceLock<u64> = OnceLock::new();

/// One slot per variant of the event oneof, so a loss can be attributed.
///
/// The match in [`Kind::of`] is exhaustive on purpose: adding a variant to the
/// oneof without a counter for it is a compile error, not a silent gap.
#[derive(Clone, Copy)]
#[repr(usize)]
enum Kind {
    PingRtt,
    BlockAnnouncement,
    AddressAnnouncement,
    ConnectionResult,
    Handshake,
    CompactBlockProbe,
    FeeFilter,
    SendCmpct,
}

impl Kind {
    const COUNT: usize = 8;

    /// The kind of an event, or `None` for an event with no kind at all,
    /// which counts towards the total and nowhere else.
    fn of(event: &PeerEvent) -> Option<Kind> {
        Some(match event.event.as_ref()? {
            Event::PingRtt(_) => Kind::PingRtt,
            Event::BlockAnnouncement(_) => Kind::BlockAnnouncement,
            Event::AddressAnnouncement(_) => Kind::AddressAnnouncement,
            Event::ConnectionResult(_) => Kind::ConnectionResult,
            Event::Handshake(_) => Kind::Handshake,
            Event::CompactBlockProbe(_) => Kind::CompactBlockProbe,
            Event::FeeFilter(_) => Kind::FeeFilter,
            Event::SendCmpct(_) => Kind::SendCmpct,
        })
    }
}

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

/// The per-kind counts as they stand, for stamping on an event.
///
/// Read one at a time, so the snapshot can lag the total by a drop that
/// landed between two reads. Counters only go up, so it can never claim a
/// loss that did not happen.
fn dropped_by_kind() -> DroppedEvents {
    let get = |k: Kind| DROPPED_BY_KIND[k as usize].load(Ordering::Relaxed);
    DroppedEvents {
        ping_rtt: get(Kind::PingRtt),
        block_announcement: get(Kind::BlockAnnouncement),
        address_announcement: get(Kind::AddressAnnouncement),
        connection_result: get(Kind::ConnectionResult),
        handshake: get(Kind::Handshake),
        compact_block_probe: get(Kind::CompactBlockProbe),
        fee_filter: get(Kind::FeeFilter),
        send_cmpct: get(Kind::SendCmpct),
    }
}

/// Queue one event, dropping it rather than blocking a connection task.
///
/// Stamps the running drop counts on the way out, which is the only way a
/// reader can tell a quiet stretch of the stream from a lossy one. The counts
/// are read before the send, so an event reports the losses that came before
/// it and never its own.
///
/// Every event goes through here so that no emit site can forget the stamp,
/// and so there is one place where the decision to drop is made.
pub(crate) fn send(tx: &mpsc::Sender<PeerEvent>, mut event: PeerEvent) {
    let dropped = DROPPED.load(Ordering::Relaxed);
    event.dropped_events = dropped;
    event.dropped_by_kind = (dropped > 0).then(dropped_by_kind);
    event.instance_id = *INSTANCE.get_or_init(fresh_instance_id);

    let kind = Kind::of(&event);
    let is_gossip = matches!(kind, Some(Kind::AddressAnnouncement));
    if (is_gossip && tx.capacity() <= GOSSIP_SHED_BELOW) || tx.try_send(event).is_err() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
        if let Some(kind) = kind {
            DROPPED_BY_KIND[kind as usize].fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::events::{AddressAnnouncement, PingRtt};
    use std::sync::Mutex;

    /// The drop counters are process-wide, so tests that read them must not
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
        let first = rx.try_recv().unwrap();
        let baseline = first.dropped_events;
        let pings_before = first.dropped_by_kind.map_or(0, |d| d.ping_rtt);

        // Fill the channel, then drop one.
        send(&tx, ping());
        send(&tx, ping());

        // The event that fit was stamped before the drop happened.
        assert_eq!(rx.try_recv().unwrap().dropped_events, baseline);
        assert!(rx.try_recv().is_err());

        // The next one to get through reports the loss, and what it was.
        send(&tx, ping());
        let after = rx.try_recv().unwrap();
        assert_eq!(after.dropped_events, baseline + 1);
        assert_eq!(after.dropped_by_kind.unwrap().ping_rtt, pings_before + 1);
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

        // ...while a ping goes straight in, and reports the shed announcement
        // as exactly that.
        send(&tx, ping());
        assert_eq!(tx.capacity(), GOSSIP_SHED_BELOW - 1);
        let first = rx.try_recv().unwrap();
        let second = rx.try_recv().unwrap();
        assert!(matches!(first.event, Some(Event::AddressAnnouncement(_))));
        assert!(matches!(second.event, Some(Event::PingRtt(_))));
        assert_eq!(second.dropped_events, first.dropped_events + 1);
        let gossip_before = first.dropped_by_kind.map_or(0, |d| d.address_announcement);
        assert_eq!(
            second.dropped_by_kind.unwrap().address_announcement,
            gossip_before + 1
        );
    }
}
