//! Handing research events to the publisher.

use common::{events::PeerEvent, tokio::sync::mpsc};
use std::sync::atomic::{AtomicU64, Ordering};

/// Events that could not be handed to the publisher since the process started.
static DROPPED: AtomicU64 = AtomicU64::new(0);

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
    if tx.try_send(event).is_err() {
        DROPPED.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stamps_the_drop_count_and_counts_a_full_channel() {
        let (tx, mut rx) = mpsc::channel(1);

        // The first event fits. Whatever other tests have dropped, this is the
        // baseline the second event has to exceed.
        send(&tx, PeerEvent::default());
        let baseline = rx.try_recv().unwrap().dropped_events;

        // Fill the channel, then drop one.
        send(&tx, PeerEvent::default());
        send(&tx, PeerEvent::default());

        // The event that fit was stamped before the drop happened.
        assert_eq!(rx.try_recv().unwrap().dropped_events, baseline);
        assert!(rx.try_recv().is_err());

        // The next one to get through reports the loss.
        send(&tx, PeerEvent::default());
        assert_eq!(rx.try_recv().unwrap().dropped_events, baseline + 1);
    }
}
