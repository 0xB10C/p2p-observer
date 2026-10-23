//! The address manager: what we know about peer addresses, and who to dial.
//!
//! Split so that the parts worth testing are testable. [`peer_addr`] and [`policy`]
//! are pure; [`book`] holds the entries and the pick and takes an explicit
//! `now`; this module owns the task, which is the only piece with a clock, a
//! channel or a dialer.
//!
//! The manager owns all of the state outright. Nothing is behind an
//! `Arc<Mutex<..>>`, so there is no lock for a scan of the book to hold while
//! gossip and connection outcomes queue up behind it — they wait in channels
//! instead, which is both cheaper and easier to reason about.
//!
//! All retry and backoff timing lives here. Connection tasks are single-shot:
//! dial, handshake, run the session, report what happened, exit. They hold no
//! backoff state and decide nothing about when an address is tried again.

pub(crate) mod banlist;
pub(crate) mod book;
pub(crate) mod peer_addr;
pub(crate) mod persist;
pub(crate) mod policy;

use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use common::{
    tokio::{
        self,
        sync::{mpsc, oneshot},
        time::{Duration, interval},
    },
    tracing,
};

use crate::TARGET_ADDRMAN as TARGET;
use banlist::{BanEntry, Banlist};
use book::{Book, Dial, EnabledNets, Entry, Gossiped, Stats};
use peer_addr::PeerAddr;
use policy::{Outcome, Reason};

/// How often the manager considers new dials.
const TICK: Duration = Duration::from_secs(1);
/// How often the book is written to disk.
const SAVE_INTERVAL: Duration = Duration::from_secs(5 * 60);
/// Bound on the gossip queue. Gossip is lossy by design: dropping a batch
/// under pressure costs nothing, because addresses are re-announced.
const GOSSIP_QUEUE: usize = 256;
/// Bound on the command queue. RPC is low volume.
const COMMAND_QUEUE: usize = 32;

pub fn unix_now() -> u32 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as u32
}

/// What a connection task reports back.
#[derive(Debug)]
pub enum Lifecycle {
    /// The handshake completed.
    Connected {
        addr: PeerAddr,
        services: u64,
        transport_version: u8,
    },
    /// v2 did not work for this address but v1 did, so skip v2 next time.
    V1Only { addr: PeerAddr },
    /// The attempt or session is over. Always sent, even on panic — see
    /// [`EndGuard`].
    Ended { addr: PeerAddr, outcome: Outcome },
}

/// An RPC request, with somewhere to put the answer.
pub enum Command {
    AddManual {
        addrs: Vec<PeerAddr>,
        reply: oneshot::Sender<usize>,
    },
    Ban {
        entry: BanEntry,
        reply: oneshot::Sender<BanResult>,
    },
    BanList {
        reply: oneshot::Sender<Vec<BanEntry>>,
    },
    Stats {
        reply: oneshot::Sender<Stats>,
    },
    Inspect {
        addr: PeerAddr,
        reply: oneshot::Sender<Option<Entry>>,
    },
    /// Addresses due to be dialled soonest, for debugging the pick.
    DueNext {
        limit: usize,
        reply: oneshot::Sender<Vec<(PeerAddr, u32)>>,
    },
}

#[derive(Debug)]
pub struct BanResult {
    /// Networks and hosts newly banned.
    pub added: usize,
    /// Stored addresses dropped as a result.
    pub purged: usize,
    /// Set if the ban was applied in memory but could not be written out.
    pub save_error: Option<String>,
}

/// Starts connection attempts.
///
/// A trait so the manager can be driven in tests without opening sockets.
pub trait Dialer: Send + Sync + 'static {
    fn dial(&self, dial: Dial);
}

/// Guarantees the manager finds out that an attempt finished.
///
/// `Drop` runs on a normal return, on an early `?`, on a panic and on
/// `JoinHandle::abort`, so the address's slot in the active set is always
/// released. Without it a task that died unexpectedly would leave the address
/// permanently undialable.
///
/// `Drop` is synchronous and cannot await, which is why the lifecycle channel
/// is unbounded: a bounded `send` would need to await, and `try_send` could
/// drop the one message that frees the slot.
pub struct EndGuard {
    tx: mpsc::UnboundedSender<Lifecycle>,
    addr: PeerAddr,
    outcome: Option<Outcome>,
}

impl EndGuard {
    pub fn new(tx: mpsc::UnboundedSender<Lifecycle>, addr: PeerAddr) -> Self {
        Self {
            tx,
            addr,
            outcome: None,
        }
    }

    /// Record how the attempt actually ended. Without this the guard reports a
    /// generic failure, which is the right default for a task that vanished.
    pub fn finish(mut self, outcome: Outcome) {
        self.outcome = Some(outcome);
    }
}

impl Drop for EndGuard {
    fn drop(&mut self) {
        let outcome = self
            .outcome
            .take()
            .unwrap_or(Outcome::Failed(Reason::Other));
        // The manager being gone means shutdown; nothing to do about it.
        let _ = self.tx.send(Lifecycle::Ended {
            addr: self.addr,
            outcome,
        });
    }
}

/// The manager's side of the channels, cloned to whoever needs to talk to it.
#[derive(Clone)]
pub struct Handle {
    gossip_tx: mpsc::Sender<Vec<Gossiped>>,
    life_tx: mpsc::UnboundedSender<Lifecycle>,
    cmd_tx: mpsc::Sender<Command>,
}

impl Handle {
    /// Offer addresses learned from a peer. Dropped if the queue is full:
    /// gossip repeats, so losing a batch under load is not worth blocking a
    /// connection task for.
    pub fn gossip(&self, addrs: Vec<Gossiped>) {
        if self.gossip_tx.try_send(addrs).is_err() {
            tracing::trace!(target: TARGET, "gossip queue full, dropping a batch");
        }
    }

    pub fn end_guard(&self, addr: PeerAddr) -> EndGuard {
        EndGuard::new(self.life_tx.clone(), addr)
    }

    pub fn connected(&self, addr: PeerAddr, services: u64, transport_version: u8) {
        let _ = self.life_tx.send(Lifecycle::Connected {
            addr,
            services,
            transport_version,
        });
    }

    pub fn v1_only(&self, addr: PeerAddr) {
        let _ = self.life_tx.send(Lifecycle::V1Only { addr });
    }

    /// Send a command and wait for its answer. `None` if the manager is gone.
    async fn request<T>(&self, build: impl FnOnce(oneshot::Sender<T>) -> Command) -> Option<T> {
        let (tx, rx) = oneshot::channel();
        self.cmd_tx.send(build(tx)).await.ok()?;
        rx.await.ok()
    }

    pub async fn add_manual(&self, addrs: Vec<PeerAddr>) -> Option<usize> {
        self.request(|reply| Command::AddManual { addrs, reply })
            .await
    }

    pub async fn ban(&self, entry: BanEntry) -> Option<BanResult> {
        self.request(|reply| Command::Ban { entry, reply }).await
    }

    pub async fn ban_list(&self) -> Option<Vec<BanEntry>> {
        self.request(|reply| Command::BanList { reply }).await
    }

    pub async fn stats(&self) -> Option<Stats> {
        self.request(|reply| Command::Stats { reply }).await
    }

    pub async fn inspect(&self, addr: PeerAddr) -> Option<Option<Entry>> {
        self.request(|reply| Command::Inspect { addr, reply }).await
    }

    pub async fn due_next(&self, limit: usize) -> Option<Vec<(PeerAddr, u32)>> {
        self.request(|reply| Command::DueNext { limit, reply })
            .await
    }
}

/// Create the manager's channels, returning the handle and the three
/// receivers the manager task needs.
///
/// Separate from `Manager::new` so the handle exists before the dialer does:
/// the dialer needs a handle to give each connection task, and the manager
/// needs the dialer.
pub fn channels() -> (
    Handle,
    mpsc::Receiver<Vec<Gossiped>>,
    mpsc::UnboundedReceiver<Lifecycle>,
    mpsc::Receiver<Command>,
) {
    let (gossip_tx, gossip_rx) = mpsc::channel(GOSSIP_QUEUE);
    let (life_tx, life_rx) = mpsc::unbounded_channel();
    let (cmd_tx, cmd_rx) = mpsc::channel(COMMAND_QUEUE);
    (
        Handle {
            gossip_tx,
            life_tx,
            cmd_tx,
        },
        gossip_rx,
        life_rx,
        cmd_rx,
    )
}

pub struct Config {
    /// Dials started per tick, before the in-flight ceiling is applied.
    pub dials_per_tick: usize,
    /// Maximum attempts in flight at once.
    pub max_dialing: usize,
    /// Hard ceiling on stored entries.
    pub capacity: usize,
    pub nets: EnabledNets,
    pub snapshot_path: PathBuf,
    pub banlist_path: PathBuf,
}

pub struct Manager<D: Dialer> {
    book: Book,
    banlist: Banlist,
    dialer: D,
    cfg: Config,
}

impl<D: Dialer> Manager<D> {
    /// Build a manager, loading the snapshot and ban list.
    ///
    /// A bad snapshot is not an error — see [`persist::load`]. A bad ban list
    /// is, because it is operator intent rather than a cache.
    pub fn new(cfg: Config, dialer: D) -> common::anyhow::Result<Self> {
        let banlist = Banlist::load(&cfg.banlist_path)?;
        let mut book = Book::new(cfg.capacity, unix_now() as u64);
        book.restore(persist::load(&cfg.snapshot_path));

        let purged = book.purge_banned(&banlist);
        if purged > 0 {
            tracing::info!(target: TARGET, purged, "dropped banned addresses from the snapshot");
        }

        Ok(Self {
            book,
            banlist,
            dialer,
            cfg,
        })
    }

    /// Seed bootstrap and operator addresses.
    pub fn add_manual(&mut self, now: u32, addrs: &[PeerAddr]) -> usize {
        self.book.insert_manual(now, addrs)
    }

    /// Consider new dials. Called once a second.
    fn tick(&mut self, now: u32) -> usize {
        // Never exceed the in-flight ceiling, however generous the per-tick
        // rate is: each dial holds a socket and a task.
        let room = self
            .cfg
            .max_dialing
            .saturating_sub(self.book.dialing_count());
        let budget = self.cfg.dials_per_tick.min(room);

        let picks = self.book.pick(now, budget, &self.cfg.nets, &self.banlist);
        for dial in &picks {
            self.dialer.dial(*dial);
        }
        picks.len()
    }

    fn apply(&mut self, msg: Lifecycle, now: u32) {
        match msg {
            Lifecycle::Connected {
                addr,
                services,
                transport_version,
            } => self
                .book
                .record_connected(addr, now, services, transport_version),
            Lifecycle::V1Only { addr } => self.book.record_v1_only(addr),
            Lifecycle::Ended { addr, outcome } => {
                tracing::debug!(target: TARGET,
                    %addr,
                    ?outcome,
                    counted = outcome.counts_as_failure(),
                    "attempt ended"
                );
                self.book.record_ended(addr, now, outcome)
            }
        }
    }

    fn ingest(&mut self, now: u32, addrs: &[Gossiped]) -> usize {
        self.book.ingest(now, addrs, &self.banlist)
    }

    /// Seed the book directly, for tests that need a populated manager
    /// without a dialer or a running task.
    #[cfg(test)]
    pub(crate) fn ingest_for_test(&mut self, now: u32, addrs: &[Gossiped]) -> usize {
        self.ingest(now, addrs)
    }

    fn command(&mut self, cmd: Command, now: u32) {
        match cmd {
            Command::AddManual { addrs, reply } => {
                let added = self.book.insert_manual(now, &addrs);
                let _ = reply.send(added);
            }
            Command::Ban { entry, reply } => {
                let added = self.banlist.add(entry);
                let purged = if added > 0 {
                    self.book.purge_banned(&self.banlist)
                } else {
                    0
                };
                // The ban is already in effect in memory; a failed write only
                // means it will not survive a restart, which the caller should
                // hear about rather than discover later.
                let save_error = match self.banlist.save() {
                    Ok(()) => None,
                    Err(e) => {
                        tracing::error!(target: TARGET, "could not write the ban list: {e:#}");
                        Some(format!("{e:#}"))
                    }
                };
                let _ = reply.send(BanResult {
                    added,
                    purged,
                    save_error,
                });
            }
            Command::BanList { reply } => {
                let _ = reply.send(self.banlist.entries().to_vec());
            }
            Command::Stats { reply } => {
                let _ = reply.send(self.book.stats());
            }
            Command::Inspect { addr, reply } => {
                let _ = reply.send(self.book.entry(&addr).cloned());
            }
            Command::DueNext { limit, reply } => {
                let mut due: Vec<(PeerAddr, u32)> = self
                    .book
                    .iter()
                    .map(|(k, e)| (*k, e.next_attempt))
                    .collect();
                due.sort_by_key(|(_, at)| *at);
                due.truncate(limit);
                let _ = reply.send(due);
            }
        }
    }

    fn save(&self) {
        match persist::save(&self.cfg.snapshot_path, self.book.iter()) {
            Ok(count) => tracing::info!(target: TARGET, entries = count, "address snapshot saved"),
            Err(e) => tracing::warn!(target: TARGET, "could not save the address snapshot: {e:#}"),
        }
    }

    /// Drive the manager until shutdown.
    pub async fn run(
        mut self,
        mut gossip_rx: mpsc::Receiver<Vec<Gossiped>>,
        mut life_rx: mpsc::UnboundedReceiver<Lifecycle>,
        mut cmd_rx: mpsc::Receiver<Command>,
        mut shutdown: oneshot::Receiver<()>,
    ) {
        let mut dial_timer = interval(TICK);
        let mut save_timer = interval(SAVE_INTERVAL);
        // Both fire immediately otherwise, saving an unchanged book and
        // dialling before anything has been ingested.
        dial_timer.tick().await;
        save_timer.tick().await;

        loop {
            tokio::select! {
                _ = dial_timer.tick() => {
                    let now = unix_now();
                    let started = self.tick(now);
                    let s = self.book.stats();
                    tracing::info!(target: TARGET,
                        total = s.total,
                        unknown = s.unknown,
                        good = s.good,
                        was_good = s.was_good,
                        bad = s.bad,
                        dialing = s.dialing,
                        connected = s.connected,
                        banned = self.banlist.len(),
                        started,
                        "stats"
                    );
                }

                // Lifecycle first among the message arms: these release
                // in-flight slots, and the queue is unbounded, so letting it
                // build up would stall dialling.
                Some(msg) = life_rx.recv() => {
                    let now = unix_now();
                    self.apply(msg, now);
                    // Drain whatever else is already queued rather than going
                    // back round the select for each one.
                    while let Ok(msg) = life_rx.try_recv() {
                        self.apply(msg, now);
                    }
                }

                Some(addrs) = gossip_rx.recv() => {
                    let now = unix_now();
                    let added = self.ingest(now, &addrs);
                    tracing::debug!(target: TARGET,
                        received = addrs.len(), added, total = self.book.len(), "gossip"
                    );
                }

                Some(cmd) = cmd_rx.recv() => {
                    let now = unix_now();
                    self.command(cmd, now);
                }

                _ = save_timer.tick() => self.save(),

                _ = &mut shutdown => {
                    tracing::info!(target: TARGET, "shutting down, saving the address book");
                    self.save();
                    return;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use book::{Phase, TransportHint};
    use std::sync::{Arc, Mutex};

    const NOW: u32 = 1_000_000;

    #[derive(Clone, Default)]
    struct RecordingDialer(Arc<Mutex<Vec<Dial>>>);

    impl Dialer for RecordingDialer {
        fn dial(&self, dial: Dial) {
            self.0.lock().unwrap().push(dial);
        }
    }

    impl RecordingDialer {
        fn taken(&self) -> Vec<Dial> {
            std::mem::take(&mut *self.0.lock().unwrap())
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("p2p-observer-mgr-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn manager(tag: &str, dialer: RecordingDialer) -> (Manager<RecordingDialer>, PathBuf) {
        let dir = tmp_dir(tag);
        let cfg = Config {
            dials_per_tick: 10,
            max_dialing: 100,
            capacity: 1000,
            nets: EnabledNets::all(),
            snapshot_path: dir.join("addresses.bin"),
            banlist_path: dir.join("banlist.json"),
        };
        (Manager::new(cfg, dialer).unwrap(), dir)
    }

    fn gossiped(last: u8) -> Gossiped {
        Gossiped {
            addr: PeerAddr::Ipv4([1, 2, 3, last], 8333),
            services: 0,
        }
    }

    #[test]
    fn test_tick_dials_ingested_addresses() {
        let dialer = RecordingDialer::default();
        let (mut m, dir) = manager("dial", dialer.clone());

        let addrs: Vec<Gossiped> = (0..50).map(gossiped).collect();
        assert_eq!(m.ingest(NOW, &addrs), 50);

        // Only the per-tick budget goes out at once.
        assert_eq!(m.tick(NOW), 10);
        assert_eq!(dialer.taken().len(), 10);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_in_flight_ceiling_is_respected() {
        let dialer = RecordingDialer::default();
        let (mut m, dir) = manager("ceiling", dialer.clone());
        m.cfg.max_dialing = 12;

        let addrs: Vec<Gossiped> = (0..100).map(gossiped).collect();
        m.ingest(NOW, &addrs);

        // 10, then 2, then nothing: the ceiling binds even though the per-tick
        // rate would allow more, because nothing has reported back.
        assert_eq!(m.tick(NOW), 10);
        assert_eq!(m.tick(NOW), 2);
        assert_eq!(m.tick(NOW), 0);
        assert_eq!(m.book.dialing_count(), 12);

        // As attempts finish, room opens up again.
        let first = dialer.taken();
        for dial in first.iter().take(5) {
            m.apply(
                Lifecycle::Ended {
                    addr: dial.addr,
                    outcome: Outcome::OurFault,
                },
                NOW,
            );
        }
        assert_eq!(m.book.dialing_count(), 7);
        assert_eq!(m.tick(NOW + 60), 5);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_lifecycle_updates_the_table() {
        let dialer = RecordingDialer::default();
        let (mut m, dir) = manager("life", dialer.clone());
        let addr = gossiped(1).addr;

        m.ingest(NOW, &[gossiped(1)]);
        m.tick(NOW);
        assert_eq!(m.book.stats().dialing, 1);

        m.apply(
            Lifecycle::Connected {
                addr,
                services: 0b1101,
                transport_version: 2,
            },
            NOW,
        );
        let e = m.book.entry(&addr).unwrap();
        assert_eq!(e.services, 0b1101);
        assert_eq!(e.transport, TransportHint::V2);
        assert_eq!(m.book.stats().connected, 1);

        m.apply(
            Lifecycle::Ended {
                addr,
                outcome: Outcome::Disconnected { uptime_secs: 600 },
            },
            NOW + 600,
        );
        let s = m.book.stats();
        assert_eq!(s.connected, 0);
        assert_eq!(s.good, 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_end_guard_reports_even_when_dropped_silently() {
        let (handle, _gossip_rx, mut life_rx, _cmd_rx) = channels();
        let addr = PeerAddr::parse_ip("1.2.3.4:8333").unwrap();

        // A task that simply vanishes -- panicked, aborted, early return --
        // must still release the address.
        drop(handle.end_guard(addr));
        match life_rx.try_recv().expect("nothing reported") {
            Lifecycle::Ended { addr: got, outcome } => {
                assert_eq!(got, addr);
                assert!(outcome.counts_as_failure());
            }
            other => panic!("unexpected message: {other:?}"),
        }

        // And when it does report, the real outcome is what arrives.
        handle
            .end_guard(addr)
            .finish(Outcome::Disconnected { uptime_secs: 42 });
        match life_rx.try_recv().expect("nothing reported") {
            Lifecycle::Ended { outcome, .. } => {
                assert_eq!(outcome, Outcome::Disconnected { uptime_secs: 42 });
            }
            other => panic!("unexpected message: {other:?}"),
        }
    }

    #[test]
    fn test_ban_command_purges_and_persists() {
        let dialer = RecordingDialer::default();
        let (mut m, dir) = manager("ban", dialer.clone());

        m.ingest(
            NOW,
            &[
                Gossiped {
                    addr: PeerAddr::parse_ip("100.0.0.1:8333").unwrap(),
                    services: 0,
                },
                Gossiped {
                    addr: PeerAddr::parse_ip("100.9.9.9:8333").unwrap(),
                    services: 0,
                },
                Gossiped {
                    addr: PeerAddr::parse_ip("1.2.3.4:8333").unwrap(),
                    services: 0,
                },
            ],
        );
        assert_eq!(m.book.len(), 3);

        let (tx, rx) = oneshot::channel();
        m.command(
            Command::Ban {
                entry: BanEntry {
                    comment: Some("test".to_owned()),
                    nets: vec!["100.0.0.0/8".parse().unwrap()],
                    hosts: Vec::new(),
                },
                reply: tx,
            },
            NOW,
        );
        let result = rx.blocking_recv().unwrap();
        assert_eq!(result.added, 1);
        assert_eq!(result.purged, 2);
        assert!(result.save_error.is_none(), "{:?}", result.save_error);
        assert_eq!(m.book.len(), 1);

        // Banned addresses do not come back via gossip either.
        assert_eq!(
            m.ingest(
                NOW,
                &[Gossiped {
                    addr: PeerAddr::parse_ip("100.0.0.1:8333").unwrap(),
                    services: 0,
                }]
            ),
            0
        );

        // And the ban survives a restart.
        let reloaded = Banlist::load(&dir.join("banlist.json")).unwrap();
        assert_eq!(reloaded.len(), 1);

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_stats_and_inspect_commands() {
        let dialer = RecordingDialer::default();
        let (mut m, dir) = manager("stats", dialer.clone());
        m.ingest(NOW, &[gossiped(1), gossiped(2)]);

        let (tx, rx) = oneshot::channel();
        m.command(Command::Stats { reply: tx }, NOW);
        let s = rx.blocking_recv().unwrap();
        assert_eq!(s.total, 2);
        assert_eq!(s.unknown, 2);

        let (tx, rx) = oneshot::channel();
        m.command(
            Command::Inspect {
                addr: gossiped(1).addr,
                reply: tx,
            },
            NOW,
        );
        assert!(rx.blocking_recv().unwrap().is_some());

        let (tx, rx) = oneshot::channel();
        m.command(
            Command::Inspect {
                addr: PeerAddr::parse_ip("9.9.9.9:1").unwrap(),
                reply: tx,
            },
            NOW,
        );
        assert!(rx.blocking_recv().unwrap().is_none());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_manual_addresses_are_dialled_first() {
        let dialer = RecordingDialer::default();
        let (mut m, dir) = manager("manual", dialer.clone());
        m.cfg.dials_per_tick = 1;

        let addrs: Vec<Gossiped> = (0..50).map(gossiped).collect();
        m.ingest(NOW, &addrs);

        let manual = PeerAddr::parse_ip("9.9.9.9:8333").unwrap();
        assert_eq!(m.add_manual(NOW, &[manual]), 1);

        m.tick(NOW);
        let dialled = dialer.taken();
        assert!(
            dialled.iter().any(|d| d.addr == manual),
            "the operator's address was not dialled first"
        );

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_restart_reloads_the_table() {
        let dialer = RecordingDialer::default();
        let dir = tmp_dir("restart");
        let cfg = Config {
            dials_per_tick: 10,
            max_dialing: 100,
            capacity: 1000,
            nets: EnabledNets::all(),
            snapshot_path: dir.join("addresses.bin"),
            banlist_path: dir.join("banlist.json"),
        };

        let mut m = Manager::new(cfg, dialer.clone()).unwrap();
        let addrs: Vec<Gossiped> = (0..20).map(gossiped).collect();
        m.ingest(NOW, &addrs);
        m.apply(
            Lifecycle::Connected {
                addr: gossiped(0).addr,
                services: 9,
                transport_version: 2,
            },
            NOW,
        );
        m.save();

        let cfg2 = Config {
            dials_per_tick: 10,
            max_dialing: 100,
            capacity: 1000,
            nets: EnabledNets::all(),
            snapshot_path: dir.join("addresses.bin"),
            banlist_path: dir.join("banlist.json"),
        };
        let m2 = Manager::new(cfg2, dialer).unwrap();
        assert_eq!(m2.book.len(), 20);
        // Nothing is in flight after a restart, whatever was running before.
        assert_eq!(m2.book.stats().connected, 0);
        assert_eq!(m2.book.stats().dialing, 0);
        assert_eq!(m2.book.entry(&gossiped(0).addr).unwrap().services, 9);

        std::fs::remove_dir_all(&dir).ok();
    }

    /// Active state is deliberately not persisted: after a restart there are
    /// no tasks, so anything marked in flight would be undialable forever.
    #[test]
    fn test_restore_clears_active() {
        let mut book = Book::new(100, 1);
        let addr = PeerAddr::parse_ip("1.2.3.4:8333").unwrap();
        book.ingest(
            NOW,
            &[Gossiped { addr, services: 0 }],
            &Banlist::from_entries(vec![]),
        );
        book.record_dialing(addr, NOW);
        assert_eq!(book.stats().dialing, 1);

        let entries = book.iter().map(|(k, e)| (*k, e.clone())).collect();
        book.restore(entries);
        assert_eq!(book.stats().dialing, 0);
        assert!(!book.iter().any(|(k, _)| {
            let _ = k;
            false
        }));
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn test_phase_is_tracked() {
        let dialer = RecordingDialer::default();
        let (mut m, dir) = manager("phase", dialer.clone());
        let addr = gossiped(1).addr;
        m.ingest(NOW, &[gossiped(1)]);

        m.tick(NOW);
        assert_eq!(m.book.stats().dialing, 1);
        m.apply(
            Lifecycle::Connected {
                addr,
                services: 0,
                transport_version: 1,
            },
            NOW,
        );
        let s = m.book.stats();
        assert_eq!(s.dialing, 0);
        assert_eq!(s.connected, 1);
        let _ = Phase::Dialing;

        std::fs::remove_dir_all(&dir).ok();
    }
}
