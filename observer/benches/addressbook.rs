//! How long the address manager's once-a-second tick costs, at the sizes the
//! book actually reaches.
//!
//! The mainnet snapshot this was written against is 19 MB at under 48 bytes an
//! entry, so a few hundred thousand entries is the real figure and two million
//! is the configured ceiling. Both are measured, because the two numbers are
//! what decide whether anything here needs an index.

mod harness;

use harness::{bench, section};
use observer::bench_api::{Banlist, Book, EnabledNets, Gossiped, Outcome, PeerAddr, Reason};

const NOW: u32 = 1_700_000_000;

fn all_nets() -> EnabledNets {
    EnabledNets {
        ipv4: true,
        ipv6: true,
        tor: true,
        cjdns: true,
        i2p: true,
    }
}

/// `n` gossiped addresses, spread over the routable v4 space so that no
/// network filter or duplicate shortens the walk.
fn gossip(from: u32, n: u32) -> Vec<Gossiped> {
    (from..from + n)
        .map(|v| Gossiped {
            addr: PeerAddr::Ipv4(
                [
                    1 + (v >> 24) as u8,
                    (v >> 16) as u8,
                    (v >> 8) as u8,
                    v as u8,
                ],
                8333,
            ),
            services: 0,
            ntime: NOW,
        })
        .collect()
}

fn filled(n: u32) -> Book {
    let mut book = Book::new(2_000_000, 1);
    let banlist = Banlist::default();
    for chunk in 0..(n / 1000).max(1) {
        book.ingest(NOW, &gossip(chunk * 1000, 1000), &banlist);
    }
    book
}

fn main() {
    let banlist = Banlist::default();
    let nets = all_nets();

    section("One tick: pick ten dials out of the book");
    for n in [10_000u32, 100_000, 500_000, 2_000_000] {
        let mut book = filled(n);
        let len = book.len();
        bench(&format!("pick(10) over {len} entries"), 9, || {
            book.pick(NOW + 100, 10, 10, &nets, &banlist)
        });
    }

    section("One tick: the same, with most entries not yet due");
    // The figure above is the worst case, and it is a real one -- a book just
    // loaded from its snapshot has every entry due at once. In steady state
    // most entries are waiting out a backoff, and the due check short-circuits
    // before the reservoir is offered anything, which is the difference
    // between walking the book and sampling it.
    for n in [500_000u32, 2_000_000] {
        let mut book = filled(n);
        let len = book.len();
        for g in gossip(0, n * 9 / 10) {
            book.record_ended(g.addr, NOW, Outcome::Failed(Reason::ConnectionRefused));
        }
        bench(
            &format!("pick(10) over {len} entries, a tenth of them due"),
            9,
            || book.pick(NOW + 100, 10, 10, &nets, &banlist),
        );
    }

    section("One tick: the stats line that goes with it");
    for n in [10_000u32, 100_000, 500_000, 2_000_000] {
        let book = filled(n);
        let len = book.len();
        bench(&format!("stats() over {len} entries"), 9, || book.stats());
    }

    section("Gossip: a thousand addresses from one peer");
    for n in [10_000u32, 500_000] {
        let mut book = filled(n);
        let len = book.len();
        let mut next = n;
        bench(&format!("ingest(1000) into {len} entries"), 9, || {
            next += 1000;
            book.ingest(NOW, &gossip(next, 1000), &banlist)
        });
    }

    section("Gossip into a full book, which is eviction");
    let mut book = filled(2_000_000);
    let mut next = 2_000_000;
    bench("ingest(1000) at capacity", 9, || {
        next += 1000;
        book.ingest(NOW, &gossip(next, 1000), &banlist)
    });

    section("One finished session");
    let mut book = filled(10_000);
    let addr = PeerAddr::Ipv4([1, 0, 0, 1], 8333);
    bench("record_ended", 99, || {
        book.record_ended(addr, NOW, Outcome::Failed(Reason::ConnectionRefused))
    });
}
