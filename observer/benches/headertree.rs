//! How long the header tree costs at the height mainnet is at.
//!
//! Two of these are what a peer can ask for. A GETHEADERS walks the locator
//! and copies up to two thousand headers out of the tree, and that asymmetry
//! -- a few hundred bytes in, a hundred and sixty kilobytes out -- is what the
//! token bucket in the protocol layer exists to bound. Knowing what one answer
//! costs is how you know whether the bucket is set anywhere near right.

mod harness;

use harness::{bench, section};
use observer::bench_api::{HeaderTree, testing};

/// A chain of `n` regtest headers on top of genesis, which is as close to
/// mainnet's shape as a test can get cheaply: the tree does the same work per
/// header either way, and regtest proof of work is satisfied by the first
/// nonce.
fn chain(n: u32) -> (HeaderTree, Vec<common::bitcoin::block::Header>) {
    let mut tree = HeaderTree::new(testing::regtest_params());
    let mut prev = tree.tip().0;
    let headers: Vec<_> = (0..n)
        .map(|i| {
            let h = testing::mine_header(prev, 1_700_000_000 + i, 1);
            prev = h.block_hash();
            h
        })
        .collect();
    tree.insert_batch(&headers);
    (tree, headers)
}

fn main() {
    section("Building the tree");
    for n in [100_000u32, 900_000] {
        bench(&format!("insert_batch of {n} headers"), 3, || chain(n));
    }

    let (tree, headers) = chain(900_000);
    let len = tree.tip().1 + 1;

    section(&format!("A tree of {len} headers"));
    bench("build_locator (what we send)", 99, || tree.build_locator());

    let stop = common::bitcoin::BlockHash::from_byte_array([0; 32]);

    // What an honest peer asks: a locator from its own tip, which we are at.
    let at_tip = tree.build_locator();
    bench("get_headers_from_locator, peer at our tip", 99, || {
        tree.get_headers_from_locator(&at_tip, stop)
    });

    // What the cheapest hostile ask looks like: one hash we have never seen,
    // which matches nothing, so the answer starts after genesis and runs to
    // the two thousand cap.
    let nowhere = [common::bitcoin::BlockHash::from_byte_array([9; 32])];
    bench("get_headers_from_locator, matching nothing", 99, || {
        tree.get_headers_from_locator(&nowhere, stop)
    });

    // And the longest locator we will walk, all of it matching nothing.
    let overlong: Vec<_> = (0..101u16)
        .map(|i| {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&i.to_le_bytes());
            common::bitcoin::BlockHash::from_byte_array(bytes)
        })
        .collect();
    bench(
        "get_headers_from_locator, 101 hashes matching nothing",
        99,
        || tree.get_headers_from_locator(&overlong, stop),
    );

    let _ = headers;
}
