//! A few lines of timing, rather than a benchmarking framework.
//!
//! What these benchmarks answer is "how long does a tick cost at the size the
//! book actually reaches", and the answers are in milliseconds, so the median
//! of a handful of runs after a warm-up is as much rigour as the question
//! needs. A framework would answer it no better and would be built on every
//! `--all-targets` run in CI.

use std::time::{Duration, Instant};

/// Runs `f` until it has been timed `runs` times, after one warm-up, and
/// prints the median against the name.
pub fn bench<T>(name: &str, runs: usize, mut f: impl FnMut() -> T) {
    let _ = f();
    let mut times: Vec<Duration> = Vec::with_capacity(runs);
    for _ in 0..runs {
        let at = Instant::now();
        let out = f();
        times.push(at.elapsed());
        // Dropped after the clock is read, so the time is the work and not the
        // teardown of whatever the work produced.
        drop(out);
    }
    times.sort();
    let median = times[times.len() / 2];
    let best = times[0];
    println!("{name:<54} {:>10.3?}  (best {:>10.3?})", median, best);
}

/// A heading, so a run reads as a table.
pub fn section(name: &str) {
    println!("\n{name}");
    println!("{}", "-".repeat(78));
}
