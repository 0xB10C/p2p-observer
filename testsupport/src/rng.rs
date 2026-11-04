//! A seeded generator, for tests that want many inputs rather than one.
//!
//! Deterministic on purpose. A test that fails once in a thousand runs and
//! names no input is worse than no test: the seed is the case, so a failure
//! can be reproduced by reading the message.
//!
//! splitmix64, which is short enough to read and good enough to pick bytes
//! with. Nothing here is for anything but tests.

/// A seeded source of pseudo-random values.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    /// Uniform in `[0, n)`. Zero for `n == 0`, so a caller need not special
    /// case an empty range.
    pub fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next_u64() % n as u64) as usize
        }
    }

    /// `n` arbitrary bytes.
    pub fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next_u64() & 0xff) as u8).collect()
    }

    /// One of `choices`, which must not be empty.
    pub fn pick<'a, T>(&mut self, choices: &'a [T]) -> &'a T {
        &choices[self.below(choices.len())]
    }

    /// True with probability `1 / n`.
    pub fn one_in(&mut self, n: usize) -> bool {
        self.below(n) == 0
    }
}
