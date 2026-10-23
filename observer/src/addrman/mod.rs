//! The address manager: what we know about peer addresses, and who to dial.
//!
//! Split so that the parts worth testing are testable. `addr` and `policy` are
//! pure; `book` holds the entries and the pick logic and takes an explicit
//! `now`; `mod` owns the task, which is the only piece with a clock, a socket
//! or a channel.

// Removed once the manager is wired into main.rs. Until then the lower layers
// have no callers and every item in them looks unused.
#![allow(dead_code)]

pub(crate) mod peer_addr;
pub(crate) mod policy;
