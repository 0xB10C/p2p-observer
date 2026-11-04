//! A scratch directory that cleans up after itself.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// A directory under the system temp directory, removed when dropped.
///
/// Tests that write state to disk and then read it back want a directory of
/// their own: sharing one means a leftover file from a previous run decides
/// what the next one sees.
pub struct TempDir {
    path: PathBuf,
}

/// Distinguishes directories made in the same process within the same
/// nanosecond, which happens when tests run in parallel.
static COUNTER: AtomicU32 = AtomicU32::new(0);

impl TempDir {
    /// Creates a directory named after `tag`, made unique by the process, the
    /// clock and a counter.
    pub fn new(tag: &str) -> Self {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("the clock is before the epoch")
            .as_nanos();
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{tag}-{}-{nanos}-{n}", std::process::id()));
        std::fs::create_dir_all(&path).expect("creating the temp directory");
        TempDir { path }
    }

    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        // A failure here would mask whatever the test was actually asserting,
        // and the worst case is a directory left in /tmp.
        let _ = std::fs::remove_dir_all(&self.path);
    }
}
