//! Snapshot of the address table.
//!
//! The snapshot is a cache, not a record. Losing it costs a few minutes of
//! GETADDR and gossip, so nothing here is allowed to stop the observer from
//! starting: an unreadable, truncated or outdated file is logged and treated
//! as an empty table. The old JSON store did the opposite — a half-written
//! file made `main` panic on the next start, and only deleting it by hand
//! would get the process up again.

use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

use common::{
    anyhow::{Context, Result},
    postcard,
    serde::{Deserialize, Serialize},
    tracing,
};

use super::key::AddrKey;
use super::table::Entry;
use crate::TARGET_ADDRMAN as TARGET;

/// Bumped whenever the stored layout changes. A snapshot written by a
/// different version is discarded rather than migrated — see the module note
/// on why that is cheap.
const FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize)]
#[serde(crate = "common::serde")]
struct Snapshot {
    version: u32,
    entries: Vec<(AddrKey, Entry)>,
}

/// Write the table out: temp file, flush, rename. Atomic within a directory,
/// so a crash leaves either the previous snapshot or this one.
pub fn save<'a>(
    path: &Path,
    entries: impl Iterator<Item = (&'a AddrKey, &'a Entry)>,
) -> Result<usize> {
    let snapshot = Snapshot {
        version: FORMAT_VERSION,
        entries: entries.map(|(k, e)| (*k, e.clone())).collect(),
    };
    let count = snapshot.entries.len();

    // postcard rather than JSON: at two million entries the difference is
    // hundreds of megabytes, and nothing outside this process reads the file.
    let bytes = postcard::to_stdvec(&snapshot).context("serialize address snapshot")?;

    let tmp = path.with_extension("bin.tmp");
    let mut file = std::fs::File::create(&tmp).context("create temporary snapshot")?;
    file.write_all(&bytes).context("write temporary snapshot")?;
    file.sync_all().context("flush temporary snapshot")?;
    drop(file);
    std::fs::rename(&tmp, path).context("rename snapshot")?;

    Ok(count)
}

/// Read the table back. Never fails: anything unexpected is logged and comes
/// back as an empty table.
pub fn load(path: &Path) -> HashMap<AddrKey, Entry> {
    let bytes = match std::fs::read(path) {
        Ok(b) => b,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            tracing::info!(target: TARGET, "no address snapshot, starting with an empty table");
            return HashMap::new();
        }
        Err(e) => {
            tracing::warn!(target: TARGET, "could not read address snapshot, starting empty: {e}");
            return HashMap::new();
        }
    };

    let snapshot: Snapshot = match postcard::from_bytes(&bytes) {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target: TARGET, "address snapshot did not parse, starting empty: {e}");
            return HashMap::new();
        }
    };

    if snapshot.version != FORMAT_VERSION {
        tracing::info!(target: TARGET,
            found = snapshot.version,
            expected = FORMAT_VERSION,
            "address snapshot has a different format version, starting empty"
        );
        return HashMap::new();
    }

    let entries: HashMap<AddrKey, Entry> = snapshot.entries.into_iter().collect();
    tracing::info!(target: TARGET, entries = entries.len(), "address snapshot loaded");
    entries
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addresses::policy::Origin;

    fn tmp_dir(tag: &str) -> std::path::PathBuf {
        let dir =
            std::env::temp_dir().join(format!("p2p-observer-snap-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sample() -> HashMap<AddrKey, Entry> {
        let mut m = HashMap::new();
        for i in 0..50u8 {
            let mut e = Entry::new(1000, 0b1101, 900, Origin::Gossip);
            e.failures = i % 4;
            e.last_success = if i % 2 == 0 { 950 } else { 0 };
            m.insert(AddrKey::Ipv4([10, 0, 0, i], 8333), e);
        }
        m.insert(
            AddrKey::TorV3([7u8; 32], 8333),
            Entry::new(1000, 0, 0, Origin::Manual),
        );
        m
    }

    #[test]
    fn test_round_trip() {
        let dir = tmp_dir("rt");
        let path = dir.join("addresses.bin");
        let entries = sample();

        let written = save(&path, entries.iter()).unwrap();
        assert_eq!(written, entries.len());
        assert!(
            !path.with_extension("bin.tmp").exists(),
            "temp file left behind"
        );

        let loaded = load(&path);
        assert_eq!(loaded.len(), entries.len());
        for (key, want) in &entries {
            let got = loaded.get(key).expect("entry missing after reload");
            assert_eq!(got.services, want.services);
            assert_eq!(got.failures, want.failures);
            assert_eq!(got.last_success, want.last_success);
            assert_eq!(got.origin, want.origin);
        }
        // Onion keys survive as their 32 bytes, not as a hostname string.
        assert!(loaded.contains_key(&AddrKey::TorV3([7u8; 32], 8333)));

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_missing_file_is_an_empty_table() {
        let dir = tmp_dir("missing");
        assert!(load(&dir.join("nope.bin")).is_empty());
        std::fs::remove_dir_all(&dir).ok();
    }

    /// The failure that used to stop the observer from starting at all.
    #[test]
    fn test_corrupt_file_is_an_empty_table_not_a_panic() {
        let dir = tmp_dir("corrupt");
        let path = dir.join("addresses.bin");

        // Truncated, as a crash mid-write would leave it.
        let entries = sample();
        save(&path, entries.iter()).unwrap();
        let bytes = std::fs::read(&path).unwrap();
        std::fs::write(&path, &bytes[..bytes.len() / 3]).unwrap();
        assert!(load(&path).is_empty());

        // Outright garbage.
        std::fs::write(&path, b"not a snapshot at all").unwrap();
        assert!(load(&path).is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn test_other_format_version_is_discarded() {
        let dir = tmp_dir("version");
        let path = dir.join("addresses.bin");

        let snapshot = Snapshot {
            version: FORMAT_VERSION + 1,
            entries: sample().into_iter().collect(),
        };
        std::fs::write(&path, postcard::to_stdvec(&snapshot).unwrap()).unwrap();

        // Discarded rather than guessed at. Relearning is cheap; misreading
        // the fields of a layout we don't know is not.
        assert!(load(&path).is_empty());

        std::fs::remove_dir_all(&dir).ok();
    }

    /// The reason for postcard over JSON.
    #[test]
    fn test_encoding_is_compact() {
        let entries = sample();
        let snapshot = Snapshot {
            version: FORMAT_VERSION,
            entries: entries.iter().map(|(k, e)| (*k, e.clone())).collect(),
        };
        let bytes = postcard::to_stdvec(&snapshot).unwrap();
        let per_entry = bytes.len() / entries.len();
        assert!(
            per_entry < 48,
            "{per_entry} bytes per entry is larger than expected"
        );
    }
}
