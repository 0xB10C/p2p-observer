//! Reading archive files back and printing what is in them.

use std::path::{Path, PathBuf};

use common::{
    anyhow::{Context, Result},
    archive::{ArchiveHeader, EventKind},
    clap::{self, Parser},
    render, tracing,
};

use crate::TARGET_REPLAYER as TARGET;
use crate::read::ArchiveReader;

#[derive(Parser, Debug)]
#[command(version, about = "Read and display p2p-observer archive files")]
pub struct Args {
    /// Archive files to read, either `.bin` or `.bin.zst`.
    #[arg(value_name = "FILE", required = true)]
    pub files: Vec<PathBuf>,
}

/// Replays every file, returning whether any of them failed.
///
/// One unreadable file does not stop the others: a truncated archive is a
/// normal thing to find after a crash, and the rest of a batch is still worth
/// reading.
pub fn run(args: &Args) -> bool {
    let mut had_error = false;

    for path in &args.files {
        if args.files.len() > 1 {
            tracing::info!(target: TARGET, "=== {} ===", path.display());
        }
        match replay_file(path) {
            Ok(events) => tracing::info!(target: TARGET, "total: {events} events"),
            Err(e) => {
                tracing::error!(target: TARGET, "{e:#}");
                had_error = true;
            }
        }
    }

    had_error
}

/// Prints one archive, returning how many events it held.
pub fn replay_file(path: &Path) -> Result<usize> {
    let archive =
        ArchiveReader::open(path).with_context(|| format!("reading archive {}", path.display()))?;

    tracing::info!(target: TARGET, "header: {}", describe(&archive.header));

    let mut count = 0;
    for (idx, event) in archive.enumerate() {
        let n = idx + 1;
        let event = event.with_context(|| format!("at event {n} in archive {}", path.display()))?;
        tracing::info!(target: TARGET, "[{n}] {}", render::event_line(&event));
        count = n;
    }

    Ok(count)
}

/// Renders the header. Spells out the recorded kinds, because "this archive
/// holds no address announcements" and "this archive was not recording them"
/// look identical from the events alone.
fn describe(header: &ArchiveHeader) -> String {
    let kinds: Vec<String> = header
        .events
        .iter()
        .map(|k| match EventKind::try_from(*k) {
            Ok(kind) => format!("{kind:?}"),
            Err(_) => format!("unknown({k})"),
        })
        .collect();
    format!(
        "created={} network={} events=[{}]",
        header.created,
        header.network,
        kinds.join(", ")
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_describe_names_every_kind() {
        let header = ArchiveHeader {
            created: 1_700_000_000,
            network: "signet".to_owned(),
            events: vec![
                EventKind::PingRtt as i32,
                EventKind::ConnectionResult as i32,
            ],
        };
        assert_eq!(
            describe(&header),
            "created=1700000000 network=signet events=[PingRtt, ConnectionResult]"
        );
    }

    /// A kind added after this build was made still reads back, rather than
    /// turning the whole header into an error.
    #[test]
    fn test_describe_keeps_an_unknown_kind() {
        let header = ArchiveHeader {
            created: 0,
            network: String::new(),
            events: vec![99],
        };
        assert_eq!(describe(&header), "created=0 network= events=[unknown(99)]");
    }
}
