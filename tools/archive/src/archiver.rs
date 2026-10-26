//! Subscribing to the observer's events and writing them to disk.

use std::fs::{self, File};
use std::io::{self, BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use common::{
    anyhow::{Context, Result, bail},
    archive::{ArchiveHeader, EventKind},
    async_nats,
    clap::{self, Parser},
    events::{PeerEvent, peer_event},
    futures_util::StreamExt,
    prost::{Message, encode_length_delimiter},
    tokio::{
        self,
        sync::watch,
        time::{Instant, sleep_until},
    },
    tracing,
};
use time::OffsetDateTime;
use time::macros::format_description;

use crate::TARGET_ARCHIVER as TARGET;

/// How long to wait for the subscription to drain before shutting down anyway.
/// Draining never completes while NATS is unreachable, because the client
/// reconnects instead of processing the unsubscribe.
pub const DRAIN_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Parser, Debug, Clone)]
#[command(version, about = "Archive p2p-observer events to disk")]
pub struct Args {
    /// The NATS server to subscribe to.
    #[arg(short = 'a', long, default_value = "nats://localhost:4222")]
    pub nats_url: String,

    /// The network to archive, as the observer spells it in its config. One
    /// archive covers one network, so this is also what goes in the header.
    #[arg(short, long)]
    pub network: String,

    /// Directory to write archive files to. Created if it does not exist.
    #[arg(short, long)]
    pub output_dir: PathBuf,

    /// Base name for archive files, e.g. "signet" for
    /// "signet.20261025-120000-000.bin.zst".
    #[arg(short, long, default_value = "archive")]
    pub base_name: String,

    /// Bytes on disk before rotating to a new file. Defaults to 1 GiB.
    #[arg(long, default_value_t = 1_073_741_824)]
    pub max_file_size: u64,

    /// Zstd compression level, 1 to 22. 0 writes plain `.bin` files.
    ///
    /// The top levels compress barely better than 18 while costing a lot more
    /// CPU and memory. Use 3 when the archiver has to keep up with a busy
    /// stream on a small machine.
    #[arg(long, default_value_t = 18)]
    pub compression_level: u32,

    /// Archive ping RTT events.
    #[arg(long)]
    pub ping_rtt: bool,

    /// Archive block announcement events.
    #[arg(long)]
    pub block_announcements: bool,

    /// Archive address announcement events.
    #[arg(long)]
    pub address_announcements: bool,

    /// Archive connection result events.
    #[arg(long)]
    pub connection_results: bool,

    /// Archive version handshake events.
    #[arg(long)]
    pub handshakes: bool,

    /// Archive compact block probe events.
    #[arg(long)]
    pub compact_block_probes: bool,

    /// Archive fee filter events.
    #[arg(long)]
    pub fee_filters: bool,

    /// Archive sendcmpct events.
    #[arg(long)]
    pub send_cmpcts: bool,
}

impl Args {
    /// Whether no event filter was given, in which case everything is archived.
    fn archives_everything(&self) -> bool {
        !(self.ping_rtt
            || self.block_announcements
            || self.address_announcements
            || self.connection_results
            || self.handshakes
            || self.compact_block_probes
            || self.fee_filters
            || self.send_cmpcts)
    }
}

/// Which events get written to disk. Derived once from the arguments so the
/// filter policy lives in one place.
#[derive(Debug, Clone, Copy)]
struct Filter {
    /// Archive whatever arrives, ignoring the fields below.
    all: bool,
    ping_rtt: bool,
    block_announcement: bool,
    address_announcement: bool,
    connection_result: bool,
    handshake: bool,
    compact_block_probe: bool,
    fee_filter: bool,
    send_cmpct: bool,
}

impl From<&Args> for Filter {
    fn from(args: &Args) -> Self {
        Self {
            all: args.archives_everything(),
            ping_rtt: args.ping_rtt,
            block_announcement: args.block_announcements,
            address_announcement: args.address_announcements,
            connection_result: args.connection_results,
            handshake: args.handshakes,
            compact_block_probe: args.compact_block_probes,
            fee_filter: args.fee_filters,
            send_cmpct: args.send_cmpcts,
        }
    }
}

impl Filter {
    fn matches(&self, event: &PeerEvent) -> bool {
        // An unset `event` is either a malformed publish or a variant added
        // after this binary was built. When nothing in particular was asked
        // for, archive it anyway: the bytes are kept verbatim, so a later
        // build can read what this one cannot name. When a filter was given,
        // an event we cannot classify is not what was asked for.
        if self.all {
            return true;
        }
        match &event.event {
            Some(peer_event::Event::PingRtt(_)) => self.ping_rtt,
            Some(peer_event::Event::BlockAnnouncement(_)) => self.block_announcement,
            Some(peer_event::Event::AddressAnnouncement(_)) => self.address_announcement,
            Some(peer_event::Event::ConnectionResult(_)) => self.connection_result,
            Some(peer_event::Event::Handshake(_)) => self.handshake,
            Some(peer_event::Event::CompactBlockProbe(_)) => self.compact_block_probe,
            Some(peer_event::Event::FeeFilter(_)) => self.fee_filter,
            Some(peer_event::Event::SendCmpct(_)) => self.send_cmpct,
            None => false,
        }
    }

    /// The kinds to record in the header, always written out in full so a
    /// reader never has to interpret an empty list.
    fn kinds(&self) -> Vec<i32> {
        [
            (self.all || self.ping_rtt, EventKind::PingRtt),
            (
                self.all || self.block_announcement,
                EventKind::BlockAnnouncement,
            ),
            (
                self.all || self.address_announcement,
                EventKind::AddressAnnouncement,
            ),
            (
                self.all || self.connection_result,
                EventKind::ConnectionResult,
            ),
            (self.all || self.handshake, EventKind::Handshake),
            (
                self.all || self.compact_block_probe,
                EventKind::CompactBlockProbe,
            ),
            (self.all || self.fee_filter, EventKind::FeeFilter),
            (self.all || self.send_cmpct, EventKind::SendCmpct),
        ]
        .into_iter()
        .filter(|(enabled, _)| *enabled)
        .map(|(_, kind)| kind as i32)
        .collect()
    }
}

/// Counts the bytes that reach the file, which for a compressed archive is not
/// the number of bytes handed to the encoder. Rotation is a question about disk
/// usage, so it is the compressed count that has to be measured.
struct TrackingWriter {
    inner: BufWriter<File>,
    bytes_written: u64,
}

impl Write for TrackingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.bytes_written += written as u64;
        Ok(written)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

enum ArchiveWriter {
    Plain(BufWriter<File>),
    Zstd(zstd::Encoder<'static, TrackingWriter>),
}

impl ArchiveWriter {
    fn new(file: File, compression_level: u32) -> io::Result<Self> {
        if compression_level == 0 {
            return Ok(Self::Plain(BufWriter::new(file)));
        }
        let tracker = TrackingWriter {
            inner: BufWriter::new(file),
            bytes_written: 0,
        };
        Ok(Self::Zstd(zstd::Encoder::new(
            tracker,
            compression_level as i32,
        )?))
    }

    /// Bytes on disk so far, for a compressed archive only. `None` means the
    /// uncompressed count is already the size on disk.
    fn compressed_bytes(&self) -> Option<u64> {
        match self {
            Self::Plain(_) => None,
            Self::Zstd(encoder) => Some(encoder.get_ref().bytes_written),
        }
    }

    fn finish(self) -> io::Result<()> {
        match self {
            Self::Plain(mut writer) => writer.flush(),
            Self::Zstd(encoder) => encoder.finish()?.flush(),
        }
    }
}

impl Write for ArchiveWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(writer) => writer.write(buf),
            Self::Zstd(encoder) => encoder.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(writer) => writer.flush(),
            Self::Zstd(encoder) => encoder.flush(),
        }
    }
}

/// The archive file currently being written.
pub struct ArchiveFile {
    path: PathBuf,
    writer: ArchiveWriter,
    /// Uncompressed bytes handed to the writer, which is the size on disk only
    /// for an uncompressed archive.
    bytes_written: u64,
}

impl ArchiveFile {
    fn create(
        output_dir: &Path,
        base_name: &str,
        compression_level: u32,
        header: &ArchiveHeader,
    ) -> io::Result<Self> {
        let ext = if compression_level == 0 {
            "bin"
        } else {
            "bin.zst"
        };

        // `create_new` so an archive is never appended to or overwritten. Two
        // files can land in the same millisecond when rotation is tight, so
        // retry rather than fail.
        let (path, file) = loop {
            let stamp = format_utc_timestamp(
                SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .expect("time went backwards")
                    .as_millis() as u64,
            );
            let path = output_dir.join(format!("{base_name}.{stamp}.{ext}"));
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
            {
                Ok(file) => break (path, file),
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(io::Error::new(
                        e.kind(),
                        format!("creating archive {}: {e}", path.display()),
                    ));
                }
            }
        };

        let mut writer = ArchiveWriter::new(file, compression_level)?;
        let bytes = header.encode_length_delimited_to_vec();
        writer.write_all(&bytes)?;
        writer.flush()?;

        tracing::info!(target: TARGET, path = %path.display(), "created archive file");

        Ok(Self {
            path,
            writer,
            bytes_written: bytes.len() as u64,
        })
    }

    /// Appends one length-delimited record.
    ///
    /// Takes the bytes as they arrived rather than a decoded event, so the
    /// archive is a faithful copy of what was published. Re-encoding a decoded
    /// event would drop any field this build does not know about, which is
    /// exactly the thing a long-lived archive should not do.
    fn write_record(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut prefix = Vec::with_capacity(10);
        encode_length_delimiter(payload.len(), &mut prefix).map_err(io::Error::other)?;
        self.writer.write_all(&prefix)?;
        self.writer.write_all(payload)?;
        self.bytes_written += (prefix.len() + payload.len()) as u64;
        Ok(())
    }

    /// Whether the file has reached its size limit.
    ///
    /// Overshoots a compressed archive, and not by a rounding error: zstd holds
    /// a whole block before emitting it, so nothing reaches the tracked count
    /// until then. The limit behaves as a floor on file size rather than a
    /// ceiling, which is the right way round for an archive — a file is never
    /// cut short of what was asked for.
    fn needs_rotation(&self, max_file_size: u64) -> bool {
        self.writer.compressed_bytes().unwrap_or(self.bytes_written) >= max_file_size
    }

    fn finalize(self) -> io::Result<()> {
        self.writer.finish()
    }
}

pub async fn run(args: Args, mut shutdown_rx: watch::Receiver<bool>) -> Result<()> {
    if args.compression_level > 22 {
        bail!(
            "compression level {} is out of range: 0 to skip compression, otherwise 1 to 22",
            args.compression_level
        );
    }

    let filter = Filter::from(&args);
    let header = ArchiveHeader {
        created: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time went backwards")
            .as_secs(),
        network: args.network.clone(),
        events: filter.kinds(),
    };

    // A single-token wildcard. The observer's RPC subjects start at
    // `p2p-observer.<network>.rpc.`, so they have one token more than this
    // matches and request traffic cannot end up in an archive.
    let subject = format!("p2p-observer.{}.*", args.network);

    let nats = async_nats::connect(&args.nats_url)
        .await
        .with_context(|| format!("connecting to NATS at {}", args.nats_url))?;
    let mut sub = nats
        .subscribe(subject.clone())
        .await
        .with_context(|| format!("subscribing to {subject}"))?;

    tracing::info!(
        target: TARGET,
        url = %args.nats_url,
        %subject,
        everything = filter.all,
        kinds = header.events.len(),
        compression_level = args.compression_level,
        max_file_size = args.max_file_size,
        "connected to NATS",
    );

    fs::create_dir_all(&args.output_dir)
        .with_context(|| format!("creating output directory {}", args.output_dir.display()))?;
    let mut file = ArchiveFile::create(
        &args.output_dir,
        &args.base_name,
        args.compression_level,
        &header,
    )
    .context("creating the first archive file")?;

    let mut files: u64 = 1;
    let mut events: u64 = 0;
    let mut draining = false;
    // Only read once `draining` is set.
    let mut drain_deadline = Instant::now();

    loop {
        tokio::select! {
            msg = sub.next() => {
                let Some(msg) = msg else {
                    break; // the subscription ended, which is how draining finishes
                };
                // Decode only to classify and to reject anything that is not an
                // event. The bytes written are the ones that arrived.
                let event = match PeerEvent::decode(msg.payload.as_ref()) {
                    Ok(event) => event,
                    Err(e) => {
                        tracing::warn!(target: TARGET, subject = %msg.subject, error = %e, "skipping undecodable payload");
                        continue;
                    }
                };
                if !filter.matches(&event) {
                    continue;
                }
                if let Err(e) = file.write_record(&msg.payload) {
                    // Losing the stream beats writing a torn archive, so stop
                    // rather than carry on past a write error.
                    tracing::error!(target: TARGET, path = %file.path.display(), error = %e, "failed to write event");
                    break;
                }
                events += 1;
                if file.needs_rotation(args.max_file_size) {
                    file = rotate(file, &args, &header).context("rotating the archive file")?;
                    files += 1;
                }
            }
            changed = shutdown_rx.changed(), if !draining => {
                match changed {
                    Ok(()) if !*shutdown_rx.borrow() => continue,
                    Ok(()) => tracing::info!(target: TARGET, "shutting down, draining the subscription"),
                    // Every sender is gone, which can only mean shutdown.
                    Err(_) => tracing::warn!(target: TARGET, "shutdown sender dropped, draining the subscription"),
                }
                draining = true;
                // Unsubscribes but keeps yielding what is already in flight.
                // `sub.next()` returns None afterwards and the loop breaks.
                if let Err(e) = sub.unsubscribe().await {
                    tracing::warn!(target: TARGET, error = %e, "failed to unsubscribe");
                    break;
                }
                drain_deadline = Instant::now() + DRAIN_TIMEOUT;
            }
            // The deadline is absolute, so rebuilding this future on every
            // iteration does not push it back.
            _ = sleep_until(drain_deadline), if draining => {
                tracing::warn!(target: TARGET, "draining timed out, shutting down anyway");
                break;
            }
        }
    }

    let path = file.path.clone();
    file.finalize()
        .with_context(|| format!("finalizing {}", path.display()))?;

    tracing::info!(target: TARGET, files, events, "archiver stopped");
    Ok(())
}

/// Closes the current archive file and opens the next one.
fn rotate(file: ArchiveFile, args: &Args, header: &ArchiveHeader) -> io::Result<ArchiveFile> {
    tracing::info!(target: TARGET, path = %file.path.display(), "rotating");
    file.finalize()?;
    ArchiveFile::create(
        &args.output_dir,
        &args.base_name,
        args.compression_level,
        header,
    )
}

/// A sortable UTC stamp, so `ls` lists an output directory in the order the
/// files were written.
fn format_utc_timestamp(epoch_ms: u64) -> String {
    let fmt = format_description!("[year][month][day]-[hour][minute][second]-[subsecond digits:3]");
    OffsetDateTime::from_unix_timestamp_nanos(epoch_ms as i128 * 1_000_000)
        .expect("timestamp out of range")
        .format(&fmt)
        .expect("timestamp formatting failed")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::read::ArchiveReader;
    use common::events::{BlockAnnouncement, Handshake, PingRtt};

    fn args(flags: &[&str]) -> Args {
        let mut argv = vec![
            "archiver",
            "--network",
            "signet",
            "--output-dir",
            "/nonexistent",
        ];
        argv.extend_from_slice(flags);
        Args::parse_from(argv)
    }

    fn ping(id: u64) -> PeerEvent {
        PeerEvent {
            connection_id: id,
            timestamp_ms: 1_700_000_000_000,
            peer_addr: "1.2.3.4:38333".to_owned(),
            user_agent: "/Satoshi:30.0.0/".to_owned(),
            transport_version: Some(2),
            event: Some(peer_event::Event::PingRtt(PingRtt {
                rtt_ms: 42,
                tcp_stats: None,
            })),
            ..Default::default()
        }
    }

    fn block() -> PeerEvent {
        PeerEvent {
            connection_id: 9,
            timestamp_ms: 1_700_000_001_000,
            peer_addr: "1.2.3.4:38333".to_owned(),
            user_agent: String::new(),
            transport_version: None,
            event: Some(peer_event::Event::BlockAnnouncement(BlockAnnouncement {
                block_hash: "00".repeat(32),
                announcement_type: 1,
                tcp_stats: None,
                batch_size: 1,
                height: Some(100),
                new_to_us: true,
            })),
            ..Default::default()
        }
    }

    fn handshake() -> PeerEvent {
        PeerEvent {
            connection_id: 9,
            timestamp_ms: 1_700_000_000_500,
            peer_addr: "1.2.3.4:38333".to_owned(),
            user_agent: "/Satoshi:30.0.0/".to_owned(),
            transport_version: Some(2),
            event: Some(peer_event::Event::Handshake(Handshake {
                protocol_version: 70016,
                services: 1033,
                start_height: 225_000,
                relay: true,
                peer_timestamp: 1_700_000_000,
                addr_recv: "0.0.0.0:0".to_owned(),
                sendaddrv2: true,
                wtxid_relay: true,
                user_agent: "/Satoshi:30.0.0/".to_owned(),
            })),
            ..Default::default()
        }
    }

    fn tmp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("p2p-observer-archive-{tag}-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn test_no_flags_archives_everything() {
        let filter = Filter::from(&args(&[]));
        assert!(filter.all);
        assert!(filter.matches(&ping(1)));
        assert!(filter.matches(&block()));
        // An event this build cannot classify is still archived verbatim.
        assert!(filter.matches(&PeerEvent::default()));
        // Every kind this build knows: ping, block, address, result,
        // handshake, probe, feefilter, sendcmpct.
        assert_eq!(filter.kinds().len(), 8);
    }

    #[test]
    fn test_a_flag_narrows_to_that_kind() {
        let filter = Filter::from(&args(&["--ping-rtt"]));
        assert!(!filter.all);
        assert!(filter.matches(&ping(1)));
        assert!(!filter.matches(&block()));
        assert!(!filter.matches(&PeerEvent::default()));
        assert_eq!(filter.kinds(), vec![EventKind::PingRtt as i32]);
    }

    #[test]
    fn test_the_newer_kinds_can_be_asked_for_alone() {
        // A reachability study wants who connected and how it ended, and none
        // of the per-session traffic.
        let filter = Filter::from(&args(&["--handshakes", "--connection-results"]));
        assert!(!filter.all);
        assert!(filter.matches(&handshake()));
        assert!(!filter.matches(&ping(1)));
        assert!(!filter.matches(&block()));
        assert_eq!(
            filter.kinds(),
            vec![
                EventKind::ConnectionResult as i32,
                EventKind::Handshake as i32
            ]
        );
    }

    #[test]
    fn test_flags_combine() {
        let filter = Filter::from(&args(&["--ping-rtt", "--block-announcements"]));
        assert!(filter.matches(&ping(1)));
        assert!(filter.matches(&block()));
        assert_eq!(
            filter.kinds(),
            vec![
                EventKind::PingRtt as i32,
                EventKind::BlockAnnouncement as i32
            ]
        );
    }

    /// Writes an archive at every compression setting and reads it back, so the
    /// header, the length prefixes and the zstd framing are all exercised
    /// together rather than one at a time.
    #[test]
    fn test_round_trip() {
        for level in [0, 1, 18] {
            let dir = tmp_dir(&format!("rt-{level}"));
            let header = ArchiveHeader {
                created: 1_700_000_000,
                network: "signet".to_owned(),
                events: Filter::from(&args(&[])).kinds(),
            };
            let written = [ping(1), block(), ping(2)];

            let mut file = ArchiveFile::create(&dir, "test", level, &header).unwrap();
            for event in &written {
                file.write_record(&event.encode_to_vec()).unwrap();
            }
            let path = file.path.clone();
            file.finalize().unwrap();

            let ext = if level == 0 { "bin" } else { "bin.zst" };
            assert!(
                path.to_string_lossy().ends_with(ext),
                "{} should end in {ext}",
                path.display()
            );

            let archive = ArchiveReader::open(&path).unwrap();
            assert_eq!(archive.header, header);
            let read: Vec<PeerEvent> = archive.map(|e| e.unwrap()).collect();
            assert_eq!(read, written);

            fs::remove_file(&path).unwrap();
        }
    }

    /// An archive with no events in it is still a valid archive: the header
    /// says what was being recorded, which is the whole point of writing it out
    /// in full.
    #[test]
    fn test_empty_archive_keeps_its_header() {
        let dir = tmp_dir("empty");
        let header = ArchiveHeader {
            created: 1_700_000_000,
            network: "mainnet".to_owned(),
            events: Filter::from(&args(&["--address-announcements"])).kinds(),
        };

        let file = ArchiveFile::create(&dir, "empty", 18, &header).unwrap();
        let path = file.path.clone();
        file.finalize().unwrap();

        let archive = ArchiveReader::open(&path).unwrap();
        assert_eq!(archive.header, header);
        assert_eq!(archive.count(), 0);

        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_rotation_tracks_bytes_on_disk() {
        let dir = tmp_dir("rotate");
        let header = ArchiveHeader {
            created: 1_700_000_000,
            network: "signet".to_owned(),
            events: Filter::from(&args(&[])).kinds(),
        };

        // Uncompressed: the record bytes are the bytes on disk, so the limit
        // bites as soon as they pass it.
        let mut file = ArchiveFile::create(&dir, "plain", 0, &header).unwrap();
        assert!(!file.needs_rotation(1024));
        while !file.needs_rotation(1024) {
            file.write_record(&ping(1).encode_to_vec()).unwrap();
        }
        assert!(file.bytes_written >= 1024);
        let path = file.path.clone();
        file.finalize().unwrap();
        assert!(fs::metadata(&path).unwrap().len() >= 1024);
        fs::remove_file(&path).unwrap();

        // Compressed: these events are near-identical, so zstd shrinks them by
        // far more than an order of magnitude. Rotation must follow the
        // compressed size, not the uncompressed one.
        let mut file = ArchiveFile::create(&dir, "zstd", 18, &header).unwrap();
        for _ in 0..2000 {
            file.write_record(&ping(1).encode_to_vec()).unwrap();
        }
        assert!(
            file.bytes_written > 10 * 1024,
            "uncompressed bytes {} should be well past the limit",
            file.bytes_written
        );
        assert!(
            !file.needs_rotation(10 * 1024),
            "compressed size should still be under the limit"
        );
        let path = file.path.clone();
        file.finalize().unwrap();
        fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_timestamp_is_sortable_utc() {
        assert_eq!(format_utc_timestamp(0), "19700101-000000-000");
        assert_eq!(
            format_utc_timestamp(1_700_000_000_123),
            "20231114-221320-123"
        );
    }
}
