//! Reading an archive file back.

use common::archive::ArchiveHeader;
use common::events::PeerEvent;
use common::prost::{Message, decode_length_delimiter};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, ErrorKind, Read};
use std::path::Path;

/// The longest record an archive may claim.
///
/// A record is one PeerEvent, and the largest the observer produces is an
/// address announcement: it carries everything a peer announced, before the
/// rate limit, and a peer can put tens of thousands of entries in one message.
/// A few megabytes is the ceiling on that; sixteen refuses nothing the
/// observer can write.
///
/// Without a cap the prefix is whatever the file says, and the buffer is sized
/// to it before a single byte of the record has been read. Five bytes of a
/// corrupt prefix asked for four gibibytes, zeroed them, and spent eighteen
/// seconds doing it before reporting that the file was too short -- on a
/// smaller machine the process is simply killed. Compression makes that worse
/// rather than better: a few hundred bytes on disk can claim gigabytes.
///
/// The same reasoning as the oversized check in the v1 transport, which
/// refuses a declared length before reserving anything for it. A file is no
/// more trustworthy than a socket -- archives are passed around, and a
/// truncated one is a normal thing to find after a crash.
const MAX_RECORD: usize = 16 << 20;

/// Reads an archive, yielding its events.
///
/// The header is consumed by [`ArchiveReader::new`], so it is available before
/// the first event is read and the iterator covers only events.
#[derive(Debug)]
pub struct ArchiveReader<R> {
    reader: BufReader<R>,
    buf: Vec<u8>,
    pub header: ArchiveHeader,
}

impl ArchiveReader<Box<dyn Read>> {
    /// Opens an archive, decompressing it when the path ends in `.zst`.
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;

        let reader: Box<dyn Read> = if path.extension() == Some(OsStr::new("zst")) {
            Box::new(zstd::Decoder::new(file)?)
        } else {
            Box::new(file)
        };

        Self::new(reader)
    }
}

impl<R: Read> ArchiveReader<R> {
    pub fn new(reader: R) -> io::Result<Self> {
        let mut reader = BufReader::new(reader);
        let mut buf = Vec::new();

        let header = read_message(&mut reader, &mut buf)?
            .ok_or_else(|| io::Error::other("missing header"))?;

        Ok(Self {
            reader,
            buf,
            header,
        })
    }
}

impl<R: Read> Iterator for ArchiveReader<R> {
    type Item = io::Result<PeerEvent>;

    fn next(&mut self) -> Option<Self::Item> {
        read_message(&mut self.reader, &mut self.buf).transpose()
    }
}

fn read_message<M: Message + Default>(
    reader: &mut impl Read,
    buf: &mut Vec<u8>,
) -> io::Result<Option<M>> {
    let len = match read_length_delimiter(reader)? {
        Some(len) => len,
        // A clean EOF at a message boundary is the normal end of the archive.
        None => return Ok(None),
    };

    if len > MAX_RECORD {
        return Err(io::Error::new(
            ErrorKind::InvalidData,
            format!("record of {len} bytes claims more than the {MAX_RECORD} allowed"),
        ));
    }

    buf.clear();
    buf.resize(len, 0);
    reader.read_exact(buf)?;

    M::decode(&buf[..]).map(Some).map_err(io::Error::other)
}

/// Reads a protobuf varint length prefix from `reader`.
///
/// Returns `Ok(None)` on a clean EOF at a message boundary, which is the normal
/// end of an archive; an EOF partway through the varint surfaces as
/// `UnexpectedEof`, because that is a truncated file rather than a finished one.
///
/// prost only decodes a length delimiter from an in-memory buffer, so the prefix
/// has to be pulled off the stream first. Its encoded length is not known up
/// front, so we read one byte at a time until the continuation bit clears and
/// hand the collected bytes to prost.
fn read_length_delimiter(reader: &mut impl Read) -> io::Result<Option<usize>> {
    let mut bytes = Vec::with_capacity(10);
    loop {
        let mut byte = [0u8; 1];
        match reader.read_exact(&mut byte) {
            Ok(()) => {}
            Err(e) if e.kind() == ErrorKind::UnexpectedEof && bytes.is_empty() => {
                return Ok(None);
            }
            Err(e) => return Err(e),
        }
        bytes.push(byte[0]);

        // Stop once the continuation bit clears. Cap at the longest a varint
        // can be so a malformed prefix cannot make us read forever; prost then
        // rejects it.
        if byte[0] & 0x80 == 0 || bytes.len() == 10 {
            break;
        }
    }

    decode_length_delimiter(&mut bytes.as_slice())
        .map(Some)
        .map_err(io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// A minimal header, for the archives these tests build by hand.
    fn header() -> ArchiveHeader {
        ArchiveHeader {
            created: 1,
            network: "signet".to_owned(),
            events: Vec::new(),
        }
    }

    /// Yields at most one byte per `read`, so a multi-byte length prefix
    /// arrives split across several reads.
    struct Trickle<R>(R);

    impl<R: Read> Read for Trickle<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if buf.is_empty() {
                return Ok(0);
            }
            self.0.read(&mut buf[..1])
        }
    }

    #[test]
    fn test_reads_single_byte_length_prefix() {
        let mut reader = Cursor::new(vec![0x05]);
        assert_eq!(read_length_delimiter(&mut reader).unwrap(), Some(5));
    }

    #[test]
    fn test_reads_multi_byte_length_prefix_split_across_reads() {
        // 300 encodes as the two-byte varint [0xAC, 0x02]. A prefix split
        // across reads must still decode to the full value.
        let mut reader = Trickle(Cursor::new(vec![0xAC, 0x02]));
        assert_eq!(read_length_delimiter(&mut reader).unwrap(), Some(300));
    }

    #[test]
    fn test_returns_none_on_clean_eof_at_boundary() {
        let mut reader = Cursor::new(Vec::new());
        assert_eq!(read_length_delimiter(&mut reader).unwrap(), None);
    }

    #[test]
    fn test_errors_on_truncated_length_prefix() {
        // A lone continuation byte with no follow-up is a truncated varint.
        let mut reader = Cursor::new(vec![0x80]);
        let err = read_length_delimiter(&mut reader).unwrap_err();
        assert_eq!(err.kind(), ErrorKind::UnexpectedEof);
    }

    #[test]
    fn test_empty_file_has_no_header() {
        let err = ArchiveReader::new(Cursor::new(Vec::new())).unwrap_err();
        assert_eq!(err.to_string(), "missing header");
    }

    /// A record longer than any event can be is refused on the strength of
    /// the claim, before anything is reserved for it.
    ///
    /// Five bytes of prefix asked for four gibibytes, zeroed them, and spent
    /// eighteen seconds doing it before reporting that the file was too
    /// short. A smaller machine does not report anything -- the process is
    /// killed. And compression makes it worse rather than better: a few
    /// hundred bytes on disk can claim gigabytes, so the cost to whoever
    /// hands you the archive is nothing.
    ///
    /// Archives are passed around, and a truncated one is a normal thing to
    /// find after a crash. A file is no more trustworthy than a socket.
    #[test]
    fn test_a_record_claiming_more_than_an_event_can_be_is_refused() {
        let mut bytes = header().encode_length_delimited_to_vec();
        // A varint claiming four gibibytes.
        bytes.extend_from_slice(&[0xff, 0xff, 0xff, 0xff, 0x0f]);

        let mut reader = ArchiveReader::new(Cursor::new(bytes)).unwrap();
        let err = reader
            .next()
            .expect("a record was claimed")
            .expect_err("and refused");
        assert_eq!(err.kind(), ErrorKind::InvalidData);
        assert!(
            err.to_string().contains("claims more than"),
            "{err}: the error should say what was refused"
        );
    }

    /// And a record at the limit is still read, so the cap refuses nothing
    /// the observer can write.
    #[test]
    fn test_a_record_at_the_limit_still_reads() {
        // An event whose encoding is large but under the cap: the user agent
        // is the only free-length field to hand.
        let big = PeerEvent {
            peer_addr: "1.2.3.4:8333".to_owned(),
            user_agent: "x".repeat(MAX_RECORD / 2),
            ..Default::default()
        };
        let mut bytes = header().encode_length_delimited_to_vec();
        bytes.extend_from_slice(&big.encode_length_delimited_to_vec());

        let mut reader = ArchiveReader::new(Cursor::new(bytes)).unwrap();
        let read = reader.next().expect("a record").expect("read");
        assert_eq!(read.user_agent.len(), MAX_RECORD / 2);
        assert!(reader.next().is_none());
    }
}
