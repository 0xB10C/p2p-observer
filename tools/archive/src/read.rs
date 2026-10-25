//! Reading an archive file back.

use common::archive::ArchiveHeader;
use common::events::PeerEvent;
use common::prost::{Message, decode_length_delimiter};
use std::ffi::OsStr;
use std::fs::File;
use std::io::{self, BufReader, ErrorKind, Read};
use std::path::Path;

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
}
