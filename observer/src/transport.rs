use crate::TARGET_PROTOCOL as TARGET;
use bip324::io::Payload;
use common::anyhow::{Context, Result};
use common::{
    bitcoin::consensus::{deserialize, serialize},
    bitcoin::hashes::sha256d,
    p2p::{
        Magic,
        message::{CommandString, NetworkMessage, RawNetworkMessage, V2NetworkMessage},
    },
    tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    tracing,
};
use std::io::{Error, ErrorKind};

pub trait TransportReader {
    async fn recv(&mut self) -> Result<NetworkMessage>;

    /// Messages received under a readable command whose payload would not
    /// deserialize, and were handed up as [`NetworkMessage::Unknown`] rather
    /// than ending the session. See [`undecodable`].
    fn undecodable(&self) -> u32 {
        0
    }
}

/// The message to hand up for a payload that would not deserialize.
///
/// A payload we cannot read under a command we can is one message lost, not a
/// stream we can no longer follow: the frame boundary is known, and the next
/// message is where it always was. Ending the session over it threw away
/// everything the peer would have said afterwards, and the archive blamed the
/// peer for a decode error that was as often a gap in our parser -- btcd's
/// thousand-entry addrv2 reply failed this way on every connection. So the
/// message goes up as `Unknown`, with its raw payload, for the protocol layer
/// to count under its command and, where it has a more forgiving parser, to
/// read anyway. Bitcoin Core does the same: a message it cannot deserialize is
/// logged and skipped.
///
/// `None` when the command itself is not a command string. Then nothing about
/// the frame can be trusted, and the session ends with a decode fault as
/// before.
fn undecodable(command: &[u8], payload: &[u8]) -> Option<NetworkMessage> {
    let end = command
        .iter()
        .position(|b| *b == 0)
        .unwrap_or(command.len());
    let command = String::from_utf8(command[..end].to_vec()).ok()?;
    let command = CommandString::try_from(command).ok()?;
    Some(NetworkMessage::Unknown {
        command,
        payload: payload.to_vec(),
    })
}

/// The commands BIP324 gives a one-byte id, in id order from 1.
///
/// The ids are the BIP's and are fixed on the wire: a message type without one
/// travels as a zero byte followed by its twelve-byte command, so this grows
/// only if the BIP itself assigns more. Spelled out here because rust-bitcoin
/// keeps the same mapping in the match arms of its encoder and decoder,
/// exporting neither, and reports a failed decode without saying which command
/// failed.
///
/// Not maintained by eye: `test_the_short_id_table_agrees_with_the_decoder`
/// holds it to that decoder's own answer wherever the decoder can be asked.
const SHORT_IDS: [&str; 28] = [
    "addr",
    "block",
    "blocktxn",
    "cmpctblock",
    "feefilter",
    "filteradd",
    "filterclear",
    "filterload",
    "getblocks",
    "getblocktxn",
    "getdata",
    "getheaders",
    "headers",
    "inv",
    "mempool",
    "merkleblock",
    "notfound",
    "ping",
    "pong",
    "sendcmpct",
    "tx",
    "getcfilters",
    "cfilter",
    "getcfheaders",
    "cfheaders",
    "getcfcheckpt",
    "cfcheckpt",
    "addrv2",
];

/// The command of a v2 message from its first bytes: a [`SHORT_IDS`] id, or
/// zero followed by the twelve-byte command.
fn v2_undecodable(contents: &[u8]) -> Option<NetworkMessage> {
    match contents.split_first()? {
        (0, rest) => undecodable(rest.get(..12)?, &rest[12..]),
        (id, rest) => {
            let command = SHORT_IDS.get(usize::from(*id) - 1)?;
            undecodable(command.as_bytes(), rest)
        }
    }
}

pub trait TransportWriter {
    async fn send(&mut self, msg: NetworkMessage) -> Result<()>;
}

/// Longest v1 payload we will read, in bytes.
///
/// The length is the one header field we have to act on before the message
/// exists: the payload buffer used to be allocated straight from it, so a
/// 24-byte header could ask for four gigabytes and the peer then filled it at
/// whatever rate it liked -- the whole message has to arrive before anything
/// can reject it, so the claim decided our memory.
///
/// Nothing above this would have decoded in any case:
/// `RawNetworkMessage::consensus_decode` reads through a reader capped at
/// `MAX_MSG_SIZE`, header included. So the check costs no message we could
/// have used, and the allocation follows our limit instead of the peer's
/// number.
const MAX_V1_PAYLOAD: usize = common::p2p::message::MAX_MSG_SIZE - 24;

/// A transport-level failure worth telling apart from the others.
///
/// Attached as context and recovered by downcasting, the same way
/// [`crate::connection::Stage`] is, and for the same reason: the alternative is
/// recognising a failure from the wording of a message. Here it is not even a
/// matter of taste -- both ends of the stream report `UnexpectedEof` and differ
/// only in *where* the stream ran out, which no `ErrorKind` expresses.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Fault {
    /// The stream ended between messages: the ordinary way a peer goes away.
    PeerClosed,
    /// The stream ended part way through a message.
    ///
    /// Only reachable on v1. The v2 framing is inside BIP324, which reports a
    /// zero-length read as `ConnectionAborted` without saying whether it landed
    /// on a packet boundary.
    Truncated,
    /// A frame arrived that could not be read at all. A readable command with
    /// a payload that would not deserialize is not this: see [`undecodable`].
    Decode,
    /// A v1 header declared a payload longer than [`MAX_V1_PAYLOAD`].
    Oversized,
    /// A v1 header did not carry this network's magic, so the stream is
    /// either out of step with the framing or not this network's at all.
    WrongMagic,
    /// A v2 packet would not decrypt, so the channel is out of sync and
    /// nothing further on it means anything.
    V2Decrypt,
    /// Our own send failed.
    Write,
}

impl std::fmt::Display for Fault {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Fault::PeerClosed => "peer closed the connection",
            Fault::Truncated => "stream ended mid-message",
            Fault::Decode => "message did not deserialize",
            Fault::Oversized => "peer declared an oversized message",
            Fault::WrongMagic => "header carried another network's magic",
            Fault::V2Decrypt => "v2 packet did not decrypt",
            Fault::Write => "send failed",
        };
        f.write_str(s)
    }
}

impl std::error::Error for Fault {}

/// The fault a transport error was tagged with, if any.
///
/// `downcast_ref` on the error, not a walk over `chain()`: `chain()` yields a
/// context layer as its `Display` text and not as the value, so a chain walk
/// only ever finds a tag that happens to be the root error. Every tag here is
/// attached as context.
pub(crate) fn fault_of(err: &common::anyhow::Error) -> Option<Fault> {
    err.downcast_ref::<Fault>().copied()
}

/// Tag a BIP324 error with the fault it stands for.
///
/// Only the two cases BIP324 reports in its own terms are tagged: a
/// zero-length read, which it turns into `ConnectionAborted`, and a decryption
/// failure. Everything else is left untagged so the ordinary `ErrorKind`
/// classification applies to it.
fn v2_fault(e: bip324::io::ProtocolError) -> common::anyhow::Error {
    use bip324::io::ProtocolError;

    let fault = match &e {
        ProtocolError::Io(io, _) if io.kind() == ErrorKind::ConnectionAborted => {
            Some(Fault::PeerClosed)
        }
        ProtocolError::Internal(bip324::Error::Decryption(_)) => Some(Fault::V2Decrypt),
        _ => None,
    };
    match fault {
        Some(f) => common::anyhow::Error::new(e).context(f),
        None => common::anyhow::Error::new(e),
    }
}

// ── V2 (BIP324) ──────────────────────────────────────────────────────────────

pub struct TransportV2Reader<R> {
    pub reader: bip324::futures::ProtocolReader<R>,
    undecodable: u32,
}

impl<R> TransportV2Reader<R> {
    pub fn new(reader: bip324::futures::ProtocolReader<R>) -> Self {
        Self {
            reader,
            undecodable: 0,
        }
    }
}

pub struct TransportV2Writer<W> {
    pub writer: bip324::futures::ProtocolWriter<W>,
}

impl<R> TransportReader for TransportV2Reader<R>
where
    R: AsyncRead + Unpin + Send,
{
    async fn recv(&mut self) -> Result<NetworkMessage> {
        let payload = self
            .reader
            .read()
            .await
            .map_err(v2_fault)
            .context("v2 read")?;
        let contents = payload.contents();
        let msg: V2NetworkMessage = match deserialize(contents) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(target: TARGET,
                    len = contents.len(),
                    hex = contents[..contents.len().min(64)].iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    "v2 deserialize failed: {e:#}"
                );
                return match v2_undecodable(contents) {
                    Some(msg) => {
                        self.undecodable = self.undecodable.saturating_add(1);
                        Ok(msg)
                    }
                    None => Err(common::anyhow::Error::new(e).context(Fault::Decode))
                        .context("v2 deserialize"),
                };
            }
        };
        Ok(msg.into_payload())
    }

    fn undecodable(&self) -> u32 {
        self.undecodable
    }
}

impl<W> TransportWriter for TransportV2Writer<W>
where
    W: AsyncWrite + Unpin + Send,
{
    async fn send(&mut self, msg: NetworkMessage) -> Result<()> {
        self.writer
            .write(&Payload::genuine(serialize(&V2NetworkMessage::new(msg))))
            .await
            .map_err(v2_fault)
            .context(Fault::Write)
            .context("v2 write")
    }
}

// ── V1 (plaintext) ───────────────────────────────────────────────────────────

/// Cancel-safe v1 reader. Buffers partial reads in `state` so that if the
/// future is dropped mid-read, the next call resumes from where it left off.
pub struct TransportV1Reader<R> {
    reader: R,
    state: V1ReadState,
    undecodable: u32,
    /// What every header has to open with, kept as the four bytes rather than
    /// as a `Magic` so the comparison is against the wire form.
    magic: [u8; 4],
}

enum V1ReadState {
    /// Reading the 24-byte header (magic + command + length + checksum).
    Header { buf: [u8; 24], pos: usize },
    /// Header is complete, reading the payload.
    Payload {
        header: [u8; 24],
        buf: Vec<u8>,
        pos: usize,
    },
}

impl<R> TransportV1Reader<R> {
    pub fn new(reader: R, magic: Magic) -> Self {
        Self {
            reader,
            state: V1ReadState::Header {
                buf: [0u8; 24],
                pos: 0,
            },
            undecodable: 0,
            magic: magic.to_bytes(),
        }
    }
}

impl<R> TransportReader for TransportV1Reader<R>
where
    R: AsyncRead + Unpin,
{
    async fn recv(&mut self) -> Result<NetworkMessage> {
        // Read header, resuming from saved position if previously cancelled.
        let header = loop {
            match &mut self.state {
                V1ReadState::Header { buf, pos } => {
                    while *pos < 24 {
                        let n = self
                            .reader
                            .read(&mut buf[*pos..])
                            .await
                            .context("v1 header read")?;
                        if n == 0 {
                            // Nothing of the header had arrived yet, so the peer
                            // closed between messages. Part of one had, and the
                            // stream was cut inside a message.
                            let fault = if *pos == 0 {
                                Fault::PeerClosed
                            } else {
                                Fault::Truncated
                            };
                            return Err(common::anyhow::Error::new(Error::new(
                                ErrorKind::UnexpectedEof,
                                "EOF while trying to read v1 transport header",
                            ))
                            .context(fault));
                        }
                        *pos += n;
                    }
                    let header = *buf;
                    // Before the length, because a header that is not ours
                    // says nothing reliable about what follows it.
                    if header[..4] != self.magic {
                        tracing::warn!(target: TARGET,
                            got = %header[..4].iter().map(|b| format!("{b:02x}")).collect::<String>(),
                            want = %self.magic.iter().map(|b| format!("{b:02x}")).collect::<String>(),
                            "v1 header carried another network's magic"
                        );
                        // The state keeps the header, as with an oversized
                        // declaration: nothing has been consumed past it, and
                        // a reset would read the body as the next header. The
                        // next call fails the same way, which is the honest
                        // answer for a stream we cannot follow.
                        return Err(common::anyhow::Error::new(Error::new(
                            ErrorKind::InvalidData,
                            "v1 header did not carry this network's magic",
                        ))
                        .context(Fault::WrongMagic));
                    }
                    let payload_len =
                        u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
                    if payload_len > MAX_V1_PAYLOAD {
                        let cmd = String::from_utf8_lossy(&header[4..16]);
                        tracing::warn!(target: TARGET,
                            cmd = %cmd.trim_end_matches('\0'),
                            payload_len,
                            limit = MAX_V1_PAYLOAD,
                            "v1 header declares an oversized payload"
                        );
                        // The state is left holding the header just read: the
                        // payload was never consumed, so there is nothing to
                        // resynchronise to and a reset would read payload
                        // bytes as the next header. Another call re-reads this
                        // header and fails the same way, which is the honest
                        // answer for a stream that cannot go on.
                        return Err(common::anyhow::Error::new(Error::new(
                            ErrorKind::InvalidData,
                            format!("v1 payload of {payload_len} bytes exceeds {MAX_V1_PAYLOAD}"),
                        ))
                        .context(Fault::Oversized));
                    }
                    let mut payload_buf = vec![0u8; 24 + payload_len];
                    payload_buf[..24].copy_from_slice(&header);
                    self.state = V1ReadState::Payload {
                        header,
                        buf: payload_buf,
                        pos: 24,
                    };
                }
                V1ReadState::Payload { header, .. } => break *header,
            }
        };

        // Read payload, resuming from saved position if previously cancelled.
        if let V1ReadState::Payload { buf, pos, .. } = &mut self.state {
            while *pos < buf.len() {
                let n = self
                    .reader
                    .read(&mut buf[*pos..])
                    .await
                    .context("v1 payload read")?;
                if n == 0 {
                    // A header was read, so this is always mid-message.
                    return Err(common::anyhow::Error::new(Error::new(
                        ErrorKind::UnexpectedEof,
                        "EOF while trying to read v1 transport payload",
                    ))
                    .context(Fault::Truncated));
                }
                *pos += n;
            }

            // Both ways a frame can fail to decode are decidable here, and
            // they are not worth the same. A payload that does not match the
            // checksum in its header says the bytes are corrupt -- which makes
            // the command naming them, and the length that found where this
            // frame ends, untrustworthy as well: there is no message to skip
            // and no boundary to skip it to. A payload that does match and
            // still will not parse is the other case entirely, and the only
            // one [`undecodable`] is for. Letting the decoder fail on both
            // counted a corrupt frame under whatever command it claimed, so a
            // peer could inflate any command's count with garbage.
            let computed = sha256d::Hash::hash(&buf[24..]).to_byte_array();
            if computed[..4] != header[20..24] {
                let cmd = String::from_utf8_lossy(&header[4..16]);
                tracing::warn!(target: TARGET,
                    cmd = %cmd.trim_end_matches('\0'),
                    payload_len = buf.len() - 24,
                    "v1 payload does not match its checksum"
                );
                // State left as it is, like the oversized case above: the
                // stream cannot be trusted to go on, and another call failing
                // the same way is the honest answer.
                return Err(common::anyhow::Error::new(Error::new(
                    ErrorKind::InvalidData,
                    "v1 payload does not match the checksum in its header",
                ))
                .context(Fault::Decode));
            }

            let raw: RawNetworkMessage = match deserialize(buf) {
                Ok(m) => m,
                Err(e) => {
                    let cmd = String::from_utf8_lossy(&header[4..16]);
                    let payload_len = buf.len() - 24;
                    tracing::warn!(target: TARGET,
                        cmd = %cmd.trim_end_matches('\0'),
                        payload_len,
                        hex = buf[24..buf.len().min(88)].iter().map(|b| format!("{b:02x}")).collect::<String>(),
                        "v1 deserialize failed: {e}"
                    );
                    let fallback = undecodable(&header[4..16], &buf[24..]);
                    // Reset state for the next message.
                    self.state = V1ReadState::Header {
                        buf: [0u8; 24],
                        pos: 0,
                    };
                    return match fallback {
                        Some(msg) => {
                            self.undecodable = self.undecodable.saturating_add(1);
                            Ok(msg)
                        }
                        None => Err(common::anyhow::Error::new(e).context(Fault::Decode))
                            .context("v1 deserialize"),
                    };
                }
            };

            // Reset state for the next message.
            self.state = V1ReadState::Header {
                buf: [0u8; 24],
                pos: 0,
            };
            Ok(raw.into_payload())
        } else {
            unreachable!()
        }
    }

    fn undecodable(&self) -> u32 {
        self.undecodable
    }
}

pub struct TransportV1Writer<W> {
    pub magic: Magic,
    pub writer: W,
}

impl<W> TransportWriter for TransportV1Writer<W>
where
    W: AsyncWrite + Unpin,
{
    async fn send(&mut self, msg: NetworkMessage) -> Result<()> {
        tracing::trace!(target: TARGET, cmd=%msg.command(), "sending message");
        self.writer
            .write_all(&serialize(&RawNetworkMessage::new(self.magic, msg)))
            .await
            .context(Fault::Write)
            .context("v1 write")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use common::bitcoin::hashes::sha256d;

    /// A v1 frame as the peer would put it on the wire.
    fn frame(command: &[u8; 12], payload: &[u8]) -> Vec<u8> {
        let mut f = serialize(&Magic::REGTEST);
        f.extend_from_slice(command);
        f.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        f.extend_from_slice(&sha256d::Hash::hash(payload).to_byte_array()[..4]);
        f.extend_from_slice(payload);
        f
    }

    /// A payload that will not deserialize under a command we can read comes
    /// up as that command with the raw bytes, is counted, and the frame after
    /// it reads as it always did.
    #[tokio::test]
    async fn test_v1_undecodable_payload_is_skipped_not_fatal() {
        // An addrv2 declaring one entry and then running out of bytes.
        let bad = [0x01, 0xff, 0xff];
        let mut stream = frame(b"addrv2\0\0\0\0\0\0", &bad);
        stream.extend(serialize(&RawNetworkMessage::new(
            Magic::REGTEST,
            NetworkMessage::Ping(7),
        )));
        let mut reader = TransportV1Reader::new(&stream[..], Magic::REGTEST);

        match reader.recv().await.unwrap() {
            NetworkMessage::Unknown { command, payload } => {
                assert_eq!(command.as_ref(), "addrv2");
                assert_eq!(payload, bad);
            }
            other => panic!("expected the frame as Unknown: {other:?}"),
        }
        assert!(matches!(
            reader.recv().await.unwrap(),
            NetworkMessage::Ping(7)
        ));
        assert_eq!(reader.undecodable(), 1);
    }

    /// A payload that does not match the checksum in its header is a
    /// different thing from one that will not parse, and is not treated as
    /// one: the bytes are corrupt, so the command naming them and the length
    /// that found where the frame ends are not to be trusted either.
    ///
    /// The frame below is a valid ping in every respect but its checksum, so
    /// nothing downstream could tell it from a real one -- and before this it
    /// came up as an unparseable `ping` and was counted as one.
    #[tokio::test]
    async fn test_v1_a_payload_that_fails_its_checksum_is_a_decode_fault() {
        let mut stream = frame(b"ping\0\0\0\0\0\0\0\0", &7u64.to_le_bytes());
        stream[20] ^= 0xff;
        stream.extend(serialize(&RawNetworkMessage::new(
            Magic::REGTEST,
            NetworkMessage::Ping(7),
        )));
        let mut reader = TransportV1Reader::new(&stream[..], Magic::REGTEST);

        let err = reader.recv().await.unwrap_err();
        assert_eq!(fault_of(&err), Some(Fault::Decode));
        assert_eq!(reader.undecodable(), 0, "corrupt is not unread");

        // And it stays failed: there is no boundary to resynchronise to, so
        // the frame that followed is not read either.
        let err = reader.recv().await.unwrap_err();
        assert_eq!(fault_of(&err), Some(Fault::Decode));
    }

    /// A frame whose command is not a command string still ends the session
    /// with a decode fault: nothing about it can be trusted.
    #[tokio::test]
    async fn test_v1_unreadable_command_is_a_decode_fault() {
        let stream = frame(b"\xff\xfe{versio\0\0\0", &[0xff]);
        let mut reader = TransportV1Reader::new(&stream[..], Magic::REGTEST);

        let err = reader.recv().await.unwrap_err();
        assert_eq!(fault_of(&err), Some(Fault::Decode));
        assert_eq!(reader.undecodable(), 0);
    }

    /// The v2 fallback names the command from the short id table or the
    /// spelled-out command, and gives up on anything outside both.
    #[test]
    fn test_v2_undecodable_names_the_command() {
        let unknown = |msg: Option<NetworkMessage>| match msg {
            Some(NetworkMessage::Unknown { command, payload }) => (command.to_string(), payload),
            other => panic!("expected Unknown: {other:?}"),
        };
        assert_eq!(
            unknown(v2_undecodable(&[28, 1, 2, 3])),
            ("addrv2".to_owned(), vec![1, 2, 3])
        );
        let mut spelled = vec![0u8];
        spelled.extend_from_slice(b"wtxidrelay\0\0");
        spelled.push(9);
        assert_eq!(
            unknown(v2_undecodable(&spelled)),
            ("wtxidrelay".to_owned(), vec![9])
        );

        assert!(v2_undecodable(&[]).is_none());
        assert!(v2_undecodable(&[29]).is_none());
        assert!(v2_undecodable(&[0, b'a']).is_none());
    }

    /// The short id table, held to the decoder that owns the same mapping
    /// rather than read over by eye.
    ///
    /// A command whose payload is a vector decodes from a single zero byte,
    /// and one with no payload from no bytes at all, so for those ids
    /// rust-bitcoin will say which command the id is. Nine of the twenty-eight
    /// answer today -- addrv2 among them, and it is the last entry, so an id
    /// inserted or dropped anywhere before it shifts one of the nine and fails
    /// here.
    #[test]
    fn test_the_short_id_table_agrees_with_the_decoder() {
        let mut checked = Vec::new();
        for id in 1..=SHORT_IDS.len() as u8 {
            // The two shapes a payload-free probe can take; an id the decoder
            // cannot answer for either way is left to the BIP.
            for probe in [vec![id], vec![id, 0x00]] {
                let Ok(decoded) = deserialize::<V2NetworkMessage>(&probe) else {
                    continue;
                };
                let Some(NetworkMessage::Unknown { command, .. }) = v2_undecodable(&probe) else {
                    panic!("short id {id} is not in the table");
                };
                assert_eq!(
                    command.to_string(),
                    decoded.into_payload().command().to_string(),
                    "short id {id}"
                );
                checked.push(id);
            }
        }
        // Without this the test would also pass if the decoder stopped
        // answering for anything at all.
        assert_eq!(checked, [1, 6, 7, 11, 13, 14, 15, 17, 28]);
    }

    /// A v1 header: magic, command, length, checksum. The magic and the length
    /// are the two fields read before the payload, which is what these tests
    /// are about; the checksum is not looked at until the body is in.
    fn header_declaring(payload_len: u32) -> Vec<u8> {
        let mut h = vec![0u8; 24];
        h[..4].copy_from_slice(&Magic::REGTEST.to_bytes());
        h[4..7].copy_from_slice(b"inv");
        h[16..20].copy_from_slice(&payload_len.to_le_bytes());
        h
    }

    /// The header does not get to choose how much memory we take: a declared
    /// payload over the limit is refused with nothing of it read, and the
    /// buffer it asked for is never allocated.
    #[tokio::test]
    async fn test_an_oversized_payload_is_refused_before_it_is_allocated() {
        let bytes = header_declaring(u32::MAX);
        let mut reader = TransportV1Reader::new(&bytes[..], Magic::REGTEST);
        let err = reader.recv().await.expect_err("an oversized declaration");
        assert_eq!(fault_of(&err), Some(Fault::Oversized), "{err:#}");
    }

    /// And it keeps failing that way. The payload was never consumed, so there
    /// is no boundary to resynchronise to, and a second call must not start
    /// reading payload bytes as the next header.
    #[tokio::test]
    async fn test_the_oversized_failure_sticks() {
        let mut bytes = header_declaring(MAX_V1_PAYLOAD as u32 + 1);
        bytes.extend_from_slice(&[0u8; 64]);
        let mut reader = TransportV1Reader::new(&bytes[..], Magic::REGTEST);
        for attempt in 0..3 {
            let err = reader.recv().await.expect_err("an oversized declaration");
            assert_eq!(fault_of(&err), Some(Fault::Oversized), "attempt {attempt}");
        }
    }

    /// A header that does not open with our magic ends the stream, whatever
    /// else it says. Nothing is decoded and the declared length is not even
    /// read: the bytes were never ours to read.
    #[tokio::test]
    async fn test_a_header_with_another_networks_magic_is_refused() {
        let mut bytes = header_declaring(32);
        bytes[..4].copy_from_slice(&Magic::BITCOIN.to_bytes());
        bytes.extend_from_slice(&[0u8; 32]);
        let mut reader = TransportV1Reader::new(&bytes[..], Magic::REGTEST);
        let err = reader.recv().await.expect_err("another network's magic");
        assert_eq!(fault_of(&err), Some(Fault::WrongMagic), "{err:#}");

        // And it keeps failing that way, for the reason an oversized header
        // does: the frame was never consumed, so there is nothing to
        // resynchronise to.
        for attempt in 0..2 {
            let err = reader.recv().await.expect_err("another network's magic");
            assert_eq!(fault_of(&err), Some(Fault::WrongMagic), "attempt {attempt}");
        }
    }

    /// The magic is checked before the length, so a frame that is wrong in
    /// both ways is reported as the one that makes the other meaningless.
    #[tokio::test]
    async fn test_the_magic_is_read_before_the_declared_length() {
        let mut bytes = header_declaring(u32::MAX);
        bytes[..4].copy_from_slice(&Magic::SIGNET.to_bytes());
        let mut reader = TransportV1Reader::new(&bytes[..], Magic::REGTEST);
        let err = reader.recv().await.expect_err("a header wrong twice over");
        assert_eq!(fault_of(&err), Some(Fault::WrongMagic), "{err:#}");
    }

    /// The limit is above every message a peer has reason to send, so an
    /// ordinary one still reads.
    #[tokio::test]
    async fn test_a_message_within_the_limit_still_reads() {
        let bytes = serialize(&RawNetworkMessage::new(
            Magic::REGTEST,
            NetworkMessage::Verack,
        ));
        let mut reader = TransportV1Reader::new(&bytes[..], Magic::REGTEST);
        let msg = reader.recv().await.expect("a verack");
        assert!(matches!(msg, NetworkMessage::Verack), "{msg:?}");
    }

    // ── Arbitrary bytes ──────────────────────────────────────────────────────
    //
    // The v1 reader is the first thing a peer's bytes reach, and the only one
    // of the two transports where a peer gets to choose the framing: a v2
    // packet that is not ours does not decrypt, while a v1 header is whatever
    // arrived. The cases above each name one way to be wrong. These say what
    // has to hold for every way at once.

    /// Deterministic, so a failure names the stream that produced it.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }

        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| (self.next() & 0xff) as u8).collect()
        }
    }

    /// A stream of frames, each wrong in a way the reader has to have an
    /// answer for: another network's magic, a command that is not a command
    /// string, a length that overruns the stream or the protocol's limit, a
    /// checksum that does not match, a payload that will not parse.
    ///
    /// Deliberately not uniform noise, which would fail at the magic every
    /// time and exercise one branch.
    fn arbitrary_stream(rng: &mut Rng) -> Vec<u8> {
        let mut out = Vec::new();
        for _ in 0..rng.below(4) + 1 {
            match rng.below(8) {
                0 => {
                    let n = rng.below(40) as usize + 1;
                    out.extend_from_slice(&rng.bytes(n));
                }
                _ => {
                    // A frame, with each field independently plausible or not.
                    let magic = if rng.below(4) == 0 {
                        rng.bytes(4)
                    } else {
                        Magic::REGTEST.to_bytes().to_vec()
                    };
                    let command: Vec<u8> = match rng.below(3) {
                        0 => rng.bytes(12),
                        1 => b"addrv2\0\0\0\0\0\0".to_vec(),
                        _ => b"ping\0\0\0\0\0\0\0\0".to_vec(),
                    };
                    let n = rng.below(24) as usize;
                    let payload = rng.bytes(n);
                    let declared: u32 = match rng.below(4) {
                        0 => u32::MAX,
                        1 => rng.next() as u32,
                        _ => payload.len() as u32,
                    };
                    let checksum = if rng.below(3) == 0 {
                        rng.bytes(4)
                    } else {
                        sha256d::Hash::hash(&payload).to_byte_array()[..4].to_vec()
                    };
                    out.extend_from_slice(&magic);
                    out.extend_from_slice(&command);
                    out.extend_from_slice(&declared.to_le_bytes());
                    out.extend_from_slice(&checksum);
                    out.extend_from_slice(&payload);
                }
            }
        }
        out
    }

    /// Whatever arrives, the reader either returns a message or fails with a
    /// fault that names what went wrong, and it does neither by panicking.
    ///
    /// The fault is the part worth asserting. An untyped error reaches the
    /// session as `DisconnectReason::OTHER`, which tells an operator watching
    /// a peer misbehave precisely nothing, and it is the one outcome here that
    /// no individual test would notice.
    #[tokio::test]
    async fn test_arbitrary_bytes_are_refused_by_name_and_never_panic() {
        let mut messages = 0u32;
        let mut faults = std::collections::BTreeSet::new();
        for seed in 0..2_000u64 {
            let mut rng = Rng(seed);
            let stream = arbitrary_stream(&mut rng);
            let mut reader = TransportV1Reader::new(&stream[..], Magic::REGTEST);

            // Until the first error: an error is terminal for a session, and
            // the oversized case deliberately stays failed, so reading past
            // one would spin.
            //
            // The bound is what says a frame always consumes something: a
            // reader that returned messages without advancing would hang here
            // rather than in production.
            for _ in 0..stream.len() + 1 {
                match reader.recv().await {
                    Ok(_) => messages += 1,
                    Err(err) => {
                        let fault = fault_of(&err);
                        assert!(
                            fault.is_some(),
                            "seed {seed}: an unnamed failure reaches an operator as OTHER: {err:#}"
                        );
                        faults.insert(format!("{:?}", fault.unwrap()));
                        break;
                    }
                }
            }
        }

        // The streams have to actually reach the interesting answers, or the
        // assertion above is about nothing.
        assert!(messages > 0, "no stream ever produced a message");
        for expected in [
            "WrongMagic",
            "Oversized",
            "Decode",
            "PeerClosed",
            "Truncated",
        ] {
            assert!(
                faults.contains(expected),
                "never reached {expected}: {faults:?}"
            );
        }
    }

    /// A payload of exactly the protocol's maximum is read, and one byte more
    /// is refused.
    ///
    /// The limit is the protocol's, not ours, so refusing a message at it
    /// would be refusing a legal message -- and the only test of the limit
    /// used a verack, four million bytes away from the boundary it was meant
    /// to be checking. Mutation testing is what pointed this out: turning the
    /// `>` into `>=` changed nothing any test could see.
    #[tokio::test]
    async fn test_a_payload_of_exactly_the_maximum_is_read() {
        let payload = vec![0x11u8; MAX_V1_PAYLOAD];
        let mut stream = frame(b"blah\0\0\0\0\0\0\0\0", &payload);
        assert_eq!(stream.len(), common::p2p::message::MAX_MSG_SIZE);
        let mut reader = TransportV1Reader::new(&stream[..], Magic::REGTEST);
        match reader.recv().await.expect("a message at the limit") {
            NetworkMessage::Unknown {
                command,
                payload: got,
            } => {
                assert_eq!(command.as_ref(), "blah");
                assert_eq!(got.len(), MAX_V1_PAYLOAD);
            }
            other => panic!("expected the frame as Unknown: {other:?}"),
        }

        // One byte more, declared and sent.
        stream = frame(b"blah\0\0\0\0\0\0\0\0", &vec![0x11u8; MAX_V1_PAYLOAD + 1]);
        let mut reader = TransportV1Reader::new(&stream[..], Magic::REGTEST);
        let err = reader.recv().await.unwrap_err();
        assert_eq!(fault_of(&err), Some(Fault::Oversized));
    }
    /// A v2 failure is named by what it was, so that a peer closing on us is
    /// not reported as a decryption failure or the other way round.
    ///
    /// Each arm is one line of a match with a guard on it, and a guard is
    /// exactly the sort of thing that reads as obviously right and is not
    /// covered by anything: mutation testing had this one both always true
    /// and always false with nothing failing.
    #[test]
    fn test_a_v2_failure_is_named_by_what_it_was() {
        use bip324::io::ProtocolError;

        // A peer that hangs up rather than speak v2. The kind is what says so,
        // and it is the kind the mapping turns on.
        let aborted = ProtocolError::from(Error::new(ErrorKind::ConnectionAborted, "closed"));
        assert_eq!(fault_of(&v2_fault(aborted)), Some(Fault::PeerClosed));

        // Any other transport failure is not that, and claiming it was would
        // put a peer's hang-up in the count of our own broken sockets.
        for kind in [
            ErrorKind::ConnectionReset,
            ErrorKind::UnexpectedEof,
            ErrorKind::TimedOut,
            ErrorKind::BrokenPipe,
        ] {
            let other = ProtocolError::from(Error::new(kind, "something else"));
            assert_eq!(fault_of(&v2_fault(other)), None, "{kind:?}");
        }
    }
}
