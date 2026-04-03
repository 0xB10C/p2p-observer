use crate::TARGET_PROTOCOL as TARGET;
use bip324::io::Payload;
use common::anyhow::{Context, Result};
use common::{
    bitcoin::consensus::{deserialize, serialize},
    p2p::{
        Magic,
        message::{NetworkMessage, RawNetworkMessage, V2NetworkMessage},
    },
    tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    tracing,
};
use std::io::{Error, ErrorKind};

pub trait TransportReader {
    async fn recv(&mut self) -> Result<NetworkMessage>;
}

pub trait TransportWriter {
    async fn send(&mut self, msg: NetworkMessage) -> Result<()>;
}

// ── V2 (BIP324) ──────────────────────────────────────────────────────────────

pub struct TransportV2Reader<R> {
    pub reader: bip324::futures::ProtocolReader<R>,
}

pub struct TransportV2Writer<W> {
    pub writer: bip324::futures::ProtocolWriter<W>,
}

impl<R> TransportReader for TransportV2Reader<R>
where
    R: AsyncRead + Unpin + Send,
{
    async fn recv(&mut self) -> Result<NetworkMessage> {
        let payload = self.reader.read().await.context("v2 read")?;
        let contents = payload.contents();
        let msg: V2NetworkMessage = match deserialize(contents) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!(target: TARGET,
                    len = contents.len(),
                    hex = contents[..contents.len().min(64)].iter().map(|b| format!("{b:02x}")).collect::<String>(),
                    "v2 deserialize failed: {e:#}"
                );
                return Err(e).context("v2 deserialize");
            }
        };
        Ok(msg.into_payload())
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
            .context("v2 write")
    }
}

// ── V1 (plaintext) ───────────────────────────────────────────────────────────

/// Cancel-safe v1 reader. Buffers partial reads in `state` so that if the
/// future is dropped mid-read, the next call resumes from where it left off.
pub struct TransportV1Reader<R> {
    reader: R,
    state: V1ReadState,
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
    pub fn new(reader: R) -> Self {
        Self {
            reader,
            state: V1ReadState::Header {
                buf: [0u8; 24],
                pos: 0,
            },
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
                            return Err(Error::new(
                                ErrorKind::UnexpectedEof,
                                "EOF while trying to read v1 transport header",
                            )
                            .into());
                        }
                        *pos += n;
                    }
                    let header = *buf;
                    let payload_len =
                        u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;
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
                    return Err(Error::new(
                        ErrorKind::UnexpectedEof,
                        "EOF while trying to read v1 transport payload",
                    )
                    .into());
                }
                *pos += n;
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
                    // Reset state for the next message.
                    self.state = V1ReadState::Header {
                        buf: [0u8; 24],
                        pos: 0,
                    };
                    return Err(e).context("v1 deserialize");
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
            .context("v1 write")
    }
}
