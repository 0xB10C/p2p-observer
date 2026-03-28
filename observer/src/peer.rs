use bip324::{futures::Protocol, io::Payload};
use common::anyhow::{Context, Result};
use common::{
    bitcoin::consensus::{deserialize, serialize},
    p2p::{
        Magic,
        message::{NetworkMessage, RawNetworkMessage, V2NetworkMessage},
    },
    tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
};

pub trait Peer {
    async fn send(&mut self, msg: NetworkMessage) -> Result<()>;
    async fn recv(&mut self) -> Result<NetworkMessage>;
}

pub struct PeerV2<R, W> {
    pub proto: Protocol<R, W>,
}

pub struct PeerV1<R, W> {
    pub magic: Magic,
    pub reader: R,
    pub writer: W,
}

impl<R, W> Peer for PeerV2<R, W>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    async fn send(&mut self, msg: NetworkMessage) -> Result<()> {
        self.proto
            .write(&Payload::genuine(serialize(&V2NetworkMessage::new(msg))))
            .await
            .context("v2 write")
    }

    async fn recv(&mut self) -> Result<NetworkMessage> {
        let payload = self.proto.read().await.context("v2 read")?;
        let msg: V2NetworkMessage = deserialize(payload.contents()).context("v2 deserialize")?;
        Ok(msg.into_payload())
    }
}

impl<R, W> Peer for PeerV1<R, W>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    async fn send(&mut self, msg: NetworkMessage) -> Result<()> {
        self.writer
            .write_all(&serialize(&RawNetworkMessage::new(self.magic, msg)))
            .await
            .context("v1 write")
    }

    async fn recv(&mut self) -> Result<NetworkMessage> {
        // V1 header: magic(4) + command(12) + length(4) + checksum(4) = 24 bytes
        let mut header = [0u8; 24];
        self.reader
            .read_exact(&mut header)
            .await
            .context("v1 header read")?;
        let payload_len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;

        let mut buf = vec![0u8; 24 + payload_len];
        buf[..24].copy_from_slice(&header);
        self.reader
            .read_exact(&mut buf[24..])
            .await
            .context("v1 payload read")?;

        let raw: RawNetworkMessage = deserialize(&buf).context("v1 deserialize")?;
        Ok(raw.into_payload())
    }
}
