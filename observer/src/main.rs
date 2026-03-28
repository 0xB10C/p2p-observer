use anyhow::{Context, Result};
use bip324::{Role, futures::Protocol, io::Payload};
use common::{
    anyhow,
    bitcoin::consensus::{deserialize, serialize},
    p2p::{
        Magic, ProtocolVersion, ServiceFlags, address,
        message::{NetworkMessage, RawNetworkMessage, V2NetworkMessage},
        message_network::{self, UserAgent},
    },
    tokio,
    tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader},
    tokio::net::TcpStream,
    tracing, tracing_subscriber,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

const USER_AGENT: &str = "/p2p-observer:0.1.0/";
const MAGIC: Magic = Magic::BITCOIN;

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let peers = ["95.217.75.216:8333"];

    let handles: Vec<_> = peers
        .iter()
        .map(|&peer| {
            tokio::spawn(async move {
                if let Err(e) = connect_peer(peer).await {
                    tracing::error!(peer, "connection failed: {e:#}");
                }
            })
        })
        .collect();

    for h in handles {
        let _ = h.await;
    }
}

async fn connect_peer(addr: &str) -> Result<()> {
    tracing::info!(addr, "connecting");
    let stream = TcpStream::connect(addr).await.context("TCP connect")?;
    let (reader, writer) = stream.into_split();

    match Protocol::new(
        MAGIC,
        Role::Initiator,
        None,
        None,
        BufReader::new(reader),
        writer,
    )
    .await
    {
        Ok(mut proto) => {
            tracing::info!(addr, "v2 connection established");
            v2_handshake(addr, &mut proto).await?;
            v2_loop(addr, &mut proto).await?;
        }
        Err(e) => {
            tracing::warn!(addr, "v2 failed ({e}), trying v1");
            let stream = TcpStream::connect(addr)
                .await
                .context("TCP reconnect for v1")?;
            let (reader, writer) = stream.into_split();
            let mut r = BufReader::new(reader);
            let mut w = writer;
            v1_handshake(addr, &mut r, &mut w).await?;
            v1_loop(addr, &mut r, &mut w).await?;
        }
    }
    Ok(())
}

// ── V2 ───────────────────────────────────────────────────────────────────────

async fn v2_send<R, W>(proto: &mut Protocol<R, W>, msg: NetworkMessage) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    proto
        .write(&Payload::genuine(serialize(&V2NetworkMessage::new(msg))))
        .await
        .context("v2 write")
}

async fn v2_handshake<R, W>(addr: &str, proto: &mut Protocol<R, W>) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    v2_send(proto, build_version()).await?;

    loop {
        let payload = proto.read().await.context("v2 read")?;
        let msg: V2NetworkMessage = deserialize(payload.contents()).context("v2 deserialize")?;
        match msg.payload() {
            NetworkMessage::Version(v) => {
                tracing::info!(
                    addr,
                    version = u32::from(v.version),
                    ua = v.user_agent.to_string(),
                    "received version"
                );
                v2_send(proto, NetworkMessage::Verack).await?;
            }
            NetworkMessage::Verack => {
                tracing::info!(addr, "v2 handshake complete");
                return Ok(());
            }
            other => tracing::debug!(addr, "ignored during handshake: {:?}", other),
        }
    }
}

async fn v2_loop<R, W>(addr: &str, proto: &mut Protocol<R, W>) -> Result<()>
where
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send,
{
    loop {
        let payload = proto.read().await.context("v2 read")?;
        let msg: V2NetworkMessage = deserialize(payload.contents()).context("v2 deserialize")?;
        match msg.payload() {
            NetworkMessage::Ping(nonce) => {
                let nonce = *nonce;
                tracing::debug!(addr, nonce, "ping -> pong");
                v2_send(proto, NetworkMessage::Pong(nonce)).await?;
            }
            other => tracing::info!(addr, "received: {:?}", other),
        }
    }
}

// ── V1 ───────────────────────────────────────────────────────────────────────

async fn v1_send<W: AsyncWrite + Unpin>(writer: &mut W, msg: NetworkMessage) -> Result<()> {
    let raw = RawNetworkMessage::new(MAGIC, msg);
    writer.write_all(&serialize(&raw)).await.context("v1 write")
}

async fn v1_recv<R: AsyncRead + Unpin>(reader: &mut R) -> Result<RawNetworkMessage> {
    // V1 header: magic(4) + command(12) + length(4) + checksum(4) = 24 bytes
    let mut header = [0u8; 24];
    reader
        .read_exact(&mut header)
        .await
        .context("v1 header read")?;
    let payload_len = u32::from_le_bytes(header[16..20].try_into().unwrap()) as usize;

    let mut buf = vec![0u8; 24 + payload_len];
    buf[..24].copy_from_slice(&header);
    reader
        .read_exact(&mut buf[24..])
        .await
        .context("v1 payload read")?;

    deserialize(&buf).context("v1 deserialize")
}

async fn v1_handshake<R, W>(addr: &str, reader: &mut R, writer: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    v1_send(writer, build_version()).await?;

    let mut got_version = false;
    let mut got_verack = false;

    while !(got_version && got_verack) {
        let raw = v1_recv(reader).await?;
        match raw.payload() {
            NetworkMessage::Version(v) => {
                tracing::debug!(addr, version = u32::from(v.version), "received version");
                v1_send(writer, NetworkMessage::Verack).await?;
                got_version = true;
            }
            NetworkMessage::Verack => {
                tracing::info!(addr, "v1 handshake complete");
                got_verack = true;
            }
            other => tracing::debug!(addr, "ignored during handshake: {:?}", other),
        }
    }
    Ok(())
}

async fn v1_loop<R, W>(addr: &str, reader: &mut R, writer: &mut W) -> Result<()>
where
    R: AsyncRead + Unpin,
    W: AsyncWrite + Unpin,
{
    loop {
        let raw = v1_recv(reader).await?;
        match raw.payload() {
            NetworkMessage::Ping(nonce) => {
                let nonce = *nonce;
                tracing::debug!(addr, nonce, "ping -> pong");
                v1_send(writer, NetworkMessage::Pong(nonce)).await?;
            }
            other => tracing::info!(addr, "received: {:?}", other),
        }
    }
}

// ── Shared ───────────────────────────────────────────────────────────────────

fn build_version() -> NetworkMessage {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time before unix epoch")
        .as_secs() as i64;

    NetworkMessage::Version(message_network::VersionMessage {
        version: ProtocolVersion::WTXID_RELAY_VERSION,
        services: ServiceFlags::NETWORK | ServiceFlags::WITNESS,
        timestamp,
        receiver: address::Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            ServiceFlags::NONE,
        ),
        sender: address::Address::new(
            &SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
            ServiceFlags::NONE,
        ),
        nonce: 0,
        user_agent: UserAgent::from_nonstandard(&USER_AGENT.to_string()),
        start_height: 0,
        relay: false,
    })
}
