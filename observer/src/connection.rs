use bip324::{Role, futures::Protocol};
use common::{
    anyhow::{Context, Result},
    p2p::{
        Magic, ProtocolVersion, ServiceFlags, address,
        message::NetworkMessage,
        message_network::{self, UserAgent},
    },
    tokio::{io::BufReader, net::TcpStream},
    tracing,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::peer::{Peer, PeerV1, PeerV2};

pub const MAGIC: Magic = Magic::BITCOIN;
const USER_AGENT: &str = "/p2p-observer:0.1.0/";

pub async fn connect(addr: &str) -> Result<()> {
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
        Ok(proto) => {
            tracing::info!(addr, "v2 connection established");
            let mut peer = PeerV2 { proto };
            version_handshake(addr, &mut peer).await?;
            message_loop(addr, &mut peer).await?;
        }
        Err(e) => {
            tracing::warn!(addr, "v2 failed ({e}), trying v1");
            let stream = TcpStream::connect(addr)
                .await
                .context("TCP reconnect for v1")?;
            let (reader, writer) = stream.into_split();
            let mut peer = PeerV1 {
                reader: BufReader::new(reader),
                writer,
            };
            version_handshake(addr, &mut peer).await?;
            message_loop(addr, &mut peer).await?;
        }
    }
    Ok(())
}

async fn version_handshake(addr: &str, peer: &mut impl Peer) -> Result<()> {
    peer.send(build_version()).await?;

    let mut got_version = false;
    let mut got_verack = false;

    while !(got_version && got_verack) {
        match peer.recv().await? {
            NetworkMessage::Version(v) => {
                tracing::info!(
                    addr,
                    version = u32::from(v.version),
                    ua = v.user_agent.to_string(),
                    "received version"
                );
                peer.send(NetworkMessage::Verack).await?;
                got_version = true;
            }
            NetworkMessage::Verack => {
                tracing::info!(addr, "handshake complete");
                got_verack = true;
            }
            other => tracing::debug!(addr, "ignored during handshake: {:?}", other),
        }
    }
    Ok(())
}

async fn message_loop(addr: &str, peer: &mut impl Peer) -> Result<()> {
    loop {
        match peer.recv().await? {
            NetworkMessage::Ping(nonce) => {
                tracing::debug!(addr, nonce, "ping -> pong");
                peer.send(NetworkMessage::Pong(nonce)).await?;
            }
            other => tracing::info!(addr, "received: {:?}", other),
        }
    }
}

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
        // Since we don't accept inbound connections, we don't have to fear about
        // connecting to ourself. The peer likely won't use zero to a open connection
        // at the same time, so this should be fine.
        nonce: 0,
        user_agent: UserAgent::from_nonstandard(&USER_AGENT.to_string()),
        start_height: 0,
        relay: false,
    })
}
