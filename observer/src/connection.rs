use bip324::{Role, futures::Protocol};
use common::{
    anyhow::{Context, Result},
    p2p::{
        Magic, ProtocolVersion, ServiceFlags, address,
        message::NetworkMessage,
        message_network::{self, UserAgent},
    },
    tokio::{
        self,
        io::BufReader,
        net::TcpStream,
        time::{Duration, interval, sleep},
    },
    tracing,
    tracing::Instrument,
};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::peer::{Peer, PeerV1, PeerV2};

pub(crate) const MAGIC: Magic = Magic::BITCOIN;
const USER_AGENT: &str = "/p2p-observer:0.1.0/";

/// Initial wait before the first reconnect attempt after a failure.
/// Doubles on each consecutive failure, reset to this value after a successful connection.
const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// How many consecutive failed connection attempts to make before giving up.
/// With BACKOFF_BASE doubling each attempt: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s.
const MAX_RECONNECT_ATTEMPTS: u32 = 8;

/// How often to send a ping to measure round-trip time.
const PING_INTERVAL: Duration = Duration::from_secs(10);

static PEER_ID: AtomicU64 = AtomicU64::new(0);

pub async fn connect_with_retry(addr: &str) {
    let id = PEER_ID.fetch_add(1, Ordering::Relaxed);
    let span = tracing::info_span!("peer", id, addr);
    retry_loop(addr).instrument(span).await
}

async fn retry_loop(addr: &str) {
    let mut backoff = BACKOFF_BASE;
    let mut attempts = 0u32;
    let mut skip_v1_fallback = false;

    loop {
        let result = try_connect(addr, &mut skip_v1_fallback).await;

        attempts += 1;
        backoff *= 2;

        match result {
            Ok(connected_at) => {
                let uptime = connected_at.elapsed();
                // Only reset backoff if the connection was stable long enough — otherwise
                // a peer that immediately evicts us after the handshake would reset the
                // backoff on every attempt, causing a reconnect flood.
                if uptime > backoff {
                    backoff = BACKOFF_BASE;
                    attempts = 0;
                }
                tracing::warn!("connection lost after {uptime:.1?}, reconnecting in {backoff:.1?}");
            }
            Err(e) => {
                tracing::warn!(
                    attempts,
                    "failed to connect ({e:#}), retrying in {backoff:.1?}"
                );
            }
        }

        if attempts >= MAX_RECONNECT_ATTEMPTS {
            tracing::error!("giving up after {attempts} attempts");
            return;
        }

        sleep(backoff).await;
    }
}

/// Attempts a v2 connection, falling back to v1 on failure.
/// Once v2 has succeeded once, `skip_v1_fallback` is set and v1 is never tried again —
/// a peer is very unlikely to downgrade, and skipping the fallback avoids wasting an
/// attempt on a protocol the peer has already proven it doesn't need.
async fn try_connect(addr: &str, skip_v1_fallback: &mut bool) -> Result<Instant> {
    if *skip_v1_fallback {
        return connect_v2(addr).await;
    }
    match connect_v2(addr).await {
        ok @ Ok(_) => {
            *skip_v1_fallback = true;
            ok
        }
        Err(e) => {
            tracing::warn!("v2 failed ({e}), trying v1");
            connect_v1(addr).await
        }
    }
}

/// Returns the `Instant` at which the version handshake completed, once the connection drops.
async fn connect_v2(addr: &str) -> Result<Instant> {
    tracing::info!("connecting (v2) ...");
    let stream = TcpStream::connect(addr).await.context("TCP connect")?;
    let (reader, writer) = stream.into_split();
    let proto = Protocol::new(
        MAGIC,
        Role::Initiator,
        None,
        None,
        BufReader::new(reader),
        writer,
    )
    .await?;
    let mut peer = PeerV2 { proto };

    version_handshake(&mut peer).await?;
    let connected_at = Instant::now();

    tracing::info!("v2 connection established");
    if let Err(e) = message_loop(&mut peer).await {
        tracing::debug!("v2 connection error: {e}");
    }
    Ok(connected_at)
}

/// Returns the `Instant` at which the version handshake completed, once the connection drops.
async fn connect_v1(addr: &str) -> Result<Instant> {
    tracing::info!("connecting (v1) ...");
    let stream = TcpStream::connect(addr).await.context("TCP connect")?;
    let (reader, writer) = stream.into_split();
    let mut peer = PeerV1 {
        reader: BufReader::new(reader),
        writer,
    };

    version_handshake(&mut peer).await?;
    let connected_at = Instant::now();

    tracing::info!("v1 connection established");
    if let Err(e) = message_loop(&mut peer).await {
        tracing::debug!("v1 connection error: {e}");
    }
    Ok(connected_at)
}

async fn version_handshake(peer: &mut impl Peer) -> Result<()> {
    peer.send(build_version()).await?;

    let mut got_version = false;
    let mut got_verack = false;

    while !(got_version && got_verack) {
        match peer.recv().await? {
            NetworkMessage::Version(v) => {
                tracing::info!(
                    version = u32::from(v.version),
                    ua = v.user_agent.to_string(),
                    "received version"
                );
                peer.send(NetworkMessage::Verack).await?;
                got_version = true;
            }
            NetworkMessage::Verack => {
                tracing::info!("handshake complete");
                got_verack = true;
            }
            other => tracing::debug!("ignored during handshake: {:?}", other),
        }
    }
    Ok(())
}

async fn message_loop(peer: &mut impl Peer) -> Result<()> {
    let mut ping_timer = interval(PING_INTERVAL);
    ping_timer.tick().await; // skip the immediate first tick

    // Note: peer.recv() is not cancel-safe — if the ping timer fires while a read_exact
    // is mid-header, the partial bytes are lost. In practice this is rare and the worst
    // outcome is a parse error and reconnect, which is acceptable for an observer.
    loop {
        tokio::select! {
            _ = ping_timer.tick() => send_ping(peer).await?,
            msg = peer.recv() => handle_message(peer, msg?).await?,
        }
    }
}

async fn send_ping(peer: &mut impl Peer) -> Result<()> {
    let nonce = unix_ms();
    tracing::debug!(ts_ms = nonce, "sending ping");
    peer.send(NetworkMessage::Ping(nonce)).await
}

async fn handle_message(peer: &mut impl Peer, msg: NetworkMessage) -> Result<()> {
    match msg {
        NetworkMessage::Ping(nonce) => handle_ping(peer, nonce).await?,
        NetworkMessage::Pong(nonce) => handle_pong(nonce),
        other => tracing::trace!("received: {:?}", other),
    }
    Ok(())
}

async fn handle_ping(peer: &mut impl Peer, nonce: u64) -> Result<()> {
    tracing::debug!(nonce, "ping -> pong");
    peer.send(NetworkMessage::Pong(nonce)).await
}

fn handle_pong(nonce: u64) {
    let rtt_ms = unix_ms().saturating_sub(nonce);
    tracing::info!(rtt_ms, "pong");
}

fn unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
        // connecting to ourself. The peer likely won't use zero to open a connection
        // at the same time, so this should be fine.
        nonce: 0,
        user_agent: UserAgent::from_nonstandard(USER_AGENT),
        start_height: 0,
        relay: false,
    })
}
