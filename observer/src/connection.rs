use bip324::{Role, futures::Protocol};
use common::{
    anyhow::{Context, Result},
    p2p::Magic,
    tokio::{
        self,
        io::BufReader,
        net::TcpStream,
        sync::mpsc,
        time::{Duration, sleep, timeout},
    },
    tracing,
    tracing::Instrument,
};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use crate::addresses::{NetAddr, StatusUpdate};
use crate::protocol::run_session;
use crate::transport::{TransportV1, TransportV2};

/// Initial wait before the first reconnect attempt after a failure.
/// Doubles on each consecutive failure, reset to this value after a successful connection.
const BACKOFF_BASE: Duration = Duration::from_secs(1);
/// How many consecutive failed connection attempts to make before giving up.
/// With BACKOFF_BASE doubling each attempt: 1s, 2s, 4s, 8s, 16s, 32s, 64s, 128s.
const MAX_RECONNECT_ATTEMPTS: u32 = 8;

/// Timeout for TCP connection attempts. The OS default (several minutes with SYN retransmits)
/// is far too long when managing many connections.
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// How many consecutive TCP timeouts to tolerate before giving up on a peer we have
/// never successfully connected to. Timeouts are a softer signal than ConnectionRefused
/// (the node might be firewalled), so we allow a small number of retries before giving up.
const MAX_TIMEOUT_ATTEMPTS_UNSEEN: u32 = 2;

static PEER_ID: AtomicU64 = AtomicU64::new(0);

pub async fn connect_with_retry(
    addr: NetAddr,
    magic: Magic,
    status_tx: mpsc::Sender<StatusUpdate>,
    new_addr_tx: mpsc::Sender<Vec<NetAddr>>,
) {
    let id = PEER_ID.fetch_add(1, Ordering::Relaxed);
    let span = tracing::info_span!("c", id, addr = %addr);

    async move {
        crate::ACTIVE_TASKS.fetch_add(1, Ordering::Relaxed);
        let Some(socket_addr) = addr.to_socket_addr() else {
            tracing::debug!("no TCP address, skipping");
            let _ = status_tx.send(StatusUpdate::TaskDone(addr)).await;
            crate::ACTIVE_TASKS.fetch_sub(1, Ordering::Relaxed);
            return;
        };
        retry_loop(&addr, socket_addr, magic, status_tx, new_addr_tx).await;
        crate::ACTIVE_TASKS.fetch_sub(1, Ordering::Relaxed);
    }
    .instrument(span)
    .await
}

async fn retry_loop(
    addr: &NetAddr,
    socket_addr: SocketAddr,
    magic: Magic,
    status_tx: mpsc::Sender<StatusUpdate>,
    new_addr_tx: mpsc::Sender<Vec<NetAddr>>,
) {
    let mut backoff = BACKOFF_BASE;
    let mut attempts = 0u32;
    let mut timeout_attempts = 0u32;
    let mut skip_v1_fallback = false;
    let mut ever_connected = false;

    loop {
        let result = try_connect(socket_addr, magic, &mut skip_v1_fallback, &new_addr_tx).await;

        attempts += 1;
        backoff *= 2;

        match result {
            Ok(connected_at) => {
                ever_connected = true;
                let uptime = connected_at.elapsed();
                // Only reset backoff if the connection was stable long enough — otherwise
                // a peer that immediately evicts us after the handshake would reset the
                // backoff on every attempt, causing a reconnect flood.
                if uptime > backoff {
                    backoff = BACKOFF_BASE;
                    attempts = 0;
                }
                let _ = status_tx
                    .send(StatusUpdate::LastSeen {
                        addr: addr.clone(),
                        at: unix_secs(),
                    })
                    .await;
                tracing::trace!(
                    uptime = format!("{:?}", uptime),
                    "connection lost. reconnecting in {backoff:.1?}"
                );
            }
            Err(e) => {
                if is_network_unreachable(&e) {
                    tracing::info!("network unreachable, not retrying");
                    let _ = status_tx
                        .send(StatusUpdate::NetworkUnreachable(addr.clone()))
                        .await;
                    break;
                }

                if is_timed_out(&e) {
                    timeout_attempts += 1;
                    if !ever_connected && timeout_attempts >= MAX_TIMEOUT_ATTEMPTS_UNSEEN {
                        tracing::info!(timeout_attempts, "timed out repeatedly, not retrying");
                        let _ = status_tx.send(StatusUpdate::TimedOut(addr.clone())).await;
                        break;
                    }
                } else {
                    timeout_attempts = 0;
                }

                if !ever_connected {
                    if is_connection_refused(&e) {
                        tracing::info!("connection refused on first attempt, not retrying");
                        let _ = status_tx
                            .send(StatusUpdate::ConnectionRefused(addr.clone()))
                            .await;
                        break;
                    } else if is_host_unreachable(&e) {
                        tracing::info!("host unreachable on first attempt, not retrying");
                        let _ = status_tx
                            .send(StatusUpdate::HostUnreachable(addr.clone()))
                            .await;
                        break;
                    }
                }

                tracing::trace!(
                    attempts,
                    backoff_ms = backoff.as_millis(),
                    error = format!("{:?}", e),
                    "failed to connect, retrying.."
                );
            }
        }

        if attempts >= MAX_RECONNECT_ATTEMPTS {
            tracing::info!(attempts, "giving up");
            if !ever_connected {
                let _ = status_tx.send(StatusUpdate::Offline(addr.clone())).await;
            }
            break;
        }

        sleep(backoff).await;
    }
    let _ = status_tx.send(StatusUpdate::TaskDone(addr.clone())).await;
}

/// Attempts a v2 connection, falling back to v1 on failure.
/// Once v2 has succeeded once, `skip_v1_fallback` is set and v1 is never tried again —
/// a peer is very unlikely to downgrade, and skipping the fallback avoids wasting an
/// attempt on a protocol the peer has already proven it doesn't need.
async fn try_connect(
    addr: SocketAddr,
    magic: Magic,
    skip_v1_fallback: &mut bool,
    new_addr_tx: &mpsc::Sender<Vec<NetAddr>>,
) -> Result<Instant> {
    if *skip_v1_fallback {
        return connect_v2(addr, magic, new_addr_tx).await;
    }
    match connect_v2(addr, magic, new_addr_tx).await {
        ok @ Ok(_) => {
            *skip_v1_fallback = true;
            ok
        }
        Err(e) => {
            // If we run into a TCP connection error, we don't need to
            // retry a v1 connection.
            if is_tcp_connect_error(&e) {
                return Err(e);
            }
            tracing::trace!("v2 failed ({e}), trying v1");
            connect_v1(addr, magic, new_addr_tx).await
        }
    }
}

async fn connect_v2(
    addr: SocketAddr,
    magic: Magic,
    new_addr_tx: &mpsc::Sender<Vec<NetAddr>>,
) -> Result<Instant> {
    tracing::trace!("connecting (v2) ...");
    let stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("TCP connect timeout")?
        .context("TCP connect")?;
    let (reader, writer) = stream.into_split();
    let proto = Protocol::new(
        magic,
        Role::Initiator,
        None,
        None,
        BufReader::new(reader),
        writer,
    )
    .await?;
    run_session(TransportV2 { proto }, 2, new_addr_tx).await
}

async fn connect_v1(
    addr: SocketAddr,
    magic: Magic,
    new_addr_tx: &mpsc::Sender<Vec<NetAddr>>,
) -> Result<Instant> {
    tracing::trace!("connecting (v1) ...");
    let stream = timeout(TCP_CONNECT_TIMEOUT, TcpStream::connect(addr))
        .await
        .context("TCP connect timeout")?
        .context("TCP connect")?;
    let (reader, writer) = stream.into_split();
    run_session(
        TransportV1 {
            magic,
            reader: BufReader::new(reader),
            writer,
        },
        1,
        new_addr_tx,
    )
    .await
}

// ── Error classification ──────────────────────────────────────────────────────

fn is_network_unreachable(err: &common::anyhow::Error) -> bool {
    has_io_error_kind(err, std::io::ErrorKind::NetworkUnreachable)
}

fn is_host_unreachable(err: &common::anyhow::Error) -> bool {
    has_io_error_kind(err, std::io::ErrorKind::HostUnreachable)
}

/// Returns true for TCP-level errors where retrying with a different transport
/// version (v1 vs v2) would not help.
fn is_tcp_connect_error(err: &common::anyhow::Error) -> bool {
    is_connection_refused(err)
        || is_network_unreachable(err)
        || is_host_unreachable(err)
        || is_timed_out(err)
}

fn is_connection_refused(err: &common::anyhow::Error) -> bool {
    has_io_error_kind(err, std::io::ErrorKind::ConnectionRefused)
}

fn is_timed_out(err: &common::anyhow::Error) -> bool {
    // Our explicit tokio::time::timeout fired.
    if err.chain().any(|c| c.is::<tokio::time::error::Elapsed>()) {
        return true;
    }
    // OS-level timeout (rare when our explicit timeout is shorter, but possible).
    has_io_error_kind(err, std::io::ErrorKind::TimedOut)
}

fn has_io_error_kind(err: &common::anyhow::Error, kind: std::io::ErrorKind) -> bool {
    err.chain().any(|cause| {
        cause
            .downcast_ref::<std::io::Error>()
            .is_some_and(|io_err| io_err.kind() == kind)
    })
}

fn unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::build_version;
    use crate::transport::{Transport, TransportV1, TransportV2};
    use bip324::{Role, futures::Protocol};
    use common::{
        p2p::message::NetworkMessage,
        tokio::{io::BufReader, net::TcpListener, sync::mpsc},
        tracing_subscriber,
    };

    /// Complete the server side of the version handshake.
    async fn server_handshake(transport: &mut impl Transport) {
        loop {
            if let NetworkMessage::Version(_) = transport.recv().await.unwrap() {
                break;
            }
        }
        transport.send(build_version()).await.unwrap();
        transport.send(NetworkMessage::Verack).await.unwrap();
        loop {
            if let NetworkMessage::Verack = transport.recv().await.unwrap() {
                break;
            }
        }
        loop {
            if let NetworkMessage::SendCmpct(_) = transport.recv().await.unwrap() {
                break;
            }
        }
    }

    const MAGIC: Magic = Magic::REGTEST;

    fn setup() {
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .try_init();
    }

    #[tokio::test]
    async fn test_v1_handshake_mock() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, writer) = stream.into_split();
            let mut transport = TransportV1 {
                magic: MAGIC,
                reader: BufReader::new(reader),
                writer,
            };
            server_handshake(&mut transport).await;
            // Drop → EOF → client message loop exits → connect_v1 returns Ok
        });

        let (tx, _rx) = mpsc::channel(1);
        let result = connect_v1(addr, MAGIC, &tx).await;
        server.await.unwrap();
        assert!(result.is_ok(), "connect_v1 failed: {result:?}");
    }

    #[tokio::test]
    async fn test_v2_handshake_mock() {
        setup();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (reader, writer) = stream.into_split();
            let proto = Protocol::new(
                MAGIC,
                Role::Responder,
                None,
                None,
                BufReader::new(reader),
                writer,
            )
            .await
            .unwrap();
            let mut transport = TransportV2 { proto };
            server_handshake(&mut transport).await;
        });

        let (tx, _rx) = mpsc::channel(1);
        let result = connect_v2(addr, MAGIC, &tx).await;
        server.await.unwrap();
        assert!(result.is_ok(), "connect_v2 failed: {result:?}");
    }
}
