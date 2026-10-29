//! The HTTP side: a server that answers `GET /metrics` with the registry in
//! the Prometheus text format, and nothing else.
//!
//! Hand-rolled on a TCP listener rather than pulled from an HTTP crate. A
//! scrape is one request on a fresh connection and the reply is one body, so
//! the whole of HTTP needed here is: read the request line, write a status
//! line, some headers and the body, close. An HTTP stack would be most of
//! the tool's dependencies for that.

use std::time::Duration;

use common::anyhow::{Context, Result, bail};
use common::tokio::io::{AsyncReadExt, AsyncWriteExt};
use common::tokio::net::{TcpListener, TcpStream};
use common::tokio::time::timeout;
use common::{tokio, tracing};
use prometheus::{Encoder, Registry, TextEncoder};

use crate::TARGET;

/// A scraper that has not finished its request head by then is not one.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Longest request head read; a scrape's is a few hundred bytes.
const MAX_HEAD: usize = 8 * 1024;
/// How long a scrape gets to take the reply.
const RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);

/// Accepts connections forever, one task per request.
pub async fn serve(listener: TcpListener, registry: Registry) {
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(accepted) => accepted,
            Err(e) => {
                // Out of file descriptors, most likely; nothing to do but
                // not spin.
                tracing::warn!(target: TARGET, error = %e, "accepting a connection");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = respond(stream, &registry).await {
                tracing::debug!(target: TARGET, %peer, error = %e, "request not served");
            }
        });
    }
}

async fn respond(mut stream: TcpStream, registry: &Registry) -> Result<()> {
    let head = timeout(REQUEST_TIMEOUT, read_head(&mut stream))
        .await
        .context("reading the request")??;
    let response = match request_path(&head) {
        Some("/metrics") | Some("/") => {
            let body = encode(registry)?;
            http_response(200, "OK", "text/plain; version=0.0.4; charset=utf-8", &body)
        }
        _ => http_response(404, "Not Found", "text/plain", b"metrics are at /metrics\n"),
    };
    timeout(RESPONSE_TIMEOUT, async {
        stream.write_all(&response).await?;
        stream.shutdown().await
    })
    .await
    .context("writing the response")??;
    Ok(())
}

/// Reads up to the end of the request head. Only the request line is looked
/// at, but the head is read whole so the client is not met with a reply
/// while still sending.
async fn read_head(stream: &mut TcpStream) -> Result<String> {
    let mut head = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        let n = stream.read(&mut chunk).await?;
        if n == 0 {
            bail!("connection closed before the request head ended");
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") {
            break;
        }
        if head.len() > MAX_HEAD {
            bail!("request head longer than {MAX_HEAD} bytes");
        }
    }
    Ok(String::from_utf8_lossy(&head).into_owned())
}

/// The path of the request line, without any query string. `None` when the
/// line is not `METHOD path VERSION`.
pub fn request_path(head: &str) -> Option<&str> {
    let line = head.lines().next()?;
    let mut parts = line.split_ascii_whitespace();
    let _method = parts.next()?;
    let target = parts.next()?;
    parts.next()?;
    Some(target.split('?').next().unwrap_or(target))
}

/// The registry in the text exposition format.
pub fn encode(registry: &Registry) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    TextEncoder::new()
        .encode(&registry.gather(), &mut body)
        .context("encoding the metrics")?;
    Ok(body)
}

fn http_response(status: u16, reason: &str, content_type: &str, body: &[u8]) -> Vec<u8> {
    let mut response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {content_type}\r\n\
         Content-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response.extend_from_slice(body);
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_path_is_the_second_token_without_the_query() {
        assert_eq!(
            request_path("GET /metrics HTTP/1.1\r\nHost: x\r\n\r\n"),
            Some("/metrics")
        );
        assert_eq!(
            request_path("GET /metrics?x=1 HTTP/1.0\r\n"),
            Some("/metrics")
        );
        assert_eq!(request_path("GET / HTTP/1.1\r\n"), Some("/"));
    }

    #[test]
    fn test_a_malformed_request_line_has_no_path() {
        assert_eq!(request_path(""), None);
        assert_eq!(request_path("GET\r\n"), None);
        assert_eq!(request_path("GET /metrics\r\n"), None);
    }

    #[test]
    fn test_response_has_the_body_length() {
        let response = http_response(200, "OK", "text/plain", b"abc");
        let text = String::from_utf8(response).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 3\r\n"));
        assert!(text.ends_with("\r\n\r\nabc"));
    }
}
