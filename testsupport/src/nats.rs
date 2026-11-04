//! A real NATS server for the duration of a test.
//!
//! The tools talk to NATS over the wire and in-process fakes of it have a way
//! of agreeing with whatever the code does, so the tests run the real thing.
//! It is found through `NATS_SERVER_BINARY` (the nix shell sets it, and CI
//! sets it from the distribution package); without it the caller skips.

use std::process::{Child, Command, Stdio};
use std::time::Duration;

use common::tokio::net::TcpListener;
use common::{async_nats, tokio};

/// A `nats-server` child process, killed when this is dropped.
pub struct NatsServer {
    child: Child,
    url: String,
}

impl NatsServer {
    /// Starts a server on a free loopback port and waits for it to accept a
    /// client.
    ///
    /// `None` means the binary was not configured, which is the signal for a
    /// test to skip rather than fail: a checkout without it is a normal thing
    /// to develop in.
    pub async fn start() -> Option<Self> {
        let binary = std::env::var("NATS_SERVER_BINARY").ok()?;
        // Take a free port; the small window until nats-server binds it is
        // fine for a test.
        let port = TcpListener::bind("127.0.0.1:0")
            .await
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let child = Command::new(binary)
            .args(["-a", "127.0.0.1", "-p", &port.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawning nats-server");
        // Wrapped first so the process is killed on every path, including
        // the panic below.
        let server = NatsServer {
            child,
            url: format!("nats://127.0.0.1:{port}"),
        };
        for _ in 0..50 {
            if async_nats::connect(&server.url).await.is_ok() {
                return Some(server);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        panic!("nats-server did not come up on {}", server.url);
    }

    /// The URL to hand to anything that should talk to this server.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// A client connected to this server.
    pub async fn client(&self) -> async_nats::Client {
        async_nats::connect(&self.url)
            .await
            .expect("connecting to the test NATS server")
    }
}

impl Drop for NatsServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
