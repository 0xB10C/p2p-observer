//! NATS request/reply interface.
//!
//! Every address query and mutation goes through the manager's command
//! channel. The handler holds no address state and takes no locks: it turns a
//! NATS message into a command, waits for the reply, and renders it as JSON.
//! The previous version reached into the shared address store behind a mutex,
//! which meant an RPC could block the connect loop.

use std::sync::{Arc, RwLock};

use crate::TARGET_RPC as TARGET;
use common::{async_nats, futures_util::StreamExt, serde_json, tracing};

use crate::addresses::banlist::BanEntry;
use crate::addresses::key::AddrKey;
use crate::addresses::{Handle, policy::Class};
use crate::headertree::{ChainTipStatus, HeaderTree};

pub(crate) struct Rpc {
    nats: async_nats::Client,
    network: String,
    handler: Handler,
}

struct Handler {
    addrman: Handle,
    header_tree: Arc<RwLock<HeaderTree>>,
}

impl Rpc {
    pub(crate) fn new(
        nats: async_nats::Client,
        network: &str,
        addrman: Handle,
        header_tree: Arc<RwLock<HeaderTree>>,
    ) -> Self {
        Self {
            nats,
            network: network.to_owned(),
            handler: Handler {
                addrman,
                header_tree,
            },
        }
    }

    fn prefix(&self) -> String {
        format!("p2p-observer.{}.rpc", self.network)
    }

    pub(crate) async fn run(self) {
        let prefix = self.prefix();
        let mut sub = self
            .nats
            .subscribe(format!("{prefix}.>"))
            .await
            .expect("failed to subscribe to RPC subjects");

        tracing::info!(target: TARGET, prefix, "listening for RPC requests");

        while let Some(msg) = sub.next().await {
            let method = msg
                .subject
                .strip_prefix(&prefix)
                .and_then(|s| s.strip_prefix('.'));

            let reply = self.handler.dispatch(method, &msg.payload).await;

            if let Some(reply_to) = msg.reply
                && let Err(e) = self.nats.publish(reply_to, reply.into()).await
            {
                tracing::warn!(target: TARGET, "failed to send RPC reply: {e}");
            }
        }
    }
}

/// The manager is gone, which only happens during shutdown.
const GONE: &str = "address manager unavailable";

impl Handler {
    async fn dispatch(&self, method: Option<&str>, payload: &[u8]) -> String {
        let result = match method {
            Some("addresses.add") => self.add_addresses(payload).await,
            Some("addresses.info") => self.addresses_info().await,
            Some("addresses.inspect") => self.inspect(payload).await,
            Some("addresses.due") => self.due_next(payload).await,
            Some("headertree.tips") => self.chain_tips(),
            Some("banlist.add") => self.ban_add(payload).await,
            Some("banlist.list") => self.ban_list().await,
            Some(other) => Err(format!("unknown method: {other}")),
            None => Err("malformed subject".to_owned()),
        };
        match result {
            Ok(value) => value,
            Err(e) => serde_json::json!({ "error": e }).to_string(),
        }
    }

    async fn addresses_info(&self) -> Result<String, String> {
        let s = self.addrman.stats().await.ok_or(GONE)?;
        Ok(serde_json::json!({
            "total": s.total,
            "unknown": s.unknown,
            "good": s.good,
            "lapsed": s.lapsed,
            "bad": s.bad,
            "dialing": s.dialing,
            "connected": s.connected,
        })
        .to_string())
    }

    async fn add_addresses(&self, payload: &[u8]) -> Result<String, String> {
        let addrs: Vec<String> =
            serde_json::from_slice(payload).map_err(|e| format!("invalid JSON: {e}"))?;

        let mut keys = Vec::with_capacity(addrs.len());
        let mut rejected = Vec::new();
        for s in &addrs {
            match AddrKey::parse_ip(s) {
                Some(key) => keys.push(key),
                None => rejected.push(s.clone()),
            }
        }

        let added = self.addrman.add_manual(keys).await.ok_or(GONE)?;
        tracing::info!(target: TARGET, received = addrs.len(), added, "addresses.add");
        Ok(serde_json::json!({ "added": added, "rejected": rejected }).to_string())
    }

    async fn inspect(&self, payload: &[u8]) -> Result<String, String> {
        let addr: String =
            serde_json::from_slice(payload).map_err(|e| format!("invalid JSON: {e}"))?;
        let key = AddrKey::parse_ip(&addr).ok_or_else(|| format!("unparseable address: {addr}"))?;

        let entry = self.addrman.inspect(key).await.ok_or(GONE)?;
        Ok(match entry {
            None => serde_json::json!(null).to_string(),
            Some(e) => serde_json::json!({
                "addr": key.to_string(),
                "class": class_name(e.class()),
                "services": e.services,
                "ntime": e.ntime,
                "last_announced": e.last_announced,
                "last_attempt": e.last_attempt,
                "last_success": e.last_success,
                "next_attempt": e.next_attempt,
                "failures": e.failures,
                "short_sessions": e.short_sessions,
                "origin": format!("{:?}", e.origin),
                "transport": format!("{:?}", e.transport),
            })
            .to_string(),
        })
    }

    async fn due_next(&self, payload: &[u8]) -> Result<String, String> {
        // An empty payload means "use the default".
        let limit: usize = if payload.is_empty() {
            20
        } else {
            serde_json::from_slice(payload).map_err(|e| format!("invalid JSON: {e}"))?
        };

        let due = self.addrman.due_next(limit).await.ok_or(GONE)?;
        let json: Vec<_> = due
            .iter()
            .map(|(key, at)| serde_json::json!({ "addr": key.to_string(), "next_attempt": at }))
            .collect();
        Ok(serde_json::to_string(&json).unwrap())
    }

    async fn ban_add(&self, payload: &[u8]) -> Result<String, String> {
        let entries: Vec<BanEntry> =
            serde_json::from_slice(payload).map_err(|e| format!("invalid JSON: {e}"))?;

        let mut added = 0;
        let mut purged = 0;
        let mut save_error = None;
        for entry in entries {
            let result = self.addrman.ban(entry).await.ok_or(GONE)?;
            added += result.added;
            purged += result.purged;
            save_error = save_error.or(result.save_error);
        }
        tracing::info!(target: TARGET, added, purged, "banlist.add");

        let mut out = serde_json::json!({ "added": added, "purged": purged });
        // The ban is in effect either way; the caller needs to know if it will
        // not survive a restart.
        if let Some(e) = save_error {
            out["save_error"] = serde_json::Value::String(e);
        }
        Ok(out.to_string())
    }

    async fn ban_list(&self) -> Result<String, String> {
        let entries = self.addrman.ban_list().await.ok_or(GONE)?;
        Ok(serde_json::to_string(&entries).unwrap())
    }

    fn chain_tips(&self) -> Result<String, String> {
        let tree = self.header_tree.read().unwrap();
        let mut tips = tree.chain_tips();
        // Deterministic order: active tip first, then descending by height.
        tips.sort_by(|a, b| {
            b.branch_len
                .cmp(&a.branch_len)
                .then(b.height.cmp(&a.height))
        });
        let json: Vec<_> = tips
            .iter()
            .map(|t| {
                serde_json::json!({
                    "height": t.height,
                    "hash": t.hash.to_string(),
                    "branch_len": t.branch_len,
                    "status": match t.status {
                        ChainTipStatus::Active => "active",
                        ChainTipStatus::HeadersOnly => "headers-only",
                    },
                })
            })
            .collect();
        Ok(serde_json::to_string(&json).unwrap())
    }
}

fn class_name(class: Class) -> &'static str {
    match class {
        Class::Unknown => "unknown",
        Class::Good => "good",
        Class::Lapsed => "lapsed",
        Class::Bad => "bad",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addresses::table::{EnabledNets, Gossiped};
    use crate::addresses::{self, Dialer, table::Dial};
    use common::bitcoin::{Network, network::Params};
    use common::tokio;

    /// The handler is exercised against a real manager task rather than a
    /// stub, so the command channel is part of what is under test.
    struct NullDialer;
    impl Dialer for NullDialer {
        fn dial(&self, _dial: Dial) {}
    }

    /// Keeps the manager task and its shutdown sender alive for the whole
    /// test, and cleans the temp directory up afterwards.
    ///
    /// Holding the sender matters: `Manager::run` treats a resolved shutdown
    /// oneshot as a signal to stop, and a dropped sender resolves it. Letting
    /// it fall out of scope at the end of the setup function shut the manager
    /// down before any test body ran.
    struct TestManager {
        task: tokio::task::JoinHandle<()>,
        _shutdown: tokio::sync::oneshot::Sender<()>,
        dir: std::path::PathBuf,
    }

    impl Drop for TestManager {
        fn drop(&mut self) {
            self.task.abort();
            std::fs::remove_dir_all(&self.dir).ok();
        }
    }

    fn handler_with_manager(tag: &str) -> (Handler, TestManager) {
        let dir =
            std::env::temp_dir().join(format!("p2p-observer-rpc-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let (handle, gossip_rx, life_rx, cmd_rx) = addresses::channels();
        let mut manager = addresses::Manager::new(
            addresses::Config {
                // Nothing is dialled in these tests.
                dials_per_tick: 0,
                max_dialing: 0,
                capacity: 1000,
                nets: EnabledNets::all(),
                snapshot_path: dir.join("addresses.bin"),
                banlist_path: dir.join("banlist.json"),
            },
            NullDialer,
        )
        .unwrap();

        manager.ingest_for_test(
            1000,
            &[
                Gossiped {
                    key: AddrKey::parse_ip("1.2.3.4:8333").unwrap(),
                    services: 9,
                    ntime: 900,
                },
                Gossiped {
                    key: AddrKey::parse_ip("5.6.7.8:8333").unwrap(),
                    services: 0,
                    ntime: 900,
                },
            ],
        );

        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(manager.run(gossip_rx, life_rx, cmd_rx, shutdown_rx));

        let header_tree = Arc::new(RwLock::new(HeaderTree::new(Params::new(Network::Regtest))));
        (
            Handler {
                addrman: handle,
                header_tree,
            },
            TestManager {
                task,
                _shutdown: shutdown_tx,
                dir,
            },
        )
    }

    #[tokio::test]
    async fn test_addresses_info() {
        let (h, _mgr) = handler_with_manager("info");

        let response = h.dispatch(Some("addresses.info"), b"").await;
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["total"], 2);
        assert_eq!(v["unknown"], 2);
        assert_eq!(v["good"], 0);
        assert_eq!(v["connected"], 0);
    }

    #[tokio::test]
    async fn test_add_addresses_reports_rejects() {
        let (h, _mgr) = handler_with_manager("add");

        let payload = serde_json::to_vec(&["9.9.9.9:8333", "not-an-address"]).unwrap();
        let response = h.dispatch(Some("addresses.add"), &payload).await;
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["added"], 1);
        // Unparseable input is reported rather than silently dropped, which is
        // what the old handler's filter_map did.
        assert_eq!(v["rejected"], serde_json::json!(["not-an-address"]));
    }

    #[tokio::test]
    async fn test_inspect() {
        let (h, _mgr) = handler_with_manager("inspect");

        let payload = serde_json::to_vec("1.2.3.4:8333").unwrap();
        let response = h.dispatch(Some("addresses.inspect"), &payload).await;
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["addr"], "1.2.3.4:8333");
        assert_eq!(v["class"], "unknown");
        assert_eq!(v["services"], 9);

        // An address we have never heard of is null, not an error.
        let payload = serde_json::to_vec("9.9.9.9:1").unwrap();
        assert_eq!(
            h.dispatch(Some("addresses.inspect"), &payload).await,
            "null"
        );
    }

    #[tokio::test]
    async fn test_due_next() {
        let (h, _mgr) = handler_with_manager("due");

        // An empty payload uses the default limit.
        let response = h.dispatch(Some("addresses.due"), b"").await;
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 2);

        let payload = serde_json::to_vec(&1usize).unwrap();
        let response = h.dispatch(Some("addresses.due"), &payload).await;
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v.as_array().unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_ban_add_purges() {
        let (h, _mgr) = handler_with_manager("ban");

        let payload = serde_json::to_vec(&[serde_json::json!({
            "comment": "spam",
            "nets": ["1.2.3.0/24"]
        })])
        .unwrap();
        let response = h.dispatch(Some("banlist.add"), &payload).await;
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["added"], 1);
        // Banning drops what is already stored, not just future announcements.
        assert_eq!(v["purged"], 1);

        let response = h.dispatch(Some("banlist.list"), b"").await;
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v[0]["comment"], "spam");
        assert_eq!(v[0]["nets"], serde_json::json!(["1.2.3.0/24"]));
    }

    #[tokio::test]
    async fn test_errors() {
        let (h, _mgr) = handler_with_manager("errors");

        for (method, payload) in [
            (Some("addresses.add"), &b"not json"[..]),
            (Some("banlist.add"), &b"not json"[..]),
            (Some("addresses.inspect"), &b"not json"[..]),
        ] {
            let v: serde_json::Value =
                serde_json::from_str(&h.dispatch(method, payload).await).unwrap();
            assert!(
                v["error"].as_str().unwrap().contains("invalid JSON"),
                "{method:?} gave {v}"
            );
        }

        let v: serde_json::Value =
            serde_json::from_str(&h.dispatch(Some("nonexistent"), b"{}").await).unwrap();
        assert!(v["error"].as_str().unwrap().contains("unknown method"));

        let v: serde_json::Value = serde_json::from_str(&h.dispatch(None, b"").await).unwrap();
        assert!(v["error"].as_str().unwrap().contains("malformed subject"));

        // A well-formed request for an address that cannot be parsed.
        let payload = serde_json::to_vec("nonsense").unwrap();
        let v: serde_json::Value =
            serde_json::from_str(&h.dispatch(Some("addresses.inspect"), &payload).await).unwrap();
        assert!(v["error"].as_str().unwrap().contains("unparseable"));
    }

    #[tokio::test]
    async fn test_chain_tips_genesis_only() {
        let (h, _mgr) = handler_with_manager("tips");

        let response = h.dispatch(Some("headertree.tips"), b"").await;
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        let tips = v.as_array().unwrap();
        assert_eq!(tips.len(), 1);
        assert_eq!(tips[0]["height"], 0);
        assert_eq!(tips[0]["status"], "active");
    }

    /// Commands answer with an error rather than hanging once the manager has
    /// gone, which is what happens during shutdown.
    #[tokio::test]
    async fn test_manager_gone_is_an_error() {
        let (h, mgr) = handler_with_manager("gone");
        mgr.task.abort();
        // Give the abort a moment to take effect.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let v: serde_json::Value =
            serde_json::from_str(&h.dispatch(Some("addresses.info"), b"").await).unwrap();
        assert_eq!(v["error"], GONE);
    }
}
