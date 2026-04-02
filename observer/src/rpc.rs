use std::sync::{Arc, Mutex};

use crate::TARGET_RPC as TARGET;
use common::{async_nats, futures_util::StreamExt, serde_json, tracing};

use crate::addresses::{AddrStore, parse_addr};

pub(crate) struct Rpc {
    nats: async_nats::Client,
    network: String,
    handler: Handler,
}

struct Handler {
    store: Arc<Mutex<AddrStore>>,
}

impl Rpc {
    pub(crate) fn new(
        nats: async_nats::Client,
        network: &str,
        store: Arc<Mutex<AddrStore>>,
    ) -> Self {
        Self {
            nats,
            network: network.to_owned(),
            handler: Handler { store },
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

            let reply = self.handler.dispatch(method, &msg.payload);

            if let Some(reply_to) = msg.reply {
                if let Err(e) = self.nats.publish(reply_to, reply.into()).await {
                    tracing::warn!(target: TARGET, "failed to send RPC reply: {e}");
                }
            }
        }
    }
}

impl Handler {
    fn dispatch(&self, method: Option<&str>, payload: &[u8]) -> String {
        let result = match method {
            Some("addresses.add") => self.handle_add_addresses(payload),
            Some("addresses.info") => self.handle_addresses_info(),
            Some(other) => Err(format!("unknown method: {other}")),
            None => Err("malformed subject".to_owned()),
        };
        match result {
            Ok(value) => value,
            Err(e) => serde_json::json!({ "error": e }).to_string(),
        }
    }

    fn handle_addresses_info(&self) -> Result<String, String> {
        let s = self.store.lock().unwrap();
        Ok(serde_json::json!({
            "unknown": s.unknown_len(),
            "good": s.good_len(),
            "bad": s.bad_len(),
            "manual": s.manual_len(),
        })
        .to_string())
    }

    fn handle_add_addresses(&self, payload: &[u8]) -> Result<String, String> {
        let addrs: Vec<String> =
            serde_json::from_slice(payload).map_err(|e| format!("invalid JSON: {e}"))?;

        let peers: Vec<_> = addrs.iter().filter_map(|s| parse_addr(s)).collect();
        let added = self.store.lock().unwrap().insert_manual(peers);
        tracing::info!(target: TARGET, received = addrs.len(), added, "add-addresses");
        Ok(serde_json::json!({ "added": added }).to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn test_handler() -> Handler {
        let store = Arc::new(Mutex::new(AddrStore::empty(Path::new("/dev/null"))));
        Handler { store }
    }

    #[test]
    fn test_add_addresses() {
        let h = test_handler();
        let payload = serde_json::to_vec(&["1.2.3.4:8333", "5.6.7.8:8333"]).unwrap();

        let response = h.dispatch(Some("addresses.add"), &payload);
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["added"], 2);
        assert_eq!(h.store.lock().unwrap().manual_len(), 2);
    }

    #[test]
    fn test_add_addresses_dedup() {
        let h = test_handler();
        let payload = serde_json::to_vec(&["1.2.3.4:8333", "1.2.3.4:8333"]).unwrap();

        let response = h.dispatch(Some("addresses.add"), &payload);
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["added"], 1);
    }

    #[test]
    fn test_add_addresses_invalid_json() {
        let h = test_handler();

        let response = h.dispatch(Some("addresses.add"), b"not json");
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(v["error"].as_str().unwrap().contains("invalid JSON"));
    }

    #[test]
    fn test_addresses_info() {
        let h = test_handler();
        let payload = serde_json::to_vec(&["1.2.3.4:8333"]).unwrap();
        h.dispatch(Some("addresses.add"), &payload);

        let response = h.dispatch(Some("addresses.info"), b"");
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert_eq!(v["manual"], 1);
        assert_eq!(v["unknown"], 0);
        assert_eq!(v["good"], 0);
        assert_eq!(v["bad"], 0);
    }

    #[test]
    fn test_unknown_method() {
        let h = test_handler();

        let response = h.dispatch(Some("nonexistent"), b"{}");
        let v: serde_json::Value = serde_json::from_str(&response).unwrap();
        assert!(v["error"].as_str().unwrap().contains("unknown method"));
    }
}
