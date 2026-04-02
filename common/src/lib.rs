// re-exports
pub extern crate anyhow;
pub extern crate async_nats;
pub extern crate bitcoin;
pub extern crate config;
pub extern crate futures_util;
pub extern crate p2p;
pub extern crate prost;
pub extern crate serde;
pub extern crate serde_json;
pub extern crate tokio;
pub extern crate tracing;
pub extern crate tracing_subscriber;

pub mod events {
    include!(concat!(env!("OUT_DIR"), "/p2p_observer.rs"));
}
