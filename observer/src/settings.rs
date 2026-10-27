use common::{
    anyhow::{Context, Result},
    config::{Config as CfgBuilder, File, FileFormat},
    p2p::Magic,
    serde::Deserialize,
};
use std::path::PathBuf;

#[derive(Debug, Deserialize)]
#[serde(crate = "common::serde")]
pub struct Config {
    #[serde(default = "default_network")]
    pub network: String,

    #[serde(default = "default_datadir")]
    pub datadir: PathBuf,

    #[serde(default)]
    pub log_levels: LogLevels,

    #[serde(default = "connections_per_second")]
    pub connections_per_second: u64,

    #[serde(default = "default_ping_interval_secs")]
    pub ping_interval_secs: u64,

    #[serde(default = "default_user_agent")]
    pub user_agent: String,

    /// Initial addresses to connect to before peer discovery takes over.
    #[serde(default)]
    pub bootstrap_addrs: Vec<String>,

    #[serde(default = "default_nats_url")]
    pub nats_url: String,

    #[serde(default)]
    pub networks: NetworksConfig,

    #[serde(default)]
    pub addrman: AddrmanConfig,

    /// Block hashes the chain must have at a height, on top of the one built
    /// in for the network. See `headertree::Checkpoint`.
    #[serde(default)]
    pub checkpoints: Vec<CheckpointConfig>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(crate = "common::serde")]
pub struct CheckpointConfig {
    pub height: u32,
    pub hash: String,
}

/// Bounds on the address manager. Both are about resource use rather than
/// policy, which is why they are configurable and the weights are not.
#[derive(Debug, Clone, Deserialize)]
#[serde(crate = "common::serde")]
pub struct AddrmanConfig {
    /// Hard ceiling on stored addresses. Inventing addresses is free for a
    /// peer, so this bound cannot depend on peers behaving.
    #[serde(default = "default_addr_capacity")]
    pub capacity: usize,

    /// Maximum connection attempts in flight at once. Each one costs a socket
    /// and a task, so this is the real limit on how hard we crawl;
    /// connections_per_second only controls how fast we ramp up to it.
    #[serde(default = "default_max_dialing")]
    pub max_dialing: usize,
}

impl Default for AddrmanConfig {
    fn default() -> Self {
        Self {
            capacity: default_addr_capacity(),
            max_dialing: default_max_dialing(),
        }
    }
}

fn default_addr_capacity() -> usize {
    crate::addresses::book::DEFAULT_CAPACITY
}

fn default_max_dialing() -> usize {
    200
}

#[derive(Debug, Clone, Deserialize)]
#[serde(crate = "common::serde")]
pub struct NetworksConfig {
    #[serde(default = "default_enabled")]
    pub ipv4: NetworkConfig,

    #[serde(default)]
    pub ipv6: NetworkConfig,

    #[serde(default)]
    pub tor: TorConfig,

    #[serde(default)]
    pub cjdns: NetworkConfig,

    #[serde(default)]
    pub i2p: NetworkConfig,
}

impl Default for NetworksConfig {
    fn default() -> Self {
        Self {
            ipv4: default_enabled(),
            ipv6: NetworkConfig::default(),
            tor: TorConfig::default(),
            cjdns: NetworkConfig::default(),
            i2p: NetworkConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(crate = "common::serde")]
pub struct NetworkConfig {
    #[serde(default)]
    pub enabled: bool,
}

fn default_enabled() -> NetworkConfig {
    NetworkConfig { enabled: true }
}

#[derive(Debug, Clone, Deserialize)]
#[serde(crate = "common::serde")]
pub struct TorConfig {
    #[serde(default)]
    pub enabled: bool,

    #[serde(default = "default_tor_proxy")]
    pub proxy_addr: String,
}

impl Default for TorConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            proxy_addr: default_tor_proxy(),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(crate = "common::serde")]
pub struct LogLevels {
    #[serde(default = "default_main_level")]
    pub main: String,
    #[serde(default = "default_connection_level")]
    pub connection: String,
    #[serde(default = "default_protocol_level")]
    pub protocol: String,
    #[serde(default = "default_publisher_level")]
    pub publisher: String,
    #[serde(default = "default_rpc_level")]
    pub rpc: String,
    #[serde(default = "default_headertree_level")]
    pub headertree: String,
    #[serde(default = "default_addrman_level")]
    pub addrman: String,
}

impl Default for LogLevels {
    fn default() -> Self {
        Self {
            main: default_main_level(),
            connection: default_connection_level(),
            protocol: default_protocol_level(),
            publisher: default_publisher_level(),
            rpc: default_rpc_level(),
            headertree: default_headertree_level(),
            addrman: default_addrman_level(),
        }
    }
}

impl LogLevels {
    pub fn to_filter_string(&self) -> String {
        format!(
            "{}={},{}={},{}={},{}={},{}={},{}={},{}={}",
            crate::TARGET_MAIN,
            self.main,
            crate::TARGET_CONNECTION,
            self.connection,
            crate::TARGET_PROTOCOL,
            self.protocol,
            crate::TARGET_PUBLISHER,
            self.publisher,
            crate::TARGET_RPC,
            self.rpc,
            crate::TARGET_HEADERTREE,
            self.headertree,
            crate::TARGET_ADDRMAN,
            self.addrman,
        )
    }
}

fn default_network() -> String {
    "signet".to_owned()
}
fn default_ping_interval_secs() -> u64 {
    120
}
fn connections_per_second() -> u64 {
    10
}
fn default_user_agent() -> String {
    crate::protocol::USER_AGENT.to_owned()
}
fn default_main_level() -> String {
    "debug".to_owned()
}
fn default_connection_level() -> String {
    "info".to_owned()
}
fn default_protocol_level() -> String {
    "debug".to_owned()
}
fn default_publisher_level() -> String {
    "warn".to_owned()
}
fn default_rpc_level() -> String {
    "info".to_owned()
}
fn default_headertree_level() -> String {
    "info".to_owned()
}
fn default_addrman_level() -> String {
    "info".to_owned()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: default_network(),
            datadir: default_datadir(),
            log_levels: LogLevels::default(),
            connections_per_second: connections_per_second(),
            ping_interval_secs: default_ping_interval_secs(),
            user_agent: default_user_agent(),
            bootstrap_addrs: Vec::new(),
            nats_url: default_nats_url(),
            networks: NetworksConfig::default(),
            addrman: AddrmanConfig::default(),
            checkpoints: Vec::new(),
        }
    }
}

fn default_nats_url() -> String {
    "nats://localhost:4222".to_owned()
}

const DEFAULT_DATADIR: &str = "./data";

fn default_datadir() -> PathBuf {
    PathBuf::from(DEFAULT_DATADIR)
}

fn default_tor_proxy() -> String {
    "127.0.0.1:9050".to_owned()
}

impl Config {
    pub fn load() -> Result<Self> {
        let path = std::env::args()
            .nth(1)
            .unwrap_or_else(|| "config.yaml".to_owned());
        println!("loading config file: {}", path);
        Self::load_from(&path)
    }

    pub fn load_from(path: &str) -> Result<Self> {
        CfgBuilder::builder()
            .add_source(
                File::with_name(path)
                    .format(FileFormat::Yaml)
                    .required(true),
            )
            .build()
            .context("build config")?
            .try_deserialize()
            .context("parse config")
    }

    pub fn log_settings(&self) {
        use common::tracing::info;
        info!(target: crate::TARGET_MAIN, "config: {:?}", self);
    }

    /// The directory holding this network's state. Callers join the bare
    /// file names onto it -- `headers.bin`, `addresses.bin`, `banlist.json` --
    /// which carry no network suffix because the directory already does.
    ///
    /// The network name reaches the path unescaped, which is safe only because
    /// `magic` has already rejected everything outside the fixed set of names.
    pub fn network_dir(&self) -> PathBuf {
        self.datadir.join(&self.network)
    }

    /// The configured checkpoints, parsed.
    pub fn checkpoints(&self) -> Result<Vec<crate::headertree::Checkpoint>> {
        self.checkpoints
            .iter()
            .map(|c| {
                let hash = c.hash.parse().with_context(|| {
                    format!("checkpoint at height {}: bad hash {:?}", c.height, c.hash)
                })?;
                Ok(crate::headertree::Checkpoint {
                    height: c.height,
                    hash,
                })
            })
            .collect()
    }

    pub fn magic(&self) -> Result<Magic> {
        match self.network.as_str() {
            "mainnet" | "bitcoin" => Ok(Magic::BITCOIN),
            "signet" => Ok(Magic::SIGNET),
            "testnet3" => Ok(Magic::TESTNET3),
            "testnet" | "testnet4" => Ok(Magic::TESTNET4),
            "regtest" => Ok(Magic::REGTEST),
            other => common::anyhow::bail!("unknown network: {other}"),
        }
    }
}

#[cfg(test)]
fn parse_str(yaml: &str) -> Config {
    CfgBuilder::builder()
        .add_source(File::from_str(yaml, FileFormat::Yaml))
        .build()
        .unwrap()
        .try_deserialize()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_defaults() {
        let cfg = parse_str("");
        assert_eq!(cfg.network, "signet");
        assert_eq!(cfg.datadir, PathBuf::from(DEFAULT_DATADIR));
        assert_eq!(cfg.ping_interval_secs, 120);
        assert_eq!(cfg.connections_per_second, 10);
        assert_eq!(cfg.user_agent, crate::protocol::USER_AGENT);
        assert!(cfg.bootstrap_addrs.is_empty());
        assert_eq!(cfg.log_levels.main, "debug");
        assert_eq!(cfg.log_levels.connection, "info");
        assert_eq!(cfg.log_levels.protocol, "debug");
        assert_eq!(cfg.log_levels.addrman, "info");
    }

    #[test]
    fn test_full_config() {
        let cfg = parse_str(
            r#"
                network: mainnet
                connections_per_second: 20
                ping_interval_secs: 60
                user_agent: "/test:1.0/"
                bootstrap_addrs:
                - "1.2.3.4:8333"
                - "5.6.7.8:8333"
                log_levels:
                  main: warn
                  connection: trace
                  protocol: info
                  addrman: error
            "#,
        );
        assert_eq!(cfg.network, "mainnet");
        assert_eq!(cfg.connections_per_second, 20);
        assert_eq!(cfg.ping_interval_secs, 60);
        assert_eq!(cfg.user_agent, "/test:1.0/");
        assert_eq!(cfg.bootstrap_addrs, vec!["1.2.3.4:8333", "5.6.7.8:8333"]);
        assert_eq!(cfg.log_levels.main, "warn");
        assert_eq!(cfg.log_levels.connection, "trace");
        assert_eq!(cfg.log_levels.protocol, "info");
        assert_eq!(cfg.log_levels.addrman, "error");
    }

    #[test]
    fn test_partial_overrides_defaults() {
        let cfg = parse_str("network: regtest\nping_interval_secs: 30");
        assert_eq!(cfg.network, "regtest");
        assert_eq!(cfg.ping_interval_secs, 30);
        assert_eq!(cfg.user_agent, crate::protocol::USER_AGENT); // default
        assert_eq!(cfg.log_levels.connection, "info"); // default
    }

    #[test]
    fn test_datadir_defaults_and_joins_the_network() {
        let cfg = parse_str("");
        assert_eq!(cfg.network_dir(), PathBuf::from("./data/signet"));

        let cfg = parse_str("datadir: /var/lib/p2p-observer\nnetwork: mainnet");
        assert_eq!(cfg.datadir, PathBuf::from("/var/lib/p2p-observer"));
        assert_eq!(
            cfg.network_dir(),
            PathBuf::from("/var/lib/p2p-observer/mainnet")
        );
    }

    #[test]
    fn test_magic_all_networks() {
        for (name, expected) in [
            ("mainnet", Magic::BITCOIN),
            ("bitcoin", Magic::BITCOIN),
            ("signet", Magic::SIGNET),
            ("testnet3", Magic::TESTNET3),
            ("testnet", Magic::TESTNET4),
            ("testnet4", Magic::TESTNET4),
            ("regtest", Magic::REGTEST),
        ] {
            let cfg = parse_str(&format!("network: {name}"));
            assert_eq!(cfg.magic().unwrap(), expected, "network={name}");
        }
    }

    #[test]
    fn test_example_config_is_valid() {
        let cfg = parse_str(include_str!("../../config-example.yaml"));
        assert!(cfg.magic().is_ok());
        assert!(!cfg.bootstrap_addrs.is_empty());
    }

    #[test]
    fn test_checkpoints() {
        let cfg = parse_str(
            r#"
                network: mainnet
                checkpoints:
                - height: 973364
                  hash: "0000000000000000000172bed57d59e3e4b79d44296a17a298e378d9f6040395"
            "#,
        );
        let checkpoints = cfg.checkpoints().unwrap();
        assert_eq!(checkpoints.len(), 1);
        assert_eq!(checkpoints[0].height, 973364);
        assert_eq!(
            checkpoints[0].hash.to_string(),
            "0000000000000000000172bed57d59e3e4b79d44296a17a298e378d9f6040395"
        );
        // None by default.
        assert!(
            parse_str("network: mainnet")
                .checkpoints()
                .unwrap()
                .is_empty()
        );
        // A bad hash is a config error, not a silently ignored checkpoint.
        let bad = parse_str("checkpoints:\n- height: 1\n  hash: nonsense\n");
        let err = bad.checkpoints().unwrap_err().to_string();
        assert!(err.contains("height 1"), "{err}");
    }

    #[test]
    fn test_invalid_network() {
        let cfg = parse_str("network: invalidnet");
        assert!(cfg.magic().is_err());
    }

    #[test]
    fn test_networks_config() {
        // defaults: ipv4 on, everything else off
        let cfg = parse_str("");
        assert!(cfg.networks.ipv4.enabled);
        assert!(!cfg.networks.ipv6.enabled);
        assert!(!cfg.networks.tor.enabled);
        assert!(!cfg.networks.cjdns.enabled);
        assert!(!cfg.networks.i2p.enabled);
        assert_eq!(cfg.networks.tor.proxy_addr, "127.0.0.1:9050");

        // enable tor
        let cfg = parse_str("networks:\n  tor:\n    enabled: true");
        assert!(cfg.networks.tor.enabled);
        assert!(cfg.networks.ipv4.enabled); // default still applies

        // enable ipv6
        let cfg = parse_str("networks:\n  ipv6:\n    enabled: true");
        assert!(cfg.networks.ipv6.enabled);
        assert!(cfg.networks.ipv4.enabled); // default still applies
    }
}
