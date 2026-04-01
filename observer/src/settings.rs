use common::{
    anyhow::{Context, Result},
    config::{Config as CfgBuilder, File, FileFormat},
    p2p::Magic,
    serde::Deserialize,
};

#[derive(Debug, Deserialize)]
#[serde(crate = "common::serde")]
pub struct Config {
    #[serde(default = "default_network")]
    pub network: String,

    #[serde(default)]
    pub log_levels: LogLevels,

    #[serde(default = "default_ping_interval_secs")]
    pub ping_interval_secs: u64,

    #[serde(default = "default_user_agent")]
    pub user_agent: String,

    /// Initial addresses to connect to before peer discovery takes over.
    #[serde(default)]
    pub bootstrap_addrs: Vec<String>,
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
    #[serde(default = "default_addresses_level")]
    pub addresses: String,
}

impl Default for LogLevels {
    fn default() -> Self {
        Self {
            main: default_main_level(),
            connection: default_connection_level(),
            protocol: default_protocol_level(),
            addresses: default_addresses_level(),
        }
    }
}

impl LogLevels {
    pub fn to_filter_string(&self) -> String {
        format!(
            "{}={},{}={},{}={},{}={}",
            crate::TARGET_MAIN,
            self.main,
            crate::TARGET_CONNECTION,
            self.connection,
            crate::TARGET_PROTOCOL,
            self.protocol,
            crate::TARGET_ADDRESSES,
            self.addresses,
        )
    }
}

fn default_network() -> String {
    "signet".to_owned()
}
fn default_ping_interval_secs() -> u64 {
    120
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
fn default_addresses_level() -> String {
    "debug".to_owned()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            network: default_network(),
            log_levels: LogLevels::default(),
            ping_interval_secs: default_ping_interval_secs(),
            user_agent: default_user_agent(),
            bootstrap_addrs: Vec::new(),
        }
    }
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
        assert_eq!(cfg.ping_interval_secs, 120);
        assert_eq!(cfg.user_agent, crate::protocol::USER_AGENT);
        assert!(cfg.bootstrap_addrs.is_empty());
        assert_eq!(cfg.log_levels.main, "debug");
        assert_eq!(cfg.log_levels.connection, "info");
        assert_eq!(cfg.log_levels.protocol, "debug");
        assert_eq!(cfg.log_levels.addresses, "debug");
    }

    #[test]
    fn test_full_config() {
        let cfg = parse_str(
            r#"
                network: mainnet
                ping_interval_secs: 60
                user_agent: "/test:1.0/"
                bootstrap_addrs:
                - "1.2.3.4:8333"
                - "5.6.7.8:8333"
                log_levels:
                  main: warn
                  connection: trace
                  protocol: info
                  addresses: error
            "#,
        );
        assert_eq!(cfg.network, "mainnet");
        assert_eq!(cfg.ping_interval_secs, 60);
        assert_eq!(cfg.user_agent, "/test:1.0/");
        assert_eq!(cfg.bootstrap_addrs, vec!["1.2.3.4:8333", "5.6.7.8:8333"]);
        assert_eq!(cfg.log_levels.main, "warn");
        assert_eq!(cfg.log_levels.connection, "trace");
        assert_eq!(cfg.log_levels.protocol, "info");
        assert_eq!(cfg.log_levels.addresses, "error");
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
    fn test_invalid_network() {
        let cfg = parse_str("network: invalidnet");
        assert!(cfg.magic().is_err());
    }
}
