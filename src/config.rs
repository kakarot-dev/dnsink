use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub blocklist: Option<BlocklistConfig>,
    #[serde(default)]
    pub feeds: FeedsConfig,
}

#[derive(Debug, Deserialize, Default)]
pub struct FeedsConfig {
    #[serde(default = "default_true")]
    pub urlhaus: bool,
    #[serde(default = "default_true")]
    pub openphish: bool,
    pub phishtank_api_key: Option<String>,
    /// Interval in seconds to re-fetch feeds (used by hot-reload)
    #[serde(default = "default_refresh_secs")]
    pub refresh_secs: u64,
}

fn default_true() -> bool {
    true
}

fn default_refresh_secs() -> u64 {
    3600
}

#[derive(Debug, Deserialize)]
pub struct BlocklistConfig {
    pub path: String,
}

#[derive(Debug, Deserialize)]
pub struct ListenConfig {
    pub address: String,
    pub port: u16,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamConfig {
    pub address: String,
    pub port: u16,
    pub timeout_ms: u64,
}

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn upstream_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(format!("{}:{}", self.upstream.address, self.upstream.port).parse()?)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: ListenConfig {
                address: "127.0.0.1".to_string(),
                port: 5353,
            },
            upstream: UpstreamConfig {
                address: "8.8.8.8".to_string(),
                port: 53,
                timeout_ms: 5000,
            },
            blocklist: None,
            feeds: FeedsConfig {
                urlhaus: true,
                openphish: true,
                phishtank_api_key: None,
                refresh_secs: 3600,
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.listen.address, "127.0.0.1");
        assert_eq!(config.listen.port, 5353);
        assert_eq!(config.upstream.address, "8.8.8.8");
        assert_eq!(config.upstream.port, 53);
        assert_eq!(config.upstream.timeout_ms, 5000);
    }

    #[test]
    fn test_config_from_toml() {
        let toml_str = r#"
[listen]
address = "0.0.0.0"
port = 1053

[upstream]
address = "1.1.1.1"
port = 53
timeout_ms = 3000
"#;
        let config: Config = toml::from_str(toml_str).unwrap();
        assert_eq!(config.listen.address, "0.0.0.0");
        assert_eq!(config.listen.port, 1053);
        assert_eq!(config.upstream.address, "1.1.1.1");
        assert_eq!(config.upstream.port, 53);
        assert_eq!(config.upstream.timeout_ms, 3000);
    }

    #[test]
    fn test_upstream_addr() {
        let config = Config::default();
        let addr = config.upstream_addr().unwrap();
        assert_eq!(addr, "8.8.8.8:53".parse::<SocketAddr>().unwrap());
    }

    #[test]
    fn test_config_load_missing_file() {
        let result = Config::load(Path::new("/nonexistent/config.toml"));
        assert!(result.is_err());
    }
}
