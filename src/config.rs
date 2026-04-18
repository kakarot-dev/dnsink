use std::net::SocketAddr;
use std::path::Path;

use serde::Deserialize;

use crate::cdn_whitelist::CdnProvider;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub upstream: UpstreamConfig,
    #[serde(default)]
    pub blocklist: Option<BlocklistConfig>,
    #[serde(default)]
    pub feeds: FeedsConfig,
    #[serde(default)]
    pub logging: LoggingConfig,
    #[serde(default)]
    pub tunneling_detection: TunnelingDetectionConfig,
    #[serde(default)]
    pub metrics: MetricsConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct MetricsConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "default_metrics_bind_addr")]
    pub bind_addr: String,
}

fn default_metrics_bind_addr() -> String {
    "127.0.0.1:9090".to_string()
}

impl Default for MetricsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            bind_addr: default_metrics_bind_addr(),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct TunnelingDetectionConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_entropy_threshold")]
    pub entropy_threshold: f64,
    #[serde(default = "default_min_subdomain_length")]
    pub min_subdomain_length: usize,
    #[serde(default)]
    pub cdn_whitelist: CdnWhitelistConfig,
}

fn default_entropy_threshold() -> f64 {
    3.5
}

fn default_min_subdomain_length() -> usize {
    20
}

impl Default for TunnelingDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            entropy_threshold: default_entropy_threshold(),
            min_subdomain_length: default_min_subdomain_length(),
            cdn_whitelist: CdnWhitelistConfig::default(),
        }
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct CdnWhitelistConfig {
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default)]
    pub providers: Vec<CdnProvider>,
}

impl Default for CdnWhitelistConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            providers: Vec::new(),
        }
    }
}

#[derive(Debug, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum LogFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Deserialize, Default)]
pub struct LoggingConfig {
    #[serde(default)]
    pub format: LogFormat,
    pub file: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
pub struct FeedsConfig {
    #[serde(default = "default_true")]
    pub urlhaus: bool,
    #[serde(default = "default_true")]
    pub openphish: bool,
    pub phishtank_api_key: Option<String>,
    /// oisd.nl big list (~32K ad/tracker domains, AdBlock syntax).
    /// Opt-in — expands the blocklist beyond the security-only feeds.
    #[serde(default)]
    pub oisd: bool,
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
    // Optional TCP-specific bind address. When None, TCP binds to the
    // same address as UDP. Needed on fly.io where UDP must bind to
    // `fly-global-services` (for correct reply source-IP) but TCP
    // must bind to a wildcard so fly-proxy's external route-in lands.
    #[serde(default)]
    pub tcp_address: Option<String>,
}

#[derive(Debug, Deserialize, Default, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamProtocol {
    #[default]
    Udp,
    Doh,
}

#[derive(Debug, Deserialize)]
pub struct UpstreamConfig {
    pub address: String,
    pub port: u16,
    pub timeout_ms: u64,
    #[serde(default)]
    pub protocol: UpstreamProtocol,
    pub doh_url: Option<String>,
}

const DEFAULT_DOH_URL: &str = "https://1.1.1.1/dns-query";

impl Config {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        let config: Config = toml::from_str(&contents)?;
        Ok(config)
    }

    pub fn upstream_addr(&self) -> anyhow::Result<SocketAddr> {
        Ok(format!("{}:{}", self.upstream.address, self.upstream.port).parse()?)
    }

    pub fn doh_url(&self) -> &str {
        self.upstream.doh_url.as_deref().unwrap_or(DEFAULT_DOH_URL)
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: ListenConfig {
                address: "127.0.0.1".to_string(),
                port: 5353,
                tcp_address: None,
            },
            upstream: UpstreamConfig {
                address: "8.8.8.8".to_string(),
                port: 53,
                timeout_ms: 5000,
                protocol: UpstreamProtocol::default(),
                doh_url: None,
            },
            blocklist: None,
            feeds: FeedsConfig {
                urlhaus: true,
                openphish: true,
                phishtank_api_key: None,
                oisd: false,
                refresh_secs: 3600,
            },
            logging: LoggingConfig::default(),
            tunneling_detection: TunnelingDetectionConfig::default(),
            metrics: MetricsConfig::default(),
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
