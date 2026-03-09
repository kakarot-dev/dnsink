use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize)]
pub struct Config {
    pub listen: ListenConfig,
    pub upstream: UpstreamConfig,
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
        }
    }
}
