mod bloom;
mod config;
mod feeds;
mod proxy;
mod trie;

use std::io::BufRead;
use std::path::PathBuf;

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use bloom::BloomFilter;
use config::Config;
use proxy::DnsProxy;
use trie::DomainTrie;

#[derive(Parser)]
#[command(name = "dnsink", about = "DNS threat gateway")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive("dnsink=debug".parse()?))
        .init();

    let cli = Cli::parse();

    let config = if cli.config.exists() {
        info!(path = %cli.config.display(), "loading config");
        Config::load(&cli.config)?
    } else {
        info!("no config file found, using defaults");
        Config::default()
    };

    info!(
        listen = %format!("{}:{}", config.listen.address, config.listen.port),
        upstream = %format!("{}:{}", config.upstream.address, config.upstream.port),
        "starting dnsink"
    );

    let (bloom, trie) = load_blocklist(&config).await?;
    let proxy = DnsProxy::new(config, bloom, trie);
    proxy.run().await
}

async fn load_blocklist(config: &Config) -> anyhow::Result<(Option<BloomFilter>, DomainTrie)> {
    let mut domains: Vec<String> = Vec::new();

    // Static file
    if let Some(bl_config) = &config.blocklist {
        let file = std::fs::File::open(&bl_config.path)?;
        let file_domains = std::io::BufReader::new(file)
            .lines()
            .filter_map(|line| {
                let line = line.ok()?;
                let trimmed = line.trim().to_lowercase();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    None
                } else {
                    Some(trimmed.trim_end_matches('.').to_string())
                }
            });
        domains.extend(file_domains);
        info!(path = %bl_config.path, "loaded static blocklist");
    }

    // URLhaus live feed
    match feeds::fetch_urlhaus().await {
        Ok(feed) => {
            info!(domains = feed.len(), "fetched URLhaus feed");
            domains.extend(feed);
        }
        Err(e) => {
            tracing::warn!(error = %e, "failed to fetch URLhaus feed, continuing without it");
        }
    }

    if domains.is_empty() {
        return Ok((None, DomainTrie::new()));
    }

    let mut bloom = BloomFilter::new(domains.len(), 0.01);
    let mut trie = DomainTrie::new();
    for domain in &domains {
        bloom.insert(domain);
        trie.insert(domain);
    }

    info!(total = domains.len(), "blocklist ready");
    Ok((Some(bloom), trie))
}
