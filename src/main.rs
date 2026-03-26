use std::fs::OpenOptions;
use std::path::PathBuf;

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use dnsink::config::{Config, LogFormat};
use dnsink::proxy::{load_blocklist, DnsProxy};

#[derive(Parser)]
#[command(name = "dnsink", about = "DNS threat gateway")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = if cli.config.exists() {
        Config::load(&cli.config)?
    } else {
        Config::default()
    };

    init_tracing(&config)?;

    info!(
        listen = %format!("{}:{}", config.listen.address, config.listen.port),
        upstream = %format!("{}:{}", config.upstream.address, config.upstream.port),
        refresh_secs = config.feeds.refresh_secs,
        "starting dnsink"
    );

    let (bloom, trie) = load_blocklist(&config).await?;
    let proxy = DnsProxy::new(config, bloom, trie)?;
    proxy.run().await
}

fn init_tracing(config: &Config) -> anyhow::Result<()> {
    let filter = EnvFilter::from_default_env().add_directive("dnsink=debug".parse()?);

    match (&config.logging.format, &config.logging.file) {
        (LogFormat::Json, Some(path)) => {
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .with_writer(file)
                .init();
        }
        (LogFormat::Json, None) => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        (LogFormat::Text, Some(path)) => {
            let file = OpenOptions::new().create(true).append(true).open(path)?;
            tracing_subscriber::fmt()
                .with_env_filter(filter)
                .with_writer(file)
                .init();
        }
        (LogFormat::Text, None) => {
            tracing_subscriber::fmt().with_env_filter(filter).init();
        }
    }

    Ok(())
}
