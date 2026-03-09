mod config;
mod proxy;

use std::path::PathBuf;

use clap::Parser;
use tracing::info;
use tracing_subscriber::EnvFilter;

use config::Config;
use proxy::DnsProxy;

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

    let proxy = DnsProxy::new(config);
    proxy.run().await
}
