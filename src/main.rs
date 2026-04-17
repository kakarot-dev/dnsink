use std::fs::OpenOptions;
use std::path::PathBuf;

use clap::Parser;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use dnsink::config::{Config, LogFormat};
use dnsink::metrics_server;
use dnsink::proxy::{load_blocklist, DnsProxy};
use dnsink::tui::App;

#[derive(Parser)]
#[command(name = "dnsink", about = "DNS threat gateway")]
struct Cli {
    /// Path to config file
    #[arg(short, long, default_value = "config.toml")]
    config: PathBuf,

    /// Launch the TUI dashboard
    #[arg(long)]
    tui: bool,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let config = if cli.config.exists() {
        Config::load(&cli.config)?
    } else {
        Config::default()
    };

    if !cli.tui {
        init_tracing(&config)?;
    }

    info!(
        listen = %format!("{}:{}", config.listen.address, config.listen.port),
        upstream = %format!("{}:{}", config.upstream.address, config.upstream.port),
        refresh_secs = config.feeds.refresh_secs,
        "starting dnsink"
    );

    let (bloom, trie) = load_blocklist(&config).await?;
    let metrics_cfg = config.metrics.clone();
    let mut proxy = DnsProxy::new(config, bloom, trie)?;

    if metrics_cfg.enabled {
        let metrics = proxy.metrics();
        let bind_addr = metrics_cfg.bind_addr.clone();
        match TcpListener::bind(&bind_addr).await {
            Ok(listener) => {
                info!(addr = %bind_addr, "spawning metrics server");
                tokio::spawn(async move {
                    if let Err(e) = metrics_server::serve(listener, metrics).await {
                        error!(error = %e, "metrics server exited");
                    }
                });
            }
            Err(e) => {
                warn!(addr = %bind_addr, error = %e, "metrics bind failed — continuing without /metrics");
            }
        }
    }

    if cli.tui {
        let (tx, rx) = mpsc::channel(1024);
        let metrics = proxy.metrics();
        proxy.set_event_tx(tx);

        // Run proxy in background, TUI in foreground
        tokio::spawn(async move {
            if let Err(e) = proxy.run().await {
                eprintln!("proxy error: {e}");
            }
        });

        let app = App::new(metrics, rx);
        app.run().await
    } else {
        proxy.run().await
    }
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
