use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::bloom::BloomFilter;
use crate::config::Config;
use crate::feeds;
use crate::trie::DomainTrie;

/// Maximum DNS message size with EDNS0 support
const MAX_DNS_MSG_SIZE: usize = 4096;

/// Blocklist state that gets atomically swapped on reload.
pub struct Blocklist {
    pub bloom: Option<BloomFilter>,
    pub trie: DomainTrie,
}

pub struct DnsProxy {
    config: Arc<Config>,
    blocklist: Arc<ArcSwap<Blocklist>>,
}

impl DnsProxy {
    pub fn new(config: Config, bloom: Option<BloomFilter>, trie: DomainTrie) -> Self {
        Self {
            config: Arc::new(config),
            blocklist: Arc::new(ArcSwap::from_pointee(Blocklist { bloom, trie })),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let listen_addr = format!("{}:{}", self.config.listen.address, self.config.listen.port);

        let udp_socket = UdpSocket::bind(&listen_addr).await?;
        let tcp_listener = TcpListener::bind(&listen_addr).await?;
        info!("listening on {listen_addr} (UDP + TCP)");

        // Spawn hot-reload task
        let reload_config = self.config.clone();
        let reload_blocklist = self.blocklist.clone();
        let refresh_secs = self.config.feeds.refresh_secs;
        if refresh_secs > 0 {
            tokio::spawn(async move {
                Self::reload_loop(reload_config, reload_blocklist, refresh_secs).await;
            });
            info!(interval_secs = refresh_secs, "hot-reload task started");
        }

        let config = self.config.clone();
        let blocklist = self.blocklist.clone();
        let udp_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_udp(udp_socket, &config, &blocklist).await {
                error!(error = %e, "UDP listener failed");
            }
        });

        let config = self.config.clone();
        let blocklist = self.blocklist.clone();
        let tcp_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_tcp(tcp_listener, config, blocklist).await {
                error!(error = %e, "TCP listener failed");
            }
        });

        // If either listener dies, we're done
        tokio::select! {
            _ = udp_handle => warn!("UDP listener exited"),
            _ = tcp_handle => warn!("TCP listener exited"),
        }

        Ok(())
    }

    async fn reload_loop(
        config: Arc<Config>,
        blocklist: Arc<ArcSwap<Blocklist>>,
        refresh_secs: u64,
    ) {
        let mut interval = tokio::time::interval(Duration::from_secs(refresh_secs));
        interval.tick().await; // skip the immediate first tick

        loop {
            interval.tick().await;
            info!("reloading blocklists");

            match load_blocklist(&config).await {
                Ok((bloom, trie)) => {
                    blocklist.store(Arc::new(Blocklist { bloom, trie }));
                    info!("blocklist reload complete");
                }
                Err(e) => {
                    warn!(error = %e, "blocklist reload failed, keeping old data");
                }
            }
        }
    }

    async fn run_udp(
        socket: UdpSocket,
        config: &Config,
        blocklist: &ArcSwap<Blocklist>,
    ) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_DNS_MSG_SIZE];

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let query_data = buf[..len].to_vec();
            let start = Instant::now();

            let upstream_addr = config.upstream_addr()?;
            let timeout = Duration::from_millis(config.upstream.timeout_ms);

            // Load a snapshot of the current blocklist — lock-free
            let bl = blocklist.load();
            let (domain, nxdomain) = Self::check_blocklist(&query_data, &bl.bloom, &bl.trie);

            if let Some(nxdomain_bytes) = nxdomain {
                let _ = socket.send_to(&nxdomain_bytes, src).await;
                Self::log_outcome(src, &domain, "blocked", start.elapsed().as_millis(), "udp");
                continue;
            }

            let fwd_socket = UdpSocket::bind("0.0.0.0:0").await?;
            let response =
                Self::forward_udp(&fwd_socket, &query_data, upstream_addr, timeout).await;

            match response {
                Ok(response_data) => {
                    if let Err(e) = socket.send_to(&response_data, src).await {
                        error!(src = %src, error = %e, "failed to send response");
                    }
                    Self::log_outcome(src, &domain, "allowed", start.elapsed().as_millis(), "udp");
                }
                Err(e) => {
                    warn!(src = %src, error = %e, "upstream query failed");
                }
            }
        }
    }

    async fn run_tcp(
        listener: TcpListener,
        config: Arc<Config>,
        blocklist: Arc<ArcSwap<Blocklist>>,
    ) -> anyhow::Result<()> {
        loop {
            let (stream, src) = listener.accept().await?;
            let upstream_addr = config.upstream_addr()?;
            let timeout = Duration::from_millis(config.upstream.timeout_ms);
            let blocklist = blocklist.clone();

            // Spawn a task per TCP connection so we don't block the accept loop
            tokio::spawn(async move {
                // Load blocklist snapshot for this connection
                let bl = blocklist.load();
                if let Err(e) = Self::handle_tcp_client(
                    stream,
                    src,
                    upstream_addr,
                    timeout,
                    &bl.bloom,
                    &bl.trie,
                )
                .await
                {
                    warn!(src = %src, error = %e, "TCP client failed");
                }
            });
        }
    }

    /// Handle a single TCP DNS client.
    ///
    /// DNS over TCP frames each message with a 2-byte big-endian length prefix:
    ///   [u16 length][DNS message bytes]
    /// This is defined in RFC 1035 Section 4.2.2.
    async fn handle_tcp_client(
        mut stream: TcpStream,
        src: SocketAddr,
        upstream: SocketAddr,
        timeout: Duration,
        bloom: &Option<BloomFilter>,
        trie: &DomainTrie,
    ) -> anyhow::Result<()> {
        // Read 2-byte length prefix
        let msg_len = stream.read_u16().await? as usize;
        if msg_len == 0 || msg_len > MAX_DNS_MSG_SIZE {
            anyhow::bail!("invalid DNS TCP message length: {msg_len}");
        }

        // Read the DNS message
        let mut query_data = vec![0u8; msg_len];
        stream.read_exact(&mut query_data).await?;
        let start = Instant::now();

        let (domain, nxdomain) = Self::check_blocklist(&query_data, bloom, trie);

        if let Some(nxdomain_bytes) = nxdomain {
            let len_bytes = (nxdomain_bytes.len() as u16).to_be_bytes();
            stream.write_all(&len_bytes).await?;
            stream.write_all(&nxdomain_bytes).await?;
            Self::log_outcome(src, &domain, "blocked", start.elapsed().as_millis(), "tcp");
            return Ok(());
        }

        // Forward upstream over UDP first, fall back to TCP if truncated
        let fwd_socket = UdpSocket::bind("0.0.0.0:0").await?;
        let mut response_data =
            Self::forward_udp(&fwd_socket, &query_data, upstream, timeout).await?;

        // Check if upstream response has TC (truncated) bit — retry over TCP
        if let Ok(msg) = Message::from_bytes(&response_data) {
            if msg.truncated() {
                debug!(src = %src, "upstream response truncated, retrying over TCP");
                response_data = Self::forward_tcp(&query_data, upstream, timeout).await?;
            }
        }

        // Write response with 2-byte length prefix
        let len_bytes = (response_data.len() as u16).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&response_data).await?;
        Self::log_outcome(src, &domain, "allowed", start.elapsed().as_millis(), "tcp");

        Ok(())
    }

    async fn forward_udp(
        socket: &UdpSocket,
        query: &[u8],
        upstream: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        socket.send_to(query, upstream).await?;

        let mut buf = vec![0u8; MAX_DNS_MSG_SIZE];
        let len = tokio::time::timeout(timeout, socket.recv(&mut buf)).await??;
        buf.truncate(len);
        Ok(buf)
    }

    /// Forward a DNS query to upstream over TCP (used when UDP response is truncated).
    async fn forward_tcp(
        query: &[u8],
        upstream: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        let mut stream = tokio::time::timeout(timeout, TcpStream::connect(upstream)).await??;

        // Send with length prefix
        let len_bytes = (query.len() as u16).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(query).await?;

        // Read response length prefix + message
        let resp_len = tokio::time::timeout(timeout, stream.read_u16()).await?? as usize;
        let mut response = vec![0u8; resp_len];
        tokio::time::timeout(timeout, stream.read_exact(&mut response)).await??;

        Ok(response)
    }

    /// Returns the queried domain and, if blocked, the NXDOMAIN response bytes.
    fn check_blocklist(
        query_data: &[u8],
        bloom: &Option<BloomFilter>,
        trie: &DomainTrie,
    ) -> (String, Option<Vec<u8>>) {
        let Some(message) = Message::from_bytes(query_data).ok() else {
            return (String::new(), None);
        };
        let Some(query) = message.queries().first() else {
            return (String::new(), None);
        };
        let domain = query
            .name()
            .to_ascii()
            .to_lowercase()
            .trim_end_matches('.')
            .to_string();

        // Stage 1: bloom pre-filter — check domain and each parent label.
        // A miss on every ancestor means definitely not blocked; skip the trie.
        if let Some(bl) = bloom {
            let maybe_blocked = Self::ancestors(&domain).any(|d| bl.contains(&d));
            if !maybe_blocked {
                return (domain, None);
            }
        }

        // Stage 2: trie is authoritative — handles exact matches and wildcards.
        if trie.contains(&domain) {
            let mut response = message.clone();
            response.set_message_type(MessageType::Response);
            response.set_response_code(ResponseCode::NXDomain);
            response.take_answers();
            response.take_additionals();
            response.take_name_servers();
            let bytes = response.to_bytes().ok();
            (domain, bytes)
        } else {
            (domain, None)
        }
    }

    /// Yields the domain and each parent: "a.b.com" → "a.b.com", "b.com", "com"
    fn ancestors(domain: &str) -> impl Iterator<Item = &str> {
        std::iter::successors(Some(domain), |d| d.find('.').map(|i| &d[i + 1..]))
    }

    fn log_outcome(src: SocketAddr, domain: &str, action: &str, latency_ms: u128, proto: &str) {
        info!(
            src = %src,
            domain = %domain,
            action = %action,
            latency_ms = %latency_ms,
            proto = %proto,
            "query"
        );
    }
}

/// Load blocklist from static file + live threat feeds.
/// Shared between initial startup and hot-reload.
pub async fn load_blocklist(config: &Config) -> anyhow::Result<(Option<BloomFilter>, DomainTrie)> {
    let mut domains: Vec<String> = Vec::new();

    // Static file
    if let Some(bl_config) = &config.blocklist {
        let file = std::fs::File::open(&bl_config.path)?;
        let file_domains = std::io::BufReader::new(file).lines().filter_map(|line| {
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

    // Live threat feeds (configurable)
    if config.feeds.urlhaus {
        load_feed(&feeds::UrlHausFeed, &mut domains).await;
    }
    if config.feeds.openphish {
        load_feed(&feeds::OpenPhishFeed, &mut domains).await;
    }
    if let Some(key) = &config.feeds.phishtank_api_key {
        load_feed(
            &feeds::PhishTankFeed {
                api_key: key.clone(),
            },
            &mut domains,
        )
        .await;
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

async fn load_feed(feed: &impl feeds::ThreatFeed, domains: &mut Vec<String>) {
    match feed.fetch().await {
        Ok(raw) => {
            let parsed = feed.parse(&raw);
            info!(feed = feed.name(), domains = parsed.len(), "fetched feed");
            domains.extend(parsed);
        }
        Err(e) => {
            warn!(feed = feed.name(), error = %e, "failed to fetch feed, skipping");
        }
    }
}
