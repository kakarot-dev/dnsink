use std::collections::HashMap;
use std::io::BufRead;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use tokio::sync::mpsc;

use crate::bloom::BloomFilter;
use crate::cdn_whitelist::CdnWhitelist;
use crate::config::{Config, UpstreamProtocol};
use crate::entropy::EntropyDetector;
use crate::feeds;
use crate::trie::DomainTrie;
use crate::tui::QueryEvent;

/// Maximum DNS message size with EDNS0 support
const MAX_DNS_MSG_SIZE: usize = 4096;

/// Atomic query counters for the TUI / metrics endpoint.
#[allow(dead_code)]
pub struct QueryMetrics {
    pub total: AtomicU64,
    pub blocked: AtomicU64,
    pub allowed: AtomicU64,
    pub total_latency_ms: AtomicU64,
    pub tunneling_flagged: AtomicU64,
    blocked_domains: Mutex<HashMap<String, u64>>,
}

impl Default for QueryMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl QueryMetrics {
    pub fn new() -> Self {
        Self {
            total: AtomicU64::new(0),
            blocked: AtomicU64::new(0),
            allowed: AtomicU64::new(0),
            total_latency_ms: AtomicU64::new(0),
            tunneling_flagged: AtomicU64::new(0),
            blocked_domains: Mutex::new(HashMap::new()),
        }
    }

    /// Increment the tunneling-flagged counter. Called when the entropy
    /// detector marks a query as suspicious.
    fn record_tunneling_flag(&self) {
        self.tunneling_flagged.fetch_add(1, Ordering::Relaxed);
    }

    fn record(&self, action: &str, latency_ms: u64, domain: &str) {
        self.total.fetch_add(1, Ordering::Relaxed);
        self.total_latency_ms
            .fetch_add(latency_ms, Ordering::Relaxed);
        match action {
            "blocked" => {
                self.blocked.fetch_add(1, Ordering::Relaxed);
                *self
                    .blocked_domains
                    .lock()
                    .unwrap()
                    .entry(domain.to_string())
                    .or_insert(0) += 1;
            }
            "allowed" => {
                self.allowed.fetch_add(1, Ordering::Relaxed);
            }
            _ => {}
        }
    }

    /// Returns the top `n` blocked domains sorted by count (descending).
    #[allow(dead_code)]
    pub fn top_blocked(&self, n: usize) -> Vec<(String, u64)> {
        let map = self.blocked_domains.lock().unwrap();
        let mut entries: Vec<(String, u64)> = map.iter().map(|(k, v)| (k.clone(), *v)).collect();
        entries.sort_unstable_by_key(|b| std::cmp::Reverse(b.1));
        entries.truncate(n);
        entries
    }

    #[allow(dead_code)]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            total: self.total.load(Ordering::Relaxed),
            blocked: self.blocked.load(Ordering::Relaxed),
            allowed: self.allowed.load(Ordering::Relaxed),
            total_latency_ms: self.total_latency_ms.load(Ordering::Relaxed),
            tunneling_flagged: self.tunneling_flagged.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
#[allow(dead_code)]
pub struct MetricsSnapshot {
    pub total: u64,
    pub blocked: u64,
    pub allowed: u64,
    pub total_latency_ms: u64,
    pub tunneling_flagged: u64,
}

impl MetricsSnapshot {
    #[allow(dead_code)]
    pub fn avg_latency_ms(&self) -> f64 {
        if self.total == 0 {
            0.0
        } else {
            self.total_latency_ms as f64 / self.total as f64
        }
    }
}

/// Result of parsing + blocklist check on a single query.
struct QueryResult {
    domain: String,
    qtype: String,
    nxdomain: Option<Vec<u8>>,
}

/// Blocklist state that gets atomically swapped on reload.
pub struct Blocklist {
    pub bloom: Option<BloomFilter>,
    pub trie: DomainTrie,
}

/// Shared context for handling a single TCP DNS client connection.
/// Groups parameters that are common across all connections to satisfy clippy::too_many_arguments.
struct TcpClientCtx<'a> {
    upstream: Option<SocketAddr>,
    timeout: Duration,
    blocklist: &'a Blocklist,
    use_doh: bool,
    http: &'a reqwest::Client,
    doh_url: &'a str,
    fwd_socket: &'a UdpSocket,
    metrics: &'a QueryMetrics,
    event_tx: &'a Option<mpsc::Sender<QueryEvent>>,
    entropy_detector: Option<&'a EntropyDetector>,
    cdn_whitelist: Option<&'a CdnWhitelist>,
}

pub struct DnsProxy {
    config: Arc<Config>,
    blocklist: Arc<ArcSwap<Blocklist>>,
    http: reqwest::Client,
    metrics: Arc<QueryMetrics>,
    event_tx: Option<mpsc::Sender<QueryEvent>>,
    /// Present only when `config.tunneling_detection.enabled` is true.
    entropy_detector: Option<Arc<EntropyDetector>>,
    /// Present only when the CDN whitelist is enabled AND has at least one
    /// provider configured. Used to suppress entropy false positives on
    /// trusted CDNs before the entropy check runs.
    cdn_whitelist: Option<Arc<CdnWhitelist>>,
}

impl DnsProxy {
    pub fn new(
        config: Config,
        bloom: Option<BloomFilter>,
        trie: DomainTrie,
    ) -> anyhow::Result<Self> {
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(config.upstream.timeout_ms))
            .build()?;
        let entropy_detector = if config.tunneling_detection.enabled {
            Some(Arc::new(EntropyDetector::new(
                config.tunneling_detection.entropy_threshold,
                config.tunneling_detection.min_subdomain_length,
            )))
        } else {
            None
        };
        let cdn_cfg = &config.tunneling_detection.cdn_whitelist;
        let cdn_whitelist = if cdn_cfg.enabled && !cdn_cfg.providers.is_empty() {
            Some(Arc::new(CdnWhitelist::with_providers(&cdn_cfg.providers)))
        } else {
            None
        };
        Ok(Self {
            config: Arc::new(config),
            blocklist: Arc::new(ArcSwap::from_pointee(Blocklist { bloom, trie })),
            http,
            metrics: Arc::new(QueryMetrics::new()),
            event_tx: None,
            entropy_detector,
            cdn_whitelist,
        })
    }

    #[allow(dead_code)]
    pub fn metrics(&self) -> Arc<QueryMetrics> {
        self.metrics.clone()
    }

    pub fn set_event_tx(&mut self, tx: mpsc::Sender<QueryEvent>) {
        self.event_tx = Some(tx);
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let port = self.config.listen.port;
        let udp_addr = format!("{}:{}", self.config.listen.address, port);
        let tcp_addr = match &self.config.listen.tcp_address {
            Some(a) => format!("{a}:{port}"),
            None => udp_addr.clone(),
        };

        let udp_socket = UdpSocket::bind(&udp_addr).await?;
        let tcp_listener = TcpListener::bind(&tcp_addr).await?;
        if udp_addr == tcp_addr {
            info!("listening on {udp_addr} (UDP + TCP)");
        } else {
            info!("listening UDP on {udp_addr}, TCP on {tcp_addr}");
        }

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
        let http = self.http.clone();
        let metrics = self.metrics.clone();
        let event_tx = self.event_tx.clone();
        let entropy_detector = self.entropy_detector.clone();
        let cdn_whitelist = self.cdn_whitelist.clone();
        let udp_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_udp(
                udp_socket,
                &config,
                &blocklist,
                &http,
                &metrics,
                &event_tx,
                entropy_detector.as_deref(),
                cdn_whitelist.as_deref(),
            )
            .await
            {
                error!(error = %e, "UDP listener failed");
            }
        });

        let config = self.config.clone();
        let blocklist = self.blocklist.clone();
        let http = self.http.clone();
        let metrics = self.metrics.clone();
        let event_tx = self.event_tx.clone();
        let entropy_detector = self.entropy_detector.clone();
        let cdn_whitelist = self.cdn_whitelist.clone();
        let tcp_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_tcp(
                tcp_listener,
                config,
                blocklist,
                http,
                metrics,
                event_tx,
                entropy_detector,
                cdn_whitelist,
            )
            .await
            {
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

    #[allow(clippy::too_many_arguments)]
    async fn run_udp(
        socket: UdpSocket,
        config: &Config,
        blocklist: &ArcSwap<Blocklist>,
        http: &reqwest::Client,
        metrics: &QueryMetrics,
        event_tx: &Option<mpsc::Sender<QueryEvent>>,
        entropy_detector: Option<&EntropyDetector>,
        cdn_whitelist: Option<&CdnWhitelist>,
    ) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_DNS_MSG_SIZE];
        let use_doh = config.upstream.protocol == UpstreamProtocol::Doh;
        // Bind a single forwarding socket upfront, reused across all queries
        let fwd_socket = UdpSocket::bind("0.0.0.0:0").await?;

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let query_data = buf[..len].to_vec();
            let start = Instant::now();

            let timeout = Duration::from_millis(config.upstream.timeout_ms);

            // Load a snapshot of the current blocklist — lock-free
            let bl = blocklist.load();
            let qr = Self::check_blocklist(&query_data, &bl.bloom, &bl.trie);

            if let Some(nxdomain_bytes) = qr.nxdomain {
                let _ = socket.send_to(&nxdomain_bytes, src).await;
                let latency = start.elapsed().as_millis();
                metrics.record("blocked", latency as u64, &qr.domain);
                Self::emit_event(
                    event_tx,
                    &qr.domain,
                    &qr.qtype,
                    "blocked",
                    latency as u64,
                    "udp",
                );
                Self::log_outcome(src, &qr.domain, &qr.qtype, "blocked", latency, "udp");
                continue;
            }

            Self::check_tunneling(entropy_detector, cdn_whitelist, &qr.domain, metrics);

            let response = if use_doh {
                Self::forward_doh(http, config.doh_url(), &query_data).await
            } else {
                let upstream_addr = config.upstream_addr()?;
                Self::forward_udp(&fwd_socket, &query_data, upstream_addr, timeout).await
            };

            let proto = if use_doh { "doh" } else { "udp" };

            match response {
                Ok(response_data) => {
                    if let Err(e) = socket.send_to(&response_data, src).await {
                        error!(src = %src, error = %e, "failed to send response");
                    }
                    let latency = start.elapsed().as_millis();
                    metrics.record("allowed", latency as u64, &qr.domain);
                    Self::emit_event(
                        event_tx,
                        &qr.domain,
                        &qr.qtype,
                        "allowed",
                        latency as u64,
                        proto,
                    );
                    Self::log_outcome(src, &qr.domain, &qr.qtype, "allowed", latency, proto);
                }
                Err(e) => {
                    warn!(src = %src, error = %e, "upstream query failed");
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn run_tcp(
        listener: TcpListener,
        config: Arc<Config>,
        blocklist: Arc<ArcSwap<Blocklist>>,
        http: reqwest::Client,
        metrics: Arc<QueryMetrics>,
        event_tx: Option<mpsc::Sender<QueryEvent>>,
        entropy_detector: Option<Arc<EntropyDetector>>,
        cdn_whitelist: Option<Arc<CdnWhitelist>>,
    ) -> anyhow::Result<()> {
        let use_doh = config.upstream.protocol == UpstreamProtocol::Doh;
        let doh_url = config.doh_url().to_string();
        let event_tx = Arc::new(event_tx);
        // Shared forwarding socket for UDP-first upstream, reused across connections
        let fwd_socket = Arc::new(UdpSocket::bind("0.0.0.0:0").await?);
        loop {
            let (stream, src) = listener.accept().await?;
            let timeout = Duration::from_millis(config.upstream.timeout_ms);
            let upstream_addr = if use_doh {
                None
            } else {
                Some(config.upstream_addr()?)
            };
            let blocklist = blocklist.clone();
            let http = http.clone();
            let doh_url = doh_url.clone();
            let fwd_socket = fwd_socket.clone();
            let metrics = metrics.clone();
            let event_tx = event_tx.clone();
            let entropy_detector = entropy_detector.clone();
            let cdn_whitelist = cdn_whitelist.clone();

            // Spawn a task per TCP connection so we don't block the accept loop
            tokio::spawn(async move {
                // Load blocklist snapshot for this connection
                let bl = blocklist.load();
                let ctx = TcpClientCtx {
                    upstream: upstream_addr,
                    timeout,
                    blocklist: &bl,
                    use_doh,
                    http: &http,
                    doh_url: &doh_url,
                    fwd_socket: &fwd_socket,
                    metrics: &metrics,
                    event_tx: &event_tx,
                    entropy_detector: entropy_detector.as_deref(),
                    cdn_whitelist: cdn_whitelist.as_deref(),
                };
                if let Err(e) = Self::handle_tcp_client(stream, src, &ctx).await {
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
        ctx: &TcpClientCtx<'_>,
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

        let qr = Self::check_blocklist(&query_data, &ctx.blocklist.bloom, &ctx.blocklist.trie);

        if let Some(nxdomain_bytes) = qr.nxdomain {
            let len_bytes = (nxdomain_bytes.len() as u16).to_be_bytes();
            stream.write_all(&len_bytes).await?;
            stream.write_all(&nxdomain_bytes).await?;
            let latency = start.elapsed().as_millis();
            ctx.metrics.record("blocked", latency as u64, &qr.domain);
            Self::emit_event(
                ctx.event_tx,
                &qr.domain,
                &qr.qtype,
                "blocked",
                latency as u64,
                "tcp",
            );
            Self::log_outcome(src, &qr.domain, &qr.qtype, "blocked", latency, "tcp");
            return Ok(());
        }

        Self::check_tunneling(
            ctx.entropy_detector,
            ctx.cdn_whitelist,
            &qr.domain,
            ctx.metrics,
        );

        let (response_data, proto) = if ctx.use_doh {
            // DoH handles large responses natively — no truncation retry needed
            (
                Self::forward_doh(ctx.http, ctx.doh_url, &query_data).await?,
                "doh",
            )
        } else {
            let upstream = ctx
                .upstream
                .ok_or_else(|| anyhow::anyhow!("upstream addr required for UDP/TCP forwarding"))?;
            let mut data =
                Self::forward_udp(ctx.fwd_socket, &query_data, upstream, ctx.timeout).await?;

            // Check if upstream response has TC (truncated) bit — retry over TCP
            if let Ok(msg) = Message::from_bytes(&data) {
                if msg.truncated() {
                    debug!(src = %src, "upstream response truncated, retrying over TCP");
                    data = Self::forward_tcp(&query_data, upstream, ctx.timeout).await?;
                }
            }
            (data, "tcp")
        };

        // Write response with 2-byte length prefix
        let len_bytes = (response_data.len() as u16).to_be_bytes();
        stream.write_all(&len_bytes).await?;
        stream.write_all(&response_data).await?;
        let latency = start.elapsed().as_millis();
        ctx.metrics.record("allowed", latency as u64, &qr.domain);
        Self::emit_event(
            ctx.event_tx,
            &qr.domain,
            &qr.qtype,
            "allowed",
            latency as u64,
            proto,
        );
        Self::log_outcome(src, &qr.domain, &qr.qtype, "allowed", latency, proto);

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

    /// Forward a DNS query via DNS-over-HTTPS (RFC 8484).
    async fn forward_doh(
        http: &reqwest::Client,
        doh_url: &str,
        query: &[u8],
    ) -> anyhow::Result<Vec<u8>> {
        let resp = http
            .post(doh_url)
            .header("content-type", "application/dns-message")
            .header("accept", "application/dns-message")
            .body(query.to_vec())
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?;
        Ok(resp.to_vec())
    }

    /// Parses the DNS query, extracts domain + qtype, checks the blocklist.
    fn check_blocklist(
        query_data: &[u8],
        bloom: &Option<BloomFilter>,
        trie: &DomainTrie,
    ) -> QueryResult {
        let message = match Message::from_bytes(query_data) {
            Ok(m) => m,
            Err(e) => {
                warn!(error = %e, "failed to parse DNS query");
                return QueryResult {
                    domain: String::new(),
                    qtype: String::new(),
                    nxdomain: None,
                };
            }
        };
        let Some(query) = message.queries().first() else {
            warn!("DNS query has no question section");
            return QueryResult {
                domain: String::new(),
                qtype: String::new(),
                nxdomain: None,
            };
        };
        let domain = query
            .name()
            .to_ascii()
            .to_lowercase()
            .trim_end_matches('.')
            .to_string();
        let qtype = query.query_type().to_string();

        // Stage 1: bloom pre-filter — check domain and each parent label.
        // A miss on every ancestor means definitely not blocked; skip the trie.
        if let Some(bl) = bloom {
            let maybe_blocked = Self::ancestors(&domain).any(|d| bl.contains(&d));
            if !maybe_blocked {
                return QueryResult {
                    domain,
                    qtype,
                    nxdomain: None,
                };
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
            match response.to_bytes() {
                Ok(bytes) => QueryResult {
                    domain,
                    qtype,
                    nxdomain: Some(bytes),
                },
                Err(e) => {
                    warn!(domain = %domain, error = %e, "failed to serialize NXDOMAIN response");
                    QueryResult {
                        domain,
                        qtype,
                        nxdomain: None,
                    }
                }
            }
        } else {
            QueryResult {
                domain,
                qtype,
                nxdomain: None,
            }
        }
    }

    /// Yields the domain and each parent: "a.b.com" → "a.b.com", "b.com", "com"
    fn ancestors(domain: &str) -> impl Iterator<Item = &str> {
        std::iter::successors(Some(domain), |d| d.find('.').map(|i| &d[i + 1..]))
    }

    fn log_outcome(
        src: SocketAddr,
        domain: &str,
        qtype: &str,
        action: &str,
        latency_ms: u128,
        proto: &str,
    ) {
        info!(
            src = %src,
            domain = %domain,
            qtype = %qtype,
            action = %action,
            latency_ms = %latency_ms,
            proto = %proto,
            "query"
        );
    }

    /// If the detector flags the domain, emit a warning log and bump the
    /// tunneling counter. Trusted CDN domains short-circuit before the
    /// entropy check to suppress known false positives. No-op when the
    /// detector is disabled.
    fn check_tunneling(
        detector: Option<&EntropyDetector>,
        cdn_whitelist: Option<&CdnWhitelist>,
        domain: &str,
        metrics: &QueryMetrics,
    ) {
        let Some(detector) = detector else { return };

        if let Some(cdn) = cdn_whitelist {
            if cdn.is_cdn(domain) {
                return;
            }
        }

        if detector.is_suspicious(domain) {
            metrics.record_tunneling_flag();
            warn!(
                domain = %domain,
                entropy_flagged = true,
                "suspicious high-entropy DNS query (possible tunneling)"
            );
        }
    }

    fn emit_event(
        tx: &Option<mpsc::Sender<QueryEvent>>,
        domain: &str,
        qtype: &str,
        action: &str,
        latency_ms: u64,
        proto: &str,
    ) {
        if let Some(tx) = tx {
            let _ = tx.try_send(QueryEvent {
                timestamp: Instant::now(),
                domain: domain.to_string(),
                qtype: qtype.to_string(),
                action: action.to_string(),
                latency_ms,
                proto: proto.to_string(),
            });
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{Header, MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;

    /// Build a minimal DNS query for the given domain.
    fn make_query(domain: &str) -> Vec<u8> {
        let mut msg = Message::new();
        let mut header = Header::new();
        header.set_id(1234);
        header.set_op_code(OpCode::Query);
        header.set_recursion_desired(true);
        msg.set_header(header);
        msg.add_query(Query::query(
            Name::from_ascii(domain).unwrap(),
            RecordType::A,
        ));
        msg.to_bytes().unwrap()
    }

    #[test]
    fn check_blocklist_blocks_exact_domain() {
        let mut bloom = BloomFilter::new(10, 0.01);
        bloom.insert(&"evil.com".to_string());
        let mut trie = DomainTrie::new();
        trie.insert("evil.com");

        let query = make_query("evil.com");
        let qr = DnsProxy::check_blocklist(&query, &Some(bloom), &trie);

        assert_eq!(qr.domain, "evil.com");
        assert_eq!(qr.qtype, "A");
        assert!(qr.nxdomain.is_some());

        // Verify the response is NXDOMAIN
        let resp = Message::from_bytes(&qr.nxdomain.unwrap()).unwrap();
        assert_eq!(resp.response_code(), ResponseCode::NXDomain);
        assert_eq!(resp.message_type(), MessageType::Response);
        assert!(resp.answers().is_empty());
    }

    #[test]
    fn check_blocklist_allows_clean_domain() {
        let mut bloom = BloomFilter::new(10, 0.01);
        bloom.insert(&"evil.com".to_string());
        let mut trie = DomainTrie::new();
        trie.insert("evil.com");

        let query = make_query("google.com");
        let qr = DnsProxy::check_blocklist(&query, &Some(bloom), &trie);

        assert_eq!(qr.domain, "google.com");
        assert!(qr.nxdomain.is_none());
    }

    #[test]
    fn check_blocklist_blocks_subdomain_via_wildcard() {
        let mut bloom = BloomFilter::new(10, 0.01);
        bloom.insert(&"malware.com".to_string());
        let mut trie = DomainTrie::new();
        trie.insert("malware.com");

        let query = make_query("sub.malware.com");
        let qr = DnsProxy::check_blocklist(&query, &Some(bloom), &trie);

        assert_eq!(qr.domain, "sub.malware.com");
        assert!(qr.nxdomain.is_some());
    }

    #[test]
    fn check_blocklist_handles_no_bloom() {
        let mut trie = DomainTrie::new();
        trie.insert("evil.com");

        let query = make_query("evil.com");
        let qr = DnsProxy::check_blocklist(&query, &None, &trie);
        assert!(
            qr.nxdomain.is_some(),
            "should block even without bloom filter"
        );
    }

    #[test]
    fn check_blocklist_handles_invalid_dns() {
        let trie = DomainTrie::new();
        let garbage = vec![0xFF, 0x00, 0x01];
        let qr = DnsProxy::check_blocklist(&garbage, &None, &trie);
        assert!(qr.domain.is_empty());
        assert!(qr.nxdomain.is_none());
    }

    #[test]
    fn nxdomain_response_preserves_query_id() {
        let mut bloom = BloomFilter::new(10, 0.01);
        bloom.insert(&"evil.com".to_string());
        let mut trie = DomainTrie::new();
        trie.insert("evil.com");

        let query_bytes = make_query("evil.com");
        let original = Message::from_bytes(&query_bytes).unwrap();
        let qr = DnsProxy::check_blocklist(&query_bytes, &Some(bloom), &trie);

        let resp = Message::from_bytes(&qr.nxdomain.unwrap()).unwrap();
        assert_eq!(resp.id(), original.id(), "response ID must match query ID");
    }

    #[tokio::test]
    async fn hot_reload_swaps_blocklist() {
        let blocklist = Arc::new(ArcSwap::from_pointee(Blocklist {
            bloom: None,
            trie: DomainTrie::new(),
        }));

        // Initially empty — nothing blocked
        let query = make_query("evil.com");
        let bl = blocklist.load();
        let qr = DnsProxy::check_blocklist(&query, &bl.bloom, &bl.trie);
        assert!(qr.nxdomain.is_none(), "should not be blocked before reload");

        // Simulate a reload: build new blocklist with evil.com
        let mut new_bloom = BloomFilter::new(10, 0.01);
        new_bloom.insert(&"evil.com".to_string());
        let mut new_trie = DomainTrie::new();
        new_trie.insert("evil.com");
        blocklist.store(Arc::new(Blocklist {
            bloom: Some(new_bloom),
            trie: new_trie,
        }));

        // After reload — evil.com is blocked
        let bl = blocklist.load();
        let qr = DnsProxy::check_blocklist(&query, &bl.bloom, &bl.trie);
        assert!(qr.nxdomain.is_some(), "should be blocked after reload");
    }

    #[test]
    fn metrics_record_and_snapshot() {
        let m = QueryMetrics::new();
        m.record("blocked", 5, "evil.com");
        m.record("allowed", 15, "google.com");
        m.record("allowed", 10, "github.com");

        let snap = m.snapshot();
        assert_eq!(snap.total, 3);
        assert_eq!(snap.blocked, 1);
        assert_eq!(snap.allowed, 2);
        assert_eq!(snap.total_latency_ms, 30);
        assert!((snap.avg_latency_ms() - 10.0).abs() < f64::EPSILON);
    }

    #[test]
    fn top_blocked_returns_sorted() {
        let m = QueryMetrics::new();
        m.record("blocked", 1, "evil.com");
        m.record("blocked", 1, "evil.com");
        m.record("blocked", 1, "evil.com");
        m.record("blocked", 1, "malware.org");
        m.record("blocked", 1, "phish.net");
        m.record("blocked", 1, "phish.net");
        m.record("allowed", 1, "google.com");

        let top = m.top_blocked(2);
        assert_eq!(top.len(), 2);
        assert_eq!(top[0], ("evil.com".to_string(), 3));
        assert_eq!(top[1], ("phish.net".to_string(), 2));
    }

    #[test]
    fn top_blocked_empty() {
        let m = QueryMetrics::new();
        m.record("allowed", 1, "google.com");
        assert!(m.top_blocked(10).is_empty());
    }
}
