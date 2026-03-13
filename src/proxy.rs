use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, ResponseCode};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::bloom::BloomFilter;
use crate::config::Config;
use crate::trie::DomainTrie;

/// Maximum DNS message size with EDNS0 support
const MAX_DNS_MSG_SIZE: usize = 4096;

struct Shared {
    config: Config,
    bloom: Option<BloomFilter>,
    trie: DomainTrie,
}

pub struct DnsProxy {
    shared: Arc<Shared>,
}

impl DnsProxy {
    pub fn new(config: Config, bloom: Option<BloomFilter>, trie: DomainTrie) -> Self {
        Self {
            shared: Arc::new(Shared { config, bloom, trie }),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let listen_addr = format!(
            "{}:{}",
            self.shared.config.listen.address, self.shared.config.listen.port
        );

        let udp_socket = UdpSocket::bind(&listen_addr).await?;
        let tcp_listener = TcpListener::bind(&listen_addr).await?;
        info!("listening on {listen_addr} (UDP + TCP)");

        let shared = self.shared.clone();
        let udp_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_udp(udp_socket, &shared).await {
                error!(error = %e, "UDP listener failed");
            }
        });

        let shared = self.shared.clone();
        let tcp_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_tcp(tcp_listener, shared).await {
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

    async fn run_udp(socket: UdpSocket, shared: &Shared) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_DNS_MSG_SIZE];

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let query_data = buf[..len].to_vec();
            let start = Instant::now();

            let upstream_addr = shared.config.upstream_addr()?;
            let timeout = Duration::from_millis(shared.config.upstream.timeout_ms);

            let (domain, nxdomain) = Self::check_blocklist(&query_data, &shared.bloom, &shared.trie);

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

    async fn run_tcp(listener: TcpListener, shared: Arc<Shared>) -> anyhow::Result<()> {
        loop {
            let (stream, src) = listener.accept().await?;
            let upstream_addr = shared.config.upstream_addr()?;
            let timeout = Duration::from_millis(shared.config.upstream.timeout_ms);
            let shared = shared.clone();

            // Spawn a task per TCP connection so we don't block the accept loop
            tokio::spawn(async move {
                if let Err(e) = Self::handle_tcp_client(stream, src, upstream_addr, timeout, &shared.bloom, &shared.trie).await {
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
                response_data =
                    Self::forward_tcp(&query_data, upstream, timeout).await?;
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
        let domain = query.name().to_ascii().to_lowercase().trim_end_matches('.').to_string();

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
