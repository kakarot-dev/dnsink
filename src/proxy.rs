use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tracing::{debug, error, info, warn};

use crate::config::Config;

/// Maximum DNS message size with EDNS0 support
const MAX_DNS_MSG_SIZE: usize = 4096;

pub struct DnsProxy {
    config: Arc<Config>,
}

impl DnsProxy {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
        }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let listen_addr = format!(
            "{}:{}",
            self.config.listen.address, self.config.listen.port
        );

        let udp_socket = UdpSocket::bind(&listen_addr).await?;
        let tcp_listener = TcpListener::bind(&listen_addr).await?;
        info!("listening on {listen_addr} (UDP + TCP)");

        let config = self.config.clone();
        let udp_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_udp(udp_socket, &config).await {
                error!(error = %e, "UDP listener failed");
            }
        });

        let config = self.config.clone();
        let tcp_handle = tokio::spawn(async move {
            if let Err(e) = Self::run_tcp(tcp_listener, &config).await {
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

    async fn run_udp(socket: UdpSocket, config: &Config) -> anyhow::Result<()> {
        let mut buf = vec![0u8; MAX_DNS_MSG_SIZE];

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let query_data = buf[..len].to_vec();

            let upstream_addr = config.upstream_addr()?;
            let timeout = Duration::from_millis(config.upstream.timeout_ms);

            Self::log_query(&query_data, src, "udp");

            let fwd_socket = UdpSocket::bind("0.0.0.0:0").await?;
            let response =
                Self::forward_udp(&fwd_socket, &query_data, upstream_addr, timeout).await;

            match response {
                Ok(response_data) => {
                    if let Err(e) = socket.send_to(&response_data, src).await {
                        error!(src = %src, error = %e, "failed to send response");
                    }
                }
                Err(e) => {
                    warn!(src = %src, error = %e, "upstream query failed");
                }
            }
        }
    }

    async fn run_tcp(listener: TcpListener, config: &Config) -> anyhow::Result<()> {
        loop {
            let (stream, src) = listener.accept().await?;
            let upstream_addr = config.upstream_addr()?;
            let timeout = Duration::from_millis(config.upstream.timeout_ms);

            // Spawn a task per TCP connection so we don't block the accept loop
            tokio::spawn(async move {
                if let Err(e) = Self::handle_tcp_client(stream, src, upstream_addr, timeout).await {
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
    ) -> anyhow::Result<()> {
        // Read 2-byte length prefix
        let msg_len = stream.read_u16().await? as usize;
        if msg_len == 0 || msg_len > MAX_DNS_MSG_SIZE {
            anyhow::bail!("invalid DNS TCP message length: {msg_len}");
        }

        // Read the DNS message
        let mut query_data = vec![0u8; msg_len];
        stream.read_exact(&mut query_data).await?;

        Self::log_query(&query_data, src, "tcp");

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

    fn log_query(data: &[u8], src: SocketAddr, proto: &str) {
        if let Ok(message) = Message::from_bytes(data) {
            if let Some(query) = message.queries().first() {
                debug!(
                    domain = %query.name(),
                    qtype = %query.query_type(),
                    src = %src,
                    proto,
                    "query"
                );
            }
        }
    }
}
