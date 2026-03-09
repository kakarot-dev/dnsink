use std::net::SocketAddr;
use std::time::Duration;

use hickory_proto::op::Message;
use hickory_proto::serialize::binary::BinDecodable;
use tokio::net::UdpSocket;
use tracing::{debug, error, info, warn};

use crate::config::Config;

pub struct DnsProxy {
    config: Config,
}

impl DnsProxy {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub async fn run(&self) -> anyhow::Result<()> {
        let listen_addr = format!(
            "{}:{}",
            self.config.listen.address, self.config.listen.port
        );

        let socket = UdpSocket::bind(&listen_addr).await?;
        info!("listening on {listen_addr}");

        let mut buf = vec![0u8; 512];

        loop {
            let (len, src) = socket.recv_from(&mut buf).await?;
            let query_data = buf[..len].to_vec();

            let upstream_addr: SocketAddr = format!(
                "{}:{}",
                self.config.upstream.address, self.config.upstream.port
            )
            .parse()?;
            let timeout = Duration::from_millis(self.config.upstream.timeout_ms);

            // Log the query domain if we can parse it
            if let Ok(message) = Message::from_bytes(&query_data) {
                if let Some(query) = message.queries().first() {
                    debug!(
                        domain = %query.name(),
                        qtype = %query.query_type(),
                        src = %src,
                        "query"
                    );
                }
            }

            let socket_clone = UdpSocket::bind("0.0.0.0:0").await?;
            let response = Self::forward_query(&socket_clone, &query_data, upstream_addr, timeout).await;

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

    async fn forward_query(
        socket: &UdpSocket,
        query: &[u8],
        upstream: SocketAddr,
        timeout: Duration,
    ) -> anyhow::Result<Vec<u8>> {
        socket.send_to(query, upstream).await?;

        let mut buf = vec![0u8; 512];
        let len = tokio::time::timeout(timeout, socket.recv(&mut buf)).await??;
        buf.truncate(len);
        Ok(buf)
    }
}
