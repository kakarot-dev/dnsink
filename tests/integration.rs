use std::net::UdpSocket as StdUdpSocket;
use std::time::Duration;

use hickory_proto::op::{Header, Message, MessageType, OpCode, Query, ResponseCode};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use dnsink::bloom::BloomFilter;
use dnsink::config::{Config, FeedsConfig, ListenConfig, LoggingConfig, UpstreamConfig};
use dnsink::proxy::DnsProxy;
use dnsink::trie::DomainTrie;

/// Find a free port by binding to port 0 and reading the assigned port.
fn free_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Build a minimal DNS A-record query for the given domain.
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

/// Create a test config pointing at the given port with no live feeds.
fn test_config(port: u16) -> Config {
    Config {
        listen: ListenConfig {
            address: "127.0.0.1".to_string(),
            port,
        },
        upstream: UpstreamConfig {
            address: "8.8.8.8".to_string(),
            port: 53,
            timeout_ms: 5000,
            protocol: Default::default(),
            doh_url: None,
        },
        blocklist: None,
        feeds: FeedsConfig {
            urlhaus: false,
            openphish: false,
            phishtank_api_key: None,
            refresh_secs: 0,
        },
        logging: LoggingConfig::default(),
        tunneling_detection: Default::default(),
        metrics: Default::default(),
    }
}

/// Build a small blocklist with two test domains.
fn test_blocklist() -> (Option<BloomFilter>, DomainTrie) {
    let domains = ["evil.com", "malware.org"];
    let mut bloom = BloomFilter::new(domains.len(), 0.01);
    let mut trie = DomainTrie::new();
    for d in &domains {
        bloom.insert(&d.to_string());
        trie.insert(d);
    }
    (Some(bloom), trie)
}

/// Spawn the proxy in the background and wait for it to bind.
async fn spawn_proxy(port: u16) -> std::sync::Arc<dnsink::proxy::QueryMetrics> {
    let config = test_config(port);
    let (bloom, trie) = test_blocklist();
    let proxy = DnsProxy::new(config, bloom, trie).unwrap();
    let metrics = proxy.metrics();
    tokio::spawn(async move {
        proxy.run().await.unwrap();
    });
    tokio::time::sleep(Duration::from_millis(100)).await;
    metrics
}

#[tokio::test]
async fn udp_blocked_domain_returns_nxdomain() {
    let port = free_port();
    spawn_proxy(port).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = make_query("evil.com");
    client
        .send_to(&query, format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("timeout waiting for response")
        .unwrap();

    let response = Message::from_bytes(&buf[..len]).unwrap();
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
    assert_eq!(response.message_type(), MessageType::Response);
    assert_eq!(response.id(), 1234);
}

#[tokio::test]
async fn udp_subdomain_of_blocked_domain_returns_nxdomain() {
    let port = free_port();
    spawn_proxy(port).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = make_query("sub.evil.com");
    client
        .send_to(&query, format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .expect("timeout waiting for response")
        .unwrap();

    let response = Message::from_bytes(&buf[..len]).unwrap();
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
}

#[tokio::test]
#[ignore] // requires network access to 8.8.8.8
async fn udp_clean_domain_gets_forwarded() {
    let port = free_port();
    spawn_proxy(port).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let query = make_query("google.com");
    client
        .send_to(&query, format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    let mut buf = vec![0u8; 4096];
    let len = tokio::time::timeout(Duration::from_secs(5), client.recv(&mut buf))
        .await
        .expect("timeout — is network available?")
        .unwrap();

    let response = Message::from_bytes(&buf[..len]).unwrap();
    assert_eq!(response.response_code(), ResponseCode::NoError);
    assert_eq!(response.message_type(), MessageType::Response);
    assert!(!response.answers().is_empty(), "should have DNS answers");
}

#[tokio::test]
async fn tcp_blocked_domain_returns_nxdomain() {
    let port = free_port();
    spawn_proxy(port).await;

    let mut stream = tokio::net::TcpStream::connect(format!("127.0.0.1:{port}"))
        .await
        .unwrap();

    // DNS over TCP: 2-byte big-endian length prefix + message
    let query = make_query("evil.com");
    let len_bytes = (query.len() as u16).to_be_bytes();
    stream.write_all(&len_bytes).await.unwrap();
    stream.write_all(&query).await.unwrap();

    // Read response: 2-byte length prefix + message
    let resp_len = stream.read_u16().await.unwrap() as usize;
    let mut resp_buf = vec![0u8; resp_len];
    stream.read_exact(&mut resp_buf).await.unwrap();

    let response = Message::from_bytes(&resp_buf).unwrap();
    assert_eq!(response.response_code(), ResponseCode::NXDomain);
    assert_eq!(response.message_type(), MessageType::Response);
    assert_eq!(response.id(), 1234);
}

#[tokio::test]
async fn metrics_update_after_queries() {
    let port = free_port();
    let metrics = spawn_proxy(port).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("127.0.0.1:{port}");
    let mut buf = vec![0u8; 4096];

    // Two blocked queries
    client
        .send_to(&make_query("evil.com"), &addr)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();

    client
        .send_to(&make_query("malware.org"), &addr)
        .await
        .unwrap();
    tokio::time::timeout(Duration::from_secs(2), client.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();

    let snap = metrics.snapshot();
    assert_eq!(snap.total, 2);
    assert_eq!(snap.blocked, 2);
    assert_eq!(snap.allowed, 0);

    let top = metrics.top_blocked(10);
    assert_eq!(top.len(), 2);
}
