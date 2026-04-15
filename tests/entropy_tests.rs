use std::net::UdpSocket as StdUdpSocket;
use std::time::Duration;

use hickory_proto::op::{Header, Message, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::net::UdpSocket;

use dnsink::cdn_whitelist::CdnProvider;
use dnsink::config::{
    CdnWhitelistConfig, Config, FeedsConfig, ListenConfig, LoggingConfig, TunnelingDetectionConfig,
    UpstreamConfig,
};
use dnsink::entropy::EntropyDetector;
use dnsink::proxy::DnsProxy;
use dnsink::trie::DomainTrie;

#[test]
fn normal_domain_not_flagged() {
    let detector = EntropyDetector::new(3.5, 20);
    assert!(!detector.is_suspicious("example.com"));
}

#[test]
fn mixed_string_has_higher_entropy_than_repeated() {
    let detector = EntropyDetector::new(3.5, 20);
    let low = detector.shannon_entropy("aaaa");
    let high = detector.shannon_entropy("a1b2c3d4");
    assert!(low < high, "expected {low} < {high}");
}

/// Find a free UDP port.
fn free_port() -> u16 {
    StdUdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

fn make_query(domain: &str) -> Vec<u8> {
    let mut msg = Message::new();
    let mut header = Header::new();
    header.set_id(1);
    header.set_op_code(OpCode::Query);
    header.set_recursion_desired(true);
    msg.set_header(header);
    msg.add_query(Query::query(
        Name::from_ascii(domain).unwrap(),
        RecordType::A,
    ));
    msg.to_bytes().unwrap()
}

/// Build a test config with tunneling detection + CDN whitelist enabled,
/// pointing upstream at a black-hole port so queries never resolve but the
/// tunneling check (which runs *before* forwarding) is exercised.
fn tunneling_test_config(listen_port: u16, upstream_port: u16) -> Config {
    Config {
        listen: ListenConfig {
            address: "127.0.0.1".to_string(),
            port: listen_port,
        },
        upstream: UpstreamConfig {
            address: "127.0.0.1".to_string(),
            port: upstream_port,
            timeout_ms: 100,
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
        tunneling_detection: TunnelingDetectionConfig {
            enabled: true,
            entropy_threshold: 3.5,
            min_subdomain_length: 20,
            cdn_whitelist: CdnWhitelistConfig {
                enabled: true,
                providers: vec![
                    CdnProvider::Aws,
                    CdnProvider::Cloudflare,
                    CdnProvider::Akamai,
                ],
            },
        },
    }
}

/// End-to-end: a high-entropy CloudFront subdomain must NOT bump
/// tunneling_flagged, because the CDN whitelist short-circuits the
/// entropy check.
#[tokio::test]
async fn cdn_domain_skips_entropy_flagging() {
    let listen_port = free_port();
    // Bind the "upstream" socket but never read from it — queries will time
    // out, but the tunneling check runs before the forward, so the counter
    // is observable regardless.
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = blackhole.local_addr().unwrap().port();

    let config = tunneling_test_config(listen_port, upstream_port);
    let proxy = DnsProxy::new(config, None, DomainTrie::new()).unwrap();
    let metrics = proxy.metrics();
    tokio::spawn(async move {
        let _ = proxy.run().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("127.0.0.1:{listen_port}");

    // High-entropy CloudFront subdomain — the false positive we're suppressing.
    let cf_query = make_query("d1a2b3c4d5e6f7g8h9i0.cloudfront.net");
    client.send_to(&cf_query, &addr).await.unwrap();

    // Give the proxy time to process the query and run check_tunneling.
    // Upstream will time out (100ms) but that's fine.
    tokio::time::sleep(Duration::from_millis(300)).await;

    let snap = metrics.snapshot();
    assert_eq!(
        snap.tunneling_flagged, 0,
        "CDN domain should not be flagged (snapshot: {snap:?})"
    );
}

/// Negative control: a genuinely high-entropy non-CDN domain DOES bump
/// the tunneling_flagged counter. Guards against a refactor that
/// accidentally disables the detector along with the whitelist.
#[tokio::test]
async fn non_cdn_high_entropy_domain_is_flagged() {
    let listen_port = free_port();
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let upstream_port = blackhole.local_addr().unwrap().port();

    let config = tunneling_test_config(listen_port, upstream_port);
    let proxy = DnsProxy::new(config, None, DomainTrie::new()).unwrap();
    let metrics = proxy.metrics();
    tokio::spawn(async move {
        let _ = proxy.run().await;
    });
    tokio::time::sleep(Duration::from_millis(100)).await;

    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = format!("127.0.0.1:{listen_port}");

    // 27 distinct chars, non-CDN parent → should flag.
    let suspicious = make_query("k8j4h2g9f7d5s3a1q6w8e4r2t0y.example.com");
    client.send_to(&suspicious, &addr).await.unwrap();

    tokio::time::sleep(Duration::from_millis(300)).await;

    let snap = metrics.snapshot();
    assert_eq!(
        snap.tunneling_flagged, 1,
        "high-entropy non-CDN domain should be flagged (snapshot: {snap:?})"
    );
}
