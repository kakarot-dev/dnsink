use std::sync::atomic::Ordering;
use std::sync::Arc;
use std::time::Duration;

use tokio::net::TcpListener;

use dnsink::metrics_server;
use dnsink::proxy::QueryMetrics;

/// Spin up the metrics server on an ephemeral port and return the bound
/// address plus the shared metrics handle. The listener is owned by the
/// spawned task; the caller only needs the URL.
async fn spawn_metrics_server() -> (String, Arc<QueryMetrics>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let metrics = Arc::new(QueryMetrics::new());
    let m = metrics.clone();
    tokio::spawn(async move {
        let _ = metrics_server::serve(listener, m).await;
    });
    // Give the accept loop a beat to enter before the first request.
    tokio::time::sleep(Duration::from_millis(50)).await;
    (format!("http://{addr}"), metrics)
}

#[tokio::test]
async fn serves_metrics_endpoint() {
    let (base, _metrics) = spawn_metrics_server().await;

    let resp = reqwest::get(format!("{base}/metrics")).await.unwrap();
    assert_eq!(resp.status(), 200);

    let ct = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    assert!(ct.contains("text/plain"), "content-type was: {ct}");
    assert!(ct.contains("version=0.0.4"));

    let body = resp.text().await.unwrap();
    for name in [
        "dnsink_queries_total",
        "dnsink_queries_blocked_total",
        "dnsink_queries_allowed_total",
        "dnsink_query_latency_ms_total",
        "dnsink_tunneling_flagged_total",
    ] {
        assert!(body.contains(name), "body missing {name}:\n{body}");
    }
}

#[tokio::test]
async fn metric_values_reflect_atomics() {
    let (base, metrics) = spawn_metrics_server().await;

    // Bump counters via the raw atomics (avoids requiring a public mutator).
    metrics.total.fetch_add(17, Ordering::Relaxed);
    metrics.blocked.fetch_add(5, Ordering::Relaxed);
    metrics.tunneling_flagged.fetch_add(2, Ordering::Relaxed);

    let body = reqwest::get(format!("{base}/metrics"))
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    // Exact-value matches — surrounded by newlines so we don't accidentally
    // match a substring in another metric's name.
    assert!(
        body.contains("\ndnsink_queries_total 17\n"),
        "body:\n{body}"
    );
    assert!(
        body.contains("\ndnsink_queries_blocked_total 5\n"),
        "body:\n{body}"
    );
    assert!(
        body.contains("\ndnsink_tunneling_flagged_total 2\n"),
        "body:\n{body}"
    );
    // Untouched counters still render as 0.
    assert!(
        body.contains("\ndnsink_queries_allowed_total 0\n"),
        "body:\n{body}"
    );
}

#[tokio::test]
async fn wrong_path_returns_404() {
    let (base, _metrics) = spawn_metrics_server().await;

    let resp = reqwest::get(format!("{base}/")).await.unwrap();
    assert_eq!(resp.status(), 404, "root should 404");

    let resp = reqwest::get(format!("{base}/healthz")).await.unwrap();
    assert_eq!(resp.status(), 404, "unknown path should 404");
}
