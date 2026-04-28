//! Prometheus /metrics endpoint.
//!
//! Hand-rolled on raw hyper 1.x (transitively already in the tree via
//! reqwest). No axum, no prometheus crate — the exposition format for
//! five counters is a single `format!` call, and the routing is a
//! method+path match.
//!
//! The caller binds the TCP listener so tests can use port 0 and read
//! back the ephemeral port. Production callers bind to the configured
//! address.

use std::convert::Infallible;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use tokio::net::TcpListener;
use tracing::{debug, info};

use crate::proxy::{MetricsSnapshot, QueryMetrics};

const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// Accept loop. Runs until the listener errors unrecoverably.
pub async fn serve(listener: TcpListener, metrics: Arc<QueryMetrics>) -> anyhow::Result<()> {
    let local = listener.local_addr()?;
    info!(addr = %local, "metrics server listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let metrics = metrics.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req: Request<Incoming>| {
                let metrics = metrics.clone();
                async move { Ok::<_, Infallible>(handle(req, &metrics)) }
            });
            if let Err(e) = http1::Builder::new().serve_connection(io, service).await {
                debug!(peer = %peer, error = %e, "metrics connection closed");
            }
        });
    }
}

fn handle(req: Request<Incoming>, metrics: &QueryMetrics) -> Response<Full<Bytes>> {
    if req.method() == Method::GET && req.uri().path() == "/metrics" {
        let body = format_metrics(&metrics.snapshot());
        return Response::builder()
            .status(StatusCode::OK)
            .header("content-type", CONTENT_TYPE)
            .body(Full::new(Bytes::from(body)))
            .expect("response builder inputs are static");
    }

    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "text/plain; charset=utf-8")
        .body(Full::new(Bytes::from_static(b"not found\n")))
        .expect("response builder inputs are static")
}

/// Prometheus 0.0.4 text exposition for the five counters on
/// `QueryMetrics`. Snapshot-based — a single consistent read per scrape,
/// which is cheaper than you'd think because `snapshot()` is just five
/// relaxed atomic loads.
fn format_metrics(s: &MetricsSnapshot) -> String {
    // One allocation, not five. Each metric is: HELP line + TYPE line + sample line.
    format!(
        concat!(
            "# HELP dnsink_queries_total Total DNS queries processed\n",
            "# TYPE dnsink_queries_total counter\n",
            "dnsink_queries_total {total}\n",
            "# HELP dnsink_queries_blocked_total Queries blocked by threat feeds\n",
            "# TYPE dnsink_queries_blocked_total counter\n",
            "dnsink_queries_blocked_total {blocked}\n",
            "# HELP dnsink_queries_allowed_total Queries forwarded upstream\n",
            "# TYPE dnsink_queries_allowed_total counter\n",
            "dnsink_queries_allowed_total {allowed}\n",
            "# HELP dnsink_query_latency_ms_total Cumulative query latency in milliseconds\n",
            "# TYPE dnsink_query_latency_ms_total counter\n",
            "dnsink_query_latency_ms_total {latency}\n",
            "# HELP dnsink_tunneling_flagged_total Queries flagged as DNS tunneling candidates\n",
            "# TYPE dnsink_tunneling_flagged_total counter\n",
            "dnsink_tunneling_flagged_total {tunneling}\n",
            "# HELP dnsink_ratelimited_total Queries silently dropped by the per-source rate limiter\n",
            "# TYPE dnsink_ratelimited_total counter\n",
            "dnsink_ratelimited_total {ratelimited}\n",
        ),
        total = s.total,
        blocked = s.blocked,
        allowed = s.allowed,
        latency = s.total_latency_ms,
        tunneling = s.tunneling_flagged,
        ratelimited = s.ratelimited,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_contains_all_metric_names() {
        let snap = MetricsSnapshot {
            total: 0,
            blocked: 0,
            allowed: 0,
            total_latency_ms: 0,
            tunneling_flagged: 0,
            ratelimited: 0,
        };
        let body = format_metrics(&snap);
        for name in [
            "dnsink_queries_total",
            "dnsink_queries_blocked_total",
            "dnsink_queries_allowed_total",
            "dnsink_query_latency_ms_total",
            "dnsink_tunneling_flagged_total",
            "dnsink_ratelimited_total",
        ] {
            assert!(body.contains(name), "missing metric: {name}\n{body}");
            assert!(body.contains(&format!("# TYPE {name} counter")));
            assert!(body.contains(&format!("# HELP {name} ")));
        }
    }

    #[test]
    fn format_renders_sample_values() {
        let snap = MetricsSnapshot {
            total: 42,
            blocked: 7,
            allowed: 35,
            total_latency_ms: 1234,
            tunneling_flagged: 3,
            ratelimited: 9,
        };
        let body = format_metrics(&snap);
        assert!(body.contains("\ndnsink_queries_total 42\n"));
        assert!(body.contains("\ndnsink_queries_blocked_total 7\n"));
        assert!(body.contains("\ndnsink_queries_allowed_total 35\n"));
        assert!(body.contains("\ndnsink_query_latency_ms_total 1234\n"));
        assert!(body.contains("\ndnsink_tunneling_flagged_total 3\n"));
        assert!(body.contains("\ndnsink_ratelimited_total 9\n"));
    }
}
