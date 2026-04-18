# dnsink

A high-performance Rust DNS proxy that blocks malware, C2, and phishing domains at the DNS layer using live threat-intelligence feeds. Shannon-entropy tunneling detection with CDN whitelisting, DoH upstream, hot-reload, Prometheus metrics, terminal dashboard.

[![CI](https://github.com/kakarot-dev/dnsink/actions/workflows/ci.yml/badge.svg)](https://github.com/kakarot-dev/dnsink/actions/workflows/ci.yml) [![Docker](https://img.shields.io/badge/ghcr.io-dnsink-blue?logo=docker)](https://github.com/kakarot-dev/dnsink/pkgs/container/dnsink) [![Deploy with flyctl](https://img.shields.io/badge/deploy%20with-flyctl-7b3fbf?logo=flydotio&logoColor=white)](https://fly.io/docs/launch/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Contents

- [Quickstart](#quickstart)
- [Features](#features)
- [How it works](#how-it-works)
- [Benchmarks](#benchmarks)
- [Deploy](#deploy)
- [Configuration](#configuration)
- [License](#license)

## Quickstart

```sh
docker run -d --name dnsink \
  -p 53:5353/tcp -p 5353:5353/udp -p 9090:9090 \
  ghcr.io/kakarot-dev/dnsink:v0.2.0

dig @127.0.0.1 +tcp example.com         # resolves
dig @127.0.0.1 +tcp malware.example.com  # NXDOMAIN
curl http://127.0.0.1:9090/metrics       # Prometheus counters
```

Or launch the terminal dashboard:

```sh
cargo run --release -- --tui
```

## Features

| | dnsink | Pi-hole | AdGuard Home | crab-hole |
|---|---|---|---|---|
| Language | Rust | Shell/PHP | Go | Rust |
| Security feeds (URLhaus, OpenPhish, PhishTank) | Yes | No | No | No |
| DNS tunneling detection (Shannon entropy + CDN whitelist) | Yes | No | No | No |
| Bloom filter pre-screening | Yes | No | No | No |
| DNS-over-HTTPS upstream | Yes | Needs cloudflared | Yes | Yes |
| Hot-reload (lock-free via ArcSwap) | Yes | Restart-based | Yes | Yes |
| Prometheus `/metrics` | Yes | No | No | No |
| Two-stage lookup | ~490 ns | — | — | — |

Unlike Pi-hole and AdGuard Home (ad-blocking focused), dnsink targets active threat infrastructure — C2 servers, phishing pages, malware domains — using feeds that update hourly. The engine is feed-agnostic: ad/tracker blocking is a one-line opt-in via `oisd = true` in config (uses [oisd.nl](https://oisd.nl)'s ~200K-domain list). Point it at any domain list you want.

## How it works

```
Client query (UDP/TCP :5353)
        |
        v
+---------------+
|   DnsProxy    |  receives raw DNS bytes, starts latency timer
+-------+-------+
        |
        v
+---------------+
| BloomFilter   |  stage 1: ~184 ns, 117 KB for 100K items, 1% FPR
|               |  definite miss -> skip trie, forward immediately
+-------+-------+
        | maybe blocked
        v
+---------------+
|  DomainTrie   |  stage 2: label-reversed radix trie
|               |  is_blocked at any ancestor = wildcard block
+-------+-------+
        |
   +----+----+
   |         |
blocked    allowed
   |         |
   v         v
NXDOMAIN  forward to upstream (UDP, TCP, or DoH)
   |         |
   +----+----+
        |
        v
   log + metrics
```

**Two-stage lookup.** The bloom filter eliminates the 99% of queries that are legitimate traffic in ~184 ns. Only probable matches reach the radix trie for authoritative confirmation. The trie stores domains in reverse-label order so wildcard blocks (`malware.com` blocks `*.malware.com`) fall out of the traversal naturally.

**Hot-reload.** Blocklists refresh on a configurable interval without dropping in-flight queries. `ArcSwap` gives lock-free reads; old data stays alive via `Arc` refcounts until outstanding queries drain.

**Tunneling detection.** Subdomain labels are scored by Shannon entropy; anything above the configured threshold with length above the minimum is flagged. A CDN whitelist (AWS / Akamai / Cloudflare) suppresses false positives on legitimate high-entropy providers using label-boundary-safe suffix matching.

## Benchmarks

Criterion, 100K domains, release build:

| Operation | Time |
|---|---|
| Bloom lookup (miss) | 184 ns |
| Bloom lookup (hit) | 87 ns |
| **Two-stage (miss)** | **288 ns** |
| **Two-stage (hit)** | **491 ns** |

## Deploy

**Docker** (distroless/cc-debian12:nonroot, multi-arch amd64 + arm64):

```sh
docker run -d -p 53:5353/tcp -p 5353:5353/udp -p 9090:9090 \
  ghcr.io/kakarot-dev/dnsink:v0.2.0
```

**Fly.io** — `fly.toml` ships with the repo. Requires a dedicated IPv4 for UDP ($2/mo):

```sh
flyctl apps create <your-app>
flyctl ips allocate-v4 --yes
flyctl deploy
```

fly.io requires UDP services to bind `fly-global-services` (wrong source IP on replies otherwise). The repo's `config.docker.toml` uses an asymmetric `listen.tcp_address` override to handle this. See [`config.docker.toml`](config.docker.toml) and [`fly.toml`](fly.toml).

## Configuration

Default config at `config.toml`. Minimal example:

```toml
[listen]
address = "127.0.0.1"
port = 5353

[upstream]
protocol = "doh"
doh_url = "https://1.1.1.1/dns-query"

[feeds]
urlhaus = true
openphish = true
refresh_secs = 3600

[tunneling_detection]
enabled = true
entropy_threshold = 3.5

[metrics]
bind_addr = "127.0.0.1:9090"
```

Full schema in [`src/config.rs`](src/config.rs).

## License

MIT
