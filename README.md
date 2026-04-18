# dnsink

A high-performance DNS proxy written in Rust that blocks malware, C2, and phishing domains at the DNS layer. No browser extensions, no per-app configuration — anything that resolves DNS gets filtered.

[![CI](https://github.com/kakarot-dev/dnsink/actions/workflows/ci.yml/badge.svg)](https://github.com/kakarot-dev/dnsink/actions/workflows/ci.yml) [![Docker](https://img.shields.io/badge/ghcr.io-dnsink-blue?logo=docker)](https://github.com/kakarot-dev/dnsink/pkgs/container/dnsink) [![Deploy with flyctl](https://img.shields.io/badge/deploy%20with-flyctl-7b3fbf?logo=flydotio&logoColor=white)](https://fly.io/docs/launch/) [![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

dnsink sits between your machine and the internet, checking every DNS query against live threat intelligence feeds. Blocked domains get an NXDOMAIN response in under 1 microsecond. Clean domains are forwarded upstream, optionally via encrypted DNS-over-HTTPS.

## Contents

- [Quickstart](#quickstart)
- [Deploy](#deploy)
  - [Docker](#docker)
  - [Fly.io](#flyio)
  - [Local build](#local-build)
- [TUI Dashboard](#tui-dashboard)
- [Configuration](#configuration)
- [Why dnsink?](#why-dnsink)
- [Features](#features)
- [Architecture](#architecture)
  - [Data flow](#data-flow)
  - [Modules](#modules)
  - [Threat feeds](#threat-feeds)
  - [Hot-reload](#hot-reload)
  - [Bloom filter](#bloom-filter)
  - [Radix trie](#radix-trie)
- [Benchmarks](#benchmarks)
- [Running tests](#running-tests)
- [Tech stack](#tech-stack)
- [License](#license)

## Quickstart

Fastest path — pull the image and run:

```sh
docker run -d --name dnsink \
  -p 53:5353/tcp \
  -p 5353:5353/udp \
  -p 9090:9090 \
  ghcr.io/kakarot-dev/dnsink:v0.2.0

# Resolve a clean domain (TCP on host :53)
dig @127.0.0.1 +tcp example.com

# UDP fallback on :5353 (distroless nonroot can't bind :53 without NET_BIND_SERVICE)
dig @127.0.0.1 -p 5353 example.com

# Scrape Prometheus metrics
curl http://127.0.0.1:9090/metrics
```

## Deploy

### Docker

Pre-built multi-arch image (`linux/amd64` + `linux/arm64`) at `ghcr.io/kakarot-dev/dnsink`. Runtime is distroless/cc-debian12:nonroot — no shell, no package manager, UID 65532.

```sh
docker pull ghcr.io/kakarot-dev/dnsink:v0.2.0

docker run -d --name dnsink \
  -p 53:5353/tcp \
  -p 5353:5353/udp \
  -p 9090:9090 \
  ghcr.io/kakarot-dev/dnsink:v0.2.0
```

UDP binds internally to port 5353 to avoid requiring `NET_BIND_SERVICE`. Map to whichever host port you want. For in-container port 53 on Kubernetes `hostNetwork` deployments, add the capability and override the config via bind-mount.

**Custom config via bind-mount:**

```sh
docker run -d --name dnsink \
  -v /path/to/my-config.toml:/etc/dnsink/config.toml:ro \
  -p 53:5353/tcp -p 5353:5353/udp -p 9090:9090 \
  ghcr.io/kakarot-dev/dnsink:v0.2.0
```

### Fly.io

The repo ships with [`fly.toml`](fly.toml) pre-configured for UDP + TCP DNS + HTTPS metrics, and [`config.docker.toml`](config.docker.toml) with fly.io-specific bind addresses.

```sh
flyctl apps create <your-app-name>
flyctl ips allocate-v4 --yes    # required for UDP ($2/mo)
flyctl ips allocate-v6
flyctl deploy
```

**fly.io bind-address note.** fly.io requires UDP services to bind to the special `fly-global-services` address — otherwise Linux uses the wrong source IP on replies and clients never see responses. TCP must bind to a wildcard for fly-proxy's ingress to land. This asymmetry is handled via the optional `listen.tcp_address` field in the config. See [`config.docker.toml`](config.docker.toml).

### Local build

```sh
git clone https://github.com/kakarot-dev/dnsink.git
cd dnsink
cargo build --release

# Run with default config (listens on 127.0.0.1:5353)
cargo run --release

# Run with TUI dashboard
cargo run --release -- --tui

# Test it
dig @127.0.0.1 -p 5353 google.com           # resolves normally
dig @127.0.0.1 -p 5353 malware.example.com  # NXDOMAIN (blocked)
```

## TUI Dashboard

Launch with `--tui` for a live terminal dashboard:

```
cargo run --release -- --tui
```

The dashboard shows:
- **Stats header** — total queries, blocked count, allowed count, average latency, uptime
- **Sparkline** — queries per second over the last 60 seconds with current and peak rate
- **Live query stream** — color-coded table of every DNS query (red = blocked, green = allowed) with domain, query type, latency, and protocol
- **Top blocked domains** — the 5 most frequently blocked domains

Keyboard shortcuts:

| Key | Action |
|-----|--------|
| `q` / `Esc` | Quit |
| `j` / `Down` | Scroll down (older queries) |
| `k` / `Up` | Scroll up (newer queries) |
| `G` / `End` | Jump to latest (re-enable auto-scroll) |
| `g` / `Home` | Jump to oldest |

Headless mode (no `--tui`) runs the proxy with standard structured logging.

## Configuration

```toml
[listen]
address = "127.0.0.1"
port = 5353
# tcp_address = "[::]"   # optional override — see Deploy > Fly.io

[upstream]
address = "8.8.8.8"
port = 53
timeout_ms = 5000
# protocol = "doh"                        # "udp" (default) or "doh"
# doh_url = "https://1.1.1.1/dns-query"   # Cloudflare default if omitted

[blocklist]
path = "blocklist.txt"   # one domain per line, # comments ok

[feeds]
urlhaus = true           # abuse.ch URLhaus feed
openphish = true         # OpenPhish community feed
# phishtank_api_key = "your-key"   # optional, enables PhishTank
refresh_secs = 3600      # hot-reload interval (0 = disabled)

[tunneling_detection]
enabled = true
entropy_threshold = 3.5
min_subdomain_length = 20

[tunneling_detection.cdn_whitelist]
enabled = true
providers = ["aws", "akamai", "cloudflare"]

[metrics]
enabled = true
bind_addr = "127.0.0.1:9090"

[logging]
format = "json"          # "text" (default) or "json"
# file = "/var/log/dnsink/queries.log"   # omit for stdout
```

## Why dnsink?

Existing DNS blockers (Pi-hole, AdGuard Home) focus on ad blocking. dnsink focuses on **security** — blocking known malware infrastructure, C2 servers, and phishing domains using real threat intelligence feeds that update hourly.

| Feature | dnsink | Pi-hole | AdGuard Home | crab-hole |
|---------|--------|---------|--------------|-----------|
| Language | Rust | Shell/PHP | Go | Rust |
| Threat intel feeds | URLhaus, OpenPhish, PhishTank | Community ad lists | Community ad lists | Community ad lists |
| DNS tunneling detection | Shannon entropy + CDN whitelist | No | No | No |
| Wildcard blocking | Radix trie | Regex | Regex | Regex |
| Bloom filter pre-screening | Yes | No | No | No |
| DNS-over-HTTPS upstream | Yes | No (needs cloudflared) | Yes | Yes |
| Hot-reload without downtime | Yes (lock-free via ArcSwap) | Yes (restart-based) | Yes | Yes |
| Prometheus `/metrics` | Yes | No | No | No |
| Terminal dashboard (TUI) | Yes (ratatui) | Web UI | Web UI | No |
| Two-stage lookup (~490 ns) | Yes | No | No | No |

## Features

- **Threat intelligence feeds** — URLhaus (abuse.ch), OpenPhish, PhishTank (optional API key). Fetched at startup, hot-reloaded on a configurable interval.
- **Two-stage blocking engine** — Bloom filter pre-screens every query in ~184 ns. Only probable matches hit the radix trie for confirmation.
- **DNS tunneling detection** — Shannon entropy on subdomain labels with a CDN whitelist (AWS / Akamai / Cloudflare) to suppress false positives on trusted providers.
- **Wildcard domain blocking** — Block `malware.com` and every subdomain automatically via label-reversed radix trie traversal.
- **DNS-over-HTTPS (DoH)** — Encrypt upstream queries to Cloudflare, Google, or any RFC 8484 endpoint.
- **Hot-reload** — Blocklists refresh without dropping in-flight queries. Lock-free reads via `ArcSwap`, reference-counted old data via `Arc`.
- **Prometheus metrics** — `/metrics` endpoint with 5 counters (queries total/blocked/allowed, cumulative latency ms, tunneling flagged). Hand-rolled on hyper 1.x, no axum dependency.
- **Terminal dashboard (TUI)** — Live query stream, queries-per-second sparkline, top blocked domains, stats. Vim-style scrolling.
- **Structured logging** — JSON or text per-query logs with domain, action, latency, protocol, and source IP.
- **UDP + TCP** — Full DNS protocol support with automatic truncation fallback.

## Architecture

### Data flow

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
| BloomFilter   |  stage 1: check domain + each parent label
|  (100K items) |  O(k) bit lookups — ~184 ns
|   ~117 KB     |  definite miss -> skip trie, forward immediately
+-------+-------+
        | maybe blocked
        v
+---------------+
|  DomainTrie   |  stage 2: authoritative answer
| (radix trie)  |  label-reversed traversal: "sub.evil.com" -> com.evil.sub
|               |  is_blocked at any ancestor = wildcard block
+-------+-------+
        |
   +----+----+
   |         |
blocked    allowed
   |         |
   v         v
NXDOMAIN  forward to upstream (UDP, TCP, or DoH)
response  with automatic truncation fallback
   |         |
   +----+----+
        |
        v
   log + metrics
   domain, action, latency, proto, qtype
        |
        v (if --tui)
   TUI dashboard via mpsc channel
```

### Modules

| Module | Responsibility |
|--------|---------------|
| `proxy.rs` | Async UDP + TCP listeners, DoH upstream, two-stage block check, hot-reload via `ArcSwap`, query metrics, structured logging |
| `bloom.rs` | Packed bit-vector bloom filter, double hashing, no external crates |
| `trie.rs` | Radix trie with label-reversed domain storage, wildcard blocking via `is_blocked` flag |
| `entropy.rs` | Shannon entropy primitive + tunneling detection heuristics |
| `cdn_whitelist.rs` | Label-boundary-safe suffix match for AWS / Akamai / Cloudflare provider domains |
| `feeds.rs` | `ThreatFeed` trait + URLhaus, OpenPhish, PhishTank implementations |
| `metrics_server.rs` | Prometheus `/metrics` HTTP endpoint on hand-rolled hyper 1.x |
| `config.rs` | TOML config parsing: listen addr, upstream (UDP/DoH), feed toggles, logging, refresh interval |
| `tui.rs` | Ratatui terminal dashboard: stats, sparkline, live stream, top blocked domains |

### Threat feeds

Feeds are fetched at startup and hot-reloaded every `refresh_secs` (default: 3600s). Each feed can be toggled independently.

| Feed | Format | Auth | Domains (approx) |
|------|--------|------|-------------------|
| [URLhaus](https://urlhaus.abuse.ch/) | Plain text URLs | None | ~25,000 |
| [OpenPhish](https://openphish.com/) | Plain text URLs | None | ~200 |
| [PhishTank](https://phishtank.org/) | JSON (`url` field) | API key (optional) | ~50,000 |

Feed failures are logged and skipped — the proxy starts with whatever feeds succeed. A failed reload keeps the previous blocklist active.

### Hot-reload

Blocklists refresh every `refresh_secs` without dropping in-flight queries:

1. Background tokio task sleeps for `refresh_secs`
2. Fetches all enabled feeds + static blocklist
3. Builds a new bloom filter and trie from scratch
4. Atomically swaps via `ArcSwap` — lock-free, wait-free reads
5. Old data stays alive via `Arc` reference counting until in-flight queries finish

### Bloom filter

Built from scratch — no external crates. Packed `Vec<u8>` bit vector (8x smaller than `Vec<bool>`), double hashing:

```
h1 = upper 32 bits of DefaultHasher(item)
h2 = lower 32 bits | 1     (forced odd, coprime with m)
index(i) = (h1 + i * h2) % m
```

Optimal parameters for 100K items at 1% false positive rate: `m = 958,506 bits` (~117 KB), `k = 7` hash functions.

### Radix trie

Labels stored in reverse order so prefix matching becomes suffix matching:

```
insert("malware.com")  ->  root -> "com" -> "malware" [is_blocked=true]

contains("sub.malware.com"):
  walk com -> malware -> is_blocked=true -> return true (wildcard hit)
  never checks "sub" node — parent already blocked
```

## Benchmarks

Measured with [Criterion](https://github.com/bheisler/criterion.rs) on 100,000 domains, release build (WSL2, Linux 5.15):

| Operation | Time |
|-----------|------|
| Bloom lookup — hit | 87 ns |
| Bloom lookup — miss | 184 ns |
| Trie lookup — exact hit | 380 ns |
| Trie lookup — wildcard hit | 320 ns |
| Trie lookup — miss | 236 ns |
| **Two-stage lookup — hit** | **491 ns** |
| **Two-stage lookup — miss** | **288 ns** |

**Two-stage miss (288 ns):** The bloom filter eliminates clean domains in ~184 ns. The trie is never consulted. This is the common case.

**Wildcard faster than exact:** `is_blocked` is checked at each trie node before descending. A blocked parent (`malware.com`) short-circuits immediately.

Native Linux or bare-metal will show lower absolute times than WSL2.

## Running tests

```sh
# Unit tests + integration tests (54 total across core, entropy, metrics)
cargo test

# Benchmarks (HTML reports in target/criterion/)
cargo bench
```

## Tech stack

- **Rust** + **tokio** — async runtime
- **hickory-proto** — DNS wire format parsing
- **reqwest** + **rustls** — DoH upstream (RFC 8484)
- **hyper** 1.x + **hyper-util** + **http-body-util** — hand-rolled `/metrics` HTTP server
- **arc-swap** — lock-free hot-reload
- **ratatui** + **crossterm** — terminal dashboard
- **tracing** — structured logging (JSON/text)
- **criterion** — benchmarks
- **clap** — CLI argument parsing

## License

MIT
