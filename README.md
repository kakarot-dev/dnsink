# dnsink

A high-performance DNS proxy written in Rust that blocks malware, C2, and phishing domains at the DNS layer. No browser extensions, no per-app configuration — anything that resolves DNS gets filtered.

dnsink sits between your machine and the internet, checking every DNS query against live threat intelligence feeds. Blocked domains get an NXDOMAIN response in under 1 microsecond. Clean domains are forwarded upstream, optionally via encrypted DNS-over-HTTPS.

## Why dnsink?

Existing DNS blockers (Pi-hole, AdGuard Home) focus on ad blocking. dnsink focuses on **security** — blocking known malware infrastructure, C2 servers, and phishing domains using real threat intelligence feeds that update hourly.

| Feature | dnsink | Pi-hole | AdGuard Home | crab-hole |
|---------|--------|---------|--------------|-----------|
| Language | Rust | Shell/PHP | Go | Rust |
| Threat intel feeds | URLhaus, OpenPhish, PhishTank | Community ad lists | Community ad lists | Community ad lists |
| Wildcard blocking | Radix trie | Regex | Regex | Regex |
| Bloom filter pre-screening | Yes | No | No | No |
| DNS-over-HTTPS upstream | Yes | No (needs cloudflared) | Yes | Yes |
| Hot-reload without downtime | Yes (lock-free via ArcSwap) | Yes (restart-based) | Yes | Yes |
| Terminal dashboard (TUI) | Yes (ratatui) | Web UI | Web UI | No |
| Two-stage lookup (~490 ns) | Yes | No | No | No |

## Features

- **Threat intelligence feeds** — URLhaus (abuse.ch), OpenPhish, PhishTank (optional API key). Fetched at startup, hot-reloaded on a configurable interval.
- **Two-stage blocking engine** — Bloom filter pre-screens every query in ~184ns. Only probable matches hit the radix trie for confirmation. Definite misses (legitimate traffic) never touch the trie.
- **Wildcard domain blocking** — Block `malware.com` and every subdomain automatically via label-reversed radix trie traversal.
- **DNS-over-HTTPS (DoH)** — Encrypt upstream queries to Cloudflare, Google, or any RFC 8484 endpoint. Your ISP sees nothing.
- **Hot-reload** — Blocklists refresh without dropping in-flight queries. Lock-free reads via `ArcSwap`, reference-counted old data via `Arc`.
- **Terminal dashboard (TUI)** — Live query stream with color-coded blocked/allowed, queries-per-second sparkline, top blocked domains, and stats. Vim-style scrolling (j/k/g/G).
- **Structured logging** — JSON or text per-query logs with domain, action, latency, protocol, and source IP. File output configurable.
- **Per-query metrics** — Atomic counters for total/blocked/allowed queries, average latency, query type distribution, and top blocked domains.
- **UDP + TCP** — Full DNS protocol support with automatic truncation fallback.
- **Per-feed toggles** — Enable/disable URLhaus, OpenPhish, PhishTank independently in config.

## Quickstart

```sh
# Clone and build
git clone https://github.com/kakarot-dev/dnsink.git
cd dnsink
cargo build --release

# Run with default config (listens on 127.0.0.1:5353)
cargo run --release

# Run with TUI dashboard
cargo run --release -- --tui

# Test it
dig @127.0.0.1 -p 5353 google.com          # resolves normally
dig @127.0.0.1 -p 5353 malware.example.com  # NXDOMAIN (blocked)
```

## TUI Dashboard

Launch with `--tui` to get a live terminal dashboard:

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

Headless mode (no `--tui` flag) runs the proxy with standard structured logging — no behavior change from previous versions.

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
| `feeds.rs` | `ThreatFeed` trait + URLhaus, OpenPhish, PhishTank implementations |
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

**Two-stage miss (288 ns):** The bloom filter eliminates clean domains in ~184 ns. The trie is never consulted. This is the common case — legitimate traffic takes the fastest path.

**Wildcard faster than exact:** `is_blocked` is checked at each trie node before descending. A blocked parent (`malware.com`) short-circuits immediately — no need to walk to the leaf.

Native Linux or bare-metal will show lower absolute times than WSL2.

## Configuration

```toml
[listen]
address = "127.0.0.1"
port = 5353

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

[logging]
format = "json"          # "text" (default) or "json"
# file = "/var/log/dnsink/queries.log"   # omit for stdout
```

## Running tests

```sh
# Unit tests (30) + integration tests (5)
cargo test

# Benchmarks (HTML reports in target/criterion/)
cargo bench
```

## Tech stack

- **Rust** + **tokio** — async runtime
- **hickory-proto** — DNS wire format parsing
- **reqwest** + **rustls** — DoH upstream (RFC 8484)
- **arc-swap** — lock-free hot-reload
- **ratatui** + **crossterm** — terminal dashboard
- **tracing** — structured logging (JSON/text)
- **criterion** — benchmarks
- **clap** — CLI argument parsing

## License

MIT
