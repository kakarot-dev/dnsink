# dnsink

A high-performance DNS proxy that blocks malware, C2, and phishing domains at the DNS layer. No browser extension, no per-app configuration — anything that uses DNS gets filtered.

## Features

- Blocks malware and phishing domains via live threat feeds (URLhaus, OpenPhish)
- Wildcard blocking: block `malware.com` and all subdomains automatically
- Two-stage lookup: bloom filter pre-screens, radix trie confirms
- UDP + TCP DNS support with automatic truncation fallback
- Structured per-query logging with action, latency, and source IP
- Optional PhishTank integration with API key

## Architecture

### Data flow

```
Client query (UDP/TCP)
        │
        ▼
┌───────────────┐
│  DnsProxy     │  receives raw DNS bytes, starts latency timer
└───────┬───────┘
        │
        ▼
┌───────────────┐
│ BloomFilter   │  stage 1: check queried domain + each parent label
│  (100K items) │  O(k) bit lookups — ~96 ns hit, ~160 ns miss
│   ~120 KB     │  definite miss → skip trie, forward immediately
└───────┬───────┘
        │ maybe blocked
        ▼
┌───────────────┐
│  DomainTrie   │  stage 2: authoritative answer
│ (radix trie)  │  label-reversed traversal: "sub.evil.com" → com→evil→sub
│               │  is_blocked flag at any node = wildcard block
└───────┬───────┘
        │
   ┌────┴────┐
   │         │
blocked    allowed
   │         │
   ▼         ▼
NXDOMAIN  forward to upstream (8.8.8.8)
response  UDP first, retry TCP if truncated
   │         │
   └────┬────┘
        │
        ▼
   log_outcome
   src, domain, action, latency_ms, proto
```

### Modules

| Module | Role |
|---|---|
| `bloom.rs` | Packed bit-vector bloom filter, double hashing, no crates |
| `trie.rs` | Radix trie with label-reversed domain storage, wildcard via `is_blocked` |
| `proxy.rs` | Async UDP + TCP listeners, two-stage block check, structured logging |
| `feeds.rs` | `ThreatFeed` trait, URLhaus, OpenPhish, PhishTank implementations |
| `config.rs` | TOML config: listen addr, upstream, blocklist path, feed API keys |

### Threat feeds

Feeds are fetched at startup and merged into the bloom filter and trie:

| Feed | Format | Auth | Domains (approx) |
|---|---|---|---|
| URLhaus | Plain text URLs | None | ~25,000 |
| OpenPhish | Plain text URLs | None | ~200 |
| PhishTank | JSON (`url` field) | API key | ~50,000 |

Feed failures are logged and skipped — the proxy starts with whatever it has.

### Bloom filter design

Built from scratch: `Vec<u8>` as a packed bit vector (8x smaller than `Vec<bool>`), double hashing for independent hash functions with no external crates:

```
h1 = upper 32 bits of DefaultHasher(item)
h2 = lower 32 bits | 1          (forced odd, coprime with m)
index(i) = (h1 + i * h2) % m
```

Optimal parameters for 100K items at 1% false positive rate:
- `m = 958,506 bits` (~117 KB)
- `k = 7` hash functions

### Trie design

Labels stored in reverse so prefix matching = suffix matching:

```
insert("malware.com")  →  root → "com" → "malware" [is_blocked=true]

contains("sub.malware.com"):
  walk com → malware → is_blocked=true → return true (wildcard hit)
  never checks "sub" node
```

## Benchmarks

Measured with Criterion on 100,000 domains, release build.

| Operation | Time |
|---|---|
| Bloom lookup — hit | 89 ns |
| Bloom lookup — miss | 158 ns |
| Trie lookup — exact hit | 396 ns |
| Trie lookup — wildcard hit | 294 ns |
| Trie lookup — miss | 190 ns |
| Two-stage lookup — hit | 449 ns |
| Two-stage lookup — miss | 294 ns |

**Why bloom miss is slower than hit:** on a hit, all `k` bits are set so the loop may return early. On a miss, all `k` positions must be checked before returning false.

**Why wildcard hit is faster than exact hit:** `is_blocked` is checked before descending to the next label. A blocked parent (`malware.com`) short-circuits immediately — the trie never walks to the leaf node.

**Two-stage miss (302 ns):** bloom eliminates the miss in ~160 ns; the trie is never consulted. This is the common case for legitimate traffic.

## Configuration

```toml
[listen]
address = "127.0.0.1"
port = 5353

[upstream]
address = "8.8.8.8"
port = 53
timeout_ms = 5000

[blocklist]
path = "blocklist.txt"   # one domain per line, # comments ok

[feeds]
phishtank_api_key = "your-key"   # optional
```

## Usage

```sh
# Run with default config
cargo run

# Custom config
cargo run -- --config /etc/dnsink/config.toml

# Point your system DNS at it
dig @127.0.0.1 -p 5353 malware.example.com   # NXDOMAIN
dig @127.0.0.1 -p 5353 google.com            # resolves normally
```

## Running benchmarks

```sh
cargo bench
# HTML reports in target/criterion/
```
