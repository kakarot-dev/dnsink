use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dnsink::bloom::BloomFilter;
use dnsink::trie::DomainTrie;

const N: usize = 100_000;

fn make_domains(n: usize) -> Vec<String> {
    (0..n)
        .map(|i| format!("domain-{i}.malware.example.com"))
        .collect()
}

// --- Bloom filter ---

fn bench_bloom(c: &mut Criterion) {
    let domains = make_domains(N);
    let mut bloom = BloomFilter::new(N, 0.01);
    for d in &domains {
        bloom.insert(d);
    }

    let mut g = c.benchmark_group("bloom_lookup");

    // Hit: domain is in the filter
    g.bench_function("hit", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let result = bloom.contains(black_box(&domains[i % N]));
            i += 1;
            result
        });
    });

    // Miss: domain is not in the filter
    g.bench_function("miss", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let result = bloom.contains(black_box(&format!("nothere-{i}.clean.com")));
            i += 1;
            result
        });
    });

    g.finish();
}

// --- Radix Trie ---

fn bench_trie(c: &mut Criterion) {
    let domains = make_domains(N);
    let mut trie = DomainTrie::new();
    for d in &domains {
        trie.insert(d);
    }

    let mut g = c.benchmark_group("trie_lookup");

    // Exact hit
    g.bench_function("exact_hit", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let result = trie.contains(black_box(&domains[i % N]));
            i += 1;
            result
        });
    });

    // Wildcard hit: subdomain of a blocked parent
    let blocked_parent = "malware.example.com";
    let mut trie_wildcard = DomainTrie::new();
    trie_wildcard.insert(blocked_parent);
    g.bench_function("wildcard_hit", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let result = trie_wildcard.contains(black_box(&format!("sub-{i}.malware.example.com")));
            i += 1;
            result
        });
    });

    // Miss
    g.bench_function("miss", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let result = trie.contains(black_box(&format!("nothere-{i}.clean.com")));
            i += 1;
            result
        });
    });

    g.finish();
}

// --- Combined two-stage lookup (bloom → trie) ---

fn bench_two_stage(c: &mut Criterion) {
    let domains = make_domains(N);
    let mut bloom = BloomFilter::new(N, 0.01);
    let mut trie = DomainTrie::new();
    for d in &domains {
        bloom.insert(d);
        trie.insert(d);
    }

    let mut g = c.benchmark_group("two_stage_lookup");

    g.bench_function("hit", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let domain = &domains[i % N];
            i += 1;
            let maybe = ancestors(black_box(domain)).any(|d| bloom.contains(&d));
            if maybe {
                trie.contains(black_box(domain))
            } else {
                false
            }
        });
    });

    g.bench_function("miss", |b| {
        let mut i = 0usize;
        b.iter(|| {
            let domain = format!("nothere-{i}.clean.com");
            i += 1;
            let maybe = ancestors(black_box(&domain)).any(|d| bloom.contains(&d));
            if maybe {
                trie.contains(black_box(&domain))
            } else {
                false
            }
        });
    });

    g.finish();
}

fn ancestors(domain: &str) -> impl Iterator<Item = &str> {
    std::iter::successors(Some(domain), |d| d.find('.').map(|i| &d[i + 1..]))
}

criterion_group!(benches, bench_bloom, bench_trie, bench_two_stage);
criterion_main!(benches);
