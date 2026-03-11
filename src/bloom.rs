use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};

pub struct BloomFilter {
    bits: Vec<u8>,
    m: usize,
    k: usize,
}

impl BloomFilter {
    pub fn new(expected_items: usize, fp_rate: f64) -> Self {
        let m = optimal_m(expected_items, fp_rate);
        let k = optimal_k(m, expected_items);
        BloomFilter {
            bits: vec![0u8; (m + 7) / 8],
            m,
            k,
        }
    }

    pub fn insert<T: Hash>(&mut self, item: &T) {
        let (h1, h2) = self.double_hash(item);
        for i in 0..self.k {
            let idx = h1.wrapping_add(i.wrapping_mul(h2)) % self.m;
            self.set_bit(idx);
        }
    }

    pub fn contains<T: Hash>(&self, item: &T) -> bool {
        let (h1, h2) = self.double_hash(item);
        (0..self.k).all(|i| {
            let idx = h1.wrapping_add(i.wrapping_mul(h2)) % self.m;
            self.get_bit(idx)
        })
    }

    fn double_hash<T: Hash>(&self, item: &T) -> (usize, usize) {
        let mut h = DefaultHasher::new();
        item.hash(&mut h);
        let hash = h.finish();

        let h1 = (hash >> 32) as usize;
        let h2 = (hash as u32) as usize | 1; // ensure odd so it's coprime with m

        (h1, h2)
    }

    fn set_bit(&mut self, idx: usize) {
        self.bits[idx / 8] |= 1 << (idx % 8);
    }

    fn get_bit(&self, idx: usize) -> bool {
        self.bits[idx / 8] & (1 << (idx % 8)) != 0
    }
}

fn optimal_m(n: usize, fp: f64) -> usize {
    let m = -(n as f64 * fp.ln()) / (2.0_f64.ln().powi(2));
    m.ceil() as usize
}

fn optimal_k(m: usize, n: usize) -> usize {
    let k = (m as f64 / n as f64) * 2.0_f64.ln();
    k.round().max(1.0) as usize
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn insert_and_contains() {
        let mut bf = BloomFilter::new(100, 0.01);
        bf.insert(&"hello");
        bf.insert(&"world");

        assert!(bf.contains(&"hello"));
        assert!(bf.contains(&"world"));
        assert!(!bf.contains(&"missing"));
    }

    #[test]
    fn no_false_negatives() {
        let mut bf = BloomFilter::new(1000, 0.01);
        let items: Vec<String> = (0..1000).map(|i| format!("item-{i}")).collect();

        for item in &items {
            bf.insert(item);
        }

        for item in &items {
            assert!(bf.contains(item), "false negative for {item}");
        }
    }

    #[test]
    fn false_positive_rate_within_bounds() {
        let n = 1000;
        let target_fp = 0.05;
        let mut bf = BloomFilter::new(n, target_fp);

        for i in 0..n {
            bf.insert(&i);
        }

        let test_count = 10_000;
        let false_positives = (n..n + test_count)
            .filter(|i| bf.contains(i))
            .count();

        let observed_fp = false_positives as f64 / test_count as f64;
        assert!(
            observed_fp < target_fp * 2.0,
            "observed FP rate {observed_fp:.4} exceeds 2x target {target_fp}"
        );
    }

    #[test]
    fn optimal_params_sanity() {
        let m = optimal_m(1000, 0.01);
        let k = optimal_k(m, 1000);
        assert!(m > 1000, "m should be larger than n");
        assert!(k >= 1, "k should be at least 1");
    }

    #[test]
    fn empty_filter_contains_nothing() {
        let bf = BloomFilter::new(100, 0.01);
        assert!(!bf.contains(&"anything"));
        assert!(!bf.contains(&42));
    }

    #[test]
    fn memory_is_compact() {
        let bf = BloomFilter::new(100_000, 0.01);
        let bytes = bf.bits.len();
        // ~120KB for 100K items at 1% FP, not ~960KB
        assert!(bytes < 150_000, "bit vector uses {bytes} bytes, expected ~120KB");
    }
}
