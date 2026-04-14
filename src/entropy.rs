//! DNS tunneling detection via Shannon entropy analysis.
//!
//! High-entropy subdomains are a signature of DNS tunneling: tools like
//! iodine and dnscat2 encode payloads into subdomain labels, which produces
//! strings that look much more random than real hostnames. Real hostnames
//! cluster around ~3.0 bits/char; base32/base64-encoded payloads land closer
//! to 4.5+.
//!
//! The classifier here is deliberately dumb: for each label long enough to
//! plausibly hold a payload, compute entropy and compare against a threshold.
//! No ML, no n-grams, no allowlisting — those can come later if the false
//! positive rate demands it.

use std::collections::HashMap;

pub struct EntropyDetector {
    threshold: f64,
    min_length: usize,
}

impl EntropyDetector {
    pub fn new(threshold: f64, min_length: usize) -> Self {
        Self {
            threshold,
            min_length,
        }
    }

    /// Returns true if any label in `domain` is long enough to be a payload
    /// carrier AND has entropy exceeding the configured threshold.
    ///
    /// Short labels (len < min_length) are skipped — they can't meaningfully
    /// carry a tunneled payload and produce noisy false positives on
    /// legitimate hex hashes like CDN cache keys.
    pub fn is_suspicious(&self, domain: &str) -> bool {
        domain
            .split('.')
            .filter(|label| label.len() >= self.min_length)
            .any(|label| self.shannon_entropy(label) > self.threshold)
    }

    /// Shannon entropy in bits/character. Empty strings return 0.0.
    pub fn shannon_entropy(&self, s: &str) -> f64 {
        if s.is_empty() {
            return 0.0;
        }
        let mut counts: HashMap<char, usize> = HashMap::new();
        for c in s.chars() {
            *counts.entry(c).or_insert(0) += 1;
        }
        let len = s.chars().count() as f64;
        counts
            .values()
            .map(|&c| {
                let p = c as f64 / len;
                -p * p.log2()
            })
            .sum()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_char_has_lower_entropy_than_mixed() {
        let detector = EntropyDetector::new(3.5, 20);
        assert!(detector.shannon_entropy("aaaa") < detector.shannon_entropy("a1b2c3d4"));
    }

    #[test]
    fn normal_domain_is_not_suspicious() {
        let detector = EntropyDetector::new(3.5, 20);
        assert!(!detector.is_suspicious("normal.example.com"));
    }

    #[test]
    fn long_but_low_entropy_label_is_not_suspicious() {
        // 23 'a's — long enough to be checked, but zero entropy.
        let detector = EntropyDetector::new(3.5, 20);
        assert!(!detector.is_suspicious("aaaaaaaaaaaaaaaaaaaaaaa.example.com"));
    }

    #[test]
    fn long_high_entropy_label_is_suspicious() {
        // 27 distinct base36-ish chars — looks like a dnscat2 payload.
        let detector = EntropyDetector::new(3.5, 20);
        assert!(detector.is_suspicious("k8j4h2g9f7d5s3a1q6w8e4r2t0y.example.com"));
    }
}
