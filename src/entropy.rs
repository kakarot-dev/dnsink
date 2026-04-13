//! DNS tunneling detection via Shannon entropy analysis.
//!
//! High-entropy subdomains are a signature of DNS tunneling: tools like
//! iodine and dnscat2 encode payloads into subdomain labels, which produces
//! strings that look much more random than real hostnames. Real hostnames
//! cluster around ~3.0 bits/char; base32/base64-encoded payloads land closer
//! to 4.5+.
//!
//! This module only contains the scaffold and the entropy primitive.
//! The actual suspiciousness classifier lands in a follow-up.

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

    /// Stub: returns false until the classifier is implemented.
    pub fn is_suspicious(&self, _domain: &str) -> bool {
        let _ = (self.threshold, self.min_length);
        false
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
}
