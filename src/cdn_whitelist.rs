//! Suffix-based allowlist for large CDN providers.
//!
//! High-entropy subdomains on CDNs (e.g. `d1a2b3c4d5e6f7.cloudfront.net`)
//! are the dominant false-positive source for the entropy-based tunneling
//! detector. This module lets the proxy short-circuit the entropy check
//! for domains that match a trusted CDN suffix.
//!
//! The suffix match is label-boundary aware: `notcloudflare.com` does
//! **not** match `cloudflare.com`, even though a naive `ends_with` would
//! say it does.

use std::collections::HashSet;

const CLOUDFLARE_SUFFIXES: &[&str] = &[
    "cloudflare.com",
    "cloudflare-dns.com",
    "cdn.cloudflare.net",
    "workers.dev",
    "pages.dev",
];

const AWS_SUFFIXES: &[&str] = &[
    "cloudfront.net",
    "amazonaws.com",
    "s3.amazonaws.com",
    "execute-api.us-east-1.amazonaws.com",
    "elb.amazonaws.com",
    "awsglobalaccelerator.com",
];

const AKAMAI_SUFFIXES: &[&str] = &[
    "akamaiedge.net",
    "akamaized.net",
    "akamaihd.net",
    "edgekey.net",
    "edgesuite.net",
    "akamai.net",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CdnProvider {
    Aws,
    Akamai,
    Cloudflare,
}

impl CdnProvider {
    fn suffixes(self) -> &'static [&'static str] {
        match self {
            CdnProvider::Aws => AWS_SUFFIXES,
            CdnProvider::Akamai => AKAMAI_SUFFIXES,
            CdnProvider::Cloudflare => CLOUDFLARE_SUFFIXES,
        }
    }
}

pub struct CdnWhitelist {
    suffixes: HashSet<String>,
}

impl CdnWhitelist {
    pub fn new() -> Self {
        Self {
            suffixes: HashSet::new(),
        }
    }

    pub fn with_providers(providers: &[CdnProvider]) -> Self {
        let mut suffixes = HashSet::new();
        for provider in providers {
            for s in provider.suffixes() {
                suffixes.insert(s.to_lowercase());
            }
        }
        Self { suffixes }
    }

    /// Returns true if `domain` matches any whitelisted suffix on a label
    /// boundary. Case-insensitive. Tolerates a trailing dot.
    pub fn is_cdn(&self, domain: &str) -> bool {
        let domain = domain.trim_end_matches('.').to_lowercase();
        for suffix in &self.suffixes {
            if domain == *suffix {
                return true;
            }
            if domain.len() > suffix.len()
                && domain.ends_with(suffix.as_str())
                && domain.as_bytes()[domain.len() - suffix.len() - 1] == b'.'
            {
                return true;
            }
        }
        false
    }

    pub fn len(&self) -> usize {
        self.suffixes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.suffixes.is_empty()
    }
}

impl Default for CdnWhitelist {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all_providers() -> CdnWhitelist {
        CdnWhitelist::with_providers(&[
            CdnProvider::Aws,
            CdnProvider::Akamai,
            CdnProvider::Cloudflare,
        ])
    }

    #[test]
    fn cloudflare_subdomain_matches() {
        let w = all_providers();
        assert!(w.is_cdn("d1.cloudflare.com"));
    }

    #[test]
    fn cloudfront_high_entropy_subdomain_matches() {
        let w = all_providers();
        assert!(w.is_cdn("d1a2b3c4d5e6f7.cloudfront.net"));
    }

    #[test]
    fn non_cdn_domain_does_not_match() {
        let w = all_providers();
        assert!(!w.is_cdn("malicious.example.com"));
    }

    #[test]
    fn suffix_substring_does_not_falsely_match() {
        let w = all_providers();
        assert!(!w.is_cdn("notcloudflare.com"));
    }

    #[test]
    fn exact_suffix_matches() {
        let w = all_providers();
        assert!(w.is_cdn("cloudfront.net"));
    }

    #[test]
    fn empty_whitelist_returns_false() {
        let w = CdnWhitelist::new();
        assert!(!w.is_cdn("anything.cloudfront.net"));
        assert!(w.is_empty());
    }

    #[test]
    fn trailing_dot_is_tolerated() {
        let w = all_providers();
        assert!(w.is_cdn("d1.cloudflare.com."));
    }

    #[test]
    fn case_insensitive_match() {
        let w = all_providers();
        assert!(w.is_cdn("D1A2.CloudFront.NET"));
    }
}
