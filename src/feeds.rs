use std::collections::HashSet;

#[allow(async_fn_in_trait)]
pub trait ThreatFeed {
    fn name(&self) -> &str;
    async fn fetch(&self) -> anyhow::Result<String>;
    fn parse(&self, raw: &str) -> Vec<String>;
}

fn parse_url_list(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut domains = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(host) = extract_host(line) {
            if seen.insert(host.clone()) {
                domains.push(host);
            }
        }
    }
    domains
}

// --- URLhaus ---

pub struct UrlHausFeed;

const URLHAUS_URL: &str = "https://urlhaus.abuse.ch/downloads/text/";

impl ThreatFeed for UrlHausFeed {
    fn name(&self) -> &str {
        "URLhaus"
    }
    async fn fetch(&self) -> anyhow::Result<String> {
        Ok(reqwest::get(URLHAUS_URL).await?.text().await?)
    }
    fn parse(&self, raw: &str) -> Vec<String> {
        parse_url_list(raw)
    }
}

// --- OpenPhish ---

pub struct OpenPhishFeed;

const OPENPHISH_URL: &str = "https://openphish.com/feed.txt";

impl ThreatFeed for OpenPhishFeed {
    fn name(&self) -> &str {
        "OpenPhish"
    }
    async fn fetch(&self) -> anyhow::Result<String> {
        Ok(reqwest::get(OPENPHISH_URL).await?.text().await?)
    }
    fn parse(&self, raw: &str) -> Vec<String> {
        parse_url_list(raw)
    }
}

// --- oisd (ad/tracker blocklist) ---

pub struct OisdFeed;

const OISD_URL: &str = "https://big.oisd.nl/";

impl ThreatFeed for OisdFeed {
    fn name(&self) -> &str {
        "oisd"
    }
    async fn fetch(&self) -> anyhow::Result<String> {
        Ok(reqwest::get(OISD_URL).await?.text().await?)
    }
    fn parse(&self, raw: &str) -> Vec<String> {
        parse_adblock_list(raw)
    }
}

/// Parse AdBlock Plus syntax into bare DNS-resolvable domains.
/// Accepts `||domain^` and `||domain^$modifiers` — rejects rules with
/// paths, wildcards, or regex markers (not DNS-scoped).
fn parse_adblock_list(raw: &str) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut domains = Vec::new();
    for line in raw.lines() {
        let line = line.trim();
        if line.is_empty()
            || line.starts_with('!')
            || line.starts_with('#')
            || line.starts_with('[')
        {
            continue;
        }
        let Some(after_anchor) = line.strip_prefix("||") else {
            continue;
        };
        let Some(caret_idx) = after_anchor.find('^') else {
            continue;
        };
        let domain = &after_anchor[..caret_idx];
        if domain.is_empty()
            || !domain.contains('.')
            || domain.contains('/')
            || domain.contains('*')
        {
            continue;
        }
        let lower = domain.to_lowercase();
        if seen.insert(lower.clone()) {
            domains.push(lower);
        }
    }
    domains
}

// --- PhishTank ---

pub struct PhishTankFeed {
    pub api_key: String,
}

impl ThreatFeed for PhishTankFeed {
    fn name(&self) -> &str {
        "PhishTank"
    }

    async fn fetch(&self) -> anyhow::Result<String> {
        let url = format!(
            "https://data.phishtank.com/data/{}/online-valid.json",
            self.api_key
        );
        Ok(reqwest::get(&url).await?.text().await?)
    }

    fn parse(&self, raw: &str) -> Vec<String> {
        let entries: Vec<serde_json::Value> = match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };

        let mut seen = HashSet::new();
        let mut domains = Vec::new();

        for entry in &entries {
            if let Some(url) = entry["url"].as_str() {
                if let Some(host) = extract_host(url) {
                    if seen.insert(host.clone()) {
                        domains.push(host);
                    }
                }
            }
        }

        domains
    }
}

fn extract_host(url: &str) -> Option<String> {
    let after_scheme = url.split_once("://")?.1;
    let host = after_scheme.split('/').next()?;
    let host = host.split(':').next()?;
    let host = host.trim().to_lowercase();
    if host.is_empty() {
        None
    } else {
        Some(host)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extracts_plain_host() {
        assert_eq!(
            extract_host("http://malware.example.com/payload"),
            Some("malware.example.com".into())
        );
    }

    #[test]
    fn extracts_host_with_port() {
        assert_eq!(
            extract_host("http://malware.example.com:8080/payload"),
            Some("malware.example.com".into())
        );
    }

    #[test]
    fn extracts_https_host() {
        assert_eq!(
            extract_host("https://evil.co.uk/drop"),
            Some("evil.co.uk".into())
        );
    }

    #[test]
    fn skips_invalid_url() {
        assert_eq!(extract_host("not-a-url"), None);
    }

    #[test]
    fn urlhaus_parse_skips_comments_and_dedupes() {
        let raw = "# comment\nhttp://evil.com/a\nhttp://evil.com/b\nhttp://other.com/x\n";
        let domains = UrlHausFeed.parse(raw);
        assert_eq!(domains, vec!["evil.com", "other.com"]);
    }

    #[test]
    fn oisd_parses_adblock_domains() {
        let raw = "! Title: oisd big\n[Adblock Plus]\n||ads.example.com^\n||track.net^\n";
        let domains = OisdFeed.parse(raw);
        assert_eq!(domains, vec!["ads.example.com", "track.net"]);
    }

    #[test]
    fn oisd_strips_modifiers_and_dedupes() {
        let raw = "||evil.com^\n||evil.com^$third-party\n||other.net^$image,script\n";
        let domains = OisdFeed.parse(raw);
        assert_eq!(domains, vec!["evil.com", "other.net"]);
    }

    #[test]
    fn oisd_skips_paths_wildcards_and_metadata() {
        let raw =
            "! comment\n[metadata]\n||good.com^\n||bad.com/path^\n||*.wild.com^\n||/regex/^\n";
        let domains = OisdFeed.parse(raw);
        assert_eq!(domains, vec!["good.com"]);
    }

    #[test]
    fn phishtank_parse_extracts_hosts() {
        let raw = r#"[
            {"url": "http://phish.example.com/login", "phish_id": "1"},
            {"url": "http://phish.example.com/steal", "phish_id": "2"},
            {"url": "https://other.net/fake", "phish_id": "3"}
        ]"#;
        let feed = PhishTankFeed {
            api_key: String::new(),
        };
        let domains = feed.parse(raw);
        assert_eq!(domains, vec!["phish.example.com", "other.net"]);
    }

    #[test]
    fn phishtank_parse_handles_invalid_json() {
        let domains = PhishTankFeed {
            api_key: String::new(),
        }
        .parse("not json");
        assert!(domains.is_empty());
    }
}
