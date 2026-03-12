use std::collections::HashSet;

const URLHAUS_URL: &str = "https://urlhaus.abuse.ch/downloads/text/";

pub async fn fetch_urlhaus() -> anyhow::Result<Vec<String>> {
    let body = reqwest::get(URLHAUS_URL).await?.text().await?;

    let mut seen = HashSet::new();
    let mut domains = Vec::new();

    for line in body.lines() {
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

    Ok(domains)
}

fn extract_host(url: &str) -> Option<String> {
    // Expected format: "http://hostname/path" or "https://hostname/path"
    let after_scheme = url.split_once("://")?.1;
    let host = after_scheme.split('/').next()?;
    // Strip port if present
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
        assert_eq!(extract_host("http://malware.example.com/payload"), Some("malware.example.com".into()));
    }

    #[test]
    fn extracts_host_with_port() {
        assert_eq!(extract_host("http://malware.example.com:8080/payload"), Some("malware.example.com".into()));
    }

    #[test]
    fn extracts_https_host() {
        assert_eq!(extract_host("https://evil.co.uk/drop"), Some("evil.co.uk".into()));
    }

    #[test]
    fn skips_invalid_url() {
        assert_eq!(extract_host("not-a-url"), None);
    }
}
