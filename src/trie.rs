use std::collections::HashMap;

struct TrieNode {
    children: HashMap<String, TrieNode>,
    is_blocked: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: HashMap::new(),
            is_blocked: false,
        }
    }
}

pub struct DomainTrie {
    root: TrieNode,
}

impl Default for DomainTrie {
    fn default() -> Self {
        Self::new()
    }
}

impl DomainTrie {
    pub fn new() -> Self {
        Self {
            root: TrieNode::new(),
        }
    }

    pub fn insert(&mut self, domain: &str) {
        let mut node = &mut self.root;
        for label in domain.split('.').rev() {
            node = node
                .children
                .entry(label.to_string())
                .or_insert_with(TrieNode::new);
        }
        node.is_blocked = true;
    }

    pub fn contains(&self, domain: &str) -> bool {
        let mut node = &self.root;
        for label in domain.split('.').rev() {
            if node.is_blocked {
                return true;
            }
            match node.children.get(label) {
                Some(child) => node = child,
                None => return false,
            }
        }
        node.is_blocked
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_domain_blocked() {
        let mut trie = DomainTrie::new();
        trie.insert("malware.com");
        assert!(trie.contains("malware.com"));
    }

    #[test]
    fn subdomain_blocked_by_parent() {
        let mut trie = DomainTrie::new();
        trie.insert("malware.com");
        assert!(trie.contains("sub.malware.com"));
        assert!(trie.contains("deep.sub.malware.com"));
    }

    #[test]
    fn unrelated_domain_not_blocked() {
        let mut trie = DomainTrie::new();
        trie.insert("malware.com");
        assert!(!trie.contains("google.com"));
        assert!(!trie.contains("notmalware.com"));
    }
}
