use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};

/// Thread-safe DNS resolver supporting pinned IP destinations.
/// Ensures HTTPS connections to origins use the origin hostname for TLS SNI and certificate validation
/// while connecting directly to pre-resolved / pinned IP addresses without DNS rebinding vulnerabilities.
/// In strict fail-closed mode, unpinned domains immediately return an error, preventing ambient DNS fallback.
#[derive(Clone)]
pub struct PinnedDnsResolver {
    pinned: Arc<RwLock<HashMap<String, Vec<SocketAddr>>>>,
    version: Arc<AtomicU64>,
}

impl Default for PinnedDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl PinnedDnsResolver {
    /// Creates a strict pinned DNS resolver (fail-closed, zero unpinned DNS fallback).
    /// Used for upstream origin resolution to completely eliminate DNS rebinding & DNS leakage.
    pub fn new() -> Self {
        Self {
            pinned: Arc::new(RwLock::new(HashMap::new())),
            version: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Increments and returns the next epoch version for staged DNS atomic updates.
    pub fn next_version(&self) -> u64 {
        self.version.fetch_add(1, Ordering::SeqCst) + 1
    }

    /// Replaces all domain mappings atomically.
    pub fn set_all(&self, mappings: HashMap<String, Vec<SocketAddr>>) {
        let mut map = self.pinned.write().unwrap();
        *map = mappings;
    }

    /// Merges additional domain mappings into the active resolver without evicting existing pins.
    /// Used during staged atomic route updates so in-flight requests on retiring routes maintain valid pins.
    pub fn merge_mappings(&self, additional: &HashMap<String, Vec<SocketAddr>>) {
        let mut map = self.pinned.write().unwrap();
        for (domain, addrs) in additional {
            let entry = map.entry(domain.clone()).or_default();
            for addr in addrs {
                if !entry.contains(addr) {
                    entry.push(*addr);
                }
            }
        }
    }

    /// Conditionally prunes retired mappings to match the target set only if the version
    /// has not been superseded by a newer route update.
    pub fn prune_if_version(
        &self,
        mappings: HashMap<String, Vec<SocketAddr>>,
        expected_version: u64,
    ) -> bool {
        if self.version.load(Ordering::SeqCst) == expected_version {
            let mut map = self.pinned.write().unwrap();
            if self.version.load(Ordering::SeqCst) == expected_version {
                *map = mappings;
                return true;
            }
        }
        false
    }
}

impl Resolve for PinnedDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let domain = name.as_str().to_ascii_lowercase();
        if let Some(addrs) = self.pinned.read().unwrap().get(&domain).cloned() {
            let boxed: Addrs = Box::new(addrs.into_iter());
            return Box::pin(std::future::ready(Ok(boxed)));
        }

        let err = std::io::Error::new(
            std::io::ErrorKind::PermissionDenied,
            format!(
                "Strict DNS: domain '{}' has no pinned IP destination configured",
                domain
            ),
        );
        Box::pin(std::future::ready(Err(
            Box::new(err) as Box<dyn std::error::Error + Send + Sync>
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_pinned_dns_resolver_strict_behavior() {
        let resolver = PinnedDnsResolver::new();
        let mut map = HashMap::new();
        let addr: SocketAddr = "93.184.216.34:443".parse().unwrap();
        map.insert("example.com".to_string(), vec![addr]);
        resolver.set_all(map);

        let name: Name = "example.com".parse().unwrap();
        let mut res = resolver.resolve(name).await.unwrap();
        assert_eq!(res.next(), Some(addr));

        let unpinned: Name = "unpinned.com".parse().unwrap();
        let err = resolver.resolve(unpinned).await;
        assert!(err.is_err());
        assert_eq!(
            err.err().unwrap().to_string(),
            "Strict DNS: domain 'unpinned.com' has no pinned IP destination configured"
        );
    }

    #[tokio::test]
    async fn test_pinned_dns_merge_mappings() {
        let resolver = PinnedDnsResolver::new();
        let mut initial = HashMap::new();
        let addr1: SocketAddr = "93.184.216.34:443".parse().unwrap();
        initial.insert("a.com".to_string(), vec![addr1]);
        resolver.set_all(initial);

        let mut additional = HashMap::new();
        let addr2: SocketAddr = "93.184.216.35:443".parse().unwrap();
        additional.insert("b.com".to_string(), vec![addr2]);
        resolver.merge_mappings(&additional);

        let name_a: Name = "a.com".parse().unwrap();
        assert_eq!(resolver.resolve(name_a).await.unwrap().next(), Some(addr1));

        let name_b: Name = "b.com".parse().unwrap();
        assert_eq!(resolver.resolve(name_b).await.unwrap().next(), Some(addr2));
    }

    #[tokio::test]
    async fn test_pinned_dns_prune_if_version() {
        let resolver = PinnedDnsResolver::new();
        let v1 = resolver.next_version();
        let addr1: SocketAddr = "93.184.216.34:443".parse().unwrap();
        let mut map1 = HashMap::new();
        map1.insert("old.com".to_string(), vec![addr1]);
        resolver.set_all(map1);

        let v2 = resolver.next_version();
        let addr2: SocketAddr = "93.184.216.35:443".parse().unwrap();
        let mut map2 = HashMap::new();
        map2.insert("new.com".to_string(), vec![addr2]);

        // Attempting to prune with outdated version v1 should fail and preserve map1
        assert!(!resolver.prune_if_version(map2.clone(), v1));
        assert!(resolver.resolve("old.com".parse().unwrap()).await.is_ok());

        // Pruning with current version v2 succeeds and updates mappings
        assert!(resolver.prune_if_version(map2, v2));
        assert!(resolver.resolve("new.com".parse().unwrap()).await.is_ok());
        assert!(resolver.resolve("old.com".parse().unwrap()).await.is_err());
    }
}
