use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// Default grace period for retaining retired generation domain pins (30 seconds).
pub const DEFAULT_DNS_PIN_GRACE_PERIOD: Duration = Duration::from_secs(30);

/// Retained DNS pin from a retired generation during its draining grace period.
#[derive(Clone, Debug)]
pub struct RetainedPin {
    pub addrs: Vec<SocketAddr>,
    pub expires_at: Instant,
    pub generation: u64,
}

#[derive(Debug)]
struct DnsResolverInner {
    generation: u64,
    grace_period: Duration,
    active: HashMap<String, Vec<SocketAddr>>,
    retained: HashMap<String, Vec<RetainedPin>>,
}

/// Thread-safe DNS resolver supporting pinned IP destinations with generational lifecycle.
/// Ensures HTTPS connections to origins use the origin hostname for TLS SNI and certificate validation
/// while connecting directly to pre-resolved / pinned IP addresses without DNS rebinding vulnerabilities.
/// Retains retiring generation pins for a grace period so in-flight requests finish cleanly.
/// In strict fail-closed mode, unpinned domains immediately return an error, preventing ambient DNS fallback.
#[derive(Clone)]
pub struct PinnedDnsResolver {
    inner: Arc<RwLock<DnsResolverInner>>,
}

impl Default for PinnedDnsResolver {
    fn default() -> Self {
        Self::new()
    }
}

impl PinnedDnsResolver {
    /// Creates a strict pinned DNS resolver with the default grace period (30s).
    pub fn new() -> Self {
        Self::new_with_grace_period(DEFAULT_DNS_PIN_GRACE_PERIOD)
    }

    /// Creates a strict pinned DNS resolver with an explicit grace period.
    pub fn new_with_grace_period(grace_period: Duration) -> Self {
        Self {
            inner: Arc::new(RwLock::new(DnsResolverInner {
                generation: 1,
                grace_period,
                active: HashMap::new(),
                retained: HashMap::new(),
            })),
        }
    }

    /// Returns the currently configured grace period for retiring pins.
    pub fn grace_period(&self) -> Duration {
        self.inner.read().unwrap().grace_period
    }

    /// Updates the grace period duration.
    pub fn set_grace_period(&self, grace_period: Duration) {
        let mut inner = self.inner.write().unwrap();
        inner.grace_period = grace_period;
    }

    /// Returns the currently active route/DNS generation ID.
    pub fn active_generation(&self) -> u64 {
        self.inner.read().unwrap().generation
    }

    /// Replaces active domain mappings with automatic generation increment,
    /// moving retired pins to the generational retention pool.
    pub fn set_all(&self, mappings: HashMap<String, Vec<SocketAddr>>) {
        let next_gen = {
            let inner = self.inner.read().unwrap();
            inner.generation.wrapping_add(1)
        };
        self.update_generation(next_gen, mappings);
    }

    /// Updates domain mappings to a specific generation ID.
    /// Retires existing active pins not present in `new_mappings` into the retained
    /// pool with an expiration timestamp based on `grace_period`.
    pub fn update_generation(
        &self,
        generation: u64,
        new_mappings: HashMap<String, Vec<SocketAddr>>,
    ) {
        let mut inner = self.inner.write().unwrap();
        let now = Instant::now();
        let expires_at = now + inner.grace_period;
        let old_gen = inner.generation;

        let old_active = std::mem::take(&mut inner.active);
        for (domain, old_addrs) in old_active {
            if let Some(new_addrs) = new_mappings.get(&domain) {
                let missing: Vec<SocketAddr> = old_addrs
                    .into_iter()
                    .filter(|a| !new_addrs.contains(a))
                    .collect();
                if !missing.is_empty() {
                    inner.retained.entry(domain).or_default().push(RetainedPin {
                        addrs: missing,
                        expires_at,
                        generation: old_gen,
                    });
                }
            } else {
                inner.retained.entry(domain).or_default().push(RetainedPin {
                    addrs: old_addrs,
                    expires_at,
                    generation: old_gen,
                });
            }
        }

        inner.active = new_mappings;
        inner.generation = generation;

        // Clean up any previously expired pins
        inner.retained.retain(|_domain, pins| {
            pins.retain(|p| p.expires_at > now);
            !pins.is_empty()
        });
    }

    /// Merges additional domain mappings into the active resolver without evicting existing pins.
    /// Used during staged atomic route updates so in-flight requests on retiring routes maintain valid pins.
    pub fn merge_mappings(&self, additional: &HashMap<String, Vec<SocketAddr>>) {
        let mut inner = self.inner.write().unwrap();
        for (domain, addrs) in additional {
            let entry = inner.active.entry(domain.clone()).or_default();
            for addr in addrs {
                if !entry.contains(addr) {
                    entry.push(*addr);
                }
            }
        }
    }

    /// Purges all expired retained pins past their grace period.
    pub fn prune_expired(&self) {
        let mut inner = self.inner.write().unwrap();
        let now = Instant::now();
        inner.retained.retain(|_domain, pins| {
            pins.retain(|p| p.expires_at > now);
            !pins.is_empty()
        });
    }

    /// Checks whether a domain is currently mapped either in active pins or unexpired retained pins.
    pub fn is_pinned(&self, domain: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();
        let inner = self.inner.read().unwrap();
        let now = Instant::now();

        if inner.active.contains_key(&domain_lower) {
            return true;
        }

        if let Some(pins) = inner.retained.get(&domain_lower) {
            return pins.iter().any(|p| p.expires_at > now);
        }

        false
    }

    /// Checks whether a domain is currently in the retained drain pool.
    pub fn is_retained(&self, domain: &str) -> bool {
        let domain_lower = domain.to_ascii_lowercase();
        let inner = self.inner.read().unwrap();
        let now = Instant::now();

        if let Some(pins) = inner.retained.get(&domain_lower) {
            return pins.iter().any(|p| p.expires_at > now);
        }

        false
    }
}

impl Resolve for PinnedDnsResolver {
    fn resolve(&self, name: Name) -> Resolving {
        let domain = name.as_str().to_ascii_lowercase();
        let inner = self.inner.read().unwrap();
        let now = Instant::now();

        let mut resolved_addrs = Vec::new();

        // 1. Primary path: active generation mappings
        if let Some(addrs) = inner.active.get(&domain) {
            resolved_addrs.extend_from_slice(addrs);
        }

        // 2. Secondary path: unexpired retained generation pins (grace period)
        if let Some(pins) = inner.retained.get(&domain) {
            for p in pins {
                if p.expires_at > now {
                    for addr in &p.addrs {
                        if !resolved_addrs.contains(addr) {
                            resolved_addrs.push(*addr);
                        }
                    }
                }
            }
        }

        if !resolved_addrs.is_empty() {
            let boxed: Addrs = Box::new(resolved_addrs.into_iter());
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
    async fn test_pinned_dns_generational_retention_and_expiry() {
        let grace = Duration::from_millis(50);
        let resolver = PinnedDnsResolver::new_with_grace_period(grace);

        let mut gen1_map = HashMap::new();
        let addr1: SocketAddr = "93.184.216.34:443".parse().unwrap();
        gen1_map.insert("gen1.internal".to_string(), vec![addr1]);
        resolver.update_generation(1, gen1_map);

        assert!(resolver.is_pinned("gen1.internal"));
        assert!(!resolver.is_retained("gen1.internal"));

        // Transition to Generation 2 (gen1.internal is retired, gen2.internal is active)
        let mut gen2_map = HashMap::new();
        let addr2: SocketAddr = "93.184.216.35:443".parse().unwrap();
        gen2_map.insert("gen2.internal".to_string(), vec![addr2]);
        resolver.update_generation(2, gen2_map);

        assert_eq!(resolver.active_generation(), 2);
        assert!(resolver.is_pinned("gen2.internal"));
        assert!(!resolver.is_retained("gen2.internal"));

        // During grace period: gen1.internal MUST still resolve via retained pool
        assert!(resolver.is_retained("gen1.internal"));
        assert!(resolver.is_pinned("gen1.internal"));
        let name_gen1: Name = "gen1.internal".parse().unwrap();
        let mut res1 = resolver.resolve(name_gen1).await.unwrap();
        assert_eq!(res1.next(), Some(addr1));

        // After grace period expires: gen1.internal MUST be purged and fail closed
        tokio::time::sleep(Duration::from_millis(70)).await;
        resolver.prune_expired();

        assert!(!resolver.is_retained("gen1.internal"));
        assert!(!resolver.is_pinned("gen1.internal"));
        let name_gen1_expired: Name = "gen1.internal".parse().unwrap();
        let res1_expired = resolver.resolve(name_gen1_expired).await;
        assert!(res1_expired.is_err());
        assert!(res1_expired.err().unwrap().to_string().contains(
            "Strict DNS: domain 'gen1.internal' has no pinned IP destination configured"
        ));
    }
}
