use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct UpstreamNode {
    pub url: String,
    pub healthy: bool,
    pub latency_ms: u64,
    pub ewma_latency_ms: f64,
    pub consecutive_passes: u32,
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RoutingError {
    UnknownHost(String),
    NoHealthyUpstreams(String),
}

impl std::fmt::Display for RoutingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RoutingError::UnknownHost(host) => {
                write!(f, "No tenant domain route configured for host: {}", host)
            }
            RoutingError::NoHealthyUpstreams(host) => {
                write!(f, "No healthy upstream nodes available for host: {}", host)
            }
        }
    }
}

impl std::error::Error for RoutingError {}

#[derive(Clone, Debug)]
pub struct DomainRoute {
    pub host: String,
    pub origins: Vec<UpstreamNode>,
}

#[derive(Clone)]
pub struct Router {
    default_nodes: Arc<RwLock<Vec<UpstreamNode>>>,
    routes: Arc<RwLock<HashMap<String, Vec<UpstreamNode>>>>,
    route_indices: Arc<RwLock<HashMap<String, Arc<AtomicUsize>>>>,
    default_index: Arc<AtomicUsize>,
    #[allow(dead_code)]
    timeout: Duration,
    is_multi_tenant: bool,
}

impl Router {
    pub const EWMA_ALPHA: f64 = 0.2;

    fn create_node(url: String) -> UpstreamNode {
        UpstreamNode {
            url,
            healthy: true,
            latency_ms: 10,
            ewma_latency_ms: 10.0,
            consecutive_passes: 2,
            consecutive_failures: 0,
        }
    }

    /// Creates a single-tenant router with default targets (V0 backwards compatibility)
    pub fn new(targets: Vec<String>, timeout_ms: u64) -> Self {
        let nodes = targets.into_iter().map(Self::create_node).collect();
        Self {
            default_nodes: Arc::new(RwLock::new(nodes)),
            routes: Arc::new(RwLock::new(HashMap::new())),
            route_indices: Arc::new(RwLock::new(HashMap::new())),
            default_index: Arc::new(AtomicUsize::new(0)),
            timeout: Duration::from_millis(timeout_ms),
            is_multi_tenant: false,
        }
    }

    /// Creates a multi-tenant router with explicit host-to-origin domain routes (P1 Multi-Tenant Ingress)
    pub fn new_multi_tenant(
        routes_input: Vec<DomainRoute>,
        default_targets: Vec<String>,
        timeout_ms: u64,
    ) -> Self {
        let mut routes_map = HashMap::new();
        let mut indices_map = HashMap::new();

        for route in routes_input {
            let norm_host = normalize_host(&route.host);
            routes_map.insert(norm_host.clone(), route.origins);
            indices_map.insert(norm_host, Arc::new(AtomicUsize::new(0)));
        }

        let default_nodes = default_targets.into_iter().map(Self::create_node).collect();

        Self {
            default_nodes: Arc::new(RwLock::new(default_nodes)),
            routes: Arc::new(RwLock::new(routes_map)),
            route_indices: Arc::new(RwLock::new(indices_map)),
            default_index: Arc::new(AtomicUsize::new(0)),
            timeout: Duration::from_millis(timeout_ms),
            is_multi_tenant: true,
        }
    }

    /// Builds a router from declarative UpstreamConfig
    pub fn from_upstream_config(cfg: &crate::config::UpstreamConfig) -> Self {
        if !cfg.routes.is_empty() {
            let domain_routes = cfg
                .routes
                .iter()
                .map(|r| DomainRoute {
                    host: r.host.clone(),
                    origins: r.targets.iter().cloned().map(Self::create_node).collect(),
                })
                .collect();
            Self::new_multi_tenant(domain_routes, cfg.targets.clone(), cfg.timeout_ms)
        } else {
            Self::new(cfg.targets.clone(), cfg.timeout_ms)
        }
    }

    /// Selects lowest EWMA latency healthy upstream node for the given tenant host.
    /// Fast-path invariant: O(N) scan within tenant's pool with round-robin tie-breaking.
    /// Rejects unknown hosts with RoutingError::UnknownHost when multi-tenant routing is active.
    pub fn select_upstream_for_host(&self, host: &str) -> Result<String, RoutingError> {
        let norm_host = normalize_host(host);

        if self.is_multi_tenant {
            let routes = self.routes.read().unwrap();
            if let Some(nodes) = routes.get(&norm_host) {
                let indices = self.route_indices.read().unwrap();
                let counter = indices
                    .get(&norm_host)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));

                select_from_nodes(nodes, &counter)
                    .ok_or_else(|| RoutingError::NoHealthyUpstreams(norm_host))
            } else {
                Err(RoutingError::UnknownHost(norm_host))
            }
        } else {
            let default_nodes = self.default_nodes.read().unwrap();
            select_from_nodes(&default_nodes, &self.default_index)
                .ok_or_else(|| RoutingError::NoHealthyUpstreams(norm_host))
        }
    }

    /// Selects an upstream from the default pool or first configured route (legacy/fallback)
    #[allow(dead_code)]
    pub fn select_upstream(&self) -> Option<String> {
        let default_nodes = self.default_nodes.read().unwrap();
        if !default_nodes.is_empty() {
            select_from_nodes(&default_nodes, &self.default_index)
        } else {
            let routes = self.routes.read().unwrap();
            for (_host, nodes) in routes.iter() {
                if let Some(target) = select_from_nodes(nodes, &self.default_index) {
                    return Some(target);
                }
            }
            None
        }
    }

    /// Updates probe latency and health hysteresis for a given target URL across all pools
    pub fn mark_health(&self, url: &str, healthy: bool, latency_ms: u64) {
        // 1. Update in default nodes
        {
            let mut nodes = self.default_nodes.write().unwrap();
            if let Some(node) = nodes.iter_mut().find(|n| n.url == url) {
                update_node_health(node, healthy, latency_ms);
            }
        }

        // 2. Update across all tenant routes
        {
            let mut routes = self.routes.write().unwrap();
            for nodes in routes.values_mut() {
                for node in nodes.iter_mut() {
                    if node.url == url {
                        update_node_health(node, healthy, latency_ms);
                    }
                }
            }
        }
    }

    /// Returns all unique upstream target URLs for health probing
    pub fn all_targets(&self) -> Vec<String> {
        let mut set = HashSet::new();

        {
            let nodes = self.default_nodes.read().unwrap();
            for n in nodes.iter() {
                set.insert(n.url.clone());
            }
        }

        {
            let routes = self.routes.read().unwrap();
            for nodes in routes.values() {
                for n in nodes.iter() {
                    set.insert(n.url.clone());
                }
            }
        }

        set.into_iter().collect()
    }

    #[allow(dead_code)]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }
}

pub fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    if let Some(pos) = trimmed.find(':') {
        trimmed[..pos].to_ascii_lowercase()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

fn select_from_nodes(nodes: &[UpstreamNode], index_counter: &AtomicUsize) -> Option<String> {
    // Pass 1: Find minimum EWMA latency among healthy nodes
    let mut min_latency = f64::MAX;
    for node in nodes.iter() {
        if node.healthy && node.ewma_latency_ms < min_latency {
            min_latency = node.ewma_latency_ms;
        }
    }

    if min_latency == f64::MAX {
        return None;
    }

    // Pass 2: Count tied lowest-latency healthy nodes (within 1e-6 epsilon)
    let mut tied_count = 0;
    for node in nodes.iter() {
        if node.healthy && (node.ewma_latency_ms - min_latency).abs() < 1e-6 {
            tied_count += 1;
        }
    }

    if tied_count == 0 {
        return None;
    }

    // Pass 3: Pick deterministic tied node using atomic round-robin counter
    let pick_index = index_counter.fetch_add(1, Ordering::Relaxed) % tied_count;
    let mut current_idx = 0;
    for node in nodes.iter() {
        if node.healthy && (node.ewma_latency_ms - min_latency).abs() < 1e-6 {
            if current_idx == pick_index {
                return Some(node.url.clone());
            }
            current_idx += 1;
        }
    }

    None
}

fn update_node_health(node: &mut UpstreamNode, healthy: bool, latency_ms: u64) {
    if healthy {
        node.consecutive_passes += 1;
        node.consecutive_failures = 0;
        node.latency_ms = latency_ms;

        // Threshold: 2 consecutive passes required to become healthy (prevents flapping)
        if node.consecutive_passes >= 2 {
            node.healthy = true;
        }

        // EWMA latency smoothed update only on successful probes
        if latency_ms > 0 {
            if node.ewma_latency_ms <= 0.0 {
                node.ewma_latency_ms = latency_ms as f64;
            } else {
                node.ewma_latency_ms = Router::EWMA_ALPHA * (latency_ms as f64)
                    + (1.0 - Router::EWMA_ALPHA) * node.ewma_latency_ms;
            }
        }
    } else {
        node.consecutive_failures += 1;
        node.consecutive_passes = 0;

        // Threshold: 3 consecutive failures required to become unhealthy (absorbs transient packet drops)
        if node.consecutive_failures >= 3 {
            node.healthy = false;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_select_upstream_healthy_and_unhealthy_with_hysteresis() {
        let targets = vec![
            "https://origin-1.example.com".to_string(),
            "https://origin-2.example.com".to_string(),
        ];
        let router = Router::new(targets, 5000);

        // Initially both are healthy -> selects upstream
        let u1 = router.select_upstream();
        assert!(u1.is_some());

        // Probe 1 & 2 failures on origin-1: should STILL be healthy due to 3-failure threshold
        router.mark_health("https://origin-1.example.com", false, 999);
        router.mark_health("https://origin-1.example.com", false, 999);
        {
            let nodes = router.default_nodes.read().unwrap();
            let n1 = nodes
                .iter()
                .find(|n| n.url == "https://origin-1.example.com")
                .unwrap();
            assert!(
                n1.healthy,
                "origin-1 should remain healthy after only 2 failures"
            );
        }

        // Probe 3 failure on origin-1: now trips to unhealthy
        router.mark_health("https://origin-1.example.com", false, 999);
        {
            let nodes = router.default_nodes.read().unwrap();
            let n1 = nodes
                .iter()
                .find(|n| n.url == "https://origin-1.example.com")
                .unwrap();
            assert!(
                !n1.healthy,
                "origin-1 should become unhealthy after 3 consecutive failures"
            );
        }

        let u2 = router.select_upstream().unwrap();
        assert_eq!(u2, "https://origin-2.example.com");

        // Fail origin-2 three times as well -> must return None
        router.mark_health("https://origin-2.example.com", false, 999);
        router.mark_health("https://origin-2.example.com", false, 999);
        router.mark_health("https://origin-2.example.com", false, 999);
        let u3 = router.select_upstream();
        assert!(
            u3.is_none(),
            "expected None when all upstreams are unhealthy"
        );

        // Recovery hysteresis: Probe 1 success -> should STILL be unhealthy (needs 2 passes)
        router.mark_health("https://origin-1.example.com", true, 12);
        {
            let nodes = router.default_nodes.read().unwrap();
            let n1 = nodes
                .iter()
                .find(|n| n.url == "https://origin-1.example.com")
                .unwrap();
            assert!(
                !n1.healthy,
                "origin-1 should remain unhealthy after only 1 passing probe"
            );
        }
        assert!(router.select_upstream().is_none());

        // Probe 2 success -> becomes healthy and resumes routing
        router.mark_health("https://origin-1.example.com", true, 12);
        let u4 = router.select_upstream();
        assert_eq!(u4, Some("https://origin-1.example.com".to_string()));
    }

    #[test]
    fn test_ewma_latency_routing_preference() {
        let targets = vec![
            "https://slow-origin.example.com".to_string(),
            "https://fast-origin.example.com".to_string(),
        ];
        let router = Router::new(targets, 5000);

        router.mark_health("https://slow-origin.example.com", true, 150);
        router.mark_health("https://fast-origin.example.com", true, 5);

        let selected = router.select_upstream().unwrap();
        assert_eq!(selected, "https://fast-origin.example.com");
    }

    #[test]
    fn test_multi_tenant_host_isolation_and_unknown_host_rejection() {
        // P1 Finding 1: Multi-tenant host/domain -> origin routing
        let routes = vec![
            DomainRoute {
                host: "customer-a.example.com".to_string(),
                origins: vec![Router::create_node("https://origin-a.internal".to_string())],
            },
            DomainRoute {
                host: "customer-b.example.com".to_string(),
                origins: vec![Router::create_node("https://origin-b.internal".to_string())],
            },
        ];

        let router = Router::new_multi_tenant(routes, vec![], 5000);

        // Customer A must route strictly to origin A
        let upstream_a = router
            .select_upstream_for_host("customer-a.example.com")
            .unwrap();
        assert_eq!(upstream_a, "https://origin-a.internal");

        // Customer B must route strictly to origin B
        let upstream_b = router
            .select_upstream_for_host("CUSTOMER-B.EXAMPLE.COM:443")
            .unwrap();
        assert_eq!(upstream_b, "https://origin-b.internal");

        // Unknown customer must return UnknownHost error (mapped to 421 Misdirected Request)
        let unknown_err = router
            .select_upstream_for_host("customer-c.example.com")
            .unwrap_err();
        assert_eq!(
            unknown_err,
            RoutingError::UnknownHost("customer-c.example.com".to_string())
        );
    }

    #[test]
    fn test_multi_tenant_no_healthy_upstreams_error() {
        let routes = vec![DomainRoute {
            host: "api.customer.com".to_string(),
            origins: vec![Router::create_node(
                "https://origin-fail.internal".to_string(),
            )],
        }];

        let router = Router::new_multi_tenant(routes, vec![], 5000);

        // Fail origin 3 times to trip health threshold
        router.mark_health("https://origin-fail.internal", false, 999);
        router.mark_health("https://origin-fail.internal", false, 999);
        router.mark_health("https://origin-fail.internal", false, 999);

        let err = router
            .select_upstream_for_host("api.customer.com")
            .unwrap_err();
        assert_eq!(
            err,
            RoutingError::NoHealthyUpstreams("api.customer.com".to_string())
        );
    }

    #[test]
    fn test_normalize_host() {
        assert_eq!(normalize_host("example.com"), "example.com");
        assert_eq!(normalize_host("Example.COM:8080"), "example.com");
        assert_eq!(normalize_host("  SUB.Domain.net:443  "), "sub.domain.net");
    }
}
