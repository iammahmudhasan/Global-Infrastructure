use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
pub enum RouterError {
    UnknownHost(String),
    NoHealthyUpstreams(String),
    DuplicateHost(String),
    EmptyHost,
    EmptyTargets(String),
    InvalidTargetUrl {
        host: String,
        url: String,
        reason: String,
    },
    UnsafeTargetUrl {
        host: String,
        url: String,
        reason: String,
    },
    InvalidPayload(String),
}

pub type RoutingError = RouterError;

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterError::UnknownHost(host) => {
                write!(f, "No tenant domain route configured for host: {}", host)
            }
            RouterError::NoHealthyUpstreams(host) => {
                write!(f, "No healthy upstream nodes available for host: {}", host)
            }
            RouterError::DuplicateHost(host) => {
                write!(f, "Duplicate domain route configured for host: {}", host)
            }
            RouterError::EmptyHost => {
                write!(f, "Domain route host cannot be empty")
            }
            RouterError::EmptyTargets(host) => {
                write!(
                    f,
                    "Domain route for host '{}' has no upstream targets configured",
                    host
                )
            }
            RouterError::InvalidTargetUrl { host, url, reason } => {
                write!(
                    f,
                    "Invalid target URL '{}' for host '{}': {}",
                    url, host, reason
                )
            }
            RouterError::UnsafeTargetUrl { host, url, reason } => {
                write!(
                    f,
                    "Unsafe target URL '{}' for host '{}': {}",
                    url, host, reason
                )
            }
            RouterError::InvalidPayload(reason) => {
                write!(f, "Invalid configuration payload: {}", reason)
            }
        }
    }
}

impl std::error::Error for RouterError {}

#[derive(Clone, Debug)]
pub struct DomainRoute {
    pub host: String,
    pub origins: Vec<UpstreamNode>,
}

#[derive(Clone, Debug)]
pub struct Router {
    default_nodes: Arc<RwLock<Vec<UpstreamNode>>>,
    routes: Arc<RwLock<HashMap<String, Vec<UpstreamNode>>>>,
    route_indices: Arc<RwLock<HashMap<String, Arc<AtomicUsize>>>>,
    default_index: Arc<AtomicUsize>,
    #[allow(dead_code)]
    timeout: Duration,
    is_multi_tenant: Arc<AtomicBool>,
}

impl Router {
    pub const EWMA_ALPHA: f64 = 0.2;

    pub fn create_node(url: String) -> UpstreamNode {
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
            is_multi_tenant: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Creates a multi-tenant router with explicit host-to-origin domain routes (P1 Multi-Tenant Ingress).
    /// Enforces fail-closed configuration validation: rejects duplicate hosts, empty targets, and unsafe target URLs.
    pub fn new_multi_tenant(
        routes_input: Vec<DomainRoute>,
        default_targets: Vec<String>,
        timeout_ms: u64,
    ) -> Result<Self, RouterError> {
        let mut routes_map = HashMap::new();
        let mut indices_map = HashMap::new();

        for route in routes_input {
            let norm_host = normalize_host(&route.host);
            if norm_host.is_empty() {
                return Err(RouterError::EmptyHost);
            }
            if routes_map.contains_key(&norm_host) {
                return Err(RouterError::DuplicateHost(norm_host));
            }
            if route.origins.is_empty() {
                return Err(RouterError::EmptyTargets(norm_host));
            }
            for node in &route.origins {
                validate_target_url(&norm_host, &node.url)?;
            }
            routes_map.insert(norm_host.clone(), route.origins);
            indices_map.insert(norm_host, Arc::new(AtomicUsize::new(0)));
        }

        for target in &default_targets {
            validate_target_url("default", target)?;
        }
        let default_nodes = default_targets.into_iter().map(Self::create_node).collect();

        Ok(Self {
            default_nodes: Arc::new(RwLock::new(default_nodes)),
            routes: Arc::new(RwLock::new(routes_map)),
            route_indices: Arc::new(RwLock::new(indices_map)),
            default_index: Arc::new(AtomicUsize::new(0)),
            timeout: Duration::from_millis(timeout_ms),
            is_multi_tenant: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Builds a router from declarative UpstreamConfig.
    /// Returns a validation error if routes contain duplicate hosts, empty targets, or invalid URLs.
    pub fn from_upstream_config(cfg: &crate::config::UpstreamConfig) -> Result<Self, RouterError> {
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
            for target in &cfg.targets {
                validate_target_url("default", target)?;
            }
            Ok(Self::new(cfg.targets.clone(), cfg.timeout_ms))
        }
    }

    /// Atomically updates routing tables from new domain routes (Control Plane dynamic reconfiguration)
    pub fn update_routes(
        &self,
        new_routes: Vec<DomainRoute>,
        new_defaults: Vec<String>,
    ) -> Result<(), RouterError> {
        let mut routes_map = HashMap::new();
        let mut indices_map = HashMap::new();

        for route in new_routes {
            let norm_host = normalize_host(&route.host);
            if norm_host.is_empty() {
                return Err(RouterError::EmptyHost);
            }
            if routes_map.contains_key(&norm_host) {
                return Err(RouterError::DuplicateHost(norm_host));
            }
            if route.origins.is_empty() {
                return Err(RouterError::EmptyTargets(norm_host));
            }
            for node in &route.origins {
                validate_target_url(&norm_host, &node.url)?;
            }
            routes_map.insert(norm_host.clone(), route.origins);
            indices_map.insert(norm_host, Arc::new(AtomicUsize::new(0)));
        }

        for target in &new_defaults {
            validate_target_url("default", target)?;
        }
        let default_nodes: Vec<UpstreamNode> =
            new_defaults.into_iter().map(Self::create_node).collect();

        // Atomically swap routes in memory
        {
            let mut routes_guard = self.routes.write().unwrap();
            let mut indices_guard = self.route_indices.write().unwrap();
            let mut defaults_guard = self.default_nodes.write().unwrap();

            *routes_guard = routes_map;
            *indices_guard = indices_map;
            *defaults_guard = default_nodes;
        }

        self.is_multi_tenant.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Selects lowest EWMA latency healthy upstream node for the given tenant host.
    /// Fast-path invariant: O(N) scan within tenant's pool with round-robin tie-breaking.
    /// Rejects unknown hosts with RoutingError::UnknownHost when multi-tenant routing is active.
    pub fn select_upstream_for_host(&self, host: &str) -> Result<String, RoutingError> {
        let norm_host = normalize_host(host);

        if self.is_multi_tenant.load(Ordering::Relaxed) {
            let routes = self.routes.read().unwrap();
            if let Some(nodes) = routes.get(&norm_host) {
                let indices = self.route_indices.read().unwrap();
                let counter = indices
                    .get(&norm_host)
                    .cloned()
                    .unwrap_or_else(|| Arc::new(AtomicUsize::new(0)));

                select_from_nodes(nodes, &counter)
                    .ok_or(RoutingError::NoHealthyUpstreams(norm_host))
            } else {
                Err(RoutingError::UnknownHost(norm_host))
            }
        } else {
            let default_nodes = self.default_nodes.read().unwrap();
            select_from_nodes(&default_nodes, &self.default_index)
                .ok_or(RoutingError::NoHealthyUpstreams(norm_host))
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
            for nodes in routes.values() {
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

/// Normalizes an incoming Host or authority string to lowercase, safely stripping port.
/// Handles standard domain names (example.com:443), IPv4 (127.0.0.1:8080),
/// and IPv6 addresses formatted with standard brackets ([2001:db8::1]:443 or [2001:db8::1]).
pub fn normalize_host(host: &str) -> String {
    let trimmed = host.trim();
    if trimmed.is_empty() {
        return String::new();
    }

    // 1. Bracketed IPv6 host, with or without port (e.g. "[2001:db8::1]:443" or "[2001:db8::1]")
    if trimmed.starts_with('[') {
        if let Some(end_bracket) = trimmed.find(']') {
            let ip_str = &trimmed[1..end_bracket];
            return ip_str.to_ascii_lowercase();
        }
    }

    // 2. Standard Authority parsing via hyper::http::uri::Authority
    if let Ok(authority) = trimmed.parse::<hyper::http::uri::Authority>() {
        let h = authority.host();
        return h.to_ascii_lowercase();
    }

    // 3. Fallback for host:port where host is an FQDN or IPv4
    if let Some(pos) = trimmed.rfind(':') {
        // Only strip if there's exactly one colon (to avoid stripping unbracketed IPv6 colons)
        if trimmed.matches(':').count() == 1 {
            return trimmed[..pos].to_ascii_lowercase();
        }
    }

    trimmed.to_ascii_lowercase()
}

/// Identifies link-local and cloud metadata destinations (AWS/GCP/Azure/Alibaba link-local IPs and hostnames)
fn is_forbidden_metadata_destination(host: &str) -> bool {
    let lower = host.trim().to_ascii_lowercase();
    if lower == "169.254.169.254"
        || lower == "metadata.google.internal"
        || lower == "metadata.titus.internal"
        || lower == "instance-data"
        || lower == "100.100.100.200"
    {
        return true;
    }
    if let Ok(ip) = lower.parse::<std::net::Ipv4Addr>() {
        if ip.is_link_local() {
            return true;
        }
    }
    false
}

/// Validates target upstream URLs: ensures scheme is http/https, host is valid,
/// rejects embedded user credentials, and enforces cloud metadata SSRF protection.
pub fn validate_target_url(host: &str, target_url: &str) -> Result<(), RouterError> {
    let trimmed = target_url.trim();
    if trimmed.is_empty() {
        return Err(RouterError::InvalidTargetUrl {
            host: host.to_string(),
            url: target_url.to_string(),
            reason: "Target URL cannot be empty".to_string(),
        });
    }

    let parsed = match reqwest::Url::parse(trimmed) {
        Ok(u) => u,
        Err(e) => {
            return Err(RouterError::InvalidTargetUrl {
                host: host.to_string(),
                url: target_url.to_string(),
                reason: format!("Malformed URL: {}", e),
            });
        }
    };

    if parsed.scheme() != "http" && parsed.scheme() != "https" {
        return Err(RouterError::InvalidTargetUrl {
            host: host.to_string(),
            url: target_url.to_string(),
            reason: format!("Scheme must be http or https, got '{}'", parsed.scheme()),
        });
    }

    let url_host = match parsed.host_str() {
        Some(h) if !h.is_empty() => h,
        _ => {
            return Err(RouterError::InvalidTargetUrl {
                host: host.to_string(),
                url: target_url.to_string(),
                reason: "Target URL must contain a valid host".to_string(),
            });
        }
    };

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(RouterError::InvalidTargetUrl {
            host: host.to_string(),
            url: target_url.to_string(),
            reason: "Target URL must not contain embedded user credentials".to_string(),
        });
    }

    if is_forbidden_metadata_destination(url_host) {
        return Err(RouterError::UnsafeTargetUrl {
            host: host.to_string(),
            url: target_url.to_string(),
            reason: "Target URL targets cloud metadata or forbidden link-local service".to_string(),
        });
    }

    Ok(())
}

/// Parses Control Plane PoP configuration sync JSON (or Envoy snapshot) into validated DomainRoutes
pub fn parse_pop_config_routes(json_str: &str) -> Result<Vec<DomainRoute>, RouterError> {
    #[derive(serde::Deserialize)]
    struct SyncWire {
        #[serde(default)]
        routes: Vec<crate::config::DomainRouteConfig>,
    }

    let wire: SyncWire = serde_json::from_str(json_str).map_err(|e| {
        RouterError::InvalidPayload(format!("Failed to parse PoP sync JSON: {}", e))
    })?;

    let mut result = Vec::new();
    for r in wire.routes {
        let norm_host = normalize_host(&r.host);
        if norm_host.is_empty() {
            return Err(RouterError::EmptyHost);
        }
        if r.targets.is_empty() {
            return Err(RouterError::EmptyTargets(norm_host));
        }
        for target in &r.targets {
            validate_target_url(&norm_host, target)?;
        }
        result.push(DomainRoute {
            host: r.host,
            origins: r.targets.into_iter().map(Router::create_node).collect(),
        });
    }
    Ok(result)
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

        let router = Router::new_multi_tenant(routes, vec![], 5000).unwrap();

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

        let router = Router::new_multi_tenant(routes, vec![], 5000).unwrap();

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
    fn test_normalize_host_ipv6_and_authority() {
        // Standard FQDN and port stripping
        assert_eq!(normalize_host("example.com"), "example.com");
        assert_eq!(normalize_host("Example.COM:8080"), "example.com");
        assert_eq!(normalize_host("  SUB.Domain.net:443  "), "sub.domain.net");

        // IPv4 with and without port
        assert_eq!(normalize_host("192.168.1.1:8080"), "192.168.1.1");
        assert_eq!(normalize_host("127.0.0.1"), "127.0.0.1");

        // IPv6 bracketed address with and without port (Finding 4)
        assert_eq!(normalize_host("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(normalize_host("[2001:db8::1]"), "2001:db8::1");
        assert_eq!(normalize_host("[::1]:8080"), "::1");
        assert_eq!(normalize_host("[::1]"), "::1");
    }

    #[test]
    fn test_duplicate_route_host_fails_closed() {
        // Finding 5: Duplicate domain routes must fail closed at initialization
        let routes = vec![
            DomainRoute {
                host: "customer.example.com".to_string(),
                origins: vec![Router::create_node("https://origin-a.internal".to_string())],
            },
            DomainRoute {
                host: "CUSTOMER.EXAMPLE.COM:443".to_string(),
                origins: vec![Router::create_node("https://origin-b.internal".to_string())],
            },
        ];

        let err = Router::new_multi_tenant(routes, vec![], 5000).unwrap_err();
        assert_eq!(
            err,
            RouterError::DuplicateHost("customer.example.com".to_string())
        );
    }

    #[test]
    fn test_empty_targets_and_host_validation() {
        // Finding 6: Empty targets must be rejected at initialization
        let empty_targets_route = vec![DomainRoute {
            host: "dead-tenant.example.com".to_string(),
            origins: vec![],
        }];
        let err = Router::new_multi_tenant(empty_targets_route, vec![], 5000).unwrap_err();
        assert_eq!(
            err,
            RouterError::EmptyTargets("dead-tenant.example.com".to_string())
        );

        // Empty host must be rejected
        let empty_host_route = vec![DomainRoute {
            host: "   ".to_string(),
            origins: vec![Router::create_node("https://origin-a.internal".to_string())],
        }];
        let err = Router::new_multi_tenant(empty_host_route, vec![], 5000).unwrap_err();
        assert_eq!(err, RouterError::EmptyHost);
    }

    #[test]
    fn test_target_url_ssrf_and_schema_validation() {
        // Finding 7: Validate scheme, credentials, and cloud metadata SSRF destinations
        assert!(validate_target_url("cust", "https://origin.example.com:443").is_ok());
        assert!(validate_target_url("cust", "http://10.0.0.1:8080").is_ok());

        // Invalid scheme (e.g. ftp)
        let err = validate_target_url("cust", "ftp://origin.example.com").unwrap_err();
        assert!(matches!(err, RouterError::InvalidTargetUrl { .. }));

        // Embedded user credentials rejected
        let err = validate_target_url("cust", "http://user:pass@origin.example.com").unwrap_err();
        assert!(matches!(err, RouterError::InvalidTargetUrl { .. }));

        // Link-local cloud metadata service rejected
        let err =
            validate_target_url("cust", "http://169.254.169.254/latest/meta-data").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

        let err = validate_target_url("cust", "http://metadata.google.internal/computeMetadata")
            .unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
    }

    #[test]
    fn test_atomic_route_update_and_pop_config_sync() {
        let initial_routes = vec![DomainRoute {
            host: "tenant-1.com".to_string(),
            origins: vec![Router::create_node("https://origin-1.internal".to_string())],
        }];
        let router = Router::new_multi_tenant(initial_routes, vec![], 5000).unwrap();
        assert_eq!(
            router.select_upstream_for_host("tenant-1.com").unwrap(),
            "https://origin-1.internal"
        );

        // Simulate incoming Control Plane PoP sync payload
        let pop_json = r#"{
            "pop_id": "singapore",
            "config_version": "v1.0.0-abc12345",
            "routes": [
                {
                    "host": "tenant-2.com",
                    "targets": ["https://origin-2.internal:8443"]
                }
            ]
        }"#;

        let parsed_routes = parse_pop_config_routes(pop_json).unwrap();
        assert_eq!(parsed_routes.len(), 1);
        assert_eq!(parsed_routes[0].host, "tenant-2.com");

        // Atomically update router with new Control Plane routes
        router.update_routes(parsed_routes, vec![]).unwrap();

        // New tenant is immediately active
        assert_eq!(
            router.select_upstream_for_host("tenant-2.com").unwrap(),
            "https://origin-2.internal:8443"
        );
        // Old tenant route was atomically swapped out
        assert_eq!(
            router.select_upstream_for_host("tenant-1.com").unwrap_err(),
            RoutingError::UnknownHost("tenant-1.com".to_string())
        );
    }
}
