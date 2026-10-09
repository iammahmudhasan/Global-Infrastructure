use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct UpstreamNode {
    pub url: String,
    pub sni: Option<String>,
    pub destination_addr: Option<std::net::SocketAddr>,
    pub healthy: bool,
    pub latency_ms: u64,
    pub ewma_latency_ms: f64,
    pub consecutive_passes: u32,
    pub consecutive_failures: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouterError {
    UnknownHost(String),
    NoMatchingPath {
        host: String,
        path: String,
    },
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
    InvalidPathPrefix {
        host: String,
        prefix: String,
        reason: String,
    },
}

pub type RoutingError = RouterError;

impl std::fmt::Display for RouterError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RouterError::UnknownHost(host) => {
                write!(f, "No tenant domain route configured for host: {}", host)
            }
            RouterError::NoMatchingPath { host, path } => {
                write!(
                    f,
                    "No matching path route configured for host '{}' and path '{}'",
                    host, path
                )
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
            RouterError::InvalidPathPrefix {
                host,
                prefix,
                reason,
            } => {
                write!(
                    f,
                    "Invalid path prefix '{}' for host '{}': {}",
                    prefix, host, reason
                )
            }
        }
    }
}

impl std::error::Error for RouterError {}

#[derive(Clone, Debug)]
pub struct OriginHealthState {
    pub healthy: bool,
    pub latency_ms: u64,
    pub ewma_latency_ms: f64,
    pub consecutive_passes: u32,
    pub consecutive_failures: u32,
}

#[derive(Clone, Debug)]
pub struct PathRoute {
    pub path_prefix: String,
    pub priority: u32,
    pub origins: Vec<UpstreamNode>,
    pub round_robin_index: Arc<AtomicUsize>,
}

#[derive(Clone, Debug)]
#[allow(dead_code)]
pub struct DomainSecurityPolicy {
    pub waf_enabled: bool,
    pub block_sqli: bool,
    pub block_xss: bool,
    pub block_path_traversal: bool,
    pub blocked_paths: Vec<String>,
    pub rate_limit_enabled: bool,
    pub requests_per_second: u32,
    pub burst_capacity: u32,
}

#[derive(Clone, Debug)]
pub struct DomainCachePolicy {
    pub enabled: bool,
    pub default_ttl_seconds: u64,
    pub bypass_paths: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct DomainRoute {
    pub host: String,
    pub origins: Vec<UpstreamNode>,
    pub path_routes: Vec<PathRoute>,
    pub security: Option<DomainSecurityPolicy>,
    pub cache: Option<DomainCachePolicy>,
    pub round_robin_index: Arc<AtomicUsize>,
}

impl DomainRoute {
    pub fn new(host: String, origins: Vec<UpstreamNode>) -> Self {
        let path_routes = if origins.is_empty() {
            vec![]
        } else {
            vec![PathRoute {
                path_prefix: "/".to_string(),
                priority: 0,
                origins: origins.clone(),
                round_robin_index: Arc::new(AtomicUsize::new(0)),
            }]
        };
        Self {
            host,
            origins,
            path_routes,
            security: None,
            cache: None,
            round_robin_index: Arc::new(AtomicUsize::new(0)),
        }
    }

    pub fn with_paths(
        host: String,
        path_routes: Vec<PathRoute>,
        security: Option<DomainSecurityPolicy>,
        cache: Option<DomainCachePolicy>,
    ) -> Self {
        Self {
            host,
            origins: Vec::new(),
            path_routes,
            security,
            cache,
            round_robin_index: Arc::new(AtomicUsize::new(0)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Router {
    default_nodes: Arc<RwLock<Vec<UpstreamNode>>>,
    routes: Arc<RwLock<HashMap<String, DomainRoute>>>,
    health_states: Arc<RwLock<HashMap<String, OriginHealthState>>>,
    default_index: Arc<AtomicUsize>,
    #[allow(dead_code)]
    timeout: Duration,
    is_multi_tenant: Arc<AtomicBool>,
}

impl Router {
    pub const EWMA_ALPHA: f64 = 0.2;

    pub fn create_node(url: String) -> UpstreamNode {
        Self::create_node_full(url, None, None)
    }

    pub fn create_node_full(
        url: String,
        sni: Option<String>,
        destination_addr: Option<std::net::SocketAddr>,
    ) -> UpstreamNode {
        UpstreamNode {
            url,
            sni,
            destination_addr,
            healthy: true,
            latency_ms: 10,
            ewma_latency_ms: 10.0,
            consecutive_passes: 2,
            consecutive_failures: 0,
        }
    }

    pub fn create_node_with_health(
        url: String,
        health_states: &HashMap<String, OriginHealthState>,
    ) -> UpstreamNode {
        Self::create_node_full_with_health(url, None, None, health_states)
    }

    pub fn create_node_full_with_health(
        url: String,
        sni: Option<String>,
        destination_addr: Option<std::net::SocketAddr>,
        health_states: &HashMap<String, OriginHealthState>,
    ) -> UpstreamNode {
        if let Some(h) = health_states.get(&url) {
            UpstreamNode {
                url,
                sni,
                destination_addr,
                healthy: h.healthy,
                latency_ms: h.latency_ms,
                ewma_latency_ms: h.ewma_latency_ms,
                consecutive_passes: h.consecutive_passes,
                consecutive_failures: h.consecutive_failures,
            }
        } else {
            Self::create_node_full(url, sni, destination_addr)
        }
    }

    /// Creates a single-tenant router with default targets (V0 backwards compatibility)
    pub fn new(targets: Vec<String>, timeout_ms: u64) -> Self {
        let nodes = targets.into_iter().map(Self::create_node).collect();
        Self::new_with_nodes(nodes, timeout_ms)
    }

    /// Creates a single-tenant router with pre-built upstream nodes
    pub fn new_with_nodes(nodes: Vec<UpstreamNode>, timeout_ms: u64) -> Self {
        Self {
            default_nodes: Arc::new(RwLock::new(nodes)),
            routes: Arc::new(RwLock::new(HashMap::new())),
            health_states: Arc::new(RwLock::new(HashMap::new())),
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
        for target in &default_targets {
            validate_target_url("default", target)?;
        }
        let default_nodes = default_targets.into_iter().map(Self::create_node).collect();
        Self::new_multi_tenant_with_nodes(routes_input, default_nodes, timeout_ms)
    }

    /// Creates a multi-tenant router with explicit host-to-origin domain routes and pre-constructed nodes
    pub fn new_multi_tenant_with_nodes(
        routes_input: Vec<DomainRoute>,
        default_nodes: Vec<UpstreamNode>,
        timeout_ms: u64,
    ) -> Result<Self, RouterError> {
        let mut routes_map = HashMap::new();

        for route in routes_input {
            let norm_host = normalize_host(&route.host);
            if norm_host.is_empty() {
                return Err(RouterError::EmptyHost);
            }
            if routes_map.contains_key(&norm_host) {
                return Err(RouterError::DuplicateHost(norm_host));
            }
            let total_targets = route.origins.len()
                + route
                    .path_routes
                    .iter()
                    .map(|pr| pr.origins.len())
                    .sum::<usize>();
            if total_targets == 0 {
                return Err(RouterError::EmptyTargets(norm_host));
            }
            for node in &route.origins {
                validate_target_url(&norm_host, &node.url)?;
            }
            for pr in &route.path_routes {
                for node in &pr.origins {
                    validate_target_url(&norm_host, &node.url)?;
                }
            }
            routes_map.insert(norm_host, route);
        }

        for node in &default_nodes {
            validate_target_url("default", &node.url)?;
        }

        Ok(Self {
            default_nodes: Arc::new(RwLock::new(default_nodes)),
            routes: Arc::new(RwLock::new(routes_map)),
            health_states: Arc::new(RwLock::new(HashMap::new())),
            default_index: Arc::new(AtomicUsize::new(0)),
            timeout: Duration::from_millis(timeout_ms),
            is_multi_tenant: Arc::new(AtomicBool::new(true)),
        })
    }

    /// Builds a validated upstream node from static origin configuration (anti-SSRF and IP pinning parity)
    pub fn create_node_from_static_origin(
        norm_host: &str,
        origin: &crate::config::StaticOriginConfig,
    ) -> Result<UpstreamNode, RouterError> {
        let proto = origin.protocol.to_lowercase();
        if proto != "http" && proto != "https" {
            return Err(RouterError::InvalidTargetUrl {
                host: norm_host.to_string(),
                url: origin.address.clone(),
                reason: format!("Protocol must be http or https, got '{}'", origin.protocol),
            });
        }
        if origin.port == 0 {
            return Err(RouterError::InvalidTargetUrl {
                host: norm_host.to_string(),
                url: origin.address.clone(),
                reason: "Origin port cannot be 0".to_string(),
            });
        }
        let sni_trimmed = origin
            .sni
            .as_deref()
            .map(|s| s.trim())
            .filter(|s| !s.is_empty());
        let clean_addr = origin
            .address
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');

        let ip = clean_addr.parse::<std::net::IpAddr>().map_err(|_| {
            RouterError::InvalidPayload("Static origin address must be a pinned IP".to_string())
        })?;

        if is_private_or_reserved_ip(ip) {
            return Err(RouterError::UnsafeTargetUrl {
                host: norm_host.to_string(),
                url: origin.address.clone(),
                reason: "Origin IP is private or reserved".to_string(),
            });
        }

        let dest_addr = Some(std::net::SocketAddr::new(ip, origin.port));

        let host_for_url = match ip {
            std::net::IpAddr::V6(v6) => format!("[{}]", v6),
            std::net::IpAddr::V4(v4) => v4.to_string(),
        };

        let is_https = proto == "https";
        let (url, sni, destination_addr) = match (is_https, sni_trimmed) {
            (true, Some(sni_host)) if sni_host != clean_addr => {
                let target_url = format!("https://{}:{}", sni_host, origin.port);
                (target_url, Some(sni_host.to_string()), dest_addr)
            }
            _ => {
                let target_url = format!("{}://{}:{}", proto, host_for_url, origin.port);
                (target_url, None, dest_addr)
            }
        };

        validate_target_url(norm_host, &url)?;
        Ok(Router::create_node_full(url, sni, destination_addr))
    }

    /// Builds a validated upstream node from a target URL string, resolving hostname to pinned IP
    pub fn create_node_from_target_str(
        norm_host: &str,
        target_str: &str,
    ) -> Result<UpstreamNode, RouterError> {
        validate_target_url(norm_host, target_str)?;
        let uri = target_str
            .parse::<hyper::Uri>()
            .map_err(|e| RouterError::InvalidTargetUrl {
                host: norm_host.to_string(),
                url: target_str.to_string(),
                reason: format!("Malformed URI: {}", e),
            })?;
        let scheme = uri.scheme_str().unwrap_or("http").to_lowercase();
        let host = uri.host().ok_or_else(|| RouterError::InvalidTargetUrl {
            host: norm_host.to_string(),
            url: target_str.to_string(),
            reason: "Target missing host".to_string(),
        })?;
        let port = uri
            .port_u16()
            .unwrap_or(if scheme == "https" { 443 } else { 80 });

        if let Ok(ip) = host.parse::<std::net::IpAddr>() {
            if is_private_or_reserved_ip(ip) {
                return Err(RouterError::UnsafeTargetUrl {
                    host: norm_host.to_string(),
                    url: target_str.to_string(),
                    reason: "Target IP is private or reserved".to_string(),
                });
            }
            let dest_addr = Some(std::net::SocketAddr::new(ip, port));
            let host_for_url = match ip {
                std::net::IpAddr::V6(v6) => format!("[{}]", v6),
                std::net::IpAddr::V4(v4) => v4.to_string(),
            };
            let url = format!("{}://{}:{}", scheme, host_for_url, port);
            return Ok(Router::create_node_full(url, None, dest_addr));
        }

        // Host is a domain name (e.g. "httpbin.org")
        let lookup_target = format!("{}:{}", host, port);
        use std::net::ToSocketAddrs;
        if let Ok(resolved_addrs) = lookup_target.to_socket_addrs() {
            for addr in resolved_addrs {
                if !is_private_or_reserved_ip(addr.ip()) {
                    let target_url = format!("{}://{}:{}", scheme, host, port);
                    return Ok(Router::create_node_full(
                        target_url,
                        Some(host.to_string()),
                        Some(addr),
                    ));
                }
            }
        }

        // Fallback for unresolvable host (e.g. synthetic test domains in unit tests)
        let target_url = format!("{}://{}:{}", scheme, host, port);
        Ok(Router::create_node_full(
            target_url,
            Some(host.to_string()),
            None,
        ))
    }

    /// Builds a router from declarative UpstreamConfig.
    /// Returns a validation error if routes contain duplicate hosts, empty targets, or invalid URLs.
    pub fn from_upstream_config(cfg: &crate::config::UpstreamConfig) -> Result<Self, RouterError> {
        let mut default_nodes = Vec::new();
        for o in &cfg.origins {
            default_nodes.push(Self::create_node_from_static_origin("default", o)?);
        }
        for target in &cfg.targets {
            default_nodes.push(Self::create_node_from_target_str("default", target)?);
        }

        if !cfg.routes.is_empty() {
            let mut domain_routes = Vec::new();
            for r in &cfg.routes {
                let norm_host = normalize_host(&r.host);
                if !r.path_routes.is_empty() {
                    let mut path_routes = Vec::new();
                    for pr in &r.path_routes {
                        validate_path_prefix(&r.host, &pr.path_prefix)?;
                        let mut pr_nodes = Vec::new();
                        for o in &pr.origins {
                            pr_nodes.push(Self::create_node_from_static_origin(&norm_host, o)?);
                        }
                        for t in &pr.targets {
                            pr_nodes.push(Self::create_node_from_target_str(&norm_host, t)?);
                        }
                        path_routes.push(PathRoute {
                            path_prefix: pr.path_prefix.clone(),
                            priority: pr.priority,
                            origins: pr_nodes,
                            round_robin_index: Arc::new(AtomicUsize::new(0)),
                        });
                    }
                    domain_routes.push(DomainRoute::with_paths(
                        r.host.clone(),
                        path_routes,
                        None,
                        None,
                    ));
                } else {
                    let mut r_nodes = Vec::new();
                    for o in &r.origins {
                        r_nodes.push(Self::create_node_from_static_origin(&norm_host, o)?);
                    }
                    for t in &r.targets {
                        r_nodes.push(Self::create_node_from_target_str(&norm_host, t)?);
                    }
                    domain_routes.push(DomainRoute::new(r.host.clone(), r_nodes));
                }
            }
            Self::new_multi_tenant_with_nodes(domain_routes, default_nodes, cfg.timeout_ms)
        } else {
            Ok(Self::new_with_nodes(default_nodes, cfg.timeout_ms))
        }
    }

    /// Atomically updates routing tables from new domain routes (Control Plane dynamic reconfiguration)
    /// Preserves existing node health states across route updates (P1 Finding 2)
    #[allow(dead_code)]
    pub fn update_routes(
        &self,
        mut new_routes: Vec<DomainRoute>,
        new_defaults: Vec<String>,
    ) -> Result<(), RouterError> {
        let mut routes_map = HashMap::new();

        // 1. Validate routes
        for route in &new_routes {
            let norm_host = normalize_host(&route.host);
            if norm_host.is_empty() {
                return Err(RouterError::EmptyHost);
            }
            if routes_map.contains_key(&norm_host) {
                return Err(RouterError::DuplicateHost(norm_host));
            }
            let total_targets = route.origins.len()
                + route
                    .path_routes
                    .iter()
                    .map(|pr| pr.origins.len())
                    .sum::<usize>();
            if total_targets == 0 {
                return Err(RouterError::EmptyTargets(norm_host));
            }
            for node in &route.origins {
                validate_target_url(&norm_host, &node.url)?;
            }
            for pr in &route.path_routes {
                validate_path_prefix(&norm_host, &pr.path_prefix)?;
                for node in &pr.origins {
                    validate_target_url(&norm_host, &node.url)?;
                }
            }
            routes_map.insert(norm_host, ());
        }

        for target in &new_defaults {
            validate_target_url("default", target)?;
        }

        // 2. Refresh health states into new nodes to preserve health hysteresis across updates (P1 Finding 2)
        let health_states = self.health_states.read().unwrap();
        for route in &mut new_routes {
            for node in &mut route.origins {
                if let Some(h) = health_states.get(&node.url) {
                    node.healthy = h.healthy;
                    node.latency_ms = h.latency_ms;
                    node.ewma_latency_ms = h.ewma_latency_ms;
                    node.consecutive_passes = h.consecutive_passes;
                    node.consecutive_failures = h.consecutive_failures;
                }
            }
            for pr in &mut route.path_routes {
                for node in &mut pr.origins {
                    if let Some(h) = health_states.get(&node.url) {
                        node.healthy = h.healthy;
                        node.latency_ms = h.latency_ms;
                        node.ewma_latency_ms = h.ewma_latency_ms;
                        node.consecutive_passes = h.consecutive_passes;
                        node.consecutive_failures = h.consecutive_failures;
                    }
                }
            }
        }

        let mut final_routes_map = HashMap::new();
        for route in new_routes {
            let norm_host = normalize_host(&route.host);
            final_routes_map.insert(norm_host, route);
        }

        let default_nodes: Vec<UpstreamNode> = new_defaults
            .into_iter()
            .map(|u| Self::create_node_with_health(u, &health_states))
            .collect();

        // 3. Atomically swap routes in memory
        {
            let mut routes_guard = self.routes.write().unwrap();
            let mut defaults_guard = self.default_nodes.write().unwrap();

            *routes_guard = final_routes_map;
            *defaults_guard = default_nodes;
        }

        self.is_multi_tenant.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Atomically updates routing tables and pre-publishes DNS pinning mappings into PinnedDnsResolver.
    /// Guarantees that if route validation fails, neither active routes nor DNS mappings are modified.
    pub fn update_routes_with_dns(
        &self,
        mut new_routes: Vec<DomainRoute>,
        new_defaults: Vec<String>,
        dns_resolver: &crate::dns::PinnedDnsResolver,
    ) -> Result<(), RouterError> {
        let mut routes_map = HashMap::new();

        // 1. Validate candidate routes before touching any state
        for route in &new_routes {
            let norm_host = normalize_host(&route.host);
            if norm_host.is_empty() {
                return Err(RouterError::EmptyHost);
            }
            if routes_map.contains_key(&norm_host) {
                return Err(RouterError::DuplicateHost(norm_host));
            }
            let total_targets = route.origins.len()
                + route
                    .path_routes
                    .iter()
                    .map(|pr| pr.origins.len())
                    .sum::<usize>();
            if total_targets == 0 {
                return Err(RouterError::EmptyTargets(norm_host));
            }
            for node in &route.origins {
                validate_target_url(&norm_host, &node.url)?;
            }
            for pr in &route.path_routes {
                validate_path_prefix(&norm_host, &pr.path_prefix)?;
                for node in &pr.origins {
                    validate_target_url(&norm_host, &node.url)?;
                }
            }
            routes_map.insert(norm_host, ());
        }

        for target in &new_defaults {
            validate_target_url("default", target)?;
        }

        // 2. Prepare candidate DNS mappings from validated candidate routes
        let mut candidate_dns: HashMap<String, Vec<std::net::SocketAddr>> = HashMap::new();
        let mut insert_node = |n: &UpstreamNode| {
            if let (Some(sni), Some(addr)) = (&n.sni, n.destination_addr) {
                let addrs = candidate_dns.entry(sni.to_ascii_lowercase()).or_default();
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
            }
        };

        for route in &new_routes {
            for n in &route.origins {
                insert_node(n);
            }
            for pr in &route.path_routes {
                for n in &pr.origins {
                    insert_node(n);
                }
            }
        }

        // 3. Refresh health states into new nodes
        let health_states = self.health_states.read().unwrap();
        for route in &mut new_routes {
            for node in &mut route.origins {
                if let Some(h) = health_states.get(&node.url) {
                    node.healthy = h.healthy;
                    node.latency_ms = h.latency_ms;
                    node.ewma_latency_ms = h.ewma_latency_ms;
                    node.consecutive_passes = h.consecutive_passes;
                    node.consecutive_failures = h.consecutive_failures;
                }
            }
            for pr in &mut route.path_routes {
                for node in &mut pr.origins {
                    if let Some(h) = health_states.get(&node.url) {
                        node.healthy = h.healthy;
                        node.latency_ms = h.latency_ms;
                        node.ewma_latency_ms = h.ewma_latency_ms;
                        node.consecutive_passes = h.consecutive_passes;
                        node.consecutive_failures = h.consecutive_failures;
                    }
                }
            }
        }

        let mut final_routes_map = HashMap::new();
        for route in new_routes {
            let norm_host = normalize_host(&route.host);
            final_routes_map.insert(norm_host, route);
        }

        let default_nodes: Vec<UpstreamNode> = new_defaults
            .into_iter()
            .map(|u| Self::create_node_with_health(u, &health_states))
            .collect();

        // 4. Staged DNS Pre-publish (merge candidate mappings):
        // Retains active route pins while ensuring new route pins are immediately present
        // for any request evaluated right at the transition boundary.
        dns_resolver.merge_mappings(&candidate_dns);

        // 5. Atomically swap routes in memory under exclusive write lock
        {
            let mut routes_guard = self.routes.write().unwrap();
            let mut defaults_guard = self.default_nodes.write().unwrap();

            *routes_guard = final_routes_map;
            *defaults_guard = default_nodes;
        }

        // 6. Prune DNS mappings to exact active candidate set after the route swap
        dns_resolver.set_all(candidate_dns);

        self.is_multi_tenant.store(true, Ordering::SeqCst);
        Ok(())
    }

    /// Selects lowest EWMA latency healthy upstream node for the given tenant host and request path.
    /// Fast-path invariant: longest-prefix & highest-priority match within tenant's routes (P1 Path Routing).
    pub fn select_upstream_for_host_and_path(
        &self,
        host: &str,
        path: &str,
    ) -> Result<String, RoutingError> {
        let norm_host = normalize_host(host);

        if self.is_multi_tenant.load(Ordering::Relaxed) {
            let routes = self.routes.read().unwrap();
            if let Some(domain_route) = routes.get(&norm_host) {
                let mut matching: Vec<&PathRoute> = domain_route
                    .path_routes
                    .iter()
                    .filter(|pr| path_matches_prefix(path, &pr.path_prefix))
                    .collect();

                matching.sort_by(|a, b| {
                    b.priority
                        .cmp(&a.priority)
                        .then_with(|| b.path_prefix.len().cmp(&a.path_prefix.len()))
                });

                if let Some(best) = matching.first() {
                    select_from_nodes(&best.origins, &best.round_robin_index)
                        .ok_or_else(|| RoutingError::NoHealthyUpstreams(norm_host.clone()))
                } else if !domain_route.origins.is_empty() {
                    select_from_nodes(&domain_route.origins, &domain_route.round_robin_index)
                        .ok_or_else(|| RoutingError::NoHealthyUpstreams(norm_host.clone()))
                } else {
                    Err(RoutingError::NoMatchingPath {
                        host: norm_host,
                        path: path.to_string(),
                    })
                }
            } else {
                Err(RoutingError::UnknownHost(norm_host))
            }
        } else {
            let default_nodes = self.default_nodes.read().unwrap();
            select_from_nodes(&default_nodes, &self.default_index)
                .ok_or(RoutingError::NoHealthyUpstreams(norm_host))
        }
    }

    /// Selects lowest EWMA latency healthy upstream node for the given tenant host (root path fallback)
    #[allow(dead_code)]
    pub fn select_upstream_for_host(&self, host: &str) -> Result<String, RoutingError> {
        self.select_upstream_for_host_and_path(host, "/")
    }

    /// Returns tenant security and cache policy if configured for domain
    pub fn get_domain_policy(
        &self,
        host: &str,
    ) -> Option<(Option<DomainSecurityPolicy>, Option<DomainCachePolicy>)> {
        let norm_host = normalize_host(host);
        let routes = self.routes.read().unwrap();
        routes
            .get(&norm_host)
            .map(|dr| (dr.security.clone(), dr.cache.clone()))
    }

    /// Selects an upstream from the default pool or first configured route (legacy/fallback)
    #[allow(dead_code)]
    pub fn select_upstream(&self) -> Option<String> {
        let default_nodes = self.default_nodes.read().unwrap();
        if !default_nodes.is_empty() {
            select_from_nodes(&default_nodes, &self.default_index)
        } else {
            let routes = self.routes.read().unwrap();
            for domain_route in routes.values() {
                if let Some(target) = select_from_nodes(&domain_route.origins, &self.default_index)
                {
                    return Some(target);
                }
            }
            None
        }
    }

    /// Updates probe latency and health hysteresis for a given target URL across all pools
    pub fn mark_health(&self, url: &str, healthy: bool, latency_ms: u64) {
        // 1. Update persistent health states
        {
            let mut states = self.health_states.write().unwrap();
            let entry = states
                .entry(url.to_string())
                .or_insert_with(|| OriginHealthState {
                    healthy: true,
                    latency_ms: 10,
                    ewma_latency_ms: 10.0,
                    consecutive_passes: 2,
                    consecutive_failures: 0,
                });
            entry.latency_ms = latency_ms;
            entry.ewma_latency_ms = Self::EWMA_ALPHA * (latency_ms as f64)
                + (1.0 - Self::EWMA_ALPHA) * entry.ewma_latency_ms;
            if healthy {
                entry.consecutive_passes += 1;
                entry.consecutive_failures = 0;
                if entry.consecutive_passes >= 2 {
                    entry.healthy = true;
                }
            } else {
                entry.consecutive_failures += 1;
                entry.consecutive_passes = 0;
                if entry.consecutive_failures >= 3 {
                    entry.healthy = false;
                }
            }
        }

        // 2. Update live nodes in default pool
        {
            let mut nodes = self.default_nodes.write().unwrap();
            for node in nodes.iter_mut() {
                if node.url == url {
                    update_node_health(node, healthy, latency_ms);
                }
            }
        }

        // 3. Update live nodes across all tenant routes and path routes
        {
            let mut routes = self.routes.write().unwrap();
            for domain_route in routes.values_mut() {
                for node in domain_route.origins.iter_mut() {
                    if node.url == url {
                        update_node_health(node, healthy, latency_ms);
                    }
                }
                for pr in domain_route.path_routes.iter_mut() {
                    for node in pr.origins.iter_mut() {
                        if node.url == url {
                            update_node_health(node, healthy, latency_ms);
                        }
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
            for dr in routes.values() {
                for n in &dr.origins {
                    set.insert(n.url.clone());
                }
                for pr in &dr.path_routes {
                    for n in &pr.origins {
                        set.insert(n.url.clone());
                    }
                }
            }
        }

        set.into_iter().collect()
    }

    #[allow(dead_code)]
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Returns all DNS domain -> pinned SocketAddr mappings across all active routes (deduplicated)
    pub fn dns_mappings(&self) -> HashMap<String, Vec<std::net::SocketAddr>> {
        let mut map: HashMap<String, Vec<std::net::SocketAddr>> = HashMap::new();
        let mut insert_node = |n: &UpstreamNode| {
            if let (Some(sni), Some(addr)) = (&n.sni, n.destination_addr) {
                let addrs = map.entry(sni.to_ascii_lowercase()).or_default();
                if !addrs.contains(&addr) {
                    addrs.push(addr);
                }
            }
        };

        {
            let default_nodes = self.default_nodes.read().unwrap();
            for n in default_nodes.iter() {
                insert_node(n);
            }
        }
        {
            let routes = self.routes.read().unwrap();
            for dr in routes.values() {
                for n in &dr.origins {
                    insert_node(n);
                }
                for pr in &dr.path_routes {
                    for n in &pr.origins {
                        insert_node(n);
                    }
                }
            }
        }
        map
    }

    /// Synchronizes current route DNS mappings into the given PinnedDnsResolver
    pub fn sync_dns_resolver(&self, resolver: &crate::dns::PinnedDnsResolver) {
        resolver.set_all(self.dns_mappings());
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

/// Path-segment boundary-aware prefix matching.
/// Matches exact prefix or directory hierarchy boundary (e.g., '/admin' matches '/admin' and '/admin/users' but not '/administrator').
pub fn path_matches_prefix(path: &str, prefix: &str) -> bool {
    if prefix == "/" {
        return path.starts_with('/');
    }
    if path == prefix {
        return true;
    }
    if prefix.ends_with('/') {
        path.starts_with(prefix)
    } else {
        path.starts_with(prefix) && path[prefix.len()..].starts_with('/')
    }
}

/// Validates route path_prefix ensuring non-empty and leading slash.
/// Strict industrial contract: '/' is explicit catch-all root.
/// Empty strings, relative prefixes without leading slash, and whitespace are strictly rejected.
pub fn validate_path_prefix(host: &str, prefix: &str) -> Result<(), RouterError> {
    let trimmed = prefix.trim();
    if trimmed.is_empty() {
        return Err(RouterError::InvalidPathPrefix {
            host: host.to_string(),
            prefix: prefix.to_string(),
            reason: "Path prefix cannot be empty".to_string(),
        });
    }
    if !trimmed.starts_with('/') {
        return Err(RouterError::InvalidPathPrefix {
            host: host.to_string(),
            prefix: prefix.to_string(),
            reason: "Path prefix must start with leading '/'".to_string(),
        });
    }
    if prefix.contains(' ')
        || prefix.contains('\r')
        || prefix.contains('\n')
        || prefix.contains('\t')
    {
        return Err(RouterError::InvalidPathPrefix {
            host: host.to_string(),
            prefix: prefix.to_string(),
            reason: "Path prefix must not contain whitespace characters".to_string(),
        });
    }
    Ok(())
}

/// Identifies private RFC 1918, loopback, link-local, carrier-grade NAT, multicast,
/// broadcast, special-purpose protocol, documentation, benchmarking, and IPv6 ULA / link-local destinations.
/// Fully handles IPv4-mapped IPv6 (::ffff:x.x.x.x) by extracting the mapped IPv4 and applying IPv4 policy (Anti-SSRF Parity).
pub fn is_private_or_reserved_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(ipv4) => {
            let octets = ipv4.octets();
            // 0.0.0.0/8 (Unspecified / Local identification - RFC 1122)
            if octets[0] == 0 {
                return true;
            }
            // 10.0.0.0/8 (Private-Use - RFC 1918)
            if octets[0] == 10 {
                return true;
            }
            // 100.64.0.0/10 (Shared Address Space / CGNAT - RFC 6598)
            if octets[0] == 100 && (64..=127).contains(&octets[1]) {
                return true;
            }
            // 127.0.0.0/8 (Loopback - RFC 1122)
            if octets[0] == 127 {
                return true;
            }
            // 169.254.0.0/16 (Link-local - RFC 3927)
            if octets[0] == 169 && octets[1] == 254 {
                return true;
            }
            // 172.16.0.0/12 (Private-Use - RFC 1918)
            if octets[0] == 172 && (16..=31).contains(&octets[1]) {
                return true;
            }
            // 192.0.0.0/24 (IETF Protocol Assignments - RFC 6890)
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 0 {
                return true;
            }
            // 192.0.2.0/24 (TEST-NET-1 Documentation - RFC 5737)
            if octets[0] == 192 && octets[1] == 0 && octets[2] == 2 {
                return true;
            }
            // 192.168.0.0/16 (Private-Use - RFC 1918)
            if octets[0] == 192 && octets[1] == 168 {
                return true;
            }
            // 198.18.0.0/15 (Benchmarking - RFC 2544)
            if octets[0] == 198 && (18..=19).contains(&octets[1]) {
                return true;
            }
            // 198.51.100.0/24 (TEST-NET-2 Documentation - RFC 5737)
            if octets[0] == 198 && octets[1] == 51 && octets[2] == 100 {
                return true;
            }
            // 203.0.113.0/24 (TEST-NET-3 Documentation - RFC 5737)
            if octets[0] == 203 && octets[1] == 0 && octets[2] == 113 {
                return true;
            }
            // 224.0.0.0/4 (Multicast - RFC 5771) and 240.0.0.0/4 (Reserved / Broadcast - RFC 1112)
            if octets[0] >= 224 {
                return true;
            }
            false
        }
        std::net::IpAddr::V6(ipv6) => {
            // First check if IPv6 is an IPv4-mapped address (::ffff:a.b.c.d)
            if let Some(ipv4) = ipv6.to_ipv4_mapped() {
                return is_private_or_reserved_ip(std::net::IpAddr::V4(ipv4));
            }

            if ipv6.is_loopback() || ipv6.is_unspecified() {
                return true;
            }
            let segments = ipv6.segments();
            // fe80::/10 (Link-local unicast - RFC 4291)
            if (segments[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // fc00::/7 (Unique Local Address - ULA - RFC 4193)
            if (segments[0] & 0xfe00) == 0xfc00 {
                return true;
            }
            // ff00::/8 (Multicast - RFC 4291)
            if (segments[0] & 0xff00) == 0xff00 {
                return true;
            }
            // 2001:db8::/32 (Documentation - RFC 3849)
            if segments[0] == 0x2001 && segments[1] == 0x0db8 {
                return true;
            }
            // 2001:2::/48 (Benchmarking - RFC 5180)
            if segments[0] == 0x2001 && segments[1] == 0x0002 && segments[2] == 0 {
                return true;
            }
            // 100::/64 (Discard-Only - RFC 6666)
            if segments[0] == 0x0100 && segments[1] == 0 && segments[2] == 0 && segments[3] == 0 {
                return true;
            }
            false
        }
    }
}

pub fn is_forbidden_destination(host: &str) -> bool {
    let lower = host.trim().to_ascii_lowercase();
    let unbracketed = lower.trim_start_matches('[').trim_end_matches(']');
    if unbracketed == "169.254.169.254"
        || unbracketed == "metadata.google.internal"
        || unbracketed == "metadata.titus.internal"
        || unbracketed == "instance-data"
        || unbracketed == "100.100.100.200"
        || unbracketed == "localhost"
    {
        return true;
    }
    if let Ok(ip) = unbracketed.parse::<std::net::IpAddr>() {
        return is_private_or_reserved_ip(ip);
    }
    false
}

/// Validates target upstream URLs: ensures scheme is http/https, host is valid,
/// rejects embedded user credentials, and enforces cloud metadata & private SSRF protection.
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

    if is_forbidden_destination(url_host) {
        return Err(RouterError::UnsafeTargetUrl {
            host: host.to_string(),
            url: target_url.to_string(),
            reason: "Target URL targets private RFC 1918, loopback, cloud metadata, or reserved destination".to_string(),
        });
    }

    Ok(())
}

/// Parses Control Plane PoP configuration sync JSON (or Envoy snapshot) into validated DomainRoutes
pub fn parse_pop_config_routes(json_str: &str) -> Result<Vec<DomainRoute>, RouterError> {
    #[derive(serde::Deserialize)]
    struct WireOrigin {
        address: String,
        port: u16,
        #[serde(default = "default_wire_protocol")]
        protocol: String,
        #[serde(default)]
        #[allow(dead_code)]
        sni: Option<String>,
        #[serde(default)]
        #[allow(dead_code)]
        weight: Option<u32>,
    }

    fn default_wire_protocol() -> String {
        "HTTP".to_string()
    }

    #[derive(serde::Deserialize)]
    struct WirePathRoute {
        #[serde(default = "default_wire_path_prefix")]
        path_prefix: String,
        #[serde(default)]
        priority: u32,
        #[serde(default)]
        origins: Vec<WireOrigin>,
        #[serde(default)]
        targets: Vec<String>,
    }

    fn default_wire_path_prefix() -> String {
        "/".to_string()
    }

    #[derive(serde::Deserialize)]
    struct WireSecurity {
        #[serde(default)]
        waf_enabled: bool,
        #[serde(default)]
        block_sqli: bool,
        #[serde(default)]
        block_xss: bool,
        #[serde(default)]
        block_path_traversal: bool,
        #[serde(default)]
        blocked_paths: Vec<String>,
        #[serde(default)]
        rate_limit_enabled: bool,
        #[serde(default)]
        requests_per_second: u32,
        #[serde(default)]
        burst_capacity: u32,
    }

    #[derive(serde::Deserialize)]
    struct WireCache {
        #[serde(default)]
        enabled: bool,
        #[serde(default)]
        default_ttl_seconds: u64,
        #[serde(default)]
        bypass_paths: Vec<String>,
    }

    #[derive(serde::Deserialize)]
    struct WireDomainRoute {
        host: String,
        #[serde(default)]
        origins: Vec<WireOrigin>,
        #[serde(default)]
        targets: Vec<String>,
        #[serde(default)]
        path_routes: Vec<WirePathRoute>,
        #[serde(default)]
        security: Option<WireSecurity>,
        #[serde(default)]
        cache: Option<WireCache>,
    }

    #[derive(serde::Deserialize)]
    struct SyncWire {
        #[serde(default)]
        routes: Vec<WireDomainRoute>,
    }

    let wire: SyncWire = serde_json::from_str(json_str).map_err(|e| {
        RouterError::InvalidPayload(format!("Failed to parse PoP sync JSON: {}", e))
    })?;

    fn parse_wire_origin(norm_host: &str, o: &WireOrigin) -> Result<UpstreamNode, RouterError> {
        let proto = o.protocol.to_lowercase();
        if proto != "http" && proto != "https" {
            return Err(RouterError::InvalidTargetUrl {
                host: norm_host.to_string(),
                url: o.address.clone(),
                reason: format!("Protocol must be http or https, got '{}'", o.protocol),
            });
        }
        if o.port == 0 {
            return Err(RouterError::InvalidTargetUrl {
                host: norm_host.to_string(),
                url: o.address.clone(),
                reason: "Origin port cannot be 0".to_string(),
            });
        }
        let sni_trimmed = o.sni.as_deref().map(|s| s.trim()).filter(|s| !s.is_empty());
        let clean_addr = o
            .address
            .trim()
            .trim_start_matches('[')
            .trim_end_matches(']');

        let ip = clean_addr.parse::<std::net::IpAddr>().map_err(|_| {
            RouterError::InvalidPayload(
                "Control Plane origin address must be a pinned IP".to_string(),
            )
        })?;

        if is_private_or_reserved_ip(ip) {
            return Err(RouterError::UnsafeTargetUrl {
                host: norm_host.to_string(),
                url: o.address.clone(),
                reason: "Origin IP is private or reserved".to_string(),
            });
        }

        let dest_addr = Some(std::net::SocketAddr::new(ip, o.port));

        let host_for_url = match ip {
            std::net::IpAddr::V6(v6) => format!("[{}]", v6),
            std::net::IpAddr::V4(v4) => v4.to_string(),
        };

        let is_https = proto == "https";
        let (url, sni, destination_addr) = match (is_https, sni_trimmed) {
            (true, Some(sni_host)) if sni_host != clean_addr => {
                let target_url = format!("https://{}:{}", sni_host, o.port);
                (target_url, Some(sni_host.to_string()), dest_addr)
            }
            _ => {
                let target_url = format!("{}://{}:{}", proto, host_for_url, o.port);
                (target_url, None, dest_addr)
            }
        };

        validate_target_url(norm_host, &url)?;
        Ok(Router::create_node_full(url, sni, destination_addr))
    }

    let mut result = Vec::new();
    for r in wire.routes {
        let norm_host = normalize_host(&r.host);
        if norm_host.is_empty() {
            return Err(RouterError::EmptyHost);
        }

        let sec_policy = r.security.map(|s| DomainSecurityPolicy {
            waf_enabled: s.waf_enabled,
            block_sqli: s.block_sqli,
            block_xss: s.block_xss,
            block_path_traversal: s.block_path_traversal,
            blocked_paths: s.blocked_paths,
            rate_limit_enabled: s.rate_limit_enabled,
            requests_per_second: s.requests_per_second,
            burst_capacity: s.burst_capacity,
        });

        let cache_policy = r.cache.map(|c| DomainCachePolicy {
            enabled: c.enabled,
            default_ttl_seconds: c.default_ttl_seconds,
            bypass_paths: c.bypass_paths,
        });

        let has_path_routes = !r.path_routes.is_empty();
        let mut origins = Vec::new();
        if !r.origins.is_empty() {
            for o in &r.origins {
                origins.push(parse_wire_origin(&norm_host, o)?);
            }
        } else if !has_path_routes && !r.targets.is_empty() {
            for target in &r.targets {
                validate_target_url(&norm_host, target)?;
                origins.push(Router::create_node(target.clone()));
            }
        }

        if !r.path_routes.is_empty() {
            let mut domain_path_routes = Vec::new();
            for pr in r.path_routes {
                validate_path_prefix(&norm_host, &pr.path_prefix)?;
                let mut path_origins = Vec::new();
                if !pr.origins.is_empty() {
                    for o in &pr.origins {
                        path_origins.push(parse_wire_origin(&norm_host, o)?);
                    }
                } else if !pr.targets.is_empty() {
                    for t in pr.targets {
                        validate_target_url(&norm_host, &t)?;
                        path_origins.push(Router::create_node(t));
                    }
                }
                if path_origins.is_empty() {
                    return Err(RouterError::EmptyTargets(norm_host));
                }
                domain_path_routes.push(PathRoute {
                    path_prefix: pr.path_prefix,
                    priority: pr.priority,
                    origins: path_origins,
                    round_robin_index: Arc::new(AtomicUsize::new(0)),
                });
            }

            result.push(DomainRoute {
                host: r.host,
                origins,
                path_routes: domain_path_routes,
                security: sec_policy,
                cache: cache_policy,
                round_robin_index: Arc::new(AtomicUsize::new(0)),
            });
        } else if !origins.is_empty() {
            result.push(DomainRoute {
                host: r.host,
                origins: origins.clone(),
                path_routes: vec![PathRoute {
                    path_prefix: "/".to_string(),
                    priority: 0,
                    origins,
                    round_robin_index: Arc::new(AtomicUsize::new(0)),
                }],
                security: sec_policy,
                cache: cache_policy,
                round_robin_index: Arc::new(AtomicUsize::new(0)),
            });
        } else {
            return Err(RouterError::EmptyTargets(norm_host));
        }
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
            DomainRoute::new(
                "customer-a.example.com".to_string(),
                vec![Router::create_node("https://origin-a.internal".to_string())],
            ),
            DomainRoute::new(
                "customer-b.example.com".to_string(),
                vec![Router::create_node("https://origin-b.internal".to_string())],
            ),
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
        let routes = vec![DomainRoute::new(
            "api.customer.com".to_string(),
            vec![Router::create_node(
                "https://origin-fail.internal".to_string(),
            )],
        )];

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
            DomainRoute::new(
                "customer.example.com".to_string(),
                vec![Router::create_node("https://origin-a.internal".to_string())],
            ),
            DomainRoute::new(
                "CUSTOMER.EXAMPLE.COM:443".to_string(),
                vec![Router::create_node("https://origin-b.internal".to_string())],
            ),
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
        let empty_targets_route = vec![DomainRoute::new(
            "dead-tenant.example.com".to_string(),
            vec![],
        )];
        let err = Router::new_multi_tenant(empty_targets_route, vec![], 5000).unwrap_err();
        assert_eq!(
            err,
            RouterError::EmptyTargets("dead-tenant.example.com".to_string())
        );

        // Empty host must be rejected
        let empty_host_route = vec![DomainRoute::new(
            "   ".to_string(),
            vec![Router::create_node("https://origin-a.internal".to_string())],
        )];
        let err = Router::new_multi_tenant(empty_host_route, vec![], 5000).unwrap_err();
        assert_eq!(err, RouterError::EmptyHost);
    }

    #[test]
    fn test_target_url_ssrf_and_schema_validation() {
        // Finding 7 & P2 Finding 8: Validate scheme, credentials, and cloud metadata / private SSRF destinations
        assert!(validate_target_url("cust", "https://origin.example.com:443").is_ok());
        // Genuine global unicast addresses (IPv4 and IPv6) are accepted
        assert!(validate_target_url("cust", "https://93.184.216.34:443").is_ok());
        assert!(
            validate_target_url("cust", "https://[2606:2800:220:1:248:1893:25c8:1946]:443").is_ok()
        );

        // Documentation ranges (RFC 5737 TEST-NET-1/2/3, RFC 3849 2001:db8::/32) rejected
        let err = validate_target_url("cust", "https://192.0.2.1:443").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "https://198.51.100.1:443").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "https://203.0.113.20:443").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "https://[2001:db8::1]:443").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

        // Benchmarking ranges (RFC 2544, RFC 5180) rejected
        let err = validate_target_url("cust", "https://198.18.0.1:443").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "https://[2001:2::1]:443").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

        // IPv4-mapped IPv6 encoding private/loopback/metadata addresses rejected (Anti-SSRF P1)
        let err = validate_target_url("cust", "http://[::ffff:127.0.0.1]:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "http://[::ffff:10.0.0.8]:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "http://[::ffff:192.168.1.1]:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "http://[::ffff:169.254.169.254]:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "http://[::ffff:203.0.113.20]:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

        // RFC 1918 private IPv4 destinations rejected
        let err = validate_target_url("cust", "http://10.0.0.1:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "http://172.16.5.1:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "http://192.168.1.1:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

        // Loopback IPv4 rejected
        let err = validate_target_url("cust", "http://127.0.0.1:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

        // IPv6 ULA & Link-local rejected
        let err = validate_target_url("cust", "http://[fc00::1]:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));
        let err = validate_target_url("cust", "http://[fe80::1]:8080").unwrap_err();
        assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

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
    fn test_path_routing_fallback_isolation_rejects_unmatched_path() {
        // P1 Finding 3: Path routing without root route must fail closed for unmatched paths
        let path_routes = vec![
            PathRoute {
                path_prefix: "/admin/".to_string(),
                priority: 10,
                origins: vec![Router::create_node("https://admin.internal".to_string())],
                round_robin_index: Arc::new(AtomicUsize::new(0)),
            },
            PathRoute {
                path_prefix: "/api/".to_string(),
                priority: 20,
                origins: vec![Router::create_node("https://api.internal".to_string())],
                round_robin_index: Arc::new(AtomicUsize::new(0)),
            },
        ];

        let domain_route =
            DomainRoute::with_paths("customer.example.com".to_string(), path_routes, None, None);

        let router = Router::new_multi_tenant(vec![domain_route], vec![], 5000).unwrap();

        // Matching routes route properly
        assert_eq!(
            router
                .select_upstream_for_host_and_path("customer.example.com", "/admin/users")
                .unwrap(),
            "https://admin.internal"
        );
        assert_eq!(
            router
                .select_upstream_for_host_and_path("customer.example.com", "/api/v1/data")
                .unwrap(),
            "https://api.internal"
        );

        // Unmatched path without root fallback MUST NOT leak origins - must return NoMatchingPath
        let unmatched_err = router
            .select_upstream_for_host_and_path("customer.example.com", "/unknown")
            .unwrap_err();
        assert_eq!(
            unmatched_err,
            RoutingError::NoMatchingPath {
                host: "customer.example.com".to_string(),
                path: "/unknown".to_string(),
            }
        );
    }

    #[test]
    fn test_sni_origin_resolution_and_pinned_dns_mapping() {
        // P1 Finding 2: HTTPS origin with pinned IP uses SNI hostname for URL and records destination address
        let pop_json = r#"{
            "pop_id": "singapore",
            "config_version": "v1.2.0-pinned",
            "routes": [
                {
                    "host": "customer.example.com",
                    "origins": [
                        {
                            "address": "93.184.216.34",
                            "port": 443,
                            "protocol": "HTTPS",
                            "sni": "origin.customer.com"
                        }
                    ]
                }
            ]
        }"#;

        let parsed_routes = parse_pop_config_routes(pop_json).unwrap();
        assert_eq!(parsed_routes.len(), 1);
        let node = &parsed_routes[0].origins[0];
        assert_eq!(node.url, "https://origin.customer.com:443");
        assert_eq!(node.sni, Some("origin.customer.com".to_string()));
        let expected_addr: std::net::SocketAddr = "93.184.216.34:443".parse().unwrap();
        assert_eq!(node.destination_addr, Some(expected_addr));

        let router = Router::new_multi_tenant(parsed_routes, vec![], 5000).unwrap();
        let mappings = router.dns_mappings();
        assert_eq!(
            mappings.get("origin.customer.com"),
            Some(&vec![expected_addr])
        );

        let resolver = crate::dns::PinnedDnsResolver::new();
        router.sync_dns_resolver(&resolver);
    }

    #[test]
    fn test_atomic_route_update_and_pop_config_sync() {
        let initial_routes = vec![DomainRoute::new(
            "tenant-1.com".to_string(),
            vec![Router::create_node("https://origin-1.internal".to_string())],
        )];
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

    #[test]
    fn test_ipv6_pinned_dns_resolution() {
        // P1 Finding 2: IPv6 address without brackets from Control Plane parses into SocketAddr
        // and is correctly mapped in PinnedDnsResolver to defeat DNS-rebinding attacks.
        let pop_json = r#"{
            "pop_id": "singapore",
            "config_version": "v1.2.0-ipv6",
            "routes": [
                {
                    "host": "ipv6-app.customer.com",
                    "origins": [
                        {
                            "address": "2001:4860:4860::8888",
                            "port": 443,
                            "protocol": "HTTPS",
                            "sni": "origin-v6.customer.com"
                        }
                    ]
                }
            ]
        }"#;

        let parsed_routes = parse_pop_config_routes(pop_json).unwrap();
        assert_eq!(parsed_routes.len(), 1);
        let node = &parsed_routes[0].origins[0];
        assert_eq!(node.url, "https://origin-v6.customer.com:443");
        assert_eq!(node.sni, Some("origin-v6.customer.com".to_string()));

        let expected_addr: std::net::SocketAddr = "[2001:4860:4860::8888]:443".parse().unwrap();
        assert_eq!(node.destination_addr, Some(expected_addr));

        let router = Router::new_multi_tenant(parsed_routes, vec![], 5000).unwrap();
        let mappings = router.dns_mappings();
        assert_eq!(
            mappings.get("origin-v6.customer.com"),
            Some(&vec![expected_addr])
        );

        let resolver = crate::dns::PinnedDnsResolver::new();
        router.sync_dns_resolver(&resolver);
    }

    #[test]
    fn test_path_routing_boundary_aware_matching() {
        // P2 Finding 6: Prefix matching must respect path segment boundaries
        assert!(path_matches_prefix("/admin", "/admin"));
        assert!(path_matches_prefix("/admin/dashboard", "/admin"));
        assert!(path_matches_prefix("/admin/settings/keys", "/admin"));
        assert!(path_matches_prefix("/admin/", "/admin/"));
        assert!(path_matches_prefix("/admin/users", "/admin/"));

        // Must NOT match prefixes that are sub-words without path delimiters
        assert!(!path_matches_prefix("/administrator", "/admin"));
        assert!(!path_matches_prefix("/admin_tools", "/admin"));
        assert!(!path_matches_prefix("/admin-panel", "/admin"));

        // Root prefix matches everything starting with /
        assert!(path_matches_prefix("/", "/"));
        assert!(path_matches_prefix("/api/v1", "/"));
    }

    #[test]
    fn test_path_prefix_syntax_validation() {
        // P2 Finding: Path prefix must be non-empty and start with leading '/'
        assert!(validate_path_prefix("example.com", "/").is_ok());
        assert!(validate_path_prefix("example.com", "/api").is_ok());
        assert!(validate_path_prefix("example.com", "/api/v1/").is_ok());

        // Empty prefix rejected
        let err = validate_path_prefix("example.com", "").unwrap_err();
        assert!(matches!(err, RouterError::InvalidPathPrefix { .. }));
        let err = validate_path_prefix("example.com", "   ").unwrap_err();
        assert!(matches!(err, RouterError::InvalidPathPrefix { .. }));

        // Relative prefix without leading '/' rejected
        let err = validate_path_prefix("example.com", "api").unwrap_err();
        assert!(matches!(err, RouterError::InvalidPathPrefix { .. }));
        let err = validate_path_prefix("example.com", "admin/dashboard").unwrap_err();
        assert!(matches!(err, RouterError::InvalidPathPrefix { .. }));

        // Malformed prefix with whitespace characters rejected
        let err = validate_path_prefix("example.com", "/api /test").unwrap_err();
        assert!(matches!(err, RouterError::InvalidPathPrefix { .. }));
    }

    #[tokio::test]
    async fn test_staged_dns_update_race_elimination() {
        use reqwest::dns::Resolve;

        // Route A with pinned origin A
        let snapshot_v1 = r#"{
            "routes": [{
                "host": "app.example.com",
                "origins": [{
                    "address": "93.184.216.34",
                    "port": 443,
                    "protocol": "HTTPS",
                    "sni": "origin-a.example.com"
                }]
            }]
        }"#;

        // Route B with pinned origin B (origin A removed)
        let snapshot_v2 = r#"{
            "routes": [{
                "host": "app.example.com",
                "origins": [{
                    "address": "93.184.216.35",
                    "port": 443,
                    "protocol": "HTTPS",
                    "sni": "origin-b.example.com"
                }]
            }]
        }"#;

        let routes_v1 = parse_pop_config_routes(snapshot_v1).unwrap();
        let routes_v2 = parse_pop_config_routes(snapshot_v2).unwrap();

        let dns_resolver = Arc::new(crate::dns::PinnedDnsResolver::new());
        let router = Router::new(vec![], 5000);

        // Apply snapshot 1
        router
            .update_routes_with_dns(routes_v1, vec![], &dns_resolver)
            .unwrap();

        // Origin A is resolvable
        let name_a: reqwest::dns::Name = "origin-a.example.com".parse().unwrap();
        let mut addrs_a = dns_resolver.resolve(name_a).await.unwrap();
        assert_eq!(
            addrs_a.next().unwrap(),
            "93.184.216.34:443".parse::<std::net::SocketAddr>().unwrap()
        );

        // In strict mode, an unpinned origin domain fails closed immediately with error
        let unpinned: reqwest::dns::Name = "unpinned.example.com".parse().unwrap();
        let unpinned_res = dns_resolver.resolve(unpinned).await;
        assert!(unpinned_res.is_err());
        assert!(unpinned_res
            .err()
            .unwrap()
            .to_string()
            .contains("Strict DNS"));

        // Apply snapshot 2 (staged update: merges B, swaps routes, prunes A)
        router
            .update_routes_with_dns(routes_v2, vec![], &dns_resolver)
            .unwrap();

        // Origin B is now resolvable
        let name_b: reqwest::dns::Name = "origin-b.example.com".parse().unwrap();
        let mut addrs_b = dns_resolver.resolve(name_b).await.unwrap();
        assert_eq!(
            addrs_b.next().unwrap(),
            "93.184.216.35:443".parse::<std::net::SocketAddr>().unwrap()
        );

        // Origin A was pruned after swap; in strict mode it MUST fail closed, NEVER falling back to unpinned DNS
        let name_a_after: reqwest::dns::Name = "origin-a.example.com".parse().unwrap();
        let res_a = dns_resolver.resolve(name_a_after).await;
        assert!(res_a.is_err());
        assert!(res_a.err().unwrap().to_string().contains("Strict DNS"));
    }
}
