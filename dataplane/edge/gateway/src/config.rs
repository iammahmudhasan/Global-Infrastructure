use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GatewayConfig {
    pub server: ServerConfig,
    pub upstream: UpstreamConfig,
    pub rate_limit: RateLimitConfig,
    pub waf: WafConfig,
    pub cache: CacheConfig,
    #[serde(default)]
    pub control_plane: ControlPlaneConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub node_id: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRouteConfig {
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,
    #[serde(default)]
    pub priority: u32,
    pub targets: Vec<String>,
}

fn default_path_prefix() -> String {
    "/".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRouteConfig {
    pub host: String,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub path_routes: Vec<PathRouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub routes: Vec<DomainRouteConfig>,
    pub health_check_path: String,
    pub timeout_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfig {
    pub enabled: bool,
    pub requests_per_second: u32,
    pub burst_capacity: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WafConfig {
    pub enabled: bool,
    pub block_sqli: bool,
    pub block_xss: bool,
    pub block_path_traversal: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    pub enabled: bool,
    pub default_ttl_seconds: u64,
    pub max_entries: usize,
    #[serde(default = "default_max_cache_bytes")]
    pub max_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlPlaneConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_control_plane_endpoint")]
    pub endpoint: String,
    #[serde(default = "default_pop_id")]
    pub pop_id: String,
    #[serde(default = "default_poll_interval_secs")]
    pub poll_interval_secs: u64,
    #[serde(default)]
    pub auth_token: String,
    #[serde(default)]
    pub snapshot_file: Option<String>,
}

fn default_control_plane_endpoint() -> String {
    "http://127.0.0.1:9091".to_string()
}

fn default_pop_id() -> String {
    "singapore".to_string()
}

fn default_poll_interval_secs() -> u64 {
    30
}

impl Default for ControlPlaneConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_control_plane_endpoint(),
            pop_id: default_pop_id(),
            poll_interval_secs: default_poll_interval_secs(),
            auth_token: String::new(),
            snapshot_file: None,
        }
    }
}

fn default_max_cache_bytes() -> usize {
    100 * 1024 * 1024 // 100 MB hard ceiling
}

impl Default for GatewayConfig {
    fn default() -> Self {
        Self {
            server: ServerConfig {
                listen_addr: "0.0.0.0:8080".to_string(),
                node_id: "pop-sin-01".to_string(),
                region: "ap-southeast-1".to_string(),
            },
            upstream: UpstreamConfig {
                targets: vec!["http://127.0.0.1:3000".to_string()],
                routes: vec![],
                health_check_path: "/healthz".to_string(),
                timeout_ms: 5000,
            },
            rate_limit: RateLimitConfig {
                enabled: true,
                requests_per_second: 100,
                burst_capacity: 200,
            },
            waf: WafConfig {
                enabled: true,
                block_sqli: true,
                block_xss: true,
                block_path_traversal: true,
            },
            cache: CacheConfig {
                enabled: true,
                default_ttl_seconds: 60,
                max_entries: 10000,
                max_bytes: 100 * 1024 * 1024,
            },
            control_plane: ControlPlaneConfig::default(),
        }
    }
}

impl GatewayConfig {
    pub fn load_from_file<P: AsRef<Path>>(
        path: P,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let content = fs::read_to_string(path)?;
        let config: GatewayConfig = serde_yaml::from_str(&content)?;
        Ok(config)
    }
}
