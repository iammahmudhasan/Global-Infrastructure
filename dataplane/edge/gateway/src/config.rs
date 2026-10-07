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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    pub listen_addr: String,
    pub node_id: String,
    pub region: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    pub targets: Vec<String>,
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
            },
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
