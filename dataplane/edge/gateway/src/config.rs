use serde::{Deserialize, Serialize};
use std::fs;
use std::net::IpAddr;
use std::path::Path;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IpCidr {
    pub ip: IpAddr,
    pub prefix_len: u8,
}

impl IpCidr {
    pub fn parse(s: &str) -> Result<Self, String> {
        let trimmed = s.trim();
        if let Some((ip_str, prefix_str)) = trimmed.split_once('/') {
            let ip: IpAddr = ip_str
                .trim()
                .parse()
                .map_err(|e| format!("Invalid IP in CIDR '{}': {}", s, e))?;
            let prefix_len: u8 = prefix_str
                .trim()
                .parse()
                .map_err(|e| format!("Invalid prefix length in CIDR '{}': {}", s, e))?;
            match ip {
                IpAddr::V4(_) if prefix_len > 32 => {
                    return Err(format!("IPv4 prefix length cannot exceed 32: {}", s));
                }
                IpAddr::V6(_) if prefix_len > 128 => {
                    return Err(format!("IPv6 prefix length cannot exceed 128: {}", s));
                }
                _ => {}
            }
            Ok(Self { ip, prefix_len })
        } else {
            let ip: IpAddr = trimmed
                .parse()
                .map_err(|e| format!("Invalid IP address '{}': {}", s, e))?;
            let prefix_len = match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Ok(Self { ip, prefix_len })
        }
    }

    pub fn contains(&self, target: IpAddr) -> bool {
        match (self.ip, target) {
            (IpAddr::V4(net), IpAddr::V4(t)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_u32 = u32::from(net);
                let target_u32 = u32::from(t);
                let mask = !0u32 << (32 - self.prefix_len);
                (net_u32 & mask) == (target_u32 & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(t)) => {
                if self.prefix_len == 0 {
                    return true;
                }
                let net_u128 = u128::from(net);
                let target_u128 = u128::from(t);
                let mask = !0u128 << (128 - self.prefix_len);
                (net_u128 & mask) == (target_u128 & mask)
            }
            _ => false,
        }
    }
}

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
    #[serde(default = "default_trusted_proxies")]
    pub trusted_proxies: Vec<String>,
}

fn default_trusted_proxies() -> Vec<String> {
    vec![
        "127.0.0.1/32".to_string(),
        "::1/128".to_string(),
        "172.16.0.0/12".to_string(),
        "10.0.0.0/8".to_string(),
    ]
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticOriginConfig {
    pub address: String,
    pub port: u16,
    #[serde(default = "default_static_origin_protocol")]
    pub protocol: String,
    #[serde(default)]
    pub sni: Option<String>,
    #[serde(default)]
    pub weight: Option<u32>,
}

fn default_static_origin_protocol() -> String {
    "HTTP".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathRouteConfig {
    #[serde(default = "default_path_prefix")]
    pub path_prefix: String,
    #[serde(default)]
    pub priority: u32,
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub origins: Vec<StaticOriginConfig>,
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
    pub origins: Vec<StaticOriginConfig>,
    #[serde(default)]
    pub path_routes: Vec<PathRouteConfig>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamConfig {
    #[serde(default)]
    pub targets: Vec<String>,
    #[serde(default)]
    pub origins: Vec<StaticOriginConfig>,
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
                trusted_proxies: default_trusted_proxies(),
            },
            upstream: UpstreamConfig {
                targets: vec!["http://127.0.0.1:3000".to_string()],
                origins: vec![],
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
        let mut config: GatewayConfig = serde_yaml::from_str(&content)?;
        config.apply_env_overrides();
        Ok(config)
    }

    pub fn parsed_trusted_proxies(&self) -> Vec<IpCidr> {
        self.server
            .trusted_proxies
            .iter()
            .filter_map(|s| match IpCidr::parse(s) {
                Ok(c) => Some(c),
                Err(e) => {
                    tracing::warn!(cidr = %s, error = %e, "Skipping invalid trusted proxy CIDR in configuration");
                    None
                }
            })
            .collect()
    }

    pub fn apply_env_overrides(&mut self) {
        if let Ok(v) = std::env::var("NEXUSEDGE_LISTEN_ADDR") {
            if !v.trim().is_empty() {
                self.server.listen_addr = v;
            }
        }
        if let Ok(v) = std::env::var("NEXUSEDGE_NODE_ID") {
            if !v.trim().is_empty() {
                self.server.node_id = v;
            }
        }
        if let Ok(v) = std::env::var("NEXUSEDGE_REGION") {
            if !v.trim().is_empty() {
                self.server.region = v;
            }
        }
        if let Ok(v) = std::env::var("NEXUSEDGE_TRUSTED_PROXIES") {
            let proxies: Vec<String> = v
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();
            if !proxies.is_empty() {
                self.server.trusted_proxies = proxies;
            }
        }
        if let Ok(v) = std::env::var("NEXUSEDGE_CP_ENABLED") {
            let lower = v.trim().to_ascii_lowercase();
            self.control_plane.enabled = lower == "true" || lower == "1";
        }
        if let Ok(v) = std::env::var("NEXUSEDGE_CP_ENDPOINT") {
            if !v.trim().is_empty() {
                self.control_plane.endpoint = v;
            }
        }
        if let Ok(v) = std::env::var("NEXUSEDGE_CP_POP_ID") {
            if !v.trim().is_empty() {
                self.control_plane.pop_id = v;
            }
        }
        if let Ok(v) = std::env::var("NEXUSEDGE_CP_POLL_INTERVAL_SECS") {
            if let Ok(secs) = v.trim().parse::<u64>() {
                if secs > 0 {
                    self.control_plane.poll_interval_secs = secs;
                }
            }
        }
        if let Ok(v) = std::env::var("NEXUSEDGE_CP_AUTH_TOKEN") {
            self.control_plane.auth_token = v;
        }
        if let Ok(v) = std::env::var("NEXUSEDGE_CP_SNAPSHOT_FILE") {
            if !v.trim().is_empty() {
                self.control_plane.snapshot_file = Some(v.trim().to_string());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ip_cidr_parsing_and_matching() {
        let cidr_loopback = IpCidr::parse("127.0.0.1/32").unwrap();
        assert!(cidr_loopback.contains("127.0.0.1".parse().unwrap()));
        assert!(!cidr_loopback.contains("127.0.0.2".parse().unwrap()));

        let cidr_docker = IpCidr::parse("172.16.0.0/12").unwrap();
        assert!(cidr_docker.contains("172.16.0.1".parse().unwrap()));
        assert!(cidr_docker.contains("172.18.0.2".parse().unwrap()));
        assert!(cidr_docker.contains("172.31.255.255".parse().unwrap()));
        assert!(!cidr_docker.contains("172.32.0.1".parse().unwrap()));
        assert!(!cidr_docker.contains("192.168.1.1".parse().unwrap()));

        let cidr_v6 = IpCidr::parse("::1/128").unwrap();
        assert!(cidr_v6.contains("::1".parse().unwrap()));
        assert!(!cidr_v6.contains("::2".parse().unwrap()));

        let cidr_v4_all = IpCidr::parse("0.0.0.0/0").unwrap();
        assert!(cidr_v4_all.contains("8.8.8.8".parse().unwrap()));
        assert!(!cidr_v4_all.contains("::1".parse().unwrap()));

        let single_ip = IpCidr::parse("192.168.1.100").unwrap();
        assert_eq!(single_ip.prefix_len, 32);
        assert!(single_ip.contains("192.168.1.100".parse().unwrap()));
        assert!(!single_ip.contains("192.168.1.101".parse().unwrap()));

        assert!(IpCidr::parse("invalid-ip/24").is_err());
        assert!(IpCidr::parse("10.0.0.1/33").is_err());
        assert!(IpCidr::parse("::1/129").is_err());
    }

    #[test]
    fn test_gateway_config_trusted_proxies_env_override() {
        let mut config = GatewayConfig::default();
        assert_eq!(config.server.trusted_proxies.len(), 4);

        std::env::set_var("NEXUSEDGE_TRUSTED_PROXIES", "10.10.0.0/16, 192.168.0.0/24");
        config.apply_env_overrides();
        std::env::remove_var("NEXUSEDGE_TRUSTED_PROXIES");

        assert_eq!(
            config.server.trusted_proxies,
            vec!["10.10.0.0/16", "192.168.0.0/24"]
        );
        let parsed = config.parsed_trusted_proxies();
        assert_eq!(parsed.len(), 2);
        assert!(parsed[0].contains("10.10.5.1".parse().unwrap()));
        assert!(!parsed[0].contains("10.11.5.1".parse().unwrap()));
    }
}
