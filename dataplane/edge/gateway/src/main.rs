mod cache;
mod config;
mod dns;
mod proxy;
mod rate_limit;
mod router;
mod waf;

use crate::cache::EdgeCache;
use crate::config::GatewayConfig;
use crate::dns::PinnedDnsResolver;
use crate::proxy::{handle_request, ProxyState, DEFAULT_MAX_INFLIGHT_BUFFERED_REQUESTS};
use crate::rate_limit::RateLimiter;
use crate::router::Router;
use crate::waf::WafEngine;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use reqwest::Client as HttpClient;
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // 1. Initialize logging & tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    // 2. Load Configuration (from gateway.yaml if present, or defaults)
    let mut config = if std::path::Path::new("gateway.yaml").exists() {
        info!("Loading configuration from gateway.yaml");
        GatewayConfig::load_from_file("gateway.yaml")?
    } else {
        info!("gateway.yaml not found, applying default enterprise configuration");
        let mut cfg = GatewayConfig::default();
        cfg.apply_env_overrides();
        cfg
    };
    config.apply_env_overrides();

    if config.control_plane.enabled {
        if config.control_plane.endpoint.trim().is_empty() {
            return Err("Control plane is enabled but endpoint is empty".into());
        }
        if config.control_plane.pop_id.trim().is_empty() {
            return Err("Control plane is enabled but pop_id is empty".into());
        }
    }

    println!(
        r#"
  ███╗   ██╗███████╗██╗   ██╗██╗   ██╗███████╗███████╗██████╗  ██████╗ ███████╗
  ████╗  ██║██╔════╝╚██╗ ██╔╝██║   ██║██╔════╝██╔════╝██╔══██╗██╔════╝ ██╔════╝
  ██╔██╗ ██║█████╗   ╚████╔╝ ██║   ██║███████╗█████╗  ██║  ██║██║  ███╗█████╗  
  ██║╚██╗██║██╔══╝    ╚██╔╝  ██║   ██║╚════██║██╔══╝  ██║  ██║██║   ██║██╔══╝  
  ██║ ╚████║███████╗   ██║   ╚██████╔╝███████║███████╗██████╔╝╚██████╔╝███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚══════╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝
    "#
    );
    info!("Starting NexusEdge Global Ingress Gateway");
    info!("Node ID:    {}", config.server.node_id);
    info!("Region:     {}", config.server.region);
    info!("Listening:  {}", config.server.listen_addr);
    info!(
        "WAF Shield: {}",
        if config.waf.enabled {
            "ACTIVE"
        } else {
            "DISABLED"
        }
    );
    info!(
        "DDoS Guard: {}",
        if config.rate_limit.enabled {
            "ACTIVE"
        } else {
            "DISABLED"
        }
    );
    info!(
        "Edge Cache: {}",
        if config.cache.enabled {
            "ACTIVE"
        } else {
            "DISABLED"
        }
    );

    // 3. Initialize Shared State Engines
    let dns_resolver = Arc::new(PinnedDnsResolver::new());

    let rate_limiter = RateLimiter::new(
        config.rate_limit.enabled,
        config.rate_limit.requests_per_second,
        config.rate_limit.burst_capacity,
    );
    let waf = WafEngine::new(&config.waf);
    let cache = EdgeCache::new(
        config.cache.enabled,
        config.cache.default_ttl_seconds,
        config.cache.max_entries,
        config.cache.max_bytes,
    );
    let router = Router::from_upstream_config(&config.upstream)?;
    router.sync_dns_resolver(&dns_resolver);

    let http_client = HttpClient::builder()
        .timeout(Duration::from_millis(config.upstream.timeout_ms))
        .redirect(reqwest::redirect::Policy::none()) // Prevent upstream redirect-following SSRF attacks (RFC 9110)
        .dns_resolver(Arc::clone(&dns_resolver))
        .pool_max_idle_per_host(256)
        .tcp_nodelay(true)
        .build()?;

    let inflight_buffer_semaphore = Arc::new(tokio::sync::Semaphore::new(
        DEFAULT_MAX_INFLIGHT_BUFFERED_REQUESTS,
    ));
    let aggregate_buffered_bytes = Arc::new(AtomicUsize::new(0));
    let aggregate_buffered_request_bytes = Arc::new(AtomicUsize::new(0));

    let state = Arc::new(ProxyState {
        config: config.clone(),
        rate_limiter: rate_limiter.clone(),
        waf,
        cache,
        router: router.clone(),
        http_client: http_client.clone(),
        inflight_buffer_semaphore,
        aggregate_buffered_bytes,
        aggregate_buffered_request_bytes,
    });

    // 4. Background Maintenance Task (Clean expired rate-limit buckets)
    let cleaner_limiter = rate_limiter.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        loop {
            interval.tick().await;
            cleaner_limiter.cleanup_stale();
        }
    });

    // 5. Control Plane Dynamic Snapshot Synchronizer (P1 Consistency Bridge)
    if config.control_plane.enabled || config.control_plane.snapshot_file.is_some() {
        let sync_router = router.clone();
        let sync_dns = Arc::clone(&dns_resolver);
        let cp_cfg = config.control_plane.clone();
        let sync_client = http_client.clone();

        tokio::spawn(async move {
            let interval_secs = cp_cfg.poll_interval_secs.max(5);
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;

                // Option A: Synchronize from local/mounted snapshot file
                if let Some(ref snapshot_path) = cp_cfg.snapshot_file {
                    if let Ok(content) = tokio::fs::read_to_string(snapshot_path).await {
                        if let Ok(new_routes) = router::parse_pop_config_routes(&content) {
                            if let Err(e) = sync_router.update_routes(new_routes, vec![]) {
                                tracing::warn!(
                                    "Failed to atomically swap routes from snapshot file: {}",
                                    e
                                );
                            } else {
                                sync_router.sync_dns_resolver(&sync_dns);
                                tracing::info!(
                                    "Atomically synchronized edge routes from snapshot file: {}",
                                    snapshot_path
                                );
                            }
                        }
                    }
                }

                // Option B: Poll Control Plane /v1/edge/pops/{pop_id}/config (P1 Integrity & SSRF Hardening)
                if cp_cfg.enabled {
                    if let Err(err_msg) =
                        validate_control_plane_endpoint(&cp_cfg.endpoint, &cp_cfg.auth_token)
                    {
                        tracing::error!(
                            endpoint = %cp_cfg.endpoint,
                            error = %err_msg,
                            "Control Plane endpoint rejected; skipping sync cycle"
                        );
                        continue;
                    }

                    let url = format!(
                        "{}/v1/edge/pops/{}/config",
                        cp_cfg.endpoint.trim_end_matches('/'),
                        cp_cfg.pop_id
                    );
                    let mut req_builder = sync_client.get(&url);
                    if !cp_cfg.auth_token.is_empty() {
                        req_builder = req_builder
                            .header("Authorization", format!("Bearer {}", cp_cfg.auth_token));
                    }
                    match req_builder.send().await {
                        Ok(resp) if resp.status().is_success() => {
                            let header_checksum = resp
                                .headers()
                                .get("x-snapshot-checksum")
                                .and_then(|v| v.to_str().ok())
                                .map(|s| s.trim().to_string());

                            let Some(expected_checksum) = header_checksum else {
                                tracing::error!("Missing mandatory X-Snapshot-Checksum header from Control Plane response; rejecting unauthenticated snapshot update");
                                continue;
                            };

                            if expected_checksum.is_empty() {
                                tracing::error!("Empty X-Snapshot-Checksum header from Control Plane response; rejecting snapshot update");
                                continue;
                            }

                            if let Ok(body_str) = resp.text().await {
                                let computed_hash =
                                    format!("{:x}", sha2::Sha256::digest(body_str.as_bytes()));
                                if !expected_checksum.eq_ignore_ascii_case(&computed_hash) {
                                    tracing::error!(
                                        expected = %expected_checksum,
                                        computed = %computed_hash,
                                        "Snapshot SHA-256 checksum mismatch, rejecting corrupted or tampered route update"
                                    );
                                    continue;
                                }

                                match router::parse_pop_config_routes(&body_str) {
                                    Ok(new_routes) => {
                                        if let Err(e) =
                                            sync_router.update_routes(new_routes, vec![])
                                        {
                                            tracing::warn!(
                                                "Failed to apply routes from control plane: {}",
                                                e
                                            );
                                        } else {
                                            sync_router.sync_dns_resolver(&sync_dns);
                                            tracing::info!(pop_id = %cp_cfg.pop_id, "Atomically refreshed PoP routes from Control Plane");
                                        }
                                    }
                                    Err(e) => {
                                        tracing::warn!(
                                            "Failed to parse Control Plane PoP routes payload: {}",
                                            e
                                        );
                                    }
                                }
                            }
                        }
                        Ok(resp) => {
                            tracing::warn!(status = %resp.status(), "Control Plane config endpoint returned non-success");
                        }
                        Err(e) => {
                            tracing::debug!("Control Plane sync probe idle: {:?}", e);
                        }
                    }
                }
            }
        });
    }

    // 5. Autonomous Upstream Health Probing Loop (Findings 8, 9, 14, P1 Finding 2)
    let health_router = router.clone();
    let health_client = HttpClient::builder()
        .timeout(Duration::from_millis(config.upstream.timeout_ms))
        .redirect(reqwest::redirect::Policy::none()) // Prevent SSRF / open-redirect attacks
        .dns_resolver(Arc::clone(&dns_resolver))
        .pool_max_idle_per_host(64)
        .tcp_nodelay(true)
        .build()?;
    let health_path = config.upstream.health_check_path.clone();

    tokio::spawn(async move {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(32));
        let mut interval = tokio::time::interval(Duration::from_secs(10));
        loop {
            interval.tick().await;
            let current_targets = health_router.all_targets();
            let mut join_set = tokio::task::JoinSet::new();
            for target in current_targets {
                let client = health_client.clone();
                let path = health_path.clone();
                let permit = semaphore.clone();
                join_set.spawn(async move {
                    let _permit = permit.acquire().await;
                    let check_url = format!("{}{}", target.trim_end_matches('/'), path);
                    let start = std::time::Instant::now();
                    let is_healthy = match client.get(&check_url).send().await {
                        Ok(resp) => resp.status().is_success(),
                        Err(_) => false,
                    };
                    let latency_ms = start.elapsed().as_millis() as u64;
                    (target, is_healthy, latency_ms)
                });
            }
            while let Some(res) = join_set.join_next().await {
                if let Ok((target, is_healthy, latency_ms)) = res {
                    health_router.mark_health(&target, is_healthy, latency_ms);
                }
            }
        }
    });

    // 6. Bind TCP Listener and accept connections
    let addr: SocketAddr = config.server.listen_addr.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!("Gateway successfully bound to {}", addr);

    let server_builder = ConnBuilder::new(hyper_util::rt::TokioExecutor::new());

    loop {
        let (stream, peer_addr) = match listener.accept().await {
            Ok(val) => val,
            Err(e) => {
                error!("Failed to accept incoming TCP connection: {:?}", e);
                continue;
            }
        };

        let io = TokioIo::new(stream);
        let client_ip = peer_addr.ip();
        let state_clone = Arc::clone(&state);
        let builder = server_builder.clone();

        tokio::spawn(async move {
            let service = service_fn(move |req| {
                let state = Arc::clone(&state_clone);
                async move { handle_request(req, client_ip, state).await }
            });

            if let Err(err) = builder.serve_connection(io, service).await {
                // Connection drops/resets are normal in web traffic
                tracing::debug!("Connection terminated: {:?}", err);
            }
        });
    }
}

/// Validates Control Plane sync endpoint for transport security and credential safety.
/// Requires HTTPS for all remote endpoints and mandates authentication token for remote transports.
pub fn validate_control_plane_endpoint(
    endpoint: &str,
    auth_token: &str,
) -> Result<reqwest::Url, String> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        return Err("Control Plane endpoint cannot be empty".to_string());
    }

    let parsed = reqwest::Url::parse(trimmed)
        .map_err(|e| format!("Malformed Control Plane endpoint URL: {}", e))?;

    let scheme = parsed.scheme();
    let host_str = match parsed.host_str() {
        Some(h) if !h.is_empty() => h.trim().to_ascii_lowercase(),
        _ => return Err("Control Plane endpoint must include a valid host".to_string()),
    };

    let unbracketed_host = host_str.trim_start_matches('[').trim_end_matches(']');
    let is_trusted_internal = unbracketed_host == "127.0.0.1"
        || unbracketed_host == "localhost"
        || unbracketed_host == "::1"
        || unbracketed_host == "config-controller";

    match scheme {
        "http" => {
            if !is_trusted_internal {
                return Err(format!(
                    "Insecure HTTP forbidden for remote Control Plane endpoint '{}'; HTTPS is strictly required",
                    endpoint
                ));
            }
        }
        "https" => {
            if !is_trusted_internal && auth_token.trim().is_empty() {
                return Err(format!(
                    "Remote Control Plane endpoint '{}' requires non-empty authentication token",
                    endpoint
                ));
            }
        }
        _ => {
            return Err(format!(
                "Invalid scheme '{}' for Control Plane endpoint; must be http or https",
                scheme
            ));
        }
    }

    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_control_plane_endpoint_security() {
        // Trusted internal / loopback HTTP endpoints allowed
        assert!(validate_control_plane_endpoint("http://127.0.0.1:9091", "").is_ok());
        assert!(validate_control_plane_endpoint("http://localhost:9091", "").is_ok());
        assert!(validate_control_plane_endpoint("http://[::1]:9091", "").is_ok());
        assert!(validate_control_plane_endpoint("http://config-controller:9091", "").is_ok());

        // Subdomain / prefix attack vectors on trusted hosts rejected
        let err =
            validate_control_plane_endpoint("http://127.0.0.1.attacker.example:9091", "token")
                .unwrap_err();
        assert!(err.contains("HTTPS is strictly required"));

        let err = validate_control_plane_endpoint("http://config-controller.attacker.com", "token")
            .unwrap_err();
        assert!(err.contains("HTTPS is strictly required"));

        // Remote plain HTTP forbidden even if auth_token is present or empty
        let err = validate_control_plane_endpoint("http://cp.remote.infra:9091", "secret-token")
            .unwrap_err();
        assert!(err.contains("HTTPS is strictly required"));

        // Remote HTTPS requires non-empty auth token
        let err =
            validate_control_plane_endpoint("https://cp.remote.infra:9091", "   ").unwrap_err();
        assert!(err.contains("requires non-empty authentication token"));

        assert!(
            validate_control_plane_endpoint("https://cp.remote.infra:9091", "valid-token").is_ok()
        );

        // Invalid scheme rejected
        let err = validate_control_plane_endpoint("ftp://cp.remote.infra", "token").unwrap_err();
        assert!(err.contains("must be http or https"));
    }
}
