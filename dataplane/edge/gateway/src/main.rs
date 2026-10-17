use nexusedge_gateway::cache::EdgeCache;
use nexusedge_gateway::config::GatewayConfig;
use nexusedge_gateway::dns::PinnedDnsResolver;
use nexusedge_gateway::proxy::{
    handle_request, ProxyState, DEFAULT_MAX_INFLIGHT_BUFFERED_REQUESTS,
};
use nexusedge_gateway::rate_limit::RateLimiter;
use nexusedge_gateway::router::{self, Router};
use nexusedge_gateway::sync::{
    fetch_and_apply_control_plane_snapshot_full, listen_and_apply_event_stream, GatewayAckManager,
    GatewaySyncAckPayload, SnapshotFetchContext, StreamSyncContext,
};
use nexusedge_gateway::waf::WafEngine;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use reqwest::Client as HttpClient;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};
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
    let requires_dynamic_sync =
        config.control_plane.enabled || config.control_plane.snapshot_file.is_some();
    let is_ready = Arc::new(AtomicBool::new(!requires_dynamic_sync));
    let trusted_proxies = config.parsed_trusted_proxies();
    info!(
        trusted_proxies = ?config.server.trusted_proxies,
        parsed_count = trusted_proxies.len(),
        "Configured trusted reverse proxy CIDRs"
    );

    let ai_director = match &config.ai {
        Some(ai_cfg) if ai_cfg.enabled => {
            info!(
                providers = ai_cfg.providers.len(),
                "NexusEdge Universal AI & Compute Director: ACTIVE"
            );
            Some(Arc::new(nexusedge_gateway::ai::AiTrafficDirector::new(
                ai_cfg.providers.clone(),
            )))
        }
        Some(_) => None,
        None if requires_dynamic_sync => {
            info!("NexusEdge Universal AI & Compute Director: ACTIVE (Dynamic Control Plane Sync Mode)");
            Some(Arc::new(nexusedge_gateway::ai::AiTrafficDirector::new(
                vec![],
            )))
        }
        None => None,
    };

    if !nexusedge_gateway::ai::is_dev_mode() {
        if let Some(ref director) = ai_director {
            if let Some(err) = director.auth_registry().initialization_error() {
                error!(
                    error = %err,
                    "FATAL: Production AI auth configuration is invalid. Terminating gateway startup."
                );
                return Err(format!(
                    "Fatal production startup error: AI auth registry invalid: {}",
                    err
                )
                .into());
            }
        }
    }
    let autonomous_snapshot_path = config
        .control_plane
        .snapshot_file
        .clone()
        .unwrap_or_else(|| "data/pop_snapshot.json".to_string());

    // Cold-Boot Autonomy (Shared-Nothing Edge Autonomy):
    // If local autonomous snapshot cache exists on disk, load routes immediately (0ms WAN dependency).
    if let Ok(cached_content) = tokio::fs::read_to_string(&autonomous_snapshot_path).await {
        let parsed_routes = router::parse_pop_config_routes(&cached_content);
        let parsed_ai = router::parse_pop_config_ai_providers(&cached_content);
        if let (Ok(new_routes), Ok(maybe_ai)) = (parsed_routes, parsed_ai) {
            let ai_ref = maybe_ai.as_deref();
            if let Err(e) =
                router.update_routes_with_dns_and_ai(new_routes, vec![], ai_ref, &dns_resolver)
            {
                tracing::warn!(
                    error = %e,
                    "Failed to restore routes from local autonomous snapshot"
                );
            } else {
                if let (Some(director), Some(new_ai)) = (ai_director.as_ref(), maybe_ai) {
                    director.update_providers(new_ai);
                }
                is_ready.store(true, Ordering::SeqCst);
                tracing::info!(
                    path = %autonomous_snapshot_path,
                    "Cold-booted autonomous edge routes from local disk snapshot (Zero-WAN Ready)"
                );
            }
        }
    }

    let (ack_manager, sync_client_opt) =
        if config.control_plane.enabled || config.control_plane.snapshot_file.is_some() {
            let cp_cfg = config.control_plane.clone();
            let sync_client = HttpClient::builder()
                .timeout(Duration::from_millis(config.upstream.timeout_ms.max(5000)))
                .redirect(reqwest::redirect::Policy::none())
                .build()?;

            let ack_spool_path = std::env::var("NEXUSEDGE_ACK_SPOOL_PATH")
                .ok()
                .map(std::path::PathBuf::from)
                .unwrap_or_else(|| {
                    std::path::PathBuf::from(format!("{}.ack.json", autonomous_snapshot_path))
                });

            let mgr = Arc::new(GatewayAckManager::new(
                cp_cfg.endpoint.clone(),
                cp_cfg.auth_token.clone(),
                sync_client.clone(),
                Some(ack_spool_path),
            ));
            Arc::clone(&mgr).spawn_worker();
            (Some(mgr), Some(sync_client))
        } else {
            (None, None)
        };

    let client_cache = Arc::new(std::sync::RwLock::new(std::collections::HashMap::new()));
    let state = Arc::new(ProxyState {
        config: config.clone(),
        trusted_proxies,
        rate_limiter: rate_limiter.clone(),
        waf,
        cache,
        router: router.clone(),
        http_client: http_client.clone(),
        client_cache,
        inflight_buffer_semaphore,
        aggregate_buffered_bytes,
        aggregate_buffered_request_bytes,
        is_ready: Arc::clone(&is_ready),
        ai_director,
        metrics: Arc::new(nexusedge_gateway::proxy::GatewayMetrics::default()),
        ack_manager: ack_manager.clone(),
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

    // 5. Control Plane Dynamic Snapshot Synchronizer (P1 Consistency Bridge & Readiness Gate)
    if let (Some(ref ack_manager), Some(sync_client)) = (ack_manager, sync_client_opt) {
        let sync_router = router.clone();
        let sync_dns = Arc::clone(&dns_resolver);
        let sync_is_ready = Arc::clone(&is_ready);
        let sync_ai = state.ai_director.clone();
        let cp_cfg = config.control_plane.clone();

        if cp_cfg.enabled {
            let sse_endpoint = cp_cfg.endpoint.clone();
            let sse_pop_id = cp_cfg.pop_id.clone();
            let sse_node_id = config.server.node_id.clone();
            let sse_auth_token = cp_cfg.auth_token.clone();
            let sse_client = HttpClient::builder()
                .connect_timeout(Duration::from_millis(config.upstream.timeout_ms.max(5000)))
                .redirect(reqwest::redirect::Policy::none())
                .build()?;
            let sse_router = sync_router.clone();
            let sse_dns = Arc::clone(&sync_dns);
            let sse_ai = sync_ai.clone();
            let sse_is_ready = Arc::clone(&sync_is_ready);
            let sse_snapshot_path = autonomous_snapshot_path.clone();
            let sse_ack_manager = Arc::clone(ack_manager);

            tokio::spawn(async move {
                let mut backoff_secs = 1u64;
                loop {
                    tracing::info!(
                        pop_id = %sse_pop_id,
                        endpoint = %sse_endpoint,
                        "Subscribing to Control Plane real-time SSE configuration stream..."
                    );
                    let ctx = StreamSyncContext {
                        endpoint: &sse_endpoint,
                        pop_id: &sse_pop_id,
                        gateway_id: Some(&sse_node_id),
                        ack_manager: Some(&sse_ack_manager),
                        auth_token: &sse_auth_token,
                        snapshot_path: Some(&sse_snapshot_path),
                        client: &sse_client,
                        router: &sse_router,
                        dns_resolver: &sse_dns,
                        ai_director: sse_ai.as_deref(),
                        is_ready: &sse_is_ready,
                    };
                    if let Err(e) = listen_and_apply_event_stream(&ctx).await {
                        tracing::warn!(
                            pop_id = %sse_pop_id,
                            error = %e,
                            backoff_secs = backoff_secs,
                            "Real-time SSE stream disconnected; reconnecting after backoff"
                        );
                    }
                    tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                    backoff_secs = (backoff_secs * 2).min(30);
                }
            });
        }

        let last_checksum: Arc<RwLock<Option<String>>> = Arc::new(RwLock::new(None));
        let watchdog_checksum = Arc::clone(&last_checksum);
        let watchdog_snapshot_path = autonomous_snapshot_path.clone();
        let watchdog_node_id = config.server.node_id.clone();
        let watchdog_ack_manager = Arc::clone(ack_manager);

        tokio::spawn(async move {
            let interval_secs = cp_cfg.poll_interval_secs.max(15);
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));
            loop {
                interval.tick().await;

                // Option B: Watchdog Poll Control Plane /v1/edge/pops/{pop_id}/config (RFC 7232 If-None-Match)
                if cp_cfg.enabled {
                    let etag_opt = watchdog_checksum
                        .read()
                        .ok()
                        .and_then(|guard| guard.clone());
                    let fetch_ctx = SnapshotFetchContext {
                        endpoint: &cp_cfg.endpoint,
                        pop_id: &cp_cfg.pop_id,
                        auth_token: &cp_cfg.auth_token,
                        if_none_match: etag_opt.as_deref(),
                        snapshot_path: Some(&watchdog_snapshot_path),
                    };
                    match fetch_and_apply_control_plane_snapshot_full(
                        &fetch_ctx,
                        &sync_client,
                        &sync_router,
                        &sync_dns,
                        sync_ai.as_deref(),
                    )
                    .await
                    {
                        Ok(stats) => {
                            sync_is_ready.store(true, Ordering::SeqCst);
                            if stats.modified {
                                if let Ok(mut guard) = watchdog_checksum.write() {
                                    *guard = Some(stats.checksum.clone());
                                }
                                tracing::info!(
                                    pop_id = %cp_cfg.pop_id,
                                    routes = stats.routes_applied,
                                    ai_providers = stats.ai_providers_applied,
                                    checksum = %stats.checksum,
                                    version = stats.version,
                                    "Atomically refreshed PoP routes and AI compute providers from Control Plane"
                                );
                                let ack = GatewaySyncAckPayload {
                                    gateway_id: watchdog_node_id.clone(),
                                    pop_id: cp_cfg.pop_id.clone(),
                                    applied_version: stats.version,
                                    applied_checksum: stats.checksum.clone(),
                                    status: "IN_SYNC".to_string(),
                                    error: None,
                                };
                                if let Err(e) = watchdog_ack_manager.submit_ack(ack) {
                                    tracing::error!(
                                        error = %e,
                                        "Failed to durably spool watchdog gateway ACK to disk"
                                    );
                                }
                            } else {
                                tracing::debug!(
                                    pop_id = %cp_cfg.pop_id,
                                    checksum = %stats.checksum,
                                    "Watchdog verified PoP configuration unchanged (304 Not Modified)"
                                );
                            }
                        }
                        Err(e) => {
                            if sync_is_ready.load(Ordering::SeqCst) {
                                tracing::warn!(
                                    pop_id = %cp_cfg.pop_id,
                                    error = %e,
                                    "Control Plane sync cycle failed; continuing with stale last-known-good configuration"
                                );
                            } else {
                                tracing::warn!(
                                    pop_id = %cp_cfg.pop_id,
                                    error = %e,
                                    "Initial Control Plane sync pending or failed; edge gateway remains unready"
                                );
                            }
                        }
                    }
                }
            }
        });
    }

    // 5. Autonomous Upstream Health Probing Loop (Findings 8, 9, 14, P1 Finding 2)
    nexusedge_gateway::health::spawn_active_health_prober(
        router.clone(),
        &config,
        Arc::clone(&dns_resolver),
    );

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
