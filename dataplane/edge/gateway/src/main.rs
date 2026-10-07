mod cache;
mod config;
mod proxy;
mod rate_limit;
mod router;
mod waf;

use crate::cache::EdgeCache;
use crate::config::GatewayConfig;
use crate::proxy::{handle_request, ProxyState};
use crate::rate_limit::RateLimiter;
use crate::router::Router;
use crate::waf::WafEngine;

use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use reqwest::Client as HttpClient;
use std::net::SocketAddr;
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
    let config = if std::path::Path::new("gateway.yaml").exists() {
        info!("Loading configuration from gateway.yaml");
        GatewayConfig::load_from_file("gateway.yaml")?
    } else {
        info!("gateway.yaml not found, applying default enterprise configuration");
        GatewayConfig::default()
    };

    println!(r#"
  ███╗   ██╗███████╗██╗   ██╗██╗   ██╗███████╗███████╗██████╗  ██████╗ ███████╗
  ████╗  ██║██╔════╝╚██╗ ██╔╝██║   ██║██╔════╝██╔════╝██╔══██╗██╔════╝ ██╔════╝
  ██╔██╗ ██║█████╗   ╚████╔╝ ██║   ██║███████╗█████╗  ██║  ██║██║  ███╗█████╗  
  ██║╚██╗██║██╔══╝    ╚██╔╝  ██║   ██║╚════██║██╔══╝  ██║  ██║██║   ██║██╔══╝  
  ██║ ╚████║███████╗   ██║   ╚██████╔╝███████║███████╗██████╔╝╚██████╔╝███████╗
  ╚═╝  ╚═══╝╚══════╝   ╚═╝    ╚═════╝ ╚══════╝╚══════╝╚═════╝  ╚═════╝ ╚══════╝
    "#);
    info!("Starting NexusEdge Global Ingress Gateway");
    info!("Node ID:    {}", config.server.node_id);
    info!("Region:     {}", config.server.region);
    info!("Listening:  {}", config.server.listen_addr);
    info!("WAF Shield: {}", if config.waf.enabled { "ACTIVE" } else { "DISABLED" });
    info!("DDoS Guard: {}", if config.rate_limit.enabled { "ACTIVE" } else { "DISABLED" });
    info!("Edge Cache: {}", if config.cache.enabled { "ACTIVE" } else { "DISABLED" });

    // 3. Initialize Shared State Engines
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
    );
    let router = Router::new(
        config.upstream.targets.clone(),
        config.upstream.timeout_ms,
    );

    let http_client = HttpClient::builder()
        .timeout(Duration::from_millis(config.upstream.timeout_ms))
        .pool_max_idle_per_host(256)
        .tcp_nodelay(true)
        .build()?;

    let state = Arc::new(ProxyState {
        config: config.clone(),
        rate_limiter: rate_limiter.clone(),
        waf,
        cache,
        router,
        http_client,
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

    // 5. Bind TCP Listener and accept connections
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
