use crate::cache::EdgeCache;
use crate::config::GatewayConfig;
use crate::rate_limit::RateLimiter;
use crate::router::Router;
use crate::waf::{WafEngine, WafResult};
use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use reqwest::Client as HttpClient;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn};

#[derive(Clone)]
pub struct ProxyState {
    pub config: GatewayConfig,
    pub rate_limiter: RateLimiter,
    pub waf: WafEngine,
    pub cache: EdgeCache,
    pub router: Router,
    pub http_client: HttpClient,
}

pub async fn handle_request(
    req: Request<Incoming>,
    client_ip: IpAddr,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_time = Instant::now();
    let method = req.method().clone();
    let uri_string = req.uri().to_string();

    // 1. DDoS & Token-Bucket Rate Limiter Check
    if !state.rate_limiter.check(client_ip) {
        warn!(ip = %client_ip, uri = %uri_string, "Rate limit exceeded");
        let body = serde_json::json!({
            "error": "Rate limit exceeded",
            "status": 429,
            "node": state.config.server.node_id,
            "region": state.config.server.region,
        });
        let resp = Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("Content-Type", "application/json")
            .header("Server", "NexusEdge/0.1.0")
            .header("Retry-After", "1")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        return Ok(resp);
    }

    // 2. Extract User-Agent header (clone into owned String before moving req)
    let user_agent = req
        .headers()
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    // 3. Read Body (or small initial chunk for WAF inspection)
    let body_bytes = match req.into_body().collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("Failed to read request body: {:?}", e);
            let resp = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("Malformed request body")))
                .unwrap();
            return Ok(resp);
        }
    };

    let body_sample = if !body_bytes.is_empty() {
        std::str::from_utf8(&body_bytes[..body_bytes.len().min(4096)]).ok()
    } else {
        None
    };

    // 4. WAF Inspection
    match state.waf.inspect(&uri_string, user_agent.as_deref(), body_sample) {
        WafResult::Blocked { rule, pattern } => {
            warn!(
                ip = %client_ip,
                rule = rule,
                pattern = %pattern,
                "Request blocked by WAF"
            );
            let body = serde_json::json!({
                "error": "Access Denied by NexusEdge Security Shield",
                "status": 403,
                "rule": rule,
                "node": state.config.server.node_id,
                "region": state.config.server.region,
            });
            let resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
        WafResult::Allowed => {}
    }

    // 5. Edge Cache Check (for idempotent GET requests)
    let cache_key = format!("{}:{}", method, uri_string);
    if method == Method::GET {
        if let Some(cached) = state.cache.get(&cache_key) {
            let latency_us = start_time.elapsed().as_micros();
            info!(uri = %uri_string, latency_us = latency_us, cache = "HIT", "Serving from Edge Cache");

            let mut builder = Response::builder()
                .status(cached.status)
                .header("X-Cache", "HIT")
                .header("Server", "NexusEdge/0.1.0")
                .header("X-Edge-Node", &state.config.server.node_id)
                .header("X-Edge-Region", &state.config.server.region)
                .header("X-Response-Time-Us", latency_us.to_string());

            for (k, v) in cached.headers.iter() {
                builder = builder.header(k, v);
            }

            let resp = builder.body(Full::new(cached.body)).unwrap();
            return Ok(resp);
        }
    }

    // 6. Upstream Selection
    let upstream_base = match state.router.select_upstream() {
        Some(target) => target,
        None => {
            let resp = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("No upstream nodes configured")))
                .unwrap();
            return Ok(resp);
        }
    };

    let forward_url = format!("{}{}", upstream_base.trim_end_matches('/'), uri_string);

    // 7. Proxy Forwarding via Reqwest Client
    let mut client_req = state.http_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        &forward_url,
    );

    // Forward headers (excluding hop-by-hop)
    // Note: We avoid forwarding host directly to let client determine host or pass original
    client_req = client_req.header("X-Forwarded-For", client_ip.to_string());
    client_req = client_req.header("X-Forwarded-Proto", "http");
    client_req = client_req.header("X-Edge-Pop", &state.config.server.node_id);

    if !body_bytes.is_empty() {
        client_req = client_req.body(body_bytes.clone());
    }

    match client_req.send().await {
        Ok(upstream_resp) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            let mut headers_to_cache = hyper::HeaderMap::new();
            let mut builder = Response::builder()
                .status(status)
                .header("X-Cache", "MISS")
                .header("Server", "NexusEdge/0.1.0")
                .header("X-Edge-Node", &state.config.server.node_id)
                .header("X-Edge-Region", &state.config.server.region);

            for (k, v) in upstream_resp.headers().iter() {
                if let (Ok(hn), Ok(hv)) = (
                    HeaderName::from_bytes(k.as_str().as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    headers_to_cache.insert(hn.clone(), hv.clone());
                    builder = builder.header(hn, hv);
                }
            }

            let resp_bytes = match upstream_resp.bytes().await {
                Ok(b) => b,
                Err(e) => {
                    warn!("Failed to stream upstream body: {:?}", e);
                    Bytes::new()
                }
            };

            // Store in cache if 200 OK and GET
            if method == Method::GET && status == StatusCode::OK {
                state
                    .cache
                    .put(cache_key, status, headers_to_cache, resp_bytes.clone(), None);
            }

            let latency_ms = start_time.elapsed().as_millis();
            info!(
                uri = %uri_string,
                status = %status.as_u16(),
                latency_ms = latency_ms,
                cache = "MISS",
                "Upstream request completed"
            );

            let resp = builder.body(Full::new(resp_bytes)).unwrap();
            Ok(resp)
        }
        Err(err) => {
            warn!(url = %forward_url, error = %err, "Upstream connection failed");
            let body = serde_json::json!({
                "error": "Upstream Gateway Timeout / Unreachable",
                "status": 502,
                "node": state.config.server.node_id,
                "details": err.to_string(),
            });
            let resp = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            Ok(resp)
        }
    }
}
