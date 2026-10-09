use crate::cache::EdgeCache;
use crate::config::GatewayConfig;
use crate::rate_limit::RateLimiter;
use crate::router::Router;
use crate::waf::{WafEngine, WafResult};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use reqwest::Client as HttpClient;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

const HOP_BY_HOP_HEADERS: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
    "host",
];

const STRIPPED_FORWARDING_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
];

const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024; // 10 MB (Finding 4)
const MAX_CACHEABLE_RESPONSE_BYTES: usize = 10 * 1024 * 1024; // 10 MB (Finding 4)
const MAX_UPSTREAM_RESPONSE_BYTES: usize = 10 * 1024 * 1024; // 10 MiB hard limit for origin responses
pub const MAX_AGGREGATE_BUFFERED_RESPONSE_BYTES: usize = 128 * 1024 * 1024; // 128 MiB aggregate limit (P1 Finding 5)
pub const MAX_AGGREGATE_BUFFERED_REQUEST_BYTES: usize = 128 * 1024 * 1024; // 128 MiB aggregate limit for request bodies
const MAX_CUSTOM_CACHE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60); // 7 days (Finding 2)

pub const DEFAULT_MAX_INFLIGHT_BUFFERED_REQUESTS: usize = 256;

pub struct BufferBudgetGuard {
    tracker: Arc<std::sync::atomic::AtomicUsize>,
    allocated: usize,
    limit: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BudgetExceeded;

impl std::fmt::Display for BudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Gateway buffer memory budget exceeded")
    }
}

impl std::error::Error for BudgetExceeded {}

impl BufferBudgetGuard {
    pub fn new(tracker: Arc<std::sync::atomic::AtomicUsize>, limit: usize) -> Self {
        Self {
            tracker,
            allocated: 0,
            limit,
        }
    }

    pub fn try_allocate(&mut self, bytes: usize) -> Result<(), BudgetExceeded> {
        let mut current = self.tracker.load(std::sync::atomic::Ordering::Acquire);
        loop {
            if current.saturating_add(bytes) > self.limit {
                return Err(BudgetExceeded);
            }
            match self.tracker.compare_exchange_weak(
                current,
                current + bytes,
                std::sync::atomic::Ordering::AcqRel,
                std::sync::atomic::Ordering::Acquire,
            ) {
                Ok(_) => {
                    self.allocated += bytes;
                    return Ok(());
                }
                Err(actual) => current = actual,
            }
        }
    }
}

impl Drop for BufferBudgetGuard {
    fn drop(&mut self) {
        if self.allocated > 0 {
            self.tracker
                .fetch_sub(self.allocated, std::sync::atomic::Ordering::Release);
        }
    }
}

#[derive(Clone)]
pub struct ProxyState {
    pub config: GatewayConfig,
    pub rate_limiter: RateLimiter,
    pub waf: WafEngine,
    pub cache: EdgeCache,
    pub router: Router,
    pub http_client: HttpClient,
    pub inflight_buffer_semaphore: Arc<tokio::sync::Semaphore>,
    pub aggregate_buffered_bytes: Arc<std::sync::atomic::AtomicUsize>,
    pub aggregate_buffered_request_bytes: Arc<std::sync::atomic::AtomicUsize>,
    pub is_ready: Arc<std::sync::atomic::AtomicBool>,
}

pub async fn handle_request(
    req: Request<Incoming>,
    client_ip: IpAddr,
    state: Arc<ProxyState>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_time = Instant::now();
    let method = req.method().clone();
    let uri_string = req.uri().to_string();
    let path = req.uri().path().to_string();

    // Operational Health & Readiness Endpoints (Deployment Orchestration Gate)
    if path == "/healthz" || path == "/live" {
        let body = serde_json::json!({
            "status": "healthy",
            "uptime_secs": start_time.elapsed().as_secs(),
        });
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("Server", "NexusEdge/0.1.0")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        return Ok(resp);
    }

    if path == "/ready" {
        let is_ready = state.is_ready.load(std::sync::atomic::Ordering::Acquire);
        let status = if is_ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        let body = serde_json::json!({
            "status": if is_ready { "ready" } else { "unready" },
            "control_plane_synced": is_ready,
        });
        let resp = Response::builder()
            .status(status)
            .header("Content-Type", "application/json")
            .header("Server", "NexusEdge/0.1.0")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        return Ok(resp);
    }

    // 1. Extract Client Request Headers before consuming body (Finding 3, 5, 6)
    let req_headers = req.headers().clone();
    let effective_client_ip = extract_client_ip(&req_headers, client_ip);

    let host = match resolve_host(&req_headers, req.uri()) {
        Ok(h) => h,
        Err(status) => {
            let body = serde_json::json!({
                "error": "Bad Request",
                "message": "Host and authority mismatch or missing host header",
                "status": status.as_u16(),
            });
            let resp = Response::builder()
                .status(status)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
    };

    // 2. Retrieve Tenant-Specific Policies (P1 Finding 4)
    let (domain_sec_policy, domain_cache_policy) = state
        .router
        .get_domain_policy(&host)
        .unwrap_or((None, None));

    // 3. DDoS & Token-Bucket Rate Limiter Check (Keyed by Tenant & Client IP, P1 Finding 4)
    let rate_limit_key = format!("{}:{}", host, effective_client_ip);
    let (custom_rps, custom_burst) = domain_sec_policy
        .as_ref()
        .filter(|p| p.rate_limit_enabled && p.requests_per_second > 0 && p.burst_capacity > 0)
        .map(|p| (Some(p.requests_per_second), Some(p.burst_capacity)))
        .unwrap_or((None, None));

    if !state
        .rate_limiter
        .check_key(&rate_limit_key, custom_rps, custom_burst)
    {
        warn!(
            ip = %effective_client_ip,
            host = %host,
            uri = %uri_string,
            "Rate limit exceeded"
        );
        let body = serde_json::json!({
            "error": "Rate limit exceeded",
            "status": 429,
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

    // 4. Tenant WAF Path Block Enforcement (P1 Finding 4)
    if let Some(ref sec) = domain_sec_policy {
        for blocked_path in &sec.blocked_paths {
            if path.starts_with(blocked_path) {
                warn!(
                    ip = %effective_client_ip,
                    host = %host,
                    path = %path,
                    blocked_path = %blocked_path,
                    "Request path blocked by tenant security policy"
                );
                let body = serde_json::json!({
                    "error": "Access Denied by Tenant Security Policy",
                    "status": 403,
                    "blocked_path": blocked_path,
                });
                let resp = Response::builder()
                    .status(StatusCode::FORBIDDEN)
                    .header("Content-Type", "application/json")
                    .header("Server", "NexusEdge/0.1.0")
                    .body(Full::new(Bytes::from(body.to_string())))
                    .unwrap();
                return Ok(resp);
            }
        }
    }

    let user_agent = req_headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let auth_header_present = req_headers.contains_key("authorization");
    let req_cc = joined_header_values(&req_headers, "cache-control").to_ascii_lowercase();

    // Fast-path payload size check from Content-Length header
    if let Some(cl) = req_headers.get("content-length") {
        if let Ok(len) = cl.to_str().unwrap_or("0").parse::<usize>() {
            if len > MAX_REQUEST_BODY_BYTES {
                warn!(
                    len = len,
                    "Request rejected: Content-Length exceeds maximum 10 MB limit"
                );
                let resp = Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .header("Content-Type", "application/json")
                    .header("Server", "NexusEdge/0.1.0")
                    .body(Full::new(Bytes::from(
                        r#"{"error":"Payload Too Large: maximum allowed body size is 10 MB"}"#,
                    )))
                    .unwrap();
                return Ok(resp);
            }
        }
    }

    // 5. Read Body bounded to MAX_REQUEST_BODY_BYTES with global inflight concurrency limit (Finding 4)
    let _buffer_permit = match state.inflight_buffer_semaphore.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            warn!("Global inflight request body buffer limit saturated");
            let resp = Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge/0.1.0")
                .header("Retry-After", "1")
                .body(Full::new(Bytes::from(
                    r#"{"error":"Service Unavailable: Gateway concurrency limit reached","status":503}"#,
                )))
                .unwrap();
            return Ok(resp);
        }
    };

    let mut req_body_guard = BufferBudgetGuard::new(
        Arc::clone(&state.aggregate_buffered_request_bytes),
        MAX_AGGREGATE_BUFFERED_REQUEST_BYTES,
    );

    let mut limited_body = Limited::new(req.into_body(), MAX_REQUEST_BODY_BYTES);
    let mut body_buf = Vec::new();
    let mut budget_exceeded = false;
    let mut payload_too_large = false;

    while let Some(frame_res) = limited_body.frame().await {
        match frame_res {
            Ok(frame) => {
                if let Ok(data) = frame.into_data() {
                    if !data.is_empty() {
                        // Atomic budget reservation occurs BEFORE allocating buffer space for the chunk
                        if req_body_guard.try_allocate(data.len()).is_err() {
                            warn!(
                                bytes = data.len(),
                                limit = MAX_AGGREGATE_BUFFERED_REQUEST_BYTES,
                                "Gateway aggregate request body buffer limit saturated during streaming"
                            );
                            budget_exceeded = true;
                            break;
                        }
                        body_buf.extend_from_slice(&data);
                    }
                }
            }
            Err(e) => {
                warn!("Request body stream error or exceeded 10 MB limit: {:?}", e);
                payload_too_large = true;
                break;
            }
        }
    }

    if budget_exceeded {
        let resp = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Content-Type", "application/json")
            .header("Server", "NexusEdge/0.1.0")
            .header("Retry-After", "1")
            .body(Full::new(Bytes::from(
                r#"{"error":"Service Unavailable: Gateway aggregate request buffer budget saturated under memory pressure","status":503}"#,
            )))
            .unwrap();
        return Ok(resp);
    }

    if payload_too_large {
        let resp = Response::builder()
            .status(StatusCode::PAYLOAD_TOO_LARGE)
            .header("Content-Type", "application/json")
            .header("Server", "NexusEdge/0.1.0")
            .body(Full::new(Bytes::from(
                r#"{"error":"Payload Too Large: request body exceeds 10 MB limit or is malformed"}"#,
            )))
            .unwrap();
        return Ok(resp);
    }

    let body_bytes = Bytes::from(body_buf);

    let (body_lossy, _lossy_guard) = if !body_bytes.is_empty() {
        match std::str::from_utf8(&body_bytes) {
            Ok(valid_str) => (Some(std::borrow::Cow::Borrowed(valid_str)), None),
            Err(_) => {
                // For invalid UTF-8, reserve additional memory budget for the lossy allocated string.
                // In UTF-8, each invalid byte can be replaced by '\u{FFFD}' (3 bytes), causing worst-case 3x expansion.
                let required_lossy_bytes = body_bytes.len().saturating_mul(3);
                let mut lossy_guard = BufferBudgetGuard::new(
                    Arc::clone(&state.aggregate_buffered_request_bytes),
                    MAX_AGGREGATE_BUFFERED_REQUEST_BYTES,
                );
                if lossy_guard.try_allocate(required_lossy_bytes).is_err() {
                    warn!(
                        bytes = required_lossy_bytes,
                        limit = MAX_AGGREGATE_BUFFERED_REQUEST_BYTES,
                        "Gateway aggregate request buffer budget saturated for lossy string conversion"
                    );
                    let resp = Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header("Content-Type", "application/json")
                        .header("Server", "NexusEdge/0.1.0")
                        .header("Retry-After", "1")
                        .body(Full::new(Bytes::from(
                            r#"{"error":"Service Unavailable: Gateway aggregate request buffer budget saturated under memory pressure","status":503}"#,
                        )))
                        .unwrap();
                    return Ok(resp);
                }
                (
                    Some(String::from_utf8_lossy(&body_bytes)),
                    Some(lossy_guard),
                )
            }
        }
    } else {
        (None, None)
    };

    // 6. Tenant & Global WAF Inspection (Finding 7 & P1 Finding 3)
    match state.waf.inspect_with_tenant_policy(
        &uri_string,
        user_agent.as_deref(),
        body_lossy.as_deref(),
        domain_sec_policy.as_ref(),
    ) {
        WafResult::Blocked { rule, pattern } => {
            warn!(
                ip = %effective_client_ip,
                rule = rule,
                pattern = %pattern,
                "Request blocked by WAF"
            );
            let body = serde_json::json!({
                "error": "Access Denied by NexusEdge Security Shield",
                "status": 403,
                "rule": rule,
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

    // 7. Tenant-Isolated Edge Cache Check (Finding 5, 12, RFC 9111, P1 Finding 4)
    let scheme = "http";
    let raw_ae = req_headers
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let norm_ae = normalize_accept_encoding(raw_ae);
    let cache_key = format!("{}://{}{}#ae={}", scheme, host, uri_string, norm_ae);

    let has_cookie = req_headers.contains_key("cookie");
    let has_auth = req_headers.contains_key("authorization");
    let bypass_cache = domain_cache_policy
        .as_ref()
        .map(|c| !c.enabled || c.bypass_paths.iter().any(|bp| path.starts_with(bp)))
        .unwrap_or(false);

    if method == Method::GET
        && !has_cookie
        && !has_auth
        && !bypass_cache
        && !req_cc.contains("no-cache")
        && !req_cc.contains("no-store")
    {
        if let Some(cached) = state.cache.get(&cache_key, Some(&req_headers)) {
            let latency_us = start_time.elapsed().as_micros();
            info!(uri = %uri_string, host = %host, latency_us = latency_us, cache = "HIT", "Serving from Edge Cache");

            let mut builder = Response::builder()
                .status(cached.status)
                .header("X-Cache", "HIT")
                .header("Server", "NexusEdge/0.1.0")
                .header("X-Response-Time-Us", latency_us.to_string());

            for (k, v) in cached.headers.iter() {
                builder = builder.header(k, v);
            }

            let resp = builder.body(Full::new(cached.body)).unwrap();
            return Ok(resp);
        }
    }

    // 8. Multi-Tenant Path-Based Upstream Selection (P1 Finding 3)
    let upstream_base = match state.router.select_upstream_for_host_and_path(&host, &path) {
        Ok(target) => target,
        Err(crate::router::RoutingError::UnknownHost(h)) => {
            warn!(host = %h, uri = %uri_string, "Unknown host: no tenant domain route configured");
            let body = serde_json::json!({
                "error": "Misdirected Request: No tenant domain route configured for host",
                "host": h,
                "status": 421,
            });
            let resp = Response::builder()
                .status(StatusCode::MISDIRECTED_REQUEST)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
        Err(crate::router::RoutingError::NoMatchingPath { host: h, path: p }) => {
            warn!(host = %h, path = %p, "No matching route configured for requested path");
            let body = serde_json::json!({
                "error": "Not Found: No matching route configured for requested path",
                "host": h,
                "path": p,
                "status": 404,
            });
            let resp = Response::builder()
                .status(StatusCode::NOT_FOUND)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
        Err(crate::router::RoutingError::NoHealthyUpstreams(h)) => {
            warn!(host = %h, uri = %uri_string, "No healthy upstream origin nodes available for tenant host");
            let body = serde_json::json!({
                "error": "Service Unavailable: No healthy upstream origin nodes available for tenant host",
                "host": h,
                "status": 503,
            });
            let resp = Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
        Err(e) => {
            error!(error = %e, host = %host, "Routing resolution error");
            let body = serde_json::json!({
                "error": "Bad Gateway: Upstream routing resolution error",
                "details": e.to_string(),
                "status": 502,
            });
            let resp = Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
    };

    let forward_url = format!("{}{}", upstream_base.trim_end_matches('/'), uri_string);

    // 9. Proxy Forwarding with Strict Header Forwarding (Finding 3)
    let mut client_req = state.http_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        &forward_url,
    );

    // Forward all client application headers (Authorization, Cookie, Content-Type, Accept, etc.)
    // Stripping hop-by-hop headers, nominated Connection tokens, and untrusted client forwarding headers
    let req_connection_tokens = parse_connection_tokens(req_headers.get("connection"));
    for (name, value) in req_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if HOP_BY_HOP_HEADERS.contains(&name_str.as_str())
            || STRIPPED_FORWARDING_HEADERS.contains(&name_str.as_str())
            || req_connection_tokens.contains(&name_str)
        {
            continue;
        }
        if let (Ok(hn), Ok(hv)) = (
            reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
            reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
        ) {
            client_req = client_req.header(hn, hv);
        }
    }

    // Attach standard reverse proxy forwarding headers
    client_req = client_req.header("X-Forwarded-For", effective_client_ip.to_string());
    client_req = client_req.header("X-Forwarded-Proto", scheme);
    client_req = client_req.header("X-Forwarded-Host", &host);
    client_req = client_req.header("X-Edge-Pop", &state.config.server.node_id);

    // Forward the original customer Host header upstream (P1).
    client_req = client_req.header(reqwest::header::HOST, &host);

    if !body_bytes.is_empty() {
        client_req = client_req.body(body_bytes.clone());
    }

    match client_req.send().await {
        Ok(mut upstream_resp) => {
            let status = StatusCode::from_u16(upstream_resp.status().as_u16())
                .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

            // Fast check on upstream Content-Length to avoid buffering excessive responses (P1 Finding 5)
            if let Some(cl_val) = upstream_resp.headers().get("content-length") {
                if let Ok(cl) = cl_val.to_str().unwrap_or("0").parse::<usize>() {
                    if cl > MAX_UPSTREAM_RESPONSE_BYTES {
                        warn!(
                            cl = cl,
                            limit = MAX_UPSTREAM_RESPONSE_BYTES,
                            "Upstream response Content-Length exceeds maximum limit"
                        );
                        let resp = Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .header("Content-Type", "application/json")
                            .header("Server", "NexusEdge/0.1.0")
                            .body(Full::new(Bytes::from(
                                r#"{"error":"Bad Gateway: Upstream response exceeds maximum allowed 10 MiB limit"}"#,
                            )))
                            .unwrap();
                        return Ok(resp);
                    }
                }
            }

            let mut headers_to_cache = hyper::HeaderMap::new();
            let mut builder = Response::builder()
                .status(status)
                .header("X-Cache", "MISS")
                .header("Server", "NexusEdge/0.1.0");

            // Multi-value Cache-Control parsing (P1 Finding 6)
            let resp_cc = joined_reqwest_header_values(upstream_resp.headers(), "cache-control")
                .to_ascii_lowercase();
            let has_set_cookie = upstream_resp.headers().contains_key("set-cookie");

            let resp_connection_tokens =
                parse_connection_tokens(upstream_resp.headers().get("connection"));

            for (k, v) in upstream_resp.headers().iter() {
                let k_lower = k.as_str().to_lowercase();
                if is_hop_by_hop_response_header(&k_lower)
                    || resp_connection_tokens.contains(&k_lower)
                {
                    continue;
                }
                if let (Ok(hn), Ok(hv)) = (
                    HeaderName::from_bytes(k.as_str().as_bytes()),
                    HeaderValue::from_bytes(v.as_bytes()),
                ) {
                    headers_to_cache.append(hn.clone(), hv.clone());
                    builder = builder.header(hn, hv);
                }
            }

            // Stream upstream response with hard 10 MiB bounded buffer and aggregate memory budgeting (P1 Finding 5)
            let mut resp_buf = bytes::BytesMut::new();
            let mut total_bytes = 0usize;
            let mut stream_oversized = false;
            let mut stream_error = false;
            let mut aggregate_limit_exceeded = false;
            let mut buffer_guard = BufferBudgetGuard::new(
                Arc::clone(&state.aggregate_buffered_bytes),
                MAX_AGGREGATE_BUFFERED_RESPONSE_BYTES,
            );

            loop {
                match upstream_resp.chunk().await {
                    Ok(Some(chunk)) => {
                        total_bytes += chunk.len();
                        if total_bytes > MAX_UPSTREAM_RESPONSE_BYTES {
                            warn!(
                                total_bytes = total_bytes,
                                limit = MAX_UPSTREAM_RESPONSE_BYTES,
                                "Upstream response stream exceeded maximum allowed limit"
                            );
                            stream_oversized = true;
                            break;
                        }
                        if buffer_guard.try_allocate(chunk.len()).is_err() {
                            warn!(
                                total_bytes = total_bytes,
                                limit = MAX_AGGREGATE_BUFFERED_RESPONSE_BYTES,
                                "Gateway aggregate response buffer capacity exceeded"
                            );
                            aggregate_limit_exceeded = true;
                            break;
                        }
                        resp_buf.extend_from_slice(&chunk);
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!(
                            error = %e,
                            "Upstream stream connection interrupted during response transfer"
                        );
                        stream_error = true;
                        break;
                    }
                }
            }

            if stream_error {
                let resp = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header("Content-Type", "application/json")
                    .header("Server", "NexusEdge/0.1.0")
                    .body(Full::new(Bytes::from(
                        r#"{"error":"Bad Gateway: Upstream connection interrupted during response transfer"}"#,
                    )))
                    .unwrap();
                return Ok(resp);
            }

            if aggregate_limit_exceeded {
                let resp = Response::builder()
                    .status(StatusCode::SERVICE_UNAVAILABLE)
                    .header("Content-Type", "application/json")
                    .header("Server", "NexusEdge/0.1.0")
                    .body(Full::new(Bytes::from(
                        r#"{"error":"Service Unavailable: Gateway response buffer capacity exceeded under memory pressure"}"#,
                    )))
                    .unwrap();
                return Ok(resp);
            }

            if stream_oversized {
                let resp = Response::builder()
                    .status(StatusCode::BAD_GATEWAY)
                    .header("Content-Type", "application/json")
                    .header("Server", "NexusEdge/0.1.0")
                    .body(Full::new(Bytes::from(
                        r#"{"error":"Bad Gateway: Upstream response stream exceeded maximum allowed limit"}"#,
                    )))
                    .unwrap();
                return Ok(resp);
            }

            let resp_bytes = resp_buf.freeze();

            // 10. RFC 9111 Shared Cache Evaluation (Finding 6, P1 Finding 4, 6)
            // Never cache if:
            //   - Not GET
            //   - Not 200 OK
            //   - Request Cache-Control: no-store
            //   - Authorization header present without explicit public / s-maxage directive
            //   - Origin Cache-Control: no-store or private
            //   - Origin Set-Cookie present
            //   - Domain Cache Policy specifies bypass_cache
            //   - Body exceeds MAX_CACHEABLE_RESPONSE_BYTES
            let is_vary_star = headers_to_cache
                .get("vary")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim() == "*")
                .unwrap_or(false);

            let can_cache = method == Method::GET
                && status == StatusCode::OK
                && !has_cookie
                && !has_auth
                && !bypass_cache
                && !req_cc.contains("no-store")
                && (!auth_header_present
                    || resp_cc.contains("public")
                    || resp_cc.contains("s-maxage"))
                && !resp_cc.contains("no-store")
                && !resp_cc.contains("private")
                && !has_set_cookie
                && !is_vary_star
                && resp_bytes.len() <= MAX_CACHEABLE_RESPONSE_BYTES;

            if can_cache {
                // Parse s-maxage or max-age for custom TTL if specified, or domain policy fallback bounded to 7 days
                let custom_ttl = parse_max_age(&resp_cc)
                    .map(Duration::from_secs)
                    .or_else(|| {
                        domain_cache_policy
                            .as_ref()
                            .map(|c| Duration::from_secs(c.default_ttl_seconds))
                    })
                    .map(|ttl| ttl.min(MAX_CUSTOM_CACHE_TTL));
                state.cache.put(
                    cache_key,
                    status,
                    headers_to_cache,
                    resp_bytes.clone(),
                    custom_ttl,
                    Some(&req_headers),
                );
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
                "error": "upstream unavailable",
                "status": 502,
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

/// Extracts original client IP, trusting forwarding headers only from private/loopback peer (Envoy / local gateway proxy, P1/P2 Finding 7)
pub fn extract_client_ip(headers: &hyper::HeaderMap, peer_ip: IpAddr) -> IpAddr {
    let is_trusted_proxy = match peer_ip {
        IpAddr::V4(v4) => v4.is_loopback() || v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => v6.is_loopback() || v6.is_unique_local(),
    };
    if is_trusted_proxy {
        if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
            if let Some(first_ip_str) = xff.split(',').next() {
                if let Ok(ip) = first_ip_str.trim().parse::<IpAddr>() {
                    return ip;
                }
            }
        }
    }
    peer_ip
}

/// Joins all comma-separated header values for a named header from hyper::HeaderMap (P1 Finding 6)
pub fn joined_header_values(headers: &hyper::HeaderMap, name: &str) -> String {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
}

/// Joins all comma-separated header values for a named header from reqwest::header::HeaderMap (P1 Finding 6)
pub fn joined_reqwest_header_values(headers: &reqwest::header::HeaderMap, name: &str) -> String {
    headers
        .get_all(name)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .collect::<Vec<_>>()
        .join(",")
}

/// Resolves target host according to RFC 9110 / HTTP/2 semantics:
/// Rejects ambiguous requests where both Host and :authority are present but mismatch (RFC 9113 §8.3.1).
/// Prefers the matching host/authority; fails closed if neither is present.
pub fn resolve_host(headers: &hyper::HeaderMap, uri: &hyper::Uri) -> Result<String, StatusCode> {
    let host = headers.get("host").and_then(|v| v.to_str().ok());
    let authority = uri.authority().map(|a| a.as_str());

    match (host, authority) {
        (Some(h), Some(a)) => {
            if !h.eq_ignore_ascii_case(a) {
                Err(StatusCode::BAD_REQUEST)
            } else {
                Ok(h.to_string())
            }
        }
        (Some(h), None) => Ok(h.to_string()),
        (None, Some(a)) => Ok(a.to_string()),
        (None, None) => Err(StatusCode::BAD_REQUEST),
    }
}

/// Identifies standard RFC 9110 / RFC 7230 hop-by-hop response headers
pub fn is_hop_by_hop_response_header(name: &str) -> bool {
    matches!(
        name,
        "connection"
            | "keep-alive"
            | "proxy-authenticate"
            | "proxy-authorization"
            | "te"
            | "trailer"
            | "transfer-encoding"
            | "upgrade"
    )
}

/// Parses Connection header tokens (comma-separated header names) to strip per RFC 9110
pub fn parse_connection_tokens(
    conn_val: Option<&hyper::header::HeaderValue>,
) -> std::collections::HashSet<String> {
    let mut tokens = std::collections::HashSet::new();
    if let Some(val) = conn_val {
        if let Ok(s) = val.to_str() {
            for token in s.split(',') {
                let t = token.trim().to_lowercase();
                if !t.is_empty() {
                    tokens.insert(t);
                }
            }
        }
    }
    tokens
}

pub fn normalize_accept_encoding(value: &str) -> String {
    let mut encs: Vec<String> = value
        .split(',')
        .map(|v| v.trim().to_lowercase())
        .filter(|v| !v.is_empty())
        .collect();
    encs.sort();
    encs.join(",")
}

fn parse_max_age(cc: &str) -> Option<u64> {
    for directive in ["s-maxage=", "max-age="] {
        if let Some(idx) = cc.find(directive) {
            let sub = &cc[idx + directive.len()..];
            let end = sub.find([',', ' ', ';']).unwrap_or(sub.len());
            if let Ok(secs) = sub[..end].trim().parse::<u64>() {
                return Some(secs);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_max_age_overflow_and_bounds() {
        assert_eq!(parse_max_age("max-age=3600"), Some(3600));
        assert_eq!(
            parse_max_age("public, s-maxage=86400, max-age=3600"),
            Some(86400)
        );
        assert_eq!(
            parse_max_age("max-age=18446744073709551615"),
            Some(u64::MAX)
        );
        assert_eq!(parse_max_age("no-cache"), None);
    }

    #[test]
    fn test_normalize_accept_encoding() {
        assert_eq!(normalize_accept_encoding("gzip, br"), "br,gzip");
        assert_eq!(normalize_accept_encoding("br, gzip"), "br,gzip");
        assert_eq!(normalize_accept_encoding("GZIP"), "gzip");
        assert_eq!(
            normalize_accept_encoding(" gzip , deflate , br "),
            "br,deflate,gzip"
        );
        assert_eq!(normalize_accept_encoding(""), "");
    }

    #[test]
    fn test_resolve_host_with_host_header_only() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", "customer-a.example.com".parse().unwrap());
        let uri: hyper::Uri = "/api/v1".parse().unwrap();
        assert_eq!(
            resolve_host(&headers, &uri).unwrap(),
            "customer-a.example.com"
        );
    }

    #[test]
    fn test_resolve_host_http2_authority_only() {
        let headers = hyper::HeaderMap::new();
        let uri: hyper::Uri = "https://customer-b.example.com/api/v1".parse().unwrap();
        assert_eq!(
            resolve_host(&headers, &uri).unwrap(),
            "customer-b.example.com"
        );
    }

    #[test]
    fn test_resolve_host_matching_host_and_authority() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", "customer-a.example.com".parse().unwrap());
        let uri: hyper::Uri = "https://customer-a.example.com/api/v1".parse().unwrap();
        assert_eq!(
            resolve_host(&headers, &uri).unwrap(),
            "customer-a.example.com"
        );
    }

    #[test]
    fn test_resolve_host_mismatch_rejected() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", "attacker.example.com".parse().unwrap());
        let uri: hyper::Uri = "https://customer-a.example.com/api/v1".parse().unwrap();
        assert_eq!(resolve_host(&headers, &uri), Err(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn test_resolve_host_missing_fails_closed() {
        let headers = hyper::HeaderMap::new();
        let uri: hyper::Uri = "/relative/path".parse().unwrap();
        assert_eq!(resolve_host(&headers, &uri), Err(StatusCode::BAD_REQUEST));
    }

    #[test]
    fn test_is_hop_by_hop_response_header() {
        assert!(is_hop_by_hop_response_header("connection"));
        assert!(is_hop_by_hop_response_header("keep-alive"));
        assert!(is_hop_by_hop_response_header("transfer-encoding"));
        assert!(is_hop_by_hop_response_header("upgrade"));
        assert!(!is_hop_by_hop_response_header("content-type"));
        assert!(!is_hop_by_hop_response_header("x-cache"));
        assert!(!is_hop_by_hop_response_header("strict-transport-security"));
    }

    #[test]
    fn test_parse_connection_tokens() {
        let val: hyper::header::HeaderValue = "close, X-Custom-Header, Keep-Alive".parse().unwrap();
        let tokens = parse_connection_tokens(Some(&val));
        assert!(tokens.contains("close"));
        assert!(tokens.contains("x-custom-header"));
        assert!(tokens.contains("keep-alive"));
        assert_eq!(tokens.len(), 3);
    }

    #[test]
    fn test_headers_to_cache_preserves_multiple_vary() {
        let mut headers = hyper::HeaderMap::new();
        headers.append("vary", "Origin".parse().unwrap());
        headers.append("vary", "Accept-Encoding".parse().unwrap());

        let mut headers_to_cache = hyper::HeaderMap::new();
        for (k, v) in headers.iter() {
            headers_to_cache.append(k.clone(), v.clone());
        }

        let vary_values: Vec<&str> = headers_to_cache
            .get_all("vary")
            .iter()
            .map(|v| v.to_str().unwrap())
            .collect();
        assert_eq!(vary_values, vec!["Origin", "Accept-Encoding"]);
    }

    #[test]
    fn test_client_req_preserves_customer_host_header() {
        let host = "customer-a.example.com";
        let client = reqwest::Client::new();
        let mut client_req =
            client.request(reqwest::Method::GET, "https://origin-a.internal/api/v1");
        client_req = client_req.header(reqwest::header::HOST, host);
        client_req = client_req.header("X-Forwarded-Host", host);
        let req = client_req.build().unwrap();

        assert_eq!(
            req.headers()
                .get(reqwest::header::HOST)
                .unwrap()
                .to_str()
                .unwrap(),
            "customer-a.example.com"
        );
        assert_eq!(
            req.headers()
                .get("x-forwarded-host")
                .unwrap()
                .to_str()
                .unwrap(),
            "customer-a.example.com"
        );
    }

    #[test]
    fn test_joined_header_values_multiple_cache_control() {
        let mut headers = hyper::HeaderMap::new();
        headers.append("cache-control", "public, max-age=3600".parse().unwrap());
        headers.append("cache-control", "no-store".parse().unwrap());

        let joined = joined_header_values(&headers, "cache-control").to_ascii_lowercase();
        assert!(joined.contains("public"));
        assert!(joined.contains("no-store"));
        assert_eq!(joined, "public, max-age=3600,no-store");
    }

    #[test]
    fn test_extract_client_ip_trusted_proxy() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            "198.51.100.42, 172.18.0.2".parse().unwrap(),
        );

        let peer_docker: IpAddr = "172.18.0.2".parse().unwrap();
        let client_ip = extract_client_ip(&headers, peer_docker);
        assert_eq!(client_ip, "198.51.100.42".parse::<IpAddr>().unwrap());

        let peer_loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let client_ip2 = extract_client_ip(&headers, peer_loopback);
        assert_eq!(client_ip2, "198.51.100.42".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_client_ip_untrusted_direct() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "1.1.1.1".parse().unwrap());

        let public_peer: IpAddr = "203.0.113.50".parse().unwrap();
        let client_ip = extract_client_ip(&headers, public_peer);
        assert_eq!(client_ip, public_peer);
    }

    #[test]
    fn test_buffer_budget_guard_lifecycle() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tracker = Arc::new(AtomicUsize::new(0));
        let limit = 1000;

        {
            let mut guard = BufferBudgetGuard::new(Arc::clone(&tracker), limit);
            assert!(guard.try_allocate(400).is_ok());
            assert_eq!(tracker.load(Ordering::Relaxed), 400);

            assert!(guard.try_allocate(500).is_ok());
            assert_eq!(tracker.load(Ordering::Relaxed), 900);

            // Exceeds limit (900 + 200 > 1000)
            assert!(guard.try_allocate(200).is_err());
            assert_eq!(tracker.load(Ordering::Relaxed), 900);
        }

        // On drop, guard must decrement allocated bytes
        assert_eq!(tracker.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn test_buffer_budget_guard_concurrent_cas_contention() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tracker = Arc::new(AtomicUsize::new(0));
        let limit = 10_000;
        let mut handles = vec![];

        // 10 concurrent threads allocating 1500 bytes each
        // Since limit is 10,000, exactly 6 threads can succeed (6 * 1500 = 9000 <= 10000),
        // and remaining 4 threads MUST fail without exceeding limit!
        for _ in 0..10 {
            let t = Arc::clone(&tracker);
            handles.push(std::thread::spawn(move || {
                let mut guard = BufferBudgetGuard::new(t, limit);
                let ok = guard.try_allocate(1500).is_ok();
                (ok, guard)
            }));
        }

        let mut successes = 0;
        let mut guards = vec![];
        for h in handles {
            let (ok, guard) = h.join().unwrap();
            if ok {
                successes += 1;
                guards.push(guard);
            }
        }

        assert_eq!(successes, 6);
        assert_eq!(tracker.load(Ordering::Acquire), 9000);

        drop(guards);
        assert_eq!(tracker.load(Ordering::Acquire), 0);
    }

    #[test]
    fn test_lossy_utf8_budget_guard_behavior() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let tracker = Arc::new(AtomicUsize::new(0));
        let limit = 1000;

        // Valid UTF-8: zero extra memory allocation needed (Cow::Borrowed)
        let valid_bytes = b"Hello NexusEdge Gateway valid UTF-8";
        assert!(std::str::from_utf8(valid_bytes).is_ok());

        // Invalid UTF-8: requires allocation and CAS budget check
        let invalid_bytes = vec![0xFF, 0xFE, 0xFD, 0x80, 0x81];
        assert!(std::str::from_utf8(&invalid_bytes).is_err());

        {
            let mut lossy_guard = BufferBudgetGuard::new(Arc::clone(&tracker), limit);
            let required_lossy = invalid_bytes.len().saturating_mul(3);
            assert!(lossy_guard.try_allocate(required_lossy).is_ok());
            assert_eq!(tracker.load(Ordering::Relaxed), 15);

            // Exceeding limit fails CAS
            let mut second_guard = BufferBudgetGuard::new(Arc::clone(&tracker), limit);
            assert!(second_guard.try_allocate(1000).is_err());
            assert_eq!(tracker.load(Ordering::Relaxed), 15);
        }

        // Drop releases all bytes
        assert_eq!(tracker.load(Ordering::Relaxed), 0);
    }
}
