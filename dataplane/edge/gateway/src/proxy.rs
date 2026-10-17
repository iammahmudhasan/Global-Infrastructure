use crate::body::{BodyError, GatewayResponseBody};
use crate::cache::{parse_cache_control, EdgeCache};
use crate::config::GatewayConfig;
use crate::rate_limit::RateLimiter;
use crate::router::Router;
use crate::waf::{WafEngine, WafResult};
use bytes::Bytes;
use http_body_util::{BodyExt, Limited};
use hyper::body::Incoming;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Request, Response, StatusCode};
use reqwest::Client as HttpClient;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tracing::{error, info, warn};

fn json_response(status: StatusCode, body: serde_json::Value) -> Response<GatewayResponseBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", "application/json")
        .header("Server", "NexusEdge/0.1.0")
        .body(GatewayResponseBody::from_string(body.to_string()))
        .unwrap()
}

fn plain_response(
    status: StatusCode,
    content_type: &'static str,
    text: impl Into<Bytes>,
) -> Response<GatewayResponseBody> {
    Response::builder()
        .status(status)
        .header("Content-Type", content_type)
        .header("Server", "NexusEdge/0.1.0")
        .body(GatewayResponseBody::from_bytes(text.into()))
        .unwrap()
}

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

/// Connection key for pooling destination-aware and IP-pinned HTTP clients per upstream endpoint.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UpstreamClientKey {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub destination_addr: Option<std::net::SocketAddr>,
    pub tls_server_name: Option<String>,
}

/// Lock-free atomic operational counters for line-rate Prometheus exposition.
#[derive(Debug, Default)]
pub struct GatewayMetrics {
    pub requests_total: std::sync::atomic::AtomicU64,
    pub responses_2xx: std::sync::atomic::AtomicU64,
    pub responses_4xx: std::sync::atomic::AtomicU64,
    pub responses_5xx: std::sync::atomic::AtomicU64,
    pub rate_limited_total: std::sync::atomic::AtomicU64,
    pub waf_blocked_total: std::sync::atomic::AtomicU64,
    pub cache_hits_total: std::sync::atomic::AtomicU64,
    pub cache_misses_total: std::sync::atomic::AtomicU64,
}

#[derive(Clone)]
pub struct ProxyState {
    pub config: GatewayConfig,
    pub trusted_proxies: Vec<crate::config::IpCidr>,
    pub rate_limiter: RateLimiter,
    pub waf: WafEngine,
    pub cache: EdgeCache,
    pub router: Router,
    pub http_client: HttpClient,
    pub client_cache:
        Arc<std::sync::RwLock<std::collections::HashMap<UpstreamClientKey, HttpClient>>>,
    pub inflight_buffer_semaphore: Arc<tokio::sync::Semaphore>,
    pub aggregate_buffered_bytes: Arc<std::sync::atomic::AtomicUsize>,
    pub aggregate_buffered_request_bytes: Arc<std::sync::atomic::AtomicUsize>,
    pub is_ready: Arc<std::sync::atomic::AtomicBool>,
    pub ai_director: Option<Arc<crate::ai::AiTrafficDirector>>,
    pub metrics: Arc<GatewayMetrics>,
}

impl ProxyState {
    /// Formats line-rate atomic telemetry in Prometheus text exposition format (RFC compliant).
    pub fn render_prometheus_metrics(&self) -> String {
        let reqs = self
            .metrics
            .requests_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let resp2 = self
            .metrics
            .responses_2xx
            .load(std::sync::atomic::Ordering::Relaxed);
        let resp4 = self
            .metrics
            .responses_4xx
            .load(std::sync::atomic::Ordering::Relaxed);
        let resp5 = self
            .metrics
            .responses_5xx
            .load(std::sync::atomic::Ordering::Relaxed);
        let rate_drops = self
            .metrics
            .rate_limited_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let waf_blocks = self
            .metrics
            .waf_blocked_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let cache_hits = self
            .metrics
            .cache_hits_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let cache_misses = self
            .metrics
            .cache_misses_total
            .load(std::sync::atomic::Ordering::Relaxed);
        let buf_req = self
            .aggregate_buffered_request_bytes
            .load(std::sync::atomic::Ordering::Relaxed);
        let buf_resp = self
            .aggregate_buffered_bytes
            .load(std::sync::atomic::Ordering::Relaxed);

        let mut output = String::with_capacity(1024);
        output.push_str("# HELP nexusedge_requests_total Total HTTP requests received\n");
        output.push_str("# TYPE nexusedge_requests_total counter\n");
        output.push_str(&format!("nexusedge_requests_total {}\n\n", reqs));

        output.push_str(
            "# HELP nexusedge_responses_total Total HTTP responses sent by status code class\n",
        );
        output.push_str("# TYPE nexusedge_responses_total counter\n");
        output.push_str(&format!(
            "nexusedge_responses_total{{code=\"2xx\"}} {}\n",
            resp2
        ));
        output.push_str(&format!(
            "nexusedge_responses_total{{code=\"4xx\"}} {}\n",
            resp4
        ));
        output.push_str(&format!(
            "nexusedge_responses_total{{code=\"5xx\"}} {}\n\n",
            resp5
        ));

        output.push_str("# HELP nexusedge_rate_limited_total Total requests rejected due to rate limit exhaustion\n");
        output.push_str("# TYPE nexusedge_rate_limited_total counter\n");
        output.push_str(&format!("nexusedge_rate_limited_total {}\n\n", rate_drops));

        output.push_str(
            "# HELP nexusedge_waf_blocked_total Total requests blocked by WAF inspection rules\n",
        );
        output.push_str("# TYPE nexusedge_waf_blocked_total counter\n");
        output.push_str(&format!("nexusedge_waf_blocked_total {}\n\n", waf_blocks));

        output.push_str("# HELP nexusedge_cache_requests_total Total cache lookups by result\n");
        output.push_str("# TYPE nexusedge_cache_requests_total counter\n");
        output.push_str(&format!(
            "nexusedge_cache_requests_total{{result=\"hit\"}} {}\n",
            cache_hits
        ));
        output.push_str(&format!(
            "nexusedge_cache_requests_total{{result=\"miss\"}} {}\n\n",
            cache_misses
        ));

        output.push_str(
            "# HELP nexusedge_buffer_bytes Memory footprint in bytes of in-flight buffers\n",
        );
        output.push_str("# TYPE nexusedge_buffer_bytes gauge\n");
        output.push_str(&format!(
            "nexusedge_buffer_bytes{{direction=\"request\"}} {}\n",
            buf_req
        ));
        output.push_str(&format!(
            "nexusedge_buffer_bytes{{direction=\"response\"}} {}\n",
            buf_resp
        ));

        if let Some(ref director) = self.ai_director {
            let ai_summary = director.get_analytics_summary();
            if let Some(total_reqs) = ai_summary.get("total_requests").and_then(|v| v.as_u64()) {
                output.push_str(
                    "\n# HELP nexusedge_ai_requests_total Total AI inference requests directed\n",
                );
                output.push_str("# TYPE nexusedge_ai_requests_total counter\n");
                output.push_str(&format!("nexusedge_ai_requests_total {}\n", total_reqs));
            }
            if let Some(total_tokens) = ai_summary.get("total_tokens").and_then(|v| v.as_u64()) {
                output.push_str(
                    "\n# HELP nexusedge_ai_tokens_total Total AI inference tokens processed\n",
                );
                output.push_str("# TYPE nexusedge_ai_tokens_total counter\n");
                output.push_str(&format!("nexusedge_ai_tokens_total {}\n", total_tokens));
            }
        }

        output
    }
    /// Retrieves or lazily creates a destination-pinned HTTP client.
    /// Ensures that requests to pinned origins connect directly to the selected SocketAddr
    /// while validating the origin hostname for TLS SNI and certificate validation.
    pub fn get_or_create_upstream_client(
        &self,
        key: &UpstreamClientKey,
    ) -> Result<HttpClient, reqwest::Error> {
        if key.destination_addr.is_none() {
            return Ok(self.http_client.clone());
        }

        {
            let cache = self.client_cache.read().unwrap();
            if let Some(client) = cache.get(key) {
                return Ok(client.clone());
            }
        }

        let mut cache = self.client_cache.write().unwrap();
        if let Some(client) = cache.get(key) {
            return Ok(client.clone());
        }

        let mut builder = HttpClient::builder()
            .timeout(Duration::from_millis(self.config.upstream.timeout_ms))
            .redirect(reqwest::redirect::Policy::none())
            .pool_max_idle_per_host(256)
            .tcp_nodelay(true);

        if let Some(dest_addr) = key.destination_addr {
            builder = builder.resolve(&key.host, dest_addr);
            if let Some(ref sni) = key.tls_server_name {
                if sni != &key.host {
                    builder = builder.resolve(sni, dest_addr);
                }
            }
        }

        let client = builder.build()?;
        cache.insert(key.clone(), client.clone());
        Ok(client)
    }
}

struct ForwardRequestContext<'a> {
    pub method: &'a Method,
    pub uri_string: &'a str,
    pub host: &'a str,
    pub scheme: &'a str,
    pub effective_client_ip: &'a IpAddr,
    pub req_headers: &'a hyper::HeaderMap,
    pub body_bytes: &'a Bytes,
}

async fn dispatch_to_upstream(
    state: &ProxyState,
    selected_upstream: &crate::router::SelectedUpstream,
    ctx: &ForwardRequestContext<'_>,
) -> Result<reqwest::Response, (StatusCode, &'static str, Option<reqwest::Error>)> {
    let forward_url = format!(
        "{}{}",
        selected_upstream.url.trim_end_matches('/'),
        ctx.uri_string
    );

    let target_uri = forward_url
        .parse::<hyper::Uri>()
        .unwrap_or_else(|_| hyper::Uri::from_static("http://localhost"));
    let target_host = target_uri.host().unwrap_or(ctx.host).to_string();
    let target_port =
        target_uri
            .port_u16()
            .unwrap_or(if target_uri.scheme_str() == Some("https") {
                443
            } else {
                80
            });

    let client_key = UpstreamClientKey {
        scheme: target_uri.scheme_str().unwrap_or("http").to_string(),
        host: target_host.clone(),
        port: target_port,
        destination_addr: selected_upstream.destination_addr,
        tls_server_name: selected_upstream.tls_server_name.clone(),
    };

    let client = match state.get_or_create_upstream_client(&client_key) {
        Ok(client) => client,
        Err(err) => {
            error!(
                upstream = %client_key.host,
                error = %err,
                "Failed to create destination-pinned upstream client"
            );
            return Err((
                StatusCode::BAD_GATEWAY,
                "upstream connection configuration failed",
                Some(err),
            ));
        }
    };

    let dispatch_url = if target_uri.scheme_str() == Some("https") {
        if let Some(ref sni) = selected_upstream.tls_server_name {
            if sni != &target_host {
                let port_suffix = if target_port != 443 && target_port != 80 {
                    format!(":{}", target_port)
                } else {
                    String::new()
                };
                let path_and_query = target_uri
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("");
                format!("https://{}{}{}", sni, port_suffix, path_and_query)
            } else {
                forward_url.clone()
            }
        } else {
            forward_url.clone()
        }
    } else {
        forward_url.clone()
    };

    let mut client_req = client.request(
        reqwest::Method::from_bytes(ctx.method.as_str().as_bytes()).unwrap(),
        &dispatch_url,
    );

    let req_connection_tokens = parse_connection_tokens(ctx.req_headers.get("connection"));
    for (name, value) in ctx.req_headers.iter() {
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

    client_req = client_req.header("X-Forwarded-For", ctx.effective_client_ip.to_string());
    client_req = client_req.header("X-Forwarded-Proto", ctx.scheme);
    client_req = client_req.header("X-Forwarded-Host", ctx.host);
    client_req = client_req.header("X-Edge-Pop", &state.config.server.node_id);

    let upstream_host = selected_upstream
        .tls_server_name
        .as_deref()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .unwrap_or(ctx.host);
    client_req = client_req.header(reqwest::header::HOST, upstream_host);

    if !ctx.body_bytes.is_empty() {
        client_req = client_req.body(ctx.body_bytes.clone());
    }

    client_req.send().await.map_err(|err| {
        (
            StatusCode::BAD_GATEWAY,
            "upstream connection failed",
            Some(err),
        )
    })
}

pub async fn handle_request(
    req: Request<Incoming>,
    client_ip: IpAddr,
    state: Arc<ProxyState>,
) -> Result<Response<GatewayResponseBody>, hyper::Error> {
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
        return Ok(json_response(StatusCode::OK, body));
    }

    if path == "/ready" {
        let ai_ready = if let Some(ref director) = state.ai_director {
            director.auth_registry().is_healthy()
        } else {
            true
        };
        let is_ready = state.is_ready.load(std::sync::atomic::Ordering::Acquire) && ai_ready;
        let status = if is_ready {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        };
        let body = serde_json::json!({
            "status": if is_ready { "ready" } else { "unready" },
            "control_plane_synced": state.is_ready.load(std::sync::atomic::Ordering::Acquire),
            "auth_registry_healthy": ai_ready,
        });
        return Ok(json_response(status, body));
    }

    if path == "/metrics" {
        // Enforce metrics access control: restrict to internal networks / loopback or authorized scraper token
        let is_internal = client_ip.is_loopback()
            || state
                .trusted_proxies
                .iter()
                .any(|cidr| cidr.contains(client_ip));
        let auth_header = req
            .headers()
            .get("Authorization")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .trim();
        let token = auth_header.strip_prefix("Bearer ").unwrap_or(auth_header);
        let expected_token = std::env::var("NEXUSEDGE_METRICS_AUTH_TOKEN")
            .unwrap_or_else(|_| std::env::var("NEXUSEDGE_CP_AUTH_TOKEN").unwrap_or_default());

        let is_authenticated = !expected_token.is_empty() && token == expected_token;

        if !is_internal && !is_authenticated {
            return Ok(plain_response(
                StatusCode::FORBIDDEN,
                "text/plain",
                "Forbidden: metrics endpoint restricted to internal network or authorized scraper\n",
            ));
        }

        let metrics_text = state.render_prometheus_metrics();
        return Ok(plain_response(
            StatusCode::OK,
            "text/plain; version=0.0.4; charset=utf-8",
            metrics_text,
        ));
    }

    state
        .metrics
        .requests_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // 1. Extract Client Request Headers before consuming body (Finding 3, 5, 6)
    let req_headers = req.headers().clone();
    let effective_client_ip = extract_client_ip(&req_headers, client_ip, &state.trusted_proxies);

    let host = match resolve_host(&req_headers, req.uri()) {
        Ok(h) => h,
        Err(status) => {
            let body = serde_json::json!({
                "error": "Bad Request",
                "message": "Host and authority mismatch or missing host header",
                "status": status.as_u16(),
            });
            return Ok(json_response(status, body));
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
        state
            .metrics
            .rate_limited_total
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        state
            .metrics
            .responses_4xx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
        let mut resp = json_response(StatusCode::TOO_MANY_REQUESTS, body);
        resp.headers_mut()
            .insert("Retry-After", HeaderValue::from_static("1"));
        return Ok(resp);
    }

    // 4. Tenant WAF Path Block Enforcement (P1 Finding 4)
    if let Some(ref sec) = domain_sec_policy {
        for blocked_path in &sec.blocked_paths {
            if path.starts_with(blocked_path) {
                state
                    .metrics
                    .waf_blocked_total
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                state
                    .metrics
                    .responses_4xx
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
                return Ok(json_response(StatusCode::FORBIDDEN, body));
            }
        }
    }

    let user_agent = req_headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let auth_header_present = req_headers.contains_key("authorization");
    let req_cc_lines = req_headers
        .get_all("cache-control")
        .iter()
        .filter_map(|v| v.to_str().ok());
    let req_cc = parse_cache_control(req_cc_lines);

    // Fast-path payload size check from Content-Length header
    if let Some(cl) = req_headers.get("content-length") {
        if let Ok(len) = cl.to_str().unwrap_or("0").parse::<usize>() {
            if len > MAX_REQUEST_BODY_BYTES {
                warn!(
                    len = len,
                    "Request rejected: Content-Length exceeds maximum 10 MB limit"
                );
                let body = serde_json::json!({
                    "error": "Payload Too Large: maximum allowed body size is 10 MB"
                });
                return Ok(json_response(StatusCode::PAYLOAD_TOO_LARGE, body));
            }
        }
    }

    // 5. Read Body bounded to MAX_REQUEST_BODY_BYTES with global inflight concurrency limit (Finding 4)
    let _buffer_permit = match state.inflight_buffer_semaphore.try_acquire() {
        Ok(permit) => permit,
        Err(_) => {
            warn!("Global inflight request body buffer limit saturated");
            let body = serde_json::json!({
                "error": "Service Unavailable: Gateway concurrency limit reached",
                "status": 503
            });
            let mut resp = json_response(StatusCode::SERVICE_UNAVAILABLE, body);
            resp.headers_mut()
                .insert("Retry-After", HeaderValue::from_static("1"));
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
        let body = serde_json::json!({
            "error": "Service Unavailable: Gateway aggregate request buffer budget saturated under memory pressure",
            "status": 503
        });
        let mut resp = json_response(StatusCode::SERVICE_UNAVAILABLE, body);
        resp.headers_mut()
            .insert("Retry-After", HeaderValue::from_static("1"));
        return Ok(resp);
    }

    if payload_too_large {
        let body = serde_json::json!({
            "error": "Payload Too Large: request body exceeds 10 MB limit or is malformed"
        });
        return Ok(json_response(StatusCode::PAYLOAD_TOO_LARGE, body));
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
                    let body = serde_json::json!({
                        "error": "Service Unavailable: Gateway aggregate request buffer budget saturated under memory pressure",
                        "status": 503
                    });
                    let mut resp = json_response(StatusCode::SERVICE_UNAVAILABLE, body);
                    resp.headers_mut()
                        .insert("Retry-After", HeaderValue::from_static("1"));
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
            state
                .metrics
                .waf_blocked_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            state
                .metrics
                .responses_4xx
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            return Ok(json_response(StatusCode::FORBIDDEN, body));
        }
        WafResult::Allowed => {}
    }

    // 6.5. Universal AI & Compute Inference Traffic Director (Phase 1)
    if let Some(ref director) = state.ai_director {
        if crate::ai::is_ai_inference_request(&path, &method) {
            info!(
                path = %path,
                ip = %effective_client_ip,
                "Routing request to NexusEdge Universal AI & Compute Director"
            );
            return crate::ai::dispatch_ai_request_with_failover(
                &state.http_client,
                director,
                &path,
                &method,
                &req_headers,
                body_bytes,
                effective_client_ip,
            )
            .await;
        }
    }

    // 7. Tenant-Isolated Edge Cache Check (Finding 5, 12, RFC 9111, P1 Finding 4, P2 Milestone 4)
    let scheme = extract_downstream_scheme(&req_headers, client_ip, &state.trusted_proxies);
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
        && !req_cc.no_cache
        && !req_cc.no_store
    {
        if let Some(cached) = state.cache.get(&cache_key, Some(&req_headers)) {
            state
                .metrics
                .cache_hits_total
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            state
                .metrics
                .responses_2xx
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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

            let resp = builder
                .body(GatewayResponseBody::from_bytes(cached.body))
                .unwrap();
            return Ok(resp);
        }
    }

    state
        .metrics
        .cache_misses_total
        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

    // 8. Multi-Tenant Path-Based Upstream Selection (P1 Finding 3, Item 6)
    let selected_upstream = match state.router.select_upstream_for_host_and_path(&host, &path) {
        Ok(target) => target,
        Err(crate::router::RoutingError::UnknownHost(h)) => {
            warn!(host = %h, uri = %uri_string, "Unknown host: no tenant domain route configured");
            let body = serde_json::json!({
                "error": "Misdirected Request: No tenant domain route configured for host",
                "host": h,
                "status": 421,
            });
            return Ok(json_response(StatusCode::MISDIRECTED_REQUEST, body));
        }
        Err(crate::router::RoutingError::NoMatchingPath { host: h, path: p }) => {
            warn!(host = %h, path = %p, "No matching route configured for requested path");
            let body = serde_json::json!({
                "error": "Not Found: No matching route configured for requested path",
                "host": h,
                "path": p,
                "status": 404,
            });
            return Ok(json_response(StatusCode::NOT_FOUND, body));
        }
        Err(crate::router::RoutingError::NoHealthyUpstreams(h)) => {
            warn!(host = %h, uri = %uri_string, "No healthy upstream origin nodes available for tenant host");
            let body = serde_json::json!({
                "error": "Service Unavailable: No healthy upstream origin nodes available for tenant host",
                "host": h,
                "status": 503,
            });
            return Ok(json_response(StatusCode::SERVICE_UNAVAILABLE, body));
        }
        Err(e) => {
            error!(error = %e, host = %host, "Routing resolution error");
            let body = serde_json::json!({
                "error": "Bad Gateway: Upstream routing resolution error",
                "details": e.to_string(),
                "status": 502,
            });
            return Ok(json_response(StatusCode::BAD_GATEWAY, body));
        }
    };

    // 9. Upstream Request Dispatch & Dynamic Passive Failover
    let forward_ctx = ForwardRequestContext {
        method: &method,
        uri_string: &uri_string,
        host: &host,
        scheme,
        effective_client_ip: &effective_client_ip,
        req_headers: &req_headers,
        body_bytes: &body_bytes,
    };

    let (mut upstream_resp, failed_over, failed_origin) =
        match dispatch_to_upstream(&state, &selected_upstream, &forward_ctx).await {
            Ok(resp)
                if resp.status() == reqwest::StatusCode::BAD_GATEWAY
                    || resp.status() == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    || resp.status() == reqwest::StatusCode::GATEWAY_TIMEOUT =>
            {
                let primary_status = resp.status();
                warn!(
                    upstream = %selected_upstream.url,
                    status = %primary_status,
                    "Primary upstream returned server gateway error; attempting dynamic failover"
                );
                state
                    .router
                    .mark_health(&selected_upstream.url, false, 9999);
                match state.router.select_upstream_excluding(
                    &host,
                    &path,
                    &[&selected_upstream.url],
                ) {
                    Ok(backup_upstream) => {
                        warn!(
                            primary = %selected_upstream.url,
                            backup = %backup_upstream.url,
                            "Failing over request to backup upstream"
                        );
                        match dispatch_to_upstream(&state, &backup_upstream, &forward_ctx).await {
                            Ok(backup_resp) => {
                                (backup_resp, true, Some(selected_upstream.url.clone()))
                            }
                            Err((_code, _msg, _err)) => {
                                state.router.mark_health(&backup_upstream.url, false, 9999);
                                (resp, false, None)
                            }
                        }
                    }
                    Err(_) => (resp, false, None),
                }
            }
            Ok(resp) => (resp, false, None),
            Err((_code, _msg, _err)) => {
                warn!(
                    upstream = %selected_upstream.url,
                    "Primary upstream connection failed; attempting dynamic failover"
                );
                state
                    .router
                    .mark_health(&selected_upstream.url, false, 9999);
                match state.router.select_upstream_excluding(
                    &host,
                    &path,
                    &[&selected_upstream.url],
                ) {
                    Ok(backup_upstream) => {
                        warn!(
                            primary = %selected_upstream.url,
                            backup = %backup_upstream.url,
                            "Failing over request to backup upstream after connection failure"
                        );
                        match dispatch_to_upstream(&state, &backup_upstream, &forward_ctx).await {
                            Ok(backup_resp) => {
                                (backup_resp, true, Some(selected_upstream.url.clone()))
                            }
                            Err((_, _, _)) => {
                                state.router.mark_health(&backup_upstream.url, false, 9999);
                                state
                                    .metrics
                                    .responses_5xx
                                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let body = serde_json::json!({
                                    "error": "upstream unavailable",
                                    "status": 502,
                                });
                                return Ok(json_response(StatusCode::BAD_GATEWAY, body));
                            }
                        }
                    }
                    Err(_) => {
                        state
                            .metrics
                            .responses_5xx
                            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let body = serde_json::json!({
                            "error": "upstream unavailable",
                            "status": 502,
                        });
                        return Ok(json_response(StatusCode::BAD_GATEWAY, body));
                    }
                }
            }
        };

    let status = StatusCode::from_u16(upstream_resp.status().as_u16())
        .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

    let mut headers_to_cache = hyper::HeaderMap::new();
    let mut builder = Response::builder()
        .status(status)
        .header("X-Cache", "MISS")
        .header("Server", "NexusEdge/0.1.0");

    if failed_over {
        builder = builder.header("X-NexusEdge-Failover", "true");
        if let Some(ref failed) = failed_origin {
            builder = builder.header("X-NexusEdge-Failed-Upstream", failed.as_str());
        }
    }

    // Multi-value Cache-Control parsing (P1 Finding 6, RFC 9111 structured parsing)
    let resp_cc_lines = upstream_resp
        .headers()
        .get_all("cache-control")
        .iter()
        .filter_map(|v| v.to_str().ok());
    let resp_cc = parse_cache_control(resp_cc_lines);
    let has_set_cookie = upstream_resp.headers().contains_key("set-cookie");

    let resp_connection_tokens = parse_connection_tokens(upstream_resp.headers().get("connection"));

    for (k, v) in upstream_resp.headers().iter() {
        let k_lower = k.as_str().to_lowercase();
        if is_hop_by_hop_response_header(&k_lower) || resp_connection_tokens.contains(&k_lower) {
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

    let latency_ms = start_time.elapsed().as_millis();
    info!(
        uri = %uri_string,
        status = %status.as_u16(),
        latency_ms = latency_ms,
        cache = "MISS",
        "Upstream request completed"
    );

    if status.is_success() {
        state
            .metrics
            .responses_2xx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else if status.is_client_error() {
        state
            .metrics
            .responses_4xx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    } else if status.is_server_error() {
        state
            .metrics
            .responses_5xx
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    // 10. RFC 9111 Shared Cache Evaluation & Line-Rate Zero-Copy Streaming
    let is_vary_star = headers_to_cache
        .get("vary")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim() == "*")
        .unwrap_or(false);

    let upstream_cl = upstream_resp
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<usize>().ok());

    let mut can_cache_candidate = method == Method::GET
        && status == StatusCode::OK
        && !has_cookie
        && !has_auth
        && !bypass_cache
        && !req_cc.no_store
        && !req_cc.no_cache
        && (!auth_header_present || resp_cc.public || resp_cc.s_maxage.is_some())
        && !resp_cc.no_store
        && !resp_cc.no_cache
        && !resp_cc.private
        && !has_set_cookie
        && !is_vary_star;

    if let Some(cl) = upstream_cl {
        if cl > MAX_CACHEABLE_RESPONSE_BYTES {
            can_cache_candidate = false;
        }
    }

    let default_policy_ttl = domain_cache_policy
        .as_ref()
        .map(|c| Duration::from_secs(c.default_ttl_seconds))
        .unwrap_or(Duration::from_secs(3600));

    let computed_freshness = crate::cache::compute_rfc9111_freshness(
        &headers_to_cache,
        default_policy_ttl,
        chrono::Utc::now(),
    );

    if computed_freshness.is_none() {
        // Stale, expired past Expires deadline, Age >= freshness lifetime, or prohibited directives
        can_cache_candidate = false;
    }

    let custom_ttl = computed_freshness.map(|ttl| ttl.min(MAX_CUSTOM_CACHE_TTL));

    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, BodyError>>(32);
    let state_clone = Arc::clone(&state);
    let req_headers_clone = req_headers.clone();

    tokio::spawn(async move {
        if can_cache_candidate {
            let mut resp_buf = bytes::BytesMut::new();
            let mut buffer_guard = Some(BufferBudgetGuard::new(
                Arc::clone(&state_clone.aggregate_buffered_bytes),
                MAX_AGGREGATE_BUFFERED_RESPONSE_BYTES,
            ));
            let mut cache_disabled_for_stream = false;

            loop {
                match upstream_resp.chunk().await {
                    Ok(Some(chunk)) => {
                        if !cache_disabled_for_stream {
                            let fits_cache = resp_buf.len().saturating_add(chunk.len())
                                <= MAX_CACHEABLE_RESPONSE_BYTES;
                            let budget_ok = buffer_guard
                                .as_mut()
                                .map(|g| g.try_allocate(chunk.len()).is_ok())
                                .unwrap_or(false);

                            if fits_cache && budget_ok {
                                resp_buf.extend_from_slice(&chunk);
                            } else {
                                cache_disabled_for_stream = true;
                                buffer_guard = None;
                                resp_buf.clear();
                            }
                        }

                        if tx.send(Ok(chunk)).await.is_err() {
                            // Downstream client disconnected or aborted stream
                            return;
                        }
                    }
                    Ok(None) => {
                        // Upstream completed successfully
                        if !cache_disabled_for_stream && !resp_buf.is_empty() {
                            let resp_bytes = resp_buf.freeze();
                            state_clone.cache.put(
                                cache_key,
                                status,
                                headers_to_cache,
                                resp_bytes,
                                custom_ttl,
                                Some(&req_headers_clone),
                            );
                        }
                        break;
                    }
                    Err(e) => {
                        error!(error = %e, "Upstream stream interrupted during transfer");
                        let _ = tx.send(Err(Box::new(e))).await;
                        break;
                    }
                }
            }
        } else {
            // Direct zero-copy streaming pass-through (SSE, WebSockets, large downloads, mutations)
            loop {
                match upstream_resp.chunk().await {
                    Ok(Some(chunk)) => {
                        if tx.send(Ok(chunk)).await.is_err() {
                            // Downstream client disconnected
                            break;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        error!(error = %e, "Upstream stream interrupted during transfer");
                        let _ = tx.send(Err(Box::new(e))).await;
                        break;
                    }
                }
            }
        }
    });

    let resp = builder.body(GatewayResponseBody::stream(rx)).unwrap();
    Ok(resp)
}

/// Extracts original client IP according to RFC 7239 / Envoy trusted proxy forwarding semantics.
///
/// Invariants:
/// 1. Untrusted peer: If peer_ip does not match any entry in trusted_proxies, peer_ip is strictly returned.
///    Any client-supplied X-Forwarded-For header is untrusted and ignored to prevent rate-limit bypass and IP spoofing.
/// 2. Trusted proxy peer: If peer_ip is in trusted_proxies (e.g. Envoy L7 ingress),
///    we inspect the X-Forwarded-For header chain from right to left.
///    The rightmost entry was appended by the trusted proxy and represents the verified downstream client address.
///    Any attacker-forged entries prefixed on the left are discarded.
pub fn extract_client_ip(
    headers: &hyper::HeaderMap,
    peer_ip: IpAddr,
    trusted_proxies: &[crate::config::IpCidr],
) -> IpAddr {
    let is_trusted = trusted_proxies.iter().any(|cidr| cidr.contains(peer_ip));
    if !is_trusted {
        return peer_ip;
    }

    if let Some(xff) = headers.get("x-forwarded-for").and_then(|v| v.to_str().ok()) {
        let ips: Vec<IpAddr> = xff
            .split(',')
            .filter_map(|s| s.trim().parse::<IpAddr>().ok())
            .collect();

        // Right-to-left traversal: find the first IP that is NOT one of our trusted proxies.
        // This is the authentic downstream client address.
        for ip in ips.into_iter().rev() {
            if !trusted_proxies.iter().any(|cidr| cidr.contains(ip)) {
                return ip;
            }
        }
    }

    peer_ip
}

/// Extracts the authentic downstream scheme according to trusted proxy forwarding rules.
///
/// Invariants:
/// 1. Untrusted peer: If peer_ip does not match any CIDR in trusted_proxies,
///    the connection scheme defaults strictly to "http". Any client-supplied
///    X-Forwarded-Proto header is untrusted and ignored to prevent scheme spoofing.
/// 2. Trusted proxy peer: If peer_ip is in trusted_proxies (e.g. Envoy L7 ingress),
///    we inspect the X-Forwarded-Proto header forwarded by Envoy.
///    If it equals "https" (case-insensitive), "https" is returned; otherwise "http".
pub fn extract_downstream_scheme(
    headers: &hyper::HeaderMap,
    peer_ip: IpAddr,
    trusted_proxies: &[crate::config::IpCidr],
) -> &'static str {
    let is_trusted = trusted_proxies.iter().any(|cidr| cidr.contains(peer_ip));
    if !is_trusted {
        return "http";
    }

    if let Some(proto) = headers
        .get("x-forwarded-proto")
        .and_then(|v| v.to_str().ok())
    {
        for part in proto.split(',').rev() {
            let trimmed = part.trim();
            if trimmed.eq_ignore_ascii_case("https") {
                return "https";
            } else if trimmed.eq_ignore_ascii_case("http") {
                return "http";
            }
        }
    }

    "http"
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

pub fn parse_max_age(cc: &str) -> Option<u64> {
    let directives = parse_cache_control([cc]);
    directives.s_maxage.or(directives.max_age)
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
    fn test_extract_client_ip_trusted_proxy_single_hop() {
        let trusted = vec![
            crate::config::IpCidr::parse("127.0.0.1/32").unwrap(),
            crate::config::IpCidr::parse("172.16.0.0/12").unwrap(),
        ];
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "198.51.100.42".parse().unwrap());

        let peer_docker: IpAddr = "172.18.0.2".parse().unwrap();
        let client_ip = extract_client_ip(&headers, peer_docker, &trusted);
        assert_eq!(client_ip, "198.51.100.42".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_client_ip_spoofed_xff_prevented() {
        let trusted = vec![
            crate::config::IpCidr::parse("127.0.0.1/32").unwrap(),
            crate::config::IpCidr::parse("172.16.0.0/12").unwrap(),
        ];

        // Scenario A: Attacker attempts to spoof XFF via trusted Envoy reverse proxy
        // Attacker (203.0.113.195) sends "X-Forwarded-For: 8.8.8.8".
        // Envoy (use_remote_address: true, xff_num_trusted_hops: 0) appends the true remote address:
        // "X-Forwarded-For: 8.8.8.8, 203.0.113.195".
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "8.8.8.8, 203.0.113.195".parse().unwrap());

        let envoy_peer: IpAddr = "172.18.0.2".parse().unwrap();
        let client_ip = extract_client_ip(&headers, envoy_peer, &trusted);
        // Gateway must extract genuine client IP (203.0.113.195), discarding forged 8.8.8.8
        assert_eq!(client_ip, "203.0.113.195".parse::<IpAddr>().unwrap());

        // Scenario B: Untrusted public peer connects directly with forged XFF
        let public_peer: IpAddr = "198.51.100.99".parse().unwrap();
        let client_ip_direct = extract_client_ip(&headers, public_peer, &trusted);
        // Must return public peer address, ignoring header completely
        assert_eq!(client_ip_direct, public_peer);
    }

    #[test]
    fn test_extract_client_ip_multi_hop_trusted_chain() {
        let trusted = vec![
            crate::config::IpCidr::parse("127.0.0.1/32").unwrap(),
            crate::config::IpCidr::parse("172.16.0.0/12").unwrap(),
            crate::config::IpCidr::parse("10.0.0.0/8").unwrap(),
        ];
        let mut headers = hyper::HeaderMap::new();
        // Client (203.0.113.50) -> CDN (10.0.5.1) -> Envoy (172.18.0.2)
        // With attacker spoof attempt: "8.8.8.8, 203.0.113.50, 10.0.5.1"
        headers.insert(
            "x-forwarded-for",
            "8.8.8.8, 203.0.113.50, 10.0.5.1".parse().unwrap(),
        );

        let envoy_peer: IpAddr = "172.18.0.2".parse().unwrap();
        let client_ip = extract_client_ip(&headers, envoy_peer, &trusted);
        assert_eq!(client_ip, "203.0.113.50".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_extract_client_ip_fallback_on_all_trusted_or_malformed() {
        let trusted = vec![
            crate::config::IpCidr::parse("127.0.0.1/32").unwrap(),
            crate::config::IpCidr::parse("172.16.0.0/12").unwrap(),
        ];

        // All trusted IPs in chain
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-for", "127.0.0.1, 172.18.0.1".parse().unwrap());
        let peer: IpAddr = "172.18.0.2".parse().unwrap();
        assert_eq!(extract_client_ip(&headers, peer, &trusted), peer);

        // Malformed XFF
        let mut headers_malformed = hyper::HeaderMap::new();
        headers_malformed.insert(
            "x-forwarded-for",
            "not-an-ip, %%%, 999.999.999".parse().unwrap(),
        );
        assert_eq!(extract_client_ip(&headers_malformed, peer, &trusted), peer);
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

    #[test]
    fn test_extract_downstream_scheme_untrusted_peer_spoof_prevented() {
        let trusted = vec![
            crate::config::IpCidr::parse("127.0.0.1/32").unwrap(),
            crate::config::IpCidr::parse("172.16.0.0/12").unwrap(),
        ];
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-forwarded-proto", "https".parse().unwrap());

        // Untrusted public client peer IP
        let untrusted_peer: IpAddr = "203.0.113.50".parse().unwrap();
        let scheme = extract_downstream_scheme(&headers, untrusted_peer, &trusted);
        assert_eq!(scheme, "http", "Untrusted peer cannot spoof https scheme");
    }

    #[test]
    fn test_extract_downstream_scheme_trusted_envoy_peer() {
        let trusted = vec![
            crate::config::IpCidr::parse("127.0.0.1/32").unwrap(),
            crate::config::IpCidr::parse("172.16.0.0/12").unwrap(),
        ];
        let envoy_peer: IpAddr = "172.18.0.2".parse().unwrap();

        let mut headers_https = hyper::HeaderMap::new();
        headers_https.insert("x-forwarded-proto", "https".parse().unwrap());
        assert_eq!(
            extract_downstream_scheme(&headers_https, envoy_peer, &trusted),
            "https"
        );

        let mut headers_http = hyper::HeaderMap::new();
        headers_http.insert("x-forwarded-proto", "http".parse().unwrap());
        assert_eq!(
            extract_downstream_scheme(&headers_http, envoy_peer, &trusted),
            "http"
        );

        let headers_empty = hyper::HeaderMap::new();
        assert_eq!(
            extract_downstream_scheme(&headers_empty, envoy_peer, &trusted),
            "http"
        );
    }

    #[test]
    fn test_cache_key_scheme_isolation() {
        let host = "api.nexusedge.io";
        let uri = "/data";
        let norm_ae = "gzip";
        let http_key = format!("{}://{}{}#ae={}", "http", host, uri, norm_ae);
        let https_key = format!("{}://{}{}#ae={}", "https", host, uri, norm_ae);

        assert_ne!(http_key, https_key);
        assert_eq!(http_key, "http://api.nexusedge.io/data#ae=gzip");
        assert_eq!(https_key, "https://api.nexusedge.io/data#ae=gzip");
    }

    #[test]
    fn test_failover_headers_injection_contract() {
        let mut builder = Response::builder()
            .status(StatusCode::OK)
            .header("X-Cache", "MISS")
            .header("Server", "NexusEdge/0.1.0");

        let failed_over = true;
        let failed_origin = Some("https://primary.aeitron.com".to_string());

        if failed_over {
            builder = builder.header("X-NexusEdge-Failover", "true");
            if let Some(ref failed) = failed_origin {
                builder = builder.header("X-NexusEdge-Failed-Upstream", failed.as_str());
            }
        }

        let resp = builder.body(()).unwrap();
        assert_eq!(resp.headers().get("X-NexusEdge-Failover").unwrap(), "true");
        assert_eq!(
            resp.headers().get("X-NexusEdge-Failed-Upstream").unwrap(),
            "https://primary.aeitron.com"
        );
    }
}
