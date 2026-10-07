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
use tracing::{info, warn};

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

const MAX_REQUEST_BODY_BYTES: usize = 10 * 1024 * 1024; // 10 MB (Finding 4)
const MAX_CACHEABLE_RESPONSE_BYTES: usize = 10 * 1024 * 1024; // 10 MB (Finding 4)

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

    // 2. Extract Client Request Headers before consuming body (Finding 3, 5, 6)
    let req_headers = req.headers().clone();
    let host = req_headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("localhost")
        .to_string();

    let user_agent = req_headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let auth_header_present = req_headers.contains_key("authorization");
    let req_cc = req_headers
        .get("cache-control")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_lowercase();

    // Fast-path payload size check from Content-Length header
    if let Some(cl) = req_headers.get("content-length") {
        if let Ok(len) = cl.to_str().unwrap_or("0").parse::<usize>() {
            if len > MAX_REQUEST_BODY_BYTES {
                warn!(len = len, "Request rejected: Content-Length exceeds maximum 10 MB limit");
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

    // 3. Read Body bounded to MAX_REQUEST_BODY_BYTES (Finding 4)
    let limited_body = Limited::new(req.into_body(), MAX_REQUEST_BODY_BYTES);
    let body_bytes = match limited_body.collect().await {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            warn!("Failed to read bounded request body: {:?}", e);
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

    // 5. Tenant-Isolated Edge Cache Check (Finding 5, RFC 9111)
    let scheme = "http";
    let cache_key = format!("{}://{}{}", scheme, host, uri_string);

    if method == Method::GET && !req_cc.contains("no-cache") && !req_cc.contains("no-store") {
        if let Some(cached) = state.cache.get(&cache_key) {
            let latency_us = start_time.elapsed().as_micros();
            info!(uri = %uri_string, host = %host, latency_us = latency_us, cache = "HIT", "Serving from Edge Cache");

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

    // 7. Proxy Forwarding with Strict Header Forwarding (Finding 3)
    let mut client_req = state.http_client.request(
        reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
        &forward_url,
    );

    // Forward all client application headers (Authorization, Cookie, Content-Type, Accept, etc.)
    // Stripping only hop-by-hop headers
    for (name, value) in req_headers.iter() {
        let name_str = name.as_str().to_lowercase();
        if HOP_BY_HOP_HEADERS.contains(&name_str.as_str()) {
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
    client_req = client_req.header("X-Forwarded-For", client_ip.to_string());
    client_req = client_req.header("X-Forwarded-Proto", scheme);
    client_req = client_req.header("X-Forwarded-Host", &host);
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

            let resp_cc = upstream_resp
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok())
                .unwrap_or("")
                .to_lowercase();
            let has_set_cookie = upstream_resp.headers().contains_key("set-cookie");

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

            // 8. RFC 9111 Shared Cache Evaluation (Finding 6)
            // Never cache if:
            //   - Not GET
            //   - Not 200 OK
            //   - Request Cache-Control: no-store
            //   - Authorization header present without explicit public / s-maxage directive
            //   - Origin Cache-Control: no-store or private
            //   - Origin Set-Cookie present
            //   - Body exceeds MAX_CACHEABLE_RESPONSE_BYTES
            let can_cache = method == Method::GET
                && status == StatusCode::OK
                && !req_cc.contains("no-store")
                && (!auth_header_present || resp_cc.contains("public") || resp_cc.contains("s-maxage"))
                && !resp_cc.contains("no-store")
                && !resp_cc.contains("private")
                && !has_set_cookie
                && resp_bytes.len() <= MAX_CACHEABLE_RESPONSE_BYTES;

            if can_cache {
                // Parse s-maxage or max-age for custom TTL if specified
                let custom_ttl = parse_max_age(&resp_cc).map(Duration::from_secs);
                state
                    .cache
                    .put(cache_key, status, headers_to_cache, resp_bytes.clone(), custom_ttl);
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
