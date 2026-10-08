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

const STRIPPED_FORWARDING_HEADERS: &[&str] = &[
    "x-forwarded-for",
    "x-forwarded-host",
    "x-forwarded-proto",
    "forwarded",
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
    match state
        .waf
        .inspect(&uri_string, user_agent.as_deref(), body_sample)
    {
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

    // 5. Tenant-Isolated Edge Cache Check (Finding 5, 12, RFC 9111)
    let scheme = "http";
    let raw_ae = req_headers
        .get("accept-encoding")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let norm_ae = normalize_accept_encoding(raw_ae);
    let cache_key = format!("{}://{}{}#ae={}", scheme, host, uri_string, norm_ae);

    if method == Method::GET && !req_cc.contains("no-cache") && !req_cc.contains("no-store") {
        if let Some(cached) = state.cache.get(&cache_key, Some(&req_headers)) {
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

    // 6. Upstream Selection (Finding 13: 503 Service Unavailable when no healthy nodes exist)
    let upstream_base = match state.router.select_upstream() {
        Some(target) => target,
        None => {
            warn!(uri = %uri_string, "No healthy upstream nodes available in pool");
            let body = serde_json::json!({
                "error": "Service Unavailable: No healthy upstream origin nodes available in pool",
                "status": 503,
                "node": state.config.server.node_id,
                "region": state.config.server.region,
            });
            let resp = Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
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
            let is_vary_star = headers_to_cache
                .get("vary")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.trim() == "*")
                .unwrap_or(false);

            let can_cache = method == Method::GET
                && status == StatusCode::OK
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
                // Parse s-maxage or max-age for custom TTL if specified
                let custom_ttl = parse_max_age(&resp_cc).map(Duration::from_secs);
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
}
