use crate::dns::PinnedDnsResolver;
use crate::router::{self, Router};
use reqwest::Client as HttpClient;
use sha2::Digest;
use std::fmt;

/// Maximum permissible payload budget for Control Plane dynamic configuration snapshots.
/// Enforces bounded memory allocation on edge nodes to defeat snapshot memory-bomb attacks (P2 Finding).
pub const MAX_CONTROL_PLANE_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStats {
    pub routes_applied: usize,
    pub ai_providers_applied: usize,
    pub checksum: String,
    pub modified: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    InvalidEndpoint(String),
    NetworkError(String),
    BadStatus(u16),
    MissingChecksumHeader,
    EmptyChecksumHeader,
    SnapshotTooLarge { size: usize, limit: usize },
    ChecksumMismatch { expected: String, computed: String },
    ParseError(String),
    RouteApplyError(String),
}

impl fmt::Display for SyncError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SyncError::InvalidEndpoint(e) => write!(f, "Invalid control plane endpoint: {}", e),
            SyncError::NetworkError(e) => {
                write!(f, "Network error communicating with control plane: {}", e)
            }
            SyncError::BadStatus(code) => write!(
                f,
                "Control plane returned non-success status code: {}",
                code
            ),
            SyncError::MissingChecksumHeader => write!(
                f,
                "Mandatory X-Snapshot-Checksum header missing from response"
            ),
            SyncError::EmptyChecksumHeader => write!(f, "X-Snapshot-Checksum header is empty"),
            SyncError::SnapshotTooLarge { size, limit } => write!(
                f,
                "Control plane snapshot payload too large ({} bytes exceeds limit of {} bytes)",
                size, limit
            ),
            SyncError::ChecksumMismatch { expected, computed } => {
                write!(
                    f,
                    "Snapshot SHA-256 checksum mismatch (expected: {}, computed: {})",
                    expected, computed
                )
            }
            SyncError::ParseError(e) => {
                write!(f, "Failed to parse PoP routes snapshot payload: {}", e)
            }
            SyncError::RouteApplyError(e) => write!(f, "Failed to apply routes to router: {}", e),
        }
    }
}

impl std::error::Error for SyncError {}

/// Validates Control Plane sync endpoint for transport security and credential safety.
/// Requires HTTPS for all remote endpoints and mandates authentication token for remote transports.
/// Strictly rejects user credentials in URL, query parameters, and fragments.
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

    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(
            "Control Plane endpoint cannot contain userinfo (username or password)".to_string(),
        );
    }

    if parsed.query().is_some() {
        return Err("Control Plane endpoint cannot contain query parameters".to_string());
    }

    if parsed.fragment().is_some() {
        return Err("Control Plane endpoint cannot contain URL fragment".to_string());
    }

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

/// Parameters required to query and verify a declarative PoP snapshot.
#[derive(Debug, Clone)]
pub struct SnapshotFetchContext<'a> {
    pub endpoint: &'a str,
    pub pop_id: &'a str,
    pub auth_token: &'a str,
    pub if_none_match: Option<&'a str>,
    pub snapshot_path: Option<&'a str>,
}

/// Fetches a declarative PoP configuration snapshot from the Control Plane,
/// verifies cryptographic checksum authenticity, safely parses the routes,
/// atomically replaces routing tables, and synchronizes DNS pinning maps.
pub async fn fetch_and_apply_control_plane_snapshot(
    endpoint: &str,
    pop_id: &str,
    auth_token: &str,
    client: &HttpClient,
    router: &Router,
    dns_resolver: &PinnedDnsResolver,
) -> Result<SyncStats, SyncError> {
    let ctx = SnapshotFetchContext {
        endpoint,
        pop_id,
        auth_token,
        if_none_match: None,
        snapshot_path: None,
    };
    fetch_and_apply_control_plane_snapshot_full(&ctx, client, router, dns_resolver, None).await
}

/// Extended snapshot sync including dynamic AI & compute provider pool updates,
/// RFC 7232 If-None-Match conditional caching (304 Not Modified), and local disk cache persistence.
pub async fn fetch_and_apply_control_plane_snapshot_full(
    ctx: &SnapshotFetchContext<'_>,
    client: &HttpClient,
    router: &Router,
    dns_resolver: &PinnedDnsResolver,
    ai_director: Option<&crate::ai::AiTrafficDirector>,
) -> Result<SyncStats, SyncError> {
    validate_control_plane_endpoint(ctx.endpoint, ctx.auth_token)
        .map_err(SyncError::InvalidEndpoint)?;

    let url = format!(
        "{}/v1/edge/pops/{}/config",
        ctx.endpoint.trim_end_matches('/'),
        ctx.pop_id
    );

    let mut req_builder = client.get(&url);
    if !ctx.auth_token.is_empty() {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", ctx.auth_token));
    }
    if let Some(etag) = ctx.if_none_match {
        let trimmed = etag.trim().trim_matches('"');
        if !trimmed.is_empty() {
            req_builder = req_builder.header("If-None-Match", format!("\"{}\"", trimmed));
        }
    }

    let resp = req_builder
        .send()
        .await
        .map_err(|e| SyncError::NetworkError(e.to_string()))?;

    // Fast-path: RFC 7232 304 Not Modified (zero memory allocation, zero route swapping)
    if resp.status() == reqwest::StatusCode::NOT_MODIFIED {
        return Ok(SyncStats {
            routes_applied: 0,
            ai_providers_applied: 0,
            checksum: ctx.if_none_match.unwrap_or("").to_string(),
            modified: false,
        });
    }

    if !resp.status().is_success() {
        return Err(SyncError::BadStatus(resp.status().as_u16()));
    }

    let header_checksum = resp
        .headers()
        .get("x-snapshot-checksum")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string());

    let Some(expected_checksum) = header_checksum else {
        return Err(SyncError::MissingChecksumHeader);
    };

    if expected_checksum.is_empty() {
        return Err(SyncError::EmptyChecksumHeader);
    }

    // Fast-fail check on Content-Length header if present
    if let Some(content_length) = resp.content_length() {
        if content_length > MAX_CONTROL_PLANE_SNAPSHOT_BYTES as u64 {
            return Err(SyncError::SnapshotTooLarge {
                size: content_length as usize,
                limit: MAX_CONTROL_PLANE_SNAPSHOT_BYTES,
            });
        }
    }

    // Stream response chunks up to MAX_CONTROL_PLANE_SNAPSHOT_BYTES (bounded memory guarantee)
    let mut body_bytes = Vec::new();
    let mut resp_stream = resp;
    while let Some(chunk) = resp_stream.chunk().await.map_err(|e| {
        SyncError::NetworkError(format!("Failed to read snapshot response chunk: {}", e))
    })? {
        if body_bytes.len().saturating_add(chunk.len()) > MAX_CONTROL_PLANE_SNAPSHOT_BYTES {
            return Err(SyncError::SnapshotTooLarge {
                size: body_bytes.len().saturating_add(chunk.len()),
                limit: MAX_CONTROL_PLANE_SNAPSHOT_BYTES,
            });
        }
        body_bytes.extend_from_slice(&chunk);
    }

    let computed_hash = format!("{:x}", sha2::Sha256::digest(&body_bytes));
    if !expected_checksum.eq_ignore_ascii_case(&computed_hash) {
        return Err(SyncError::ChecksumMismatch {
            expected: expected_checksum,
            computed: computed_hash,
        });
    }

    let body_str = std::str::from_utf8(&body_bytes).map_err(|e| {
        SyncError::ParseError(format!("Snapshot payload is not valid UTF-8: {}", e))
    })?;

    // Persist raw snapshot to autonomous local store if configured (Shared-Nothing Edge Autonomy)
    if let Some(path) = ctx.snapshot_path {
        if let Err(e) = persist_snapshot_to_disk(path, body_str) {
            tracing::warn!(
                path = %path,
                error = %e,
                "Failed to write snapshot to autonomous local store"
            );
        }
    }

    let new_routes = router::parse_pop_config_routes(body_str)
        .map_err(|e| SyncError::ParseError(e.to_string()))?;

    let maybe_new_ai = router::parse_pop_config_ai_providers(body_str)
        .map_err(|e| SyncError::ParseError(e.to_string()))?;

    let routes_count = new_routes.len();
    let ai_ref = maybe_new_ai.as_deref();
    router
        .update_routes_with_dns_and_ai(new_routes, vec![], ai_ref, dns_resolver)
        .map_err(|e| SyncError::RouteApplyError(e.to_string()))?;

    let mut ai_providers_applied = 0;
    if let Some(director) = ai_director {
        if let Some(new_ai) = maybe_new_ai {
            ai_providers_applied = new_ai.len();
            director.update_providers(new_ai);
        }
    }

    Ok(SyncStats {
        routes_applied: routes_count,
        ai_providers_applied,
        checksum: computed_hash,
        modified: true,
    })
}

/// Persists the raw snapshot string atomically to disk using a temporary file and rename.
pub fn persist_snapshot_to_disk(path: &str, payload: &str) -> Result<(), std::io::Error> {
    let p = std::path::Path::new(path);
    if let Some(parent) = p.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    let tmp_path = format!("{}.tmp.{}", path, std::process::id());
    std::fs::write(&tmp_path, payload.as_bytes())?;
    std::fs::rename(&tmp_path, path)?;
    Ok(())
}

/// Reads the local autonomous snapshot cache from disk.
pub fn load_snapshot_from_disk(path: &str) -> Result<String, std::io::Error> {
    std::fs::read_to_string(path)
}

/// Represents a parsed Server-Sent Event (SSE) message block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SseEvent {
    pub event_type: String,
    pub data: String,
}

/// Parses a double-newline delimited SSE text block into an SseEvent.
/// Ignores comments and keepalive pings (lines starting with ':').
pub fn parse_sse_block(block: &str) -> Option<SseEvent> {
    let mut event_type = "message".to_string();
    let mut data = String::new();
    let mut has_fields = false;

    for line in block.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with(':') {
            continue;
        }
        if let Some(rest) = line.strip_prefix("event:") {
            event_type = rest.trim().to_string();
            has_fields = true;
        } else if let Some(rest) = line.strip_prefix("data:") {
            if !data.is_empty() {
                data.push('\n');
            }
            data.push_str(rest.trim());
            has_fields = true;
        }
    }

    if has_fields {
        Some(SseEvent { event_type, data })
    } else {
        None
    }
}

/// Context parameters required for real-time SSE configuration synchronization.
pub struct StreamSyncContext<'a> {
    pub endpoint: &'a str,
    pub pop_id: &'a str,
    pub auth_token: &'a str,
    pub snapshot_path: Option<&'a str>,
    pub client: &'a HttpClient,
    pub router: &'a Router,
    pub dns_resolver: &'a PinnedDnsResolver,
    pub ai_director: Option<&'a crate::ai::AiTrafficDirector>,
    pub is_ready: &'a std::sync::atomic::AtomicBool,
}

/// Long-lived real-time streaming subscriber connecting to the Control Plane SSE endpoint.
/// Asynchronously handles push notifications (sub-50ms) and applies snapshot updates immediately.
pub async fn listen_and_apply_event_stream(ctx: &StreamSyncContext<'_>) -> Result<(), SyncError> {
    validate_control_plane_endpoint(ctx.endpoint, ctx.auth_token)
        .map_err(SyncError::InvalidEndpoint)?;

    let url = format!(
        "{}/v1/edge/pops/{}/events",
        ctx.endpoint.trim_end_matches('/'),
        ctx.pop_id
    );

    let mut req_builder = ctx.client.get(&url).header("Accept", "text/event-stream");
    if !ctx.auth_token.is_empty() {
        req_builder = req_builder
            .header("Authorization", format!("Bearer {}", ctx.auth_token))
            .header("X-API-Key", ctx.auth_token);
    }

    let mut resp = req_builder
        .send()
        .await
        .map_err(|e| SyncError::NetworkError(e.to_string()))?;

    if !resp.status().is_success() {
        return Err(SyncError::BadStatus(resp.status().as_u16()));
    }

    tracing::info!(
        pop_id = %ctx.pop_id,
        "Connected to Control Plane real-time SSE configuration event stream"
    );

    let mut buffer = String::new();
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| SyncError::NetworkError(e.to_string()))?
    {
        let text = match std::str::from_utf8(&chunk) {
            Ok(t) => t,
            Err(_) => continue,
        };
        buffer.push_str(text);

        while let Some(pos) = buffer.find("\n\n") {
            let block = buffer[..pos].to_string();
            buffer = buffer[pos + 2..].to_string();

            if let Some(event) = parse_sse_block(&block) {
                match event.event_type.as_str() {
                    "connected" => {
                        tracing::info!(
                            pop_id = %ctx.pop_id,
                            payload = %event.data,
                            "Received SSE stream initialization handshake; refreshing snapshot"
                        );
                        let fetch_ctx = SnapshotFetchContext {
                            endpoint: ctx.endpoint,
                            pop_id: ctx.pop_id,
                            auth_token: ctx.auth_token,
                            if_none_match: None,
                            snapshot_path: ctx.snapshot_path,
                        };
                        if let Ok(stats) = fetch_and_apply_control_plane_snapshot_full(
                            &fetch_ctx,
                            ctx.client,
                            ctx.router,
                            ctx.dns_resolver,
                            ctx.ai_director,
                        )
                        .await
                        {
                            ctx.is_ready
                                .store(true, std::sync::atomic::Ordering::SeqCst);
                            tracing::info!(
                                pop_id = %ctx.pop_id,
                                routes = stats.routes_applied,
                                ai_providers = stats.ai_providers_applied,
                                checksum = %stats.checksum,
                                "Applied initial Control Plane snapshot via SSE handshake"
                            );
                        }
                    }
                    "config_update" => {
                        tracing::info!(
                            pop_id = %ctx.pop_id,
                            data = %event.data,
                            "Real-time config_update received! Triggering sub-50ms snapshot refresh"
                        );
                        let fetch_ctx = SnapshotFetchContext {
                            endpoint: ctx.endpoint,
                            pop_id: ctx.pop_id,
                            auth_token: ctx.auth_token,
                            if_none_match: None,
                            snapshot_path: ctx.snapshot_path,
                        };
                        match fetch_and_apply_control_plane_snapshot_full(
                            &fetch_ctx,
                            ctx.client,
                            ctx.router,
                            ctx.dns_resolver,
                            ctx.ai_director,
                        )
                        .await
                        {
                            Ok(stats) => {
                                ctx.is_ready
                                    .store(true, std::sync::atomic::Ordering::SeqCst);
                                tracing::info!(
                                    pop_id = %ctx.pop_id,
                                    routes = stats.routes_applied,
                                    ai_providers = stats.ai_providers_applied,
                                    checksum = %stats.checksum,
                                    "Atomically synchronized edge routes from real-time push event"
                                );
                            }
                            Err(e) => {
                                tracing::warn!(
                                    pop_id = %ctx.pop_id,
                                    error = %e,
                                    "Failed to apply snapshot following real-time config_update event"
                                );
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
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

        // Userinfo rejected
        let err =
            validate_control_plane_endpoint("http://admin:secret@127.0.0.1:9091", "").unwrap_err();
        assert!(err.contains("cannot contain userinfo"));

        // Query parameters rejected
        let err =
            validate_control_plane_endpoint("http://127.0.0.1:9091?env=prod", "").unwrap_err();
        assert!(err.contains("cannot contain query parameters"));

        // URL fragment rejected
        let err = validate_control_plane_endpoint("http://127.0.0.1:9091#section", "").unwrap_err();
        assert!(err.contains("cannot contain URL fragment"));

        // Invalid scheme rejected
        let err = validate_control_plane_endpoint("ftp://cp.remote.infra", "token").unwrap_err();
        assert!(err.contains("must be http or https"));
    }

    #[test]
    fn test_parse_sse_block() {
        let block1 = "event: connected\ndata: {\"status\":\"ok\"}";
        let evt1 = parse_sse_block(block1).unwrap();
        assert_eq!(evt1.event_type, "connected");
        assert_eq!(evt1.data, "{\"status\":\"ok\"}");

        let block2 = ": keepalive ping\n";
        assert!(parse_sse_block(block2).is_none());

        let block3 = "data: simple data";
        let evt3 = parse_sse_block(block3).unwrap();
        assert_eq!(evt3.event_type, "message");
        assert_eq!(evt3.data, "simple data");

        let block4 = "event: config_update\ndata: line1\ndata: line2";
        let evt4 = parse_sse_block(block4).unwrap();
        assert_eq!(evt4.event_type, "config_update");
        assert_eq!(evt4.data, "line1\nline2");

        let empty = "   \n\n  ";
        assert!(parse_sse_block(empty).is_none());
    }

    #[test]
    fn test_persist_and_load_snapshot_to_disk() {
        let temp_dir = std::env::temp_dir();
        let file_path = temp_dir.join(format!("nexusedge_test_snap_{}.json", std::process::id()));
        let file_path_str = file_path.to_str().unwrap();

        let raw_payload = r#"{"pop_id":"singapore","routes":[],"ai_providers":[]}"#;

        // Persist
        assert!(persist_snapshot_to_disk(file_path_str, raw_payload).is_ok());

        // Load and verify exact string parity
        let loaded = load_snapshot_from_disk(file_path_str).unwrap();
        assert_eq!(loaded, raw_payload);

        // Clean up
        let _ = std::fs::remove_file(&file_path);
    }
}
