use crate::dns::PinnedDnsResolver;
use crate::router::{self, Router};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::fmt;
use std::sync::{Arc, RwLock};
use std::time::Duration;

/// Maximum permissible payload budget for Control Plane dynamic configuration snapshots.
/// Enforces bounded memory allocation on edge nodes to defeat snapshot memory-bomb attacks (P2 Finding).
pub const MAX_CONTROL_PLANE_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024; // 16 MiB

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStats {
    pub routes_applied: usize,
    pub ai_providers_applied: usize,
    pub checksum: String,
    pub version: i64,
    pub modified: bool,
}

/// Declarative synchronization ACK payload dispatched to Control Plane convergence tracker.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct GatewaySyncAckPayload {
    pub gateway_id: String,
    pub pop_id: String,
    pub applied_version: i64,
    pub applied_checksum: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
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
            version: 0,
            modified: false,
        });
    }

    if !resp.status().is_success() {
        return Err(SyncError::BadStatus(resp.status().as_u16()));
    }

    let version = resp
        .headers()
        .get("x-snapshot-version")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<i64>().ok())
        .unwrap_or(1);

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
        version,
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

use std::path::PathBuf;

/// Manages asynchronous, reliable dispatch of Gateway synchronization ACKs with exponential backoff and jitter.
/// Guarantees that ACKs are never silently dropped upon control plane transient 503s or network errors,
/// and survives daemon crashes/restarts via an atomic on-disk spool.
pub struct GatewayAckManager {
    endpoint: String,
    auth_token: String,
    client: HttpClient,
    spool_path: Option<PathBuf>,
    pub pending_ack: Arc<RwLock<Option<GatewaySyncAckPayload>>>,
    notify: Arc<tokio::sync::Notify>,
}

impl GatewayAckManager {
    pub fn new(
        endpoint: String,
        auth_token: String,
        client: HttpClient,
        spool_path: Option<PathBuf>,
    ) -> Self {
        let mut initial_ack = None;
        if let Some(ref path) = spool_path {
            if path.exists() {
                if let Ok(content) = std::fs::read_to_string(path) {
                    if let Ok(recovered) = serde_json::from_str::<GatewaySyncAckPayload>(&content) {
                        tracing::info!(
                            pop_id = %recovered.pop_id,
                            gateway_id = %recovered.gateway_id,
                            version = recovered.applied_version,
                            spool_file = %path.display(),
                            "Recovered pending edge gateway ACK from durable disk spool"
                        );
                        initial_ack = Some(recovered);
                    }
                }
            }
        }

        Self {
            endpoint,
            auth_token,
            client,
            spool_path,
            pending_ack: Arc::new(RwLock::new(initial_ack)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Enqueues the latest applied state acknowledgement and wakes the retry worker.
    /// Invariant: Atomically persists ACK payload to durable disk spool before updating memory.
    /// Fail-Closed: If persisting to disk spool fails, the ACK is rejected and not staged in memory.
    pub fn submit_ack(&self, ack: GatewaySyncAckPayload) -> Result<(), std::io::Error> {
        if let Some(ref path) = self.spool_path {
            if let Some(parent) = path.parent() {
                if !parent.as_os_str().is_empty() {
                    std::fs::create_dir_all(parent)?;
                }
            }
            let serialized = serde_json::to_string_pretty(&ack)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            let tmp_path = format!("{}.tmp.{}", path.display(), std::process::id());
            {
                use std::io::Write;
                let mut file = std::fs::File::create(&tmp_path)?;
                file.write_all(serialized.as_bytes())?;
                file.sync_all()?;
            }
            std::fs::rename(&tmp_path, path)?;

            #[cfg(unix)]
            if let Some(parent) = path.parent() {
                if let Ok(dir) = std::fs::File::open(parent) {
                    let _ = dir.sync_all();
                }
            }
        }

        if let Ok(mut guard) = self.pending_ack.write() {
            *guard = Some(ack);
        } else {
            return Err(std::io::Error::other(
                "Failed to acquire pending_ack write lock",
            ));
        }
        self.notify.notify_one();
        Ok(())
    }

    /// Returns a copy of the currently pending ACK, if any.
    pub fn pending_ack(&self) -> Option<GatewaySyncAckPayload> {
        self.pending_ack.read().ok().and_then(|g| g.clone())
    }

    /// Spawns a background task that reliably delivers pending ACKs with exponential backoff and jitter.
    pub fn spawn_worker(self: Arc<Self>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let mut backoff = Duration::from_millis(500);
            const MAX_BACKOFF: Duration = Duration::from_secs(10);

            loop {
                let current_opt = self.pending_ack.read().ok().and_then(|g| g.clone());
                match current_opt {
                    Some(ack) => {
                        match send_control_plane_ack(
                            &self.endpoint,
                            &self.auth_token,
                            &self.client,
                            &ack,
                        )
                        .await
                        {
                            Ok(()) => {
                                tracing::info!(
                                    pop_id = %ack.pop_id,
                                    gateway_id = %ack.gateway_id,
                                    version = ack.applied_version,
                                    checksum = %ack.applied_checksum,
                                    "Successfully acknowledged edge gateway synchronization state to Control Plane"
                                );
                                if let Some(ref path) = self.spool_path {
                                    // Invariant: Version-matched deletion.
                                    // Only delete the on-disk spool if its contents match the ACK that was just delivered.
                                    // If a newer ACK was written to disk while this request was in flight, retain it.
                                    if let Ok(content) = std::fs::read_to_string(path) {
                                        if let Ok(spooled) =
                                            serde_json::from_str::<GatewaySyncAckPayload>(&content)
                                        {
                                            if spooled.applied_version == ack.applied_version
                                                && spooled.applied_checksum == ack.applied_checksum
                                            {
                                                let _ = std::fs::remove_file(path);
                                            } else {
                                                tracing::debug!(
                                                    spooled_version = spooled.applied_version,
                                                    delivered_version = ack.applied_version,
                                                    "Retaining newer durable ACK on disk; not deleting superseded spool"
                                                );
                                            }
                                        }
                                    }
                                }
                                if let Ok(mut guard) = self.pending_ack.write() {
                                    if let Some(ref latest) = *guard {
                                        if latest.applied_version == ack.applied_version
                                            && latest.applied_checksum == ack.applied_checksum
                                        {
                                            *guard = None;
                                        }
                                    }
                                }
                                backoff = Duration::from_millis(500);
                            }
                            Err(e) => {
                                let jitter_ms = std::time::SystemTime::now()
                                    .duration_since(std::time::UNIX_EPOCH)
                                    .map(|d| d.subsec_millis() as u64)
                                    .unwrap_or(0)
                                    % 250;
                                let sleep_duration = backoff + Duration::from_millis(jitter_ms);
                                tracing::warn!(
                                    pop_id = %ack.pop_id,
                                    error = %e,
                                    version = ack.applied_version,
                                    backoff_ms = sleep_duration.as_millis(),
                                    "Control Plane ACK submission failed; retrying with backoff and jitter"
                                );
                                tokio::time::sleep(sleep_duration).await;
                                backoff = (backoff * 2).min(MAX_BACKOFF);
                            }
                        }
                    }
                    None => {
                        self.notify.notified().await;
                    }
                }
            }
        })
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
    pub gateway_id: Option<&'a str>,
    pub ack_manager: Option<&'a GatewayAckManager>,
}

/// Sends an authenticated synchronization ACK to the Control Plane convergence tracker (/v1/edge/gateways/ack).
pub async fn send_control_plane_ack(
    endpoint: &str,
    auth_token: &str,
    client: &HttpClient,
    ack: &GatewaySyncAckPayload,
) -> Result<(), SyncError> {
    validate_control_plane_endpoint(endpoint, auth_token).map_err(SyncError::InvalidEndpoint)?;

    let url = format!("{}/v1/edge/gateways/ack", endpoint.trim_end_matches('/'));
    let mut req = client.post(&url).json(ack);
    if !auth_token.is_empty() {
        req = req.header("Authorization", format!("Bearer {}", auth_token));
    }
    let resp = req
        .send()
        .await
        .map_err(|e| SyncError::NetworkError(e.to_string()))?;

    if resp.status().is_success() {
        Ok(())
    } else {
        Err(SyncError::BadStatus(resp.status().as_u16()))
    }
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
                                version = stats.version,
                                "Applied initial Control Plane snapshot via SSE handshake"
                            );
                            if let Some(gw_id) = ctx.gateway_id {
                                let ack = GatewaySyncAckPayload {
                                    gateway_id: gw_id.to_string(),
                                    pop_id: ctx.pop_id.to_string(),
                                    applied_version: stats.version,
                                    applied_checksum: stats.checksum,
                                    status: "IN_SYNC".to_string(),
                                    error: None,
                                };
                                if let Some(mgr) = ctx.ack_manager {
                                    if let Err(e) = mgr.submit_ack(ack) {
                                        tracing::error!(
                                            pop_id = %ctx.pop_id,
                                            error = %e,
                                            "Failed to durably spool initial gateway ACK to disk"
                                        );
                                    }
                                } else {
                                    let _ = send_control_plane_ack(
                                        ctx.endpoint,
                                        ctx.auth_token,
                                        ctx.client,
                                        &ack,
                                    )
                                    .await;
                                }
                            }
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
                                    version = stats.version,
                                    "Atomically synchronized edge routes from real-time push event"
                                );
                                if let Some(gw_id) = ctx.gateway_id {
                                    let ack = GatewaySyncAckPayload {
                                        gateway_id: gw_id.to_string(),
                                        pop_id: ctx.pop_id.to_string(),
                                        applied_version: stats.version,
                                        applied_checksum: stats.checksum,
                                        status: "IN_SYNC".to_string(),
                                        error: None,
                                    };
                                    if let Some(mgr) = ctx.ack_manager {
                                        if let Err(e) = mgr.submit_ack(ack) {
                                            tracing::error!(
                                                pop_id = %ctx.pop_id,
                                                error = %e,
                                                "Failed to durably spool gateway sync ACK to disk"
                                            );
                                        }
                                    } else {
                                        let _ = send_control_plane_ack(
                                            ctx.endpoint,
                                            ctx.auth_token,
                                            ctx.client,
                                            &ack,
                                        )
                                        .await;
                                    }
                                }
                            }
                            Err(e) => {
                                tracing::warn!(
                                    pop_id = %ctx.pop_id,
                                    error = %e,
                                    "Failed to apply snapshot following real-time config_update event"
                                );
                                if let Some(gw_id) = ctx.gateway_id {
                                    let ack = GatewaySyncAckPayload {
                                        gateway_id: gw_id.to_string(),
                                        pop_id: ctx.pop_id.to_string(),
                                        applied_version: 0,
                                        applied_checksum: String::new(),
                                        status: "ERROR".to_string(),
                                        error: Some(e.to_string()),
                                    };
                                    if let Some(mgr) = ctx.ack_manager {
                                        if let Err(e) = mgr.submit_ack(ack) {
                                            tracing::error!(
                                                pop_id = %ctx.pop_id,
                                                error = %e,
                                                "Failed to durably spool error gateway ACK to disk"
                                            );
                                        }
                                    } else {
                                        let _ = send_control_plane_ack(
                                            ctx.endpoint,
                                            ctx.auth_token,
                                            ctx.client,
                                            &ack,
                                        )
                                        .await;
                                    }
                                }
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

    #[test]
    fn test_gateway_sync_ack_payload_serialization() {
        let ack = GatewaySyncAckPayload {
            gateway_id: "edge-node-dhaka-01".to_string(),
            pop_id: "dhaka".to_string(),
            applied_version: 7,
            applied_checksum: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                .to_string(),
            status: "IN_SYNC".to_string(),
            error: None,
        };

        let json_str = serde_json::to_string(&ack).expect("serialization failed");
        assert!(json_str.contains("\"gateway_id\":\"edge-node-dhaka-01\""));
        assert!(json_str.contains("\"pop_id\":\"dhaka\""));
        assert!(json_str.contains("\"applied_version\":7"));
        assert!(json_str.contains(
            "\"applied_checksum\":\"a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2\""
        ));
        assert!(json_str.contains("\"status\":\"IN_SYNC\""));
        assert!(!json_str.contains("\"error\""));

        // Error status serialization
        let err_ack = GatewaySyncAckPayload {
            gateway_id: "edge-node-dhaka-01".to_string(),
            pop_id: "dhaka".to_string(),
            applied_version: 7,
            applied_checksum: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
                .to_string(),
            status: "ERROR".to_string(),
            error: Some("checksum mismatch".to_string()),
        };
        let err_json = serde_json::to_string(&err_ack).expect("serialization failed");
        assert!(err_json.contains("\"status\":\"ERROR\""));
        assert!(err_json.contains("\"error\":\"checksum mismatch\""));
    }

    #[tokio::test]
    async fn test_gateway_ack_manager_queue_and_supersede() {
        let client = HttpClient::new();
        let mgr = GatewayAckManager::new(
            "http://127.0.0.1:9091".to_string(),
            "test-token".to_string(),
            client,
            None,
        );

        let ack1 = GatewaySyncAckPayload {
            gateway_id: "gw-test-01".to_string(),
            pop_id: "singapore".to_string(),
            applied_version: 1,
            applied_checksum: "hash-1".to_string(),
            status: "IN_SYNC".to_string(),
            error: None,
        };
        assert!(mgr.submit_ack(ack1).is_ok());

        {
            let lock = mgr.pending_ack.read().unwrap();
            assert!(lock.is_some());
            assert_eq!(lock.as_ref().unwrap().applied_version, 1);
        }

        // Newer version 2 arrives while ACK is still pending
        let ack2 = GatewaySyncAckPayload {
            gateway_id: "gw-test-01".to_string(),
            pop_id: "singapore".to_string(),
            applied_version: 2,
            applied_checksum: "hash-2".to_string(),
            status: "IN_SYNC".to_string(),
            error: None,
        };
        assert!(mgr.submit_ack(ack2).is_ok());

        {
            let lock = mgr.pending_ack.read().unwrap();
            assert!(lock.is_some());
            assert_eq!(lock.as_ref().unwrap().applied_version, 2);
            assert_eq!(lock.as_ref().unwrap().applied_checksum, "hash-2");
        }
    }

    #[tokio::test]
    async fn test_gateway_ack_manager_durable_disk_spool_restart_recovery() {
        let temp_dir = std::env::temp_dir();
        let spool_path = temp_dir.join(format!(
            "nexusedge_test_spool_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let client = HttpClient::new();

        // 1. Initial process lifetime: instantiate manager with durable spool and submit ACK
        let mgr1 = GatewayAckManager::new(
            "http://127.0.0.1:9091".to_string(),
            "token-01".to_string(),
            client.clone(),
            Some(spool_path.clone()),
        );

        let payload = GatewaySyncAckPayload {
            gateway_id: "gw-dhaka-01".to_string(),
            pop_id: "dhaka".to_string(),
            applied_version: 42,
            applied_checksum: "hash-v42-durable".to_string(),
            status: "IN_SYNC".to_string(),
            error: None,
        };
        assert!(mgr1.submit_ack(payload.clone()).is_ok());

        // Verify spool file physically exists on disk and matches payload
        assert!(spool_path.exists());
        let raw = std::fs::read_to_string(&spool_path).expect("read spool failed");
        assert!(raw.contains("\"applied_version\": 42"));
        assert!(raw.contains("\"applied_checksum\": \"hash-v42-durable\""));

        // 2. Simulate daemon crash/restart: instantiate new manager instance pointing to existing spool
        let mgr2 = GatewayAckManager::new(
            "http://127.0.0.1:9091".to_string(),
            "token-01".to_string(),
            client.clone(),
            Some(spool_path.clone()),
        );

        // Invariant: Un-ACKed payload MUST be automatically recovered from disk spool on startup
        let recovered = mgr2.pending_ack();
        assert!(recovered.is_some());
        let rec = recovered.unwrap();
        assert_eq!(rec.applied_version, 42);
        assert_eq!(rec.applied_checksum, "hash-v42-durable");
        assert_eq!(rec.pop_id, "dhaka");
        assert_eq!(rec.gateway_id, "gw-dhaka-01");

        // Clean up
        let _ = std::fs::remove_file(&spool_path);
    }

    #[tokio::test]
    async fn test_gateway_ack_manager_newer_spool_not_deleted_by_older_ack_completion() {
        let temp_dir = std::env::temp_dir();
        let spool_path = temp_dir.join(format!(
            "nexusedge_test_spool_race_{}_{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));

        let client = HttpClient::new();
        let mgr = GatewayAckManager::new(
            "http://127.0.0.1:9091".to_string(),
            "token-01".to_string(),
            client,
            Some(spool_path.clone()),
        );

        let ack_v10 = GatewaySyncAckPayload {
            gateway_id: "gw-sin-01".to_string(),
            pop_id: "singapore".to_string(),
            applied_version: 10,
            applied_checksum: "hash-v10".to_string(),
            status: "IN_SYNC".to_string(),
            error: None,
        };
        assert!(mgr.submit_ack(ack_v10.clone()).is_ok());

        // In-flight: newer version 11 arrives before v10 request completes
        let ack_v11 = GatewaySyncAckPayload {
            gateway_id: "gw-sin-01".to_string(),
            pop_id: "singapore".to_string(),
            applied_version: 11,
            applied_checksum: "hash-v11".to_string(),
            status: "IN_SYNC".to_string(),
            error: None,
        };
        assert!(mgr.submit_ack(ack_v11.clone()).is_ok());

        // Verify on-disk spool now contains version 11
        let raw = std::fs::read_to_string(&spool_path).expect("read spool failed");
        assert!(raw.contains("\"applied_version\": 11"));

        // Simulate worker completion for v10: executes version-matched deletion for ack_v10
        if let Some(ref path) = mgr.spool_path {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(spooled) = serde_json::from_str::<GatewaySyncAckPayload>(&content) {
                    if spooled.applied_version == ack_v10.applied_version
                        && spooled.applied_checksum == ack_v10.applied_checksum
                    {
                        let _ = std::fs::remove_file(path);
                    }
                }
            }
        }

        // Invariant: spool file MUST NOT be deleted because it holds newer version 11
        assert!(spool_path.exists());
        let raw_after = std::fs::read_to_string(&spool_path).expect("read spool failed");
        assert!(raw_after.contains("\"applied_version\": 11"));

        // In-memory queue must still hold version 11
        if let Ok(mut guard) = mgr.pending_ack.write() {
            if let Some(ref latest) = *guard {
                if latest.applied_version == ack_v10.applied_version
                    && latest.applied_checksum == ack_v10.applied_checksum
                {
                    *guard = None;
                }
            }
        }
        assert_eq!(mgr.pending_ack().unwrap().applied_version, 11);

        // Now simulate worker completion for v11: executes version-matched deletion for ack_v11
        if let Some(ref path) = mgr.spool_path {
            if let Ok(content) = std::fs::read_to_string(path) {
                if let Ok(spooled) = serde_json::from_str::<GatewaySyncAckPayload>(&content) {
                    if spooled.applied_version == ack_v11.applied_version
                        && spooled.applied_checksum == ack_v11.applied_checksum
                    {
                        let _ = std::fs::remove_file(path);
                    }
                }
            }
        }

        // Invariant: now that matching v11 was acknowledged, spool file is cleanly removed
        assert!(!spool_path.exists());
    }

    #[tokio::test]
    async fn test_gateway_ack_manager_submit_ack_fails_closed_on_bad_path() {
        // Point to an invalid file path that cannot be created
        let invalid_path =
            std::path::PathBuf::from("/nonexistent_forbidden_dir_12345/sub/ack.json");
        let client = HttpClient::new();
        let mgr = GatewayAckManager::new(
            "http://127.0.0.1:9091".to_string(),
            "token-01".to_string(),
            client,
            Some(invalid_path),
        );

        let ack = GatewaySyncAckPayload {
            gateway_id: "gw-err-01".to_string(),
            pop_id: "dhaka".to_string(),
            applied_version: 99,
            applied_checksum: "hash-v99".to_string(),
            status: "IN_SYNC".to_string(),
            error: None,
        };

        // Invariant: When spool write fails, submit_ack MUST return error
        let res = mgr.submit_ack(ack);
        assert!(res.is_err());

        // Invariant: In-memory pending_ack MUST NOT be updated (fails closed)
        assert!(mgr.pending_ack().is_none());
    }
}
