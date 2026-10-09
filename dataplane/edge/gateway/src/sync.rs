use crate::dns::PinnedDnsResolver;
use crate::router::{self, Router};
use reqwest::Client as HttpClient;
use sha2::Digest;
use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SyncStats {
    pub routes_applied: usize,
    pub checksum: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum SyncError {
    InvalidEndpoint(String),
    NetworkError(String),
    BadStatus(u16),
    MissingChecksumHeader,
    EmptyChecksumHeader,
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
    validate_control_plane_endpoint(endpoint, auth_token).map_err(SyncError::InvalidEndpoint)?;

    let url = format!(
        "{}/v1/edge/pops/{}/config",
        endpoint.trim_end_matches('/'),
        pop_id
    );

    let mut req_builder = client.get(&url);
    if !auth_token.is_empty() {
        req_builder = req_builder.header("Authorization", format!("Bearer {}", auth_token));
    }

    let resp = req_builder
        .send()
        .await
        .map_err(|e| SyncError::NetworkError(e.to_string()))?;

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

    let body_str = resp
        .text()
        .await
        .map_err(|e| SyncError::NetworkError(format!("Failed to read response body: {}", e)))?;

    let computed_hash = format!("{:x}", sha2::Sha256::digest(body_str.as_bytes()));
    if !expected_checksum.eq_ignore_ascii_case(&computed_hash) {
        return Err(SyncError::ChecksumMismatch {
            expected: expected_checksum,
            computed: computed_hash,
        });
    }

    let new_routes = router::parse_pop_config_routes(&body_str)
        .map_err(|e| SyncError::ParseError(e.to_string()))?;

    let routes_count = new_routes.len();
    router
        .update_routes(new_routes, vec![])
        .map_err(|e| SyncError::RouteApplyError(e.to_string()))?;

    router.sync_dns_resolver(dns_resolver);

    Ok(SyncStats {
        routes_applied: routes_count,
        checksum: computed_hash,
    })
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
}
