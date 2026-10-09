use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use nexusedge_gateway::dns::PinnedDnsResolver;
use nexusedge_gateway::router::Router;
use nexusedge_gateway::sync::{
    fetch_and_apply_control_plane_snapshot, validate_control_plane_endpoint, SyncError,
};
use reqwest::dns::Resolve;
use reqwest::Client as HttpClient;
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;

/// Spins up a real HTTP mock Control Plane server for testing snapshot delivery,
/// checksum verification, and tampering scenarios.
async fn spawn_mock_control_plane(
    body: String,
    custom_checksum: Option<String>,
    omit_checksum: bool,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let calculated_checksum = format!("{:x}", sha2::Sha256::digest(body.as_bytes()));
    let checksum_header = if omit_checksum {
        None
    } else {
        Some(custom_checksum.unwrap_or(calculated_checksum))
    };

    tokio::spawn(async move {
        let server_builder = ConnBuilder::new(hyper_util::rt::TokioExecutor::new());
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => {
                    break;
                }
                accept_res = listener.accept() => {
                    let (stream, _) = match accept_res {
                        Ok(conn) => conn,
                        Err(_) => break,
                    };
                    let io = TokioIo::new(stream);
                    let body_clone = body.clone();
                    let checksum_clone = checksum_header.clone();
                    let builder = server_builder.clone();

                    tokio::spawn(async move {
                        let service = service_fn(move |_req: Request<hyper::body::Incoming>| {
                            let resp_body = body_clone.clone();
                            let hdr = checksum_clone.clone();
                            async move {
                                let mut builder = Response::builder()
                                    .status(StatusCode::OK)
                                    .header("Content-Type", "application/json");
                                if let Some(ref cs) = hdr {
                                    builder = builder.header("X-Snapshot-Checksum", cs);
                                }
                                let resp = builder.body(Full::new(Bytes::from(resp_body))).unwrap();
                                Ok::<_, hyper::Error>(resp)
                            }
                        });
                        let _ = builder.serve_connection(io, service).await;
                    });
                }
            }
        }
    });

    (addr, shutdown_tx)
}

#[tokio::test]
async fn test_e2e_snapshot_sync_and_route_application() {
    let snapshot_json = r#"{
        "pop_id": "dhaka-edge-01",
        "routes": [
            {
                "host": "api.nexusedge.io",
                "origins": [
                    {
                        "address": "198.51.100.10",
                        "port": 8080,
                        "protocol": "HTTP",
                        "sni": "api.nexusedge.io"
                    }
                ],
                "path_routes": [
                    {
                        "path_prefix": "/v1/auth",
                        "priority": 100,
                        "origins": [
                            {
                                "address": "198.51.100.20",
                                "port": 8080,
                                "protocol": "HTTP",
                                "sni": "auth.nexusedge.io"
                            }
                        ]
                    }
                ]
            }
        ]
    }"#
    .to_string();

    let (cp_addr, _shutdown) = spawn_mock_control_plane(snapshot_json, None, false).await;
    let endpoint = format!("http://127.0.0.1:{}", cp_addr.port());

    let dns_resolver = Arc::new(PinnedDnsResolver::new());
    let router = Router::new(vec![], 5000);
    let client = HttpClient::builder()
        .dns_resolver(Arc::clone(&dns_resolver))
        .build()
        .unwrap();

    let stats = fetch_and_apply_control_plane_snapshot(
        &endpoint,
        "dhaka-edge-01",
        "",
        &client,
        &router,
        &dns_resolver,
    )
    .await
    .expect("Expected snapshot sync to succeed");

    assert_eq!(stats.routes_applied, 1);
    assert!(!stats.checksum.is_empty());

    // Verify root path routes to default origin
    let upstream = router
        .select_upstream_for_host_and_path("api.nexusedge.io", "/")
        .unwrap();
    assert_eq!(upstream, "http://198.51.100.10:8080");

    // Verify sub-path routes to priority path origin
    let auth_upstream = router
        .select_upstream_for_host_and_path("api.nexusedge.io", "/v1/auth/login")
        .unwrap();
    assert_eq!(auth_upstream, "http://198.51.100.20:8080");
}

#[tokio::test]
async fn test_e2e_ipv6_origin_pinning_and_dns_resolution() {
    let snapshot_json = r#"{
        "pop_id": "dhaka-edge-01",
        "routes": [
            {
                "host": "ipv6.nexusedge.io",
                "origins": [
                    {
                        "address": "2001:db8::1",
                        "port": 443,
                        "protocol": "HTTPS",
                        "sni": "secure.ipv6.origin.net"
                    }
                ]
            }
        ]
    }"#
    .to_string();

    let (cp_addr, _shutdown) = spawn_mock_control_plane(snapshot_json, None, false).await;
    let endpoint = format!("http://127.0.0.1:{}", cp_addr.port());

    let dns_resolver = Arc::new(PinnedDnsResolver::new());
    let router = Router::new(vec![], 5000);
    let client = HttpClient::builder()
        .dns_resolver(Arc::clone(&dns_resolver))
        .build()
        .unwrap();

    fetch_and_apply_control_plane_snapshot(
        &endpoint,
        "dhaka-edge-01",
        "",
        &client,
        &router,
        &dns_resolver,
    )
    .await
    .expect("Snapshot with IPv6 origin must succeed");

    // Pinned DNS resolver must contain the IPv6 mapping for SNI
    let name: reqwest::dns::Name = "secure.ipv6.origin.net".parse().unwrap();
    let mut resolved_addrs = dns_resolver.resolve(name).await.unwrap();
    let first_addr = resolved_addrs.next().expect("Must have pinned socket addr");

    assert!(first_addr.is_ipv6());
    assert_eq!(
        first_addr,
        SocketAddr::new("2001:db8::1".parse().unwrap(), 443)
    );
}

#[tokio::test]
async fn test_e2e_tampered_checksum_fails_closed() {
    let snapshot_json = r#"{
        "pop_id": "dhaka-edge-01",
        "routes": [
            {
                "host": "critical.nexusedge.io",
                "origins": [
                    {
                        "address": "198.51.100.99",
                        "port": 8080,
                        "protocol": "HTTP",
                        "sni": "critical.nexusedge.io"
                    }
                ]
            }
        ]
    }"#
    .to_string();

    // Tampered checksum: provided header does NOT match the payload SHA-256
    let bogus_checksum =
        Some("deadbeefcafebabe0123456789abcdef0123456789abcdef0123456789abcdef".to_string());
    let (cp_addr, _shutdown) = spawn_mock_control_plane(snapshot_json, bogus_checksum, false).await;
    let endpoint = format!("http://127.0.0.1:{}", cp_addr.port());

    let dns_resolver = Arc::new(PinnedDnsResolver::new());
    let router = Router::new(vec![], 5000);
    let client = HttpClient::builder()
        .dns_resolver(Arc::clone(&dns_resolver))
        .build()
        .unwrap();

    let err = fetch_and_apply_control_plane_snapshot(
        &endpoint,
        "dhaka-edge-01",
        "",
        &client,
        &router,
        &dns_resolver,
    )
    .await
    .expect_err("Tampered checksum must fail");

    match err {
        SyncError::ChecksumMismatch { expected, computed } => {
            assert!(expected.starts_with("deadbeef"));
            assert!(!computed.is_empty());
        }
        other => panic!("Unexpected error type on tamper: {:?}", other),
    }

    // Routing table must remain fail-closed
    assert!(router
        .select_upstream_for_host_and_path("critical.nexusedge.io", "/")
        .is_err());
}

#[tokio::test]
async fn test_e2e_missing_checksum_header_fails_closed() {
    let snapshot_json = r#"{
        "pop_id": "dhaka-edge-01",
        "routes": [
            {
                "host": "unauthenticated.nexusedge.io",
                "origins": [
                    {
                        "address": "198.51.100.88",
                        "port": 8080,
                        "protocol": "HTTP",
                        "sni": "unauthenticated.nexusedge.io"
                    }
                ]
            }
        ]
    }"#
    .to_string();

    // Omit mandatory X-Snapshot-Checksum header completely
    let (cp_addr, _shutdown) = spawn_mock_control_plane(snapshot_json, None, true).await;
    let endpoint = format!("http://127.0.0.1:{}", cp_addr.port());

    let dns_resolver = Arc::new(PinnedDnsResolver::new());
    let router = Router::new(vec![], 5000);
    let client = HttpClient::builder()
        .dns_resolver(Arc::clone(&dns_resolver))
        .build()
        .unwrap();

    let err = fetch_and_apply_control_plane_snapshot(
        &endpoint,
        "dhaka-edge-01",
        "",
        &client,
        &router,
        &dns_resolver,
    )
    .await
    .expect_err("Missing checksum header must fail closed");

    assert_eq!(err, SyncError::MissingChecksumHeader);

    // Routing table must remain fail-closed
    assert!(router
        .select_upstream_for_host_and_path("unauthenticated.nexusedge.io", "/")
        .is_err());
}

#[tokio::test]
async fn test_e2e_endpoint_validation_security_guards() {
    // 1. User credentials in endpoint URL must be rejected
    let err =
        validate_control_plane_endpoint("http://admin:secret@127.0.0.1:9091", "").unwrap_err();
    assert!(err.contains("cannot contain userinfo"));

    // 2. Query parameters in endpoint URL must be rejected
    let err = validate_control_plane_endpoint("http://127.0.0.1:9091?debug=true", "").unwrap_err();
    assert!(err.contains("cannot contain query parameters"));

    // 3. Fragment in endpoint URL must be rejected
    let err = validate_control_plane_endpoint("http://127.0.0.1:9091#route", "").unwrap_err();
    assert!(err.contains("cannot contain URL fragment"));

    // 4. Remote HTTP is forbidden
    let err = validate_control_plane_endpoint("http://remote.controlplane.corp:9091", "token")
        .unwrap_err();
    assert!(err.contains("HTTPS is strictly required"));

    // 5. Remote HTTPS without token is forbidden
    let err =
        validate_control_plane_endpoint("https://remote.controlplane.corp:9091", "  ").unwrap_err();
    assert!(err.contains("requires non-empty authentication token"));

    // 6. Remote HTTPS with valid token is allowed
    assert!(validate_control_plane_endpoint(
        "https://remote.controlplane.corp:9091",
        "secret-token"
    )
    .is_ok());

    // 7. Loopback HTTP is allowed for local test/dev
    assert!(validate_control_plane_endpoint("http://127.0.0.1:9091", "").is_ok());
    assert!(validate_control_plane_endpoint("http://localhost:9091", "").is_ok());
    assert!(validate_control_plane_endpoint("http://[::1]:9091", "").is_ok());
}
