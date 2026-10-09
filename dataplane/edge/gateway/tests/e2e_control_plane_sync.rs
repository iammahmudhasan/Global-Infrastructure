use bytes::Bytes;
use http_body_util::Full;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use hyper_util::server::conn::auto::Builder as ConnBuilder;
use nexusedge_gateway::cache::EdgeCache;
use nexusedge_gateway::config::GatewayConfig;
use nexusedge_gateway::dns::PinnedDnsResolver;
use nexusedge_gateway::proxy::{handle_request, ProxyState};
use nexusedge_gateway::rate_limit::RateLimiter;
use nexusedge_gateway::router::{parse_pop_config_routes, Router, RouterError, RoutingError};
use nexusedge_gateway::sync::{
    fetch_and_apply_control_plane_snapshot, validate_control_plane_endpoint, SyncError,
    MAX_CONTROL_PLANE_SNAPSHOT_BYTES,
};
use nexusedge_gateway::waf::WafEngine;
use reqwest::dns::Resolve;
use reqwest::Client as HttpClient;
use sha2::Digest;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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

/// Helper that spawns a gateway HTTP server to verify readiness and liveness endpoints.
async fn spawn_mock_gateway(
    state: Arc<ProxyState>,
) -> (SocketAddr, tokio::sync::oneshot::Sender<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let server_builder = ConnBuilder::new(hyper_util::rt::TokioExecutor::new());
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept_res = listener.accept() => {
                    let (stream, remote_addr) = match accept_res {
                        Ok(conn) => conn,
                        Err(_) => break,
                    };
                    let io = TokioIo::new(stream);
                    let state_clone = Arc::clone(&state);
                    let builder = server_builder.clone();

                    tokio::spawn(async move {
                        let service = service_fn(move |req| {
                            let s = Arc::clone(&state_clone);
                            async move { handle_request(req, remote_addr.ip(), s).await }
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
                        "address": "93.184.216.34",
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
                                "address": "93.184.216.35",
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
    assert_eq!(upstream, "http://93.184.216.34:8080");

    // Verify sub-path routes to priority path origin
    let auth_upstream = router
        .select_upstream_for_host_and_path("api.nexusedge.io", "/v1/auth/login")
        .unwrap();
    assert_eq!(auth_upstream, "http://93.184.216.35:8080");
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
                        "address": "2606:2800:220:1:248:1893:25c8:1946",
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
        SocketAddr::new("2606:2800:220:1:248:1893:25c8:1946".parse().unwrap(), 443)
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
                        "address": "93.184.216.34",
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
                        "address": "93.184.216.34",
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

#[tokio::test]
async fn test_e2e_cross_service_contract_path_isolation() {
    let fixture_path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../../tests/fixtures/pop-config-sync.json"
    );
    let content = std::fs::read_to_string(fixture_path).expect("Must read golden fixture");

    let parsed_routes = parse_pop_config_routes(&content).expect("Must parse golden fixture");
    assert_eq!(parsed_routes.len(), 1);

    let router = Router::new_multi_tenant(parsed_routes, vec![], 5000)
        .expect("Must build multi-tenant router from golden fixture");

    // 1. /api/users routes to api origin
    let api_target = router
        .select_upstream_for_host_and_path("customer.example.com", "/api/users")
        .expect("Must route to API origin");
    assert_eq!(api_target, "https://api-origin.example:443");

    // 2. /admin/dashboard routes to admin origin
    let admin_target = router
        .select_upstream_for_host_and_path("customer.example.com", "/admin/dashboard")
        .expect("Must route to Admin origin");
    assert_eq!(admin_target, "https://admin-origin.example:443");

    // 3. /unknown has no matching path route -> must fail closed with NoMatchingPath (HTTP 404)
    let unknown_err = router
        .select_upstream_for_host_and_path("customer.example.com", "/unknown")
        .expect_err("/unknown must return NoMatchingPath");
    assert!(
        matches!(unknown_err, RoutingError::NoMatchingPath { ref host, ref path } if host == "customer.example.com" && path == "/unknown")
    );

    // 4. / has no matching route configured -> must fail closed with NoMatchingPath
    let root_err = router
        .select_upstream_for_host_and_path("customer.example.com", "/")
        .expect_err("/ must return NoMatchingPath when no root route configured");
    assert!(
        matches!(root_err, RoutingError::NoMatchingPath { ref host, ref path } if host == "customer.example.com" && path == "/")
    );

    // 5. /administrator must NOT match /admin/ prefix
    let prefix_mismatch_err = router
        .select_upstream_for_host_and_path("customer.example.com", "/administrator")
        .expect_err("/administrator must not match /admin/");
    assert!(matches!(
        prefix_mismatch_err,
        RoutingError::NoMatchingPath { .. }
    ));
}

#[tokio::test]
async fn test_e2e_ssrf_sni_bypass_rejection() {
    // 1. Public IPv4 + valid SNI -> Accept
    let public_v4_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "93.184.216.34",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.example.com"
            }]
        }]
    }"#;
    assert!(parse_pop_config_routes(public_v4_json).is_ok());

    // 2. Public IPv6 + valid SNI -> Accept
    let public_v6_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "2606:2800:220:1:248:1893:25c8:1946",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.example.com"
            }]
        }]
    }"#;
    assert!(parse_pop_config_routes(public_v6_json).is_ok());

    // 3. Documentation IPv4 TEST-NET-1 (192.0.2.1) -> Reject
    let testnet1_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "192.0.2.1",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.example.com"
            }]
        }]
    }"#;
    assert!(matches!(
        parse_pop_config_routes(testnet1_json).unwrap_err(),
        RouterError::UnsafeTargetUrl { .. }
    ));

    // 4. Documentation IPv4 TEST-NET-2 (198.51.100.1) -> Reject
    let testnet2_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "198.51.100.1",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.example.com"
            }]
        }]
    }"#;
    assert!(matches!(
        parse_pop_config_routes(testnet2_json).unwrap_err(),
        RouterError::UnsafeTargetUrl { .. }
    ));

    // 5. Documentation IPv4 TEST-NET-3 (203.0.113.1) -> Reject
    let testnet3_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "203.0.113.1",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.example.com"
            }]
        }]
    }"#;
    assert!(matches!(
        parse_pop_config_routes(testnet3_json).unwrap_err(),
        RouterError::UnsafeTargetUrl { .. }
    ));

    // 6. Documentation IPv6 (2001:db8::1) -> Reject
    let doc_v6_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "2001:db8::1",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.example.com"
            }]
        }]
    }"#;
    assert!(matches!(
        parse_pop_config_routes(doc_v6_json).unwrap_err(),
        RouterError::UnsafeTargetUrl { .. }
    ));

    // 7. IPv4-mapped IPv6 Loopback (::ffff:127.0.0.1) -> Reject
    let mapped_loopback_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "::ffff:127.0.0.1",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.customer.com"
            }]
        }]
    }"#;
    assert!(matches!(
        parse_pop_config_routes(mapped_loopback_json).unwrap_err(),
        RouterError::UnsafeTargetUrl { .. }
    ));

    // 8. IPv4-mapped IPv6 RFC 1918 Private (::ffff:10.0.0.1) -> Reject
    let mapped_private_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "::ffff:10.0.0.1",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.customer.com"
            }]
        }]
    }"#;
    assert!(matches!(
        parse_pop_config_routes(mapped_private_json).unwrap_err(),
        RouterError::UnsafeTargetUrl { .. }
    ));

    // 9. IPv4-mapped IPv6 Cloud Metadata (::ffff:169.254.169.254) -> Reject
    let mapped_metadata_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "::ffff:169.254.169.254",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.customer.com"
            }]
        }]
    }"#;
    assert!(matches!(
        parse_pop_config_routes(mapped_metadata_json).unwrap_err(),
        RouterError::UnsafeTargetUrl { .. }
    ));

    // 10. IPv4-mapped IPv6 TEST-NET (::ffff:198.51.100.5) -> Reject
    let mapped_testnet_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "::ffff:198.51.100.5",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.customer.com"
            }]
        }]
    }"#;
    assert!(matches!(
        parse_pop_config_routes(mapped_testnet_json).unwrap_err(),
        RouterError::UnsafeTargetUrl { .. }
    ));

    // 11. 10.0.0.8 + public-looking SNI -> Reject
    let private_v4_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "10.0.0.8",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.customer.com"
            }]
        }]
    }"#;
    let err = parse_pop_config_routes(private_v4_json).unwrap_err();
    assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

    // 12. 127.0.0.1 + SNI -> Reject
    let loopback_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "127.0.0.1",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.customer.com"
            }]
        }]
    }"#;
    let err = parse_pop_config_routes(loopback_json).unwrap_err();
    assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

    // 13. 169.254.169.254 + SNI -> Reject
    let metadata_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "169.254.169.254",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.customer.com"
            }]
        }]
    }"#;
    let err = parse_pop_config_routes(metadata_json).unwrap_err();
    assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

    // 14. IPv6 fc00::/7 ULA + SNI -> Reject
    let ula_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "fc00::1",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.customer.com"
            }]
        }]
    }"#;
    let err = parse_pop_config_routes(ula_json).unwrap_err();
    assert!(matches!(err, RouterError::UnsafeTargetUrl { .. }));

    // 15. Hostname address without pinned IP -> Reject
    let unpinned_json = r#"{
        "routes": [{
            "host": "test.example.com",
            "origins": [{
                "address": "unpinned-origin.customer.com",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "origin.customer.com"
            }]
        }]
    }"#;
    let err = parse_pop_config_routes(unpinned_json).unwrap_err();
    assert!(matches!(err, RouterError::InvalidPayload(..)));
}

#[tokio::test]
async fn test_e2e_atomic_dns_and_route_consistency() {
    let initial_json = r#"{
        "routes": [{
            "host": "tenant-initial.com",
            "origins": [{
                "address": "93.184.216.34",
                "port": 443,
                "protocol": "HTTPS",
                "sni": "initial-origin.tenant.com"
            }]
        }]
    }"#;
    let initial_routes = parse_pop_config_routes(initial_json).unwrap();
    let dns_resolver = Arc::new(PinnedDnsResolver::new());
    let router = Router::new(vec![], 5000);

    router
        .update_routes_with_dns(initial_routes, vec![], &dns_resolver)
        .expect("Initial route setup must succeed");

    assert_eq!(
        router
            .select_upstream_for_host_and_path("tenant-initial.com", "/")
            .unwrap(),
        "https://initial-origin.tenant.com:443"
    );

    // Candidate payload with an invalid/duplicate host
    let mut bad_candidate = parse_pop_config_routes(initial_json).unwrap();
    let duplicate = bad_candidate[0].clone();
    bad_candidate.push(duplicate);

    // update_routes_with_dns must fail validation
    let update_err = router
        .update_routes_with_dns(bad_candidate, vec![], &dns_resolver)
        .expect_err("Duplicate host candidate must fail validation");
    assert!(matches!(update_err, RouterError::DuplicateHost(..)));

    // Active routing table and DNS resolver must remain 100% intact (last known good)
    assert_eq!(
        router
            .select_upstream_for_host_and_path("tenant-initial.com", "/")
            .unwrap(),
        "https://initial-origin.tenant.com:443"
    );
    let resolved_name: reqwest::dns::Name = "initial-origin.tenant.com".parse().unwrap();
    let mut resolved_addrs = dns_resolver.resolve(resolved_name).await.unwrap();
    assert_eq!(
        resolved_addrs.next().unwrap(),
        SocketAddr::new("93.184.216.34".parse().unwrap(), 443)
    );
}

#[tokio::test]
async fn test_e2e_snapshot_content_length_budget_exceeded() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let server_builder = ConnBuilder::new(hyper_util::rt::TokioExecutor::new());
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept_res = listener.accept() => {
                    let (stream, _) = match accept_res {
                        Ok(conn) => conn,
                        Err(_) => break,
                    };
                    let io = TokioIo::new(stream);
                    let builder = server_builder.clone();
                    tokio::spawn(async move {
                        let service = service_fn(|_req: Request<hyper::body::Incoming>| async {
                            // Produce payload of 16 MiB + 1024 bytes so Full sets Content-Length matching body length
                            let big_body = vec![b' '; MAX_CONTROL_PLANE_SNAPSHOT_BYTES + 1024];
                            let resp = Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "application/json")
                                .header("X-Snapshot-Checksum", "deadbeef")
                                .body(Full::new(Bytes::from(big_body)))
                                .unwrap();
                            Ok::<_, hyper::Error>(resp)
                        });
                        let _ = builder.serve_connection(io, service).await;
                    });
                }
            }
        }
    });

    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let dns_resolver = Arc::new(PinnedDnsResolver::new());
    let router = Router::new(vec![], 5000);
    let client = HttpClient::new();

    let err = fetch_and_apply_control_plane_snapshot(
        &endpoint,
        "dhaka-edge-01",
        "",
        &client,
        &router,
        &dns_resolver,
    )
    .await
    .expect_err("Oversized content-length must fail immediately");

    match err {
        SyncError::SnapshotTooLarge { size, limit } => {
            assert_eq!(size, MAX_CONTROL_PLANE_SNAPSHOT_BYTES + 1024);
            assert_eq!(limit, MAX_CONTROL_PLANE_SNAPSHOT_BYTES);
        }
        other => panic!("Expected SnapshotTooLarge, got: {:?}", other),
    }

    let _ = shutdown_tx.send(());
}

struct ChunkedBody {
    chunks: std::collections::VecDeque<Bytes>,
}

impl hyper::body::Body for ChunkedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        if let Some(chunk) = self.chunks.pop_front() {
            std::task::Poll::Ready(Some(Ok(hyper::body::Frame::data(chunk))))
        } else {
            std::task::Poll::Ready(None)
        }
    }

    fn is_end_stream(&self) -> bool {
        self.chunks.is_empty()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        let mut hint = hyper::body::SizeHint::new();
        hint.set_lower(0);
        hint
    }
}

#[tokio::test]
async fn test_e2e_snapshot_streaming_chunk_overflow() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (shutdown_tx, mut shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    tokio::spawn(async move {
        let server_builder = ConnBuilder::new(hyper_util::rt::TokioExecutor::new());
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                accept_res = listener.accept() => {
                    let (stream, _) = match accept_res {
                        Ok(conn) => conn,
                        Err(_) => break,
                    };
                    let io = TokioIo::new(stream);
                    let builder = server_builder.clone();
                    tokio::spawn(async move {
                        let service = service_fn(|_req: Request<hyper::body::Incoming>| async {
                            // Produce 17 chunks of 1 MiB each with ChunkedBody (no Content-Length header)
                            let mut chunks = std::collections::VecDeque::new();
                            for _ in 0..17 {
                                chunks.push_back(Bytes::from(vec![b' '; 1024 * 1024]));
                            }
                            let body = ChunkedBody { chunks };
                            let resp = Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "application/json")
                                .header("X-Snapshot-Checksum", "deadbeef")
                                .body(body)
                                .unwrap();
                            Ok::<_, hyper::Error>(resp)
                        });
                        let _ = builder.serve_connection(io, service).await;
                    });
                }
            }
        }
    });

    let endpoint = format!("http://127.0.0.1:{}", addr.port());
    let dns_resolver = Arc::new(PinnedDnsResolver::new());
    let router = Router::new(vec![], 5000);
    let client = HttpClient::new();

    let err = fetch_and_apply_control_plane_snapshot(
        &endpoint,
        "dhaka-edge-01",
        "",
        &client,
        &router,
        &dns_resolver,
    )
    .await
    .expect_err("Streaming snapshot exceeding budget must be rejected");

    match err {
        SyncError::SnapshotTooLarge { size, limit } => {
            assert!(size > MAX_CONTROL_PLANE_SNAPSHOT_BYTES);
            assert_eq!(limit, MAX_CONTROL_PLANE_SNAPSHOT_BYTES);
        }
        other => panic!("Expected SnapshotTooLarge, got: {:?}", other),
    }

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_e2e_readiness_and_liveness_probes() {
    let config = GatewayConfig::default();
    let is_ready = Arc::new(AtomicBool::new(false));
    let state = Arc::new(ProxyState {
        rate_limiter: RateLimiter::new(
            config.rate_limit.enabled,
            config.rate_limit.requests_per_second,
            config.rate_limit.burst_capacity,
        ),
        waf: WafEngine::new(&config.waf),
        cache: EdgeCache::new(
            config.cache.enabled,
            config.cache.default_ttl_seconds,
            config.cache.max_entries,
            config.cache.max_bytes,
        ),
        router: Router::new(vec![], 5000),
        http_client: HttpClient::new(),
        inflight_buffer_semaphore: Arc::new(tokio::sync::Semaphore::new(100)),
        aggregate_buffered_bytes: Arc::new(AtomicUsize::new(0)),
        aggregate_buffered_request_bytes: Arc::new(AtomicUsize::new(0)),
        is_ready: Arc::clone(&is_ready),
        config,
    });

    let (addr, shutdown_tx) = spawn_mock_gateway(state).await;
    let client = HttpClient::new();

    // 1. /healthz must always return 200 OK (liveness probe)
    let health_resp = client
        .get(format!("http://127.0.0.1:{}/healthz", addr.port()))
        .send()
        .await
        .expect("Healthz probe request must succeed");
    assert_eq!(health_resp.status(), reqwest::StatusCode::OK);

    // 2. /ready must return 503 SERVICE_UNAVAILABLE when not ready
    let unready_resp = client
        .get(format!("http://127.0.0.1:{}/ready", addr.port()))
        .send()
        .await
        .expect("Ready probe request must succeed");
    assert_eq!(
        unready_resp.status(),
        reqwest::StatusCode::SERVICE_UNAVAILABLE
    );

    // 3. Flip readiness flag to true (simulating successful initial control plane sync)
    is_ready.store(true, Ordering::Release);

    // 4. /ready must now return 200 OK
    let ready_resp = client
        .get(format!("http://127.0.0.1:{}/ready", addr.port()))
        .send()
        .await
        .expect("Ready probe request must succeed");
    assert_eq!(ready_resp.status(), reqwest::StatusCode::OK);

    let _ = shutdown_tx.send(());
}

#[tokio::test]
async fn test_e2e_strict_dns_fails_closed_on_unpinned_host() {
    let resolver = PinnedDnsResolver::new();
    let mut mappings = std::collections::HashMap::new();
    mappings.insert(
        "pinned.example.com".to_string(),
        vec!["93.184.216.34:443".parse().unwrap()],
    );
    resolver.set_all(mappings);

    // Pinned hostname resolves
    let host: reqwest::dns::Name = "pinned.example.com".parse().unwrap();
    let mut resolved = resolver
        .resolve(host)
        .await
        .expect("Pinned host must resolve");
    assert_eq!(resolved.next(), Some("93.184.216.34:443".parse().unwrap()));

    // Unpinned hostname fails closed with PermissionDenied (never falls back to ambient DNS)
    let unpinned: reqwest::dns::Name = "unpinned.malicious.internal".parse().unwrap();
    let res = resolver.resolve(unpinned).await;
    assert!(res.is_err(), "Unpinned host must fail closed");
    let err = res.err().unwrap();
    assert!(err.to_string().contains("Strict DNS"));
}
