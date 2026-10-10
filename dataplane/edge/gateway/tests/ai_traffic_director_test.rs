use bytes::Bytes;
use hyper::{Method, StatusCode};
use nexusedge_gateway::ai::{dispatch_ai_request_with_failover, AiProvider, AiTrafficDirector};
use reqwest::Client as HttpClient;
use std::time::Duration;

#[tokio::test]
async fn test_ai_traffic_director_sovereignty_and_transparent_failover() {
    // 1. Setup mock upstream servers
    // Mock Provider 1 (Primary - simulates 429 Rate Limit)
    let mock_server_429 = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_429 = mock_server_429.local_addr().unwrap();

    // Mock Provider 2 (Fallback - returns 200 OK with choices)
    let mock_server_ok = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_ok = mock_server_ok.local_addr().unwrap();

    // Spawn 429 responder
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = mock_server_429.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = "HTTP/1.1 429 Too Many Requests\r\nContent-Type: application/json\r\nContent-Length: 53\r\n\r\n{\"error\": {\"message\": \"Rate limit exceeded on Azure\"}}";
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    // Spawn 200 OK responder
    tokio::spawn(async move {
        if let Ok((mut stream, _)) = mock_server_ok.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let body = "{\"id\":\"chatcmpl-01\",\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"Hello from CoreWeave vLLM\"}}]}";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    // 2. Configure AI Providers with Priority & Cooldown
    let providers = vec![
        AiProvider {
            id: "azure-primary".to_string(),
            name: "Azure OpenAI EastUS".to_string(),
            endpoint: format!("http://{}", addr_429),
            provider_type: "azure".to_string(),
            api_key: Some("azure-secret-key".to_string()),
            cost_per_m_tokens: 2.50,
            priority: 0,
            sovereignty_jurisdiction: Some("US".to_string()),
            failover_cooldown_secs: 10,
        },
        AiProvider {
            id: "coreweave-fallback".to_string(),
            name: "CoreWeave Las Vegas".to_string(),
            endpoint: format!("http://{}", addr_ok),
            provider_type: "coreweave".to_string(),
            api_key: Some("coreweave-secret-key".to_string()),
            cost_per_m_tokens: 0.60,
            priority: 1,
            sovereignty_jurisdiction: Some("US".to_string()),
            failover_cooldown_secs: 10,
        },
    ];

    let director = AiTrafficDirector::new(providers);
    let client = HttpClient::builder()
        .timeout(Duration::from_millis(2000))
        .build()
        .unwrap();

    let req_payload = Bytes::from_static(
        br#"{"model": "llama-3.3-70b", "messages": [{"role": "user", "content": "Hello"}]}"#,
    );
    let mut req_headers = hyper::HeaderMap::new();
    req_headers.insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );

    // 3. Dispatch AI request: Azure fails with 429, CoreWeave transparently succeeds!
    let resp = dispatch_ai_request_with_failover(
        &client,
        &director,
        "/v1/chat/completions",
        &Method::POST,
        &req_headers,
        req_payload,
        "127.0.0.1".parse().unwrap(),
    )
    .await
    .expect("dispatch should succeed via fallback");

    assert_eq!(resp.status(), StatusCode::OK);
    let provider_hdr = resp
        .headers()
        .get("x-nexusedge-provider")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(provider_hdr, "coreweave-fallback");

    let failover_hdr = resp
        .headers()
        .get("x-nexusedge-failover-count")
        .unwrap()
        .to_str()
        .unwrap();
    assert_eq!(failover_hdr, "1"); // Exactly 1 transparent failover occurred!

    // Verify metrics endpoint reflection
    let metrics = director.get_metrics_summary();
    assert_eq!(metrics["providers_count"], 2);
    let p_azure = &metrics["providers"][0];
    assert_eq!(p_azure["rate_limited_429"], 1);
    assert_eq!(p_azure["failovers_triggered"], 1);
}
