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

#[tokio::test]
async fn test_ai_cost_arbitrage_and_token_savings_telemetry() {
    let mock_server = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = mock_server.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = mock_server.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let body = "{\"id\":\"chatcmpl-02\",\"choices\":[{\"message\":{\"role\":\"assistant\",\"content\":\"Arbitraged response\"}}],\"usage\":{\"prompt_tokens\":500,\"completion_tokens\":500,\"total_tokens\":1000}}";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    let providers = vec![
        AiProvider {
            id: "hyperscaler-expensive".to_string(),
            name: "Cloud Baseline".to_string(),
            endpoint: "http://127.0.0.1:9".to_string(),
            provider_type: "openai".to_string(),
            api_key: None,
            cost_per_m_tokens: 2.50, // $2.50 / 1M tokens baseline
            priority: 10,
            sovereignty_jurisdiction: None,
            failover_cooldown_secs: 10,
        },
        AiProvider {
            id: "spot-coreweave".to_string(),
            name: "CoreWeave Spot".to_string(),
            endpoint: format!("http://{}", addr),
            provider_type: "vllm".to_string(),
            api_key: None,
            cost_per_m_tokens: 0.50, // $0.50 / 1M tokens (80% cheaper)
            priority: 1,
            sovereignty_jurisdiction: None,
            failover_cooldown_secs: 10,
        },
    ];

    let director = AiTrafficDirector::new(providers);
    let client = HttpClient::builder()
        .timeout(Duration::from_millis(2000))
        .build()
        .unwrap();

    let req_payload = Bytes::from_static(
        br#"{"model": "llama-3.3-70b", "messages": [{"role": "user", "content": "Cost test"}]}"#,
    );
    let mut req_headers = hyper::HeaderMap::new();
    req_headers.insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    req_headers.insert(
        "x-nexusedge-routing-strategy",
        hyper::header::HeaderValue::from_static("cost"),
    );

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
    .expect("dispatch should succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    assert_eq!(
        resp.headers().get("x-nexusedge-provider").unwrap(),
        "spot-coreweave"
    );
    assert_eq!(
        resp.headers().get("x-nexusedge-tokens-total").unwrap(),
        "1000"
    );
    assert_eq!(
        resp.headers().get("x-nexusedge-cost-per-mtokens").unwrap(),
        "0.50"
    );
    assert_eq!(
        resp.headers()
            .get("x-nexusedge-estimated-savings-usd")
            .unwrap(),
        "0.002000"
    );

    // Verify /v1/nexusedge/ai/analytics
    let analytics_resp = dispatch_ai_request_with_failover(
        &client,
        &director,
        "/v1/nexusedge/ai/analytics",
        &Method::GET,
        &hyper::HeaderMap::new(),
        Bytes::new(),
        "127.0.0.1".parse().unwrap(),
    )
    .await
    .expect("analytics endpoint should succeed");

    assert_eq!(analytics_resp.status(), StatusCode::OK);
    let body_bytes = analytics_resp.into_body();
    let analytics: serde_json::Value =
        serde_json::from_slice(&body_bytes.into_inner().unwrap()).unwrap();

    let econ = &analytics["economics"];
    assert_eq!(econ["total_tokens_routed"], 1000);
    assert_eq!(econ["prompt_tokens"], 500);
    assert_eq!(econ["completion_tokens"], 500);
    assert_eq!(econ["cost_spent_usd"], 0.0005);
    assert_eq!(econ["cost_saved_usd"], 0.002);
    assert_eq!(econ["savings_percentage"], 80.0);
}

#[test]
fn test_ai_multi_strategy_selection() {
    use nexusedge_gateway::ai::RoutingStrategy;

    let providers = vec![
        AiProvider {
            id: "cheap-provider".to_string(),
            name: "Cheap Spot GPU".to_string(),
            endpoint: "http://cheap.internal".to_string(),
            provider_type: "vllm".to_string(),
            api_key: None,
            cost_per_m_tokens: 0.40,
            priority: 5,
            sovereignty_jurisdiction: None,
            failover_cooldown_secs: 10,
        },
        AiProvider {
            id: "fast-provider".to_string(),
            name: "Low Latency Node".to_string(),
            endpoint: "http://fast.internal".to_string(),
            provider_type: "vllm".to_string(),
            api_key: None,
            cost_per_m_tokens: 2.20,
            priority: 1,
            sovereignty_jurisdiction: None,
            failover_cooldown_secs: 10,
        },
    ];

    let director = AiTrafficDirector::new(providers);
    let candidates = director.select_candidates_with_strategy(None, RoutingStrategy::Cost);

    // Record sample TTFT on fast-provider
    candidates[1].record_success(Some(15));
    // Record sample TTFT on cheap-provider
    candidates[0].record_success(Some(180));

    // Under Cost strategy: cheap-provider ($0.40) must be first
    let cost_candidates = director.select_candidates_with_strategy(None, RoutingStrategy::Cost);
    assert_eq!(cost_candidates[0].provider.id, "cheap-provider");

    // Under Latency strategy: fast-provider (15ms) must be first
    let latency_candidates =
        director.select_candidates_with_strategy(None, RoutingStrategy::Latency);
    assert_eq!(latency_candidates[0].provider.id, "fast-provider");

    // Under Priority strategy: fast-provider (priority 1 vs 5) must be first
    let priority_candidates =
        director.select_candidates_with_strategy(None, RoutingStrategy::Priority);
    assert_eq!(priority_candidates[0].provider.id, "fast-provider");
}

#[test]
fn test_ai_protocol_bidirectional_translation() {
    use nexusedge_gateway::ai::{
        translate_anthropic_to_openai_payload, translate_anthropic_to_openai_response,
        translate_openai_to_anthropic_payload, translate_openai_to_anthropic_response,
    };

    // 1. OpenAI -> Anthropic Payload Translation
    let openai_req = br#"{
        "model": "gpt-4o",
        "messages": [
            {"role": "system", "content": "You are a cloud architect."},
            {"role": "user", "content": "How do I optimize egress cost?"}
        ],
        "max_tokens": 512,
        "temperature": 0.5
    }"#;

    let anthropic_req_bytes = translate_openai_to_anthropic_payload(openai_req).unwrap();
    let anthropic_req_val: serde_json::Value =
        serde_json::from_slice(&anthropic_req_bytes).unwrap();

    assert_eq!(anthropic_req_val["system"], "You are a cloud architect.");
    assert_eq!(anthropic_req_val["messages"].as_array().unwrap().len(), 1);
    assert_eq!(
        anthropic_req_val["messages"][0]["content"],
        "How do I optimize egress cost?"
    );
    assert_eq!(anthropic_req_val["max_tokens"], 512);

    // 2. Anthropic -> OpenAI Payload Translation
    let anthropic_req = br#"{
        "model": "claude-3-5-sonnet-20241022",
        "system": "You are a high-speed router.",
        "messages": [
            {"role": "user", "content": "Route to the nearest BDIX node."}
        ],
        "max_tokens": 1024
    }"#;

    let openai_req_bytes = translate_anthropic_to_openai_payload(anthropic_req).unwrap();
    let openai_req_val: serde_json::Value = serde_json::from_slice(&openai_req_bytes).unwrap();

    let msgs = openai_req_val["messages"].as_array().unwrap();
    assert_eq!(msgs.len(), 2);
    assert_eq!(msgs[0]["role"], "system");
    assert_eq!(msgs[0]["content"], "You are a high-speed router.");
    assert_eq!(msgs[1]["role"], "user");
    assert_eq!(msgs[1]["content"], "Route to the nearest BDIX node.");

    // 3. OpenAI -> Anthropic Response Translation
    let openai_resp = br#"{
        "id": "chatcmpl-test-99",
        "model": "llama-3.3-70b",
        "choices": [
            {
                "message": {"role": "assistant", "content": "Egress optimized by 82%."},
                "finish_reason": "stop"
            }
        ],
        "usage": {"prompt_tokens": 40, "completion_tokens": 20, "total_tokens": 60}
    }"#;

    let anthropic_resp_bytes =
        translate_openai_to_anthropic_response(openai_resp, "claude-3-5-sonnet").unwrap();
    let anthropic_resp_val: serde_json::Value =
        serde_json::from_slice(&anthropic_resp_bytes).unwrap();

    assert_eq!(anthropic_resp_val["id"], "msg_chatcmpl-test-99");
    assert_eq!(anthropic_resp_val["type"], "message");
    assert_eq!(
        anthropic_resp_val["content"][0]["text"],
        "Egress optimized by 82%."
    );
    assert_eq!(anthropic_resp_val["usage"]["input_tokens"], 40);
    assert_eq!(anthropic_resp_val["usage"]["output_tokens"], 20);

    // 4. Anthropic -> OpenAI Response Translation
    let anthropic_resp = br#"{
        "id": "msg_01X-anthropic-test",
        "type": "message",
        "role": "assistant",
        "model": "claude-3-5-sonnet-20241022",
        "content": [{"type": "text", "text": "Dhaka IX node reached in 1.2ms."}],
        "stop_reason": "end_turn",
        "usage": {"input_tokens": 50, "output_tokens": 25}
    }"#;

    let openai_resp_bytes =
        translate_anthropic_to_openai_response(anthropic_resp, "gpt-4o").unwrap();
    let openai_resp_val: serde_json::Value = serde_json::from_slice(&openai_resp_bytes).unwrap();

    assert_eq!(openai_resp_val["id"], "chatcmpl_msg_01X-anthropic-test");
    assert_eq!(openai_resp_val["object"], "chat.completion");
    assert_eq!(
        openai_resp_val["choices"][0]["message"]["content"],
        "Dhaka IX node reached in 1.2ms."
    );
    assert_eq!(openai_resp_val["usage"]["prompt_tokens"], 50);
    assert_eq!(openai_resp_val["usage"]["completion_tokens"], 25);
    assert_eq!(openai_resp_val["usage"]["total_tokens"], 75);
}

#[tokio::test]
async fn test_anthropic_client_to_vllm_cross_protocol_dispatch() {
    // Upstream vLLM server expecting OpenAI /chat/completions format
    let mock_vllm = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr_vllm = mock_vllm.local_addr().unwrap();

    tokio::spawn(async move {
        if let Ok((mut stream, _)) = mock_vllm.accept().await {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut buf = [0u8; 4096];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let req_str = String::from_utf8_lossy(&buf[..n]);

            // Upstream must receive dispatch to /chat/completions
            assert!(
                req_str.contains("POST /chat/completions"),
                "Request was not routed to /chat/completions: {}",
                req_str
            );
            // Must contain Bearer token injected from key vault
            assert!(req_str.contains("authorization: Bearer vllm-secret-key"));

            let body = r#"{"id":"vllm-cmpl-01","choices":[{"message":{"role":"assistant","content":"Response generated on CoreWeave vLLM spot."}}],"usage":{"prompt_tokens":12,"completion_tokens":8,"total_tokens":20}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
        }
    });

    let providers = vec![AiProvider {
        id: "coreweave-vllm".to_string(),
        name: "CoreWeave vLLM Llama-3.3".to_string(),
        endpoint: format!("http://{}", addr_vllm),
        provider_type: "vllm".to_string(),
        api_key: Some("vllm-secret-key".to_string()),
        cost_per_m_tokens: 0.50,
        priority: 0,
        sovereignty_jurisdiction: None,
        failover_cooldown_secs: 10,
    }];

    let director = AiTrafficDirector::new(providers);
    let client = HttpClient::builder()
        .timeout(Duration::from_millis(2000))
        .build()
        .unwrap();

    // Client sends Anthropic format to /v1/messages
    let anthropic_payload = Bytes::from_static(
        br#"{"model": "claude-3-5-sonnet", "system": "You are helpful.", "messages": [{"role": "user", "content": "Hello vLLM"}]}"#,
    );
    let mut req_headers = hyper::HeaderMap::new();
    req_headers.insert(
        "content-type",
        hyper::header::HeaderValue::from_static("application/json"),
    );
    req_headers.insert(
        "x-api-key",
        hyper::header::HeaderValue::from_static("anthropic-client-key"),
    );

    let resp = dispatch_ai_request_with_failover(
        &client,
        &director,
        "/v1/messages",
        &Method::POST,
        &req_headers,
        anthropic_payload,
        "127.0.0.1".parse().unwrap(),
    )
    .await
    .expect("cross-protocol dispatch must succeed");

    assert_eq!(resp.status(), StatusCode::OK);
    let body_bytes = http_body_util::BodyExt::collect(resp.into_body())
        .await
        .unwrap()
        .to_bytes();
    let resp_val: serde_json::Value = serde_json::from_slice(&body_bytes).unwrap();

    // Client receives translated Anthropic message schema
    assert_eq!(resp_val["type"], "message");
    assert_eq!(
        resp_val["content"][0]["text"],
        "Response generated on CoreWeave vLLM spot."
    );
    assert_eq!(resp_val["usage"]["input_tokens"], 12);
    assert_eq!(resp_val["usage"]["output_tokens"], 8);
}
