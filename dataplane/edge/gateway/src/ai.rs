use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Response, StatusCode};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::warn;

/// Standard endpoints recognized as OpenAI / vLLM compatible AI inference requests.
pub const AI_CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
pub const AI_COMPLETIONS_PATH: &str = "/v1/completions";
pub const AI_EMBEDDINGS_PATH: &str = "/v1/embeddings";
pub const AI_MODELS_PATH: &str = "/v1/models";

pub const AI_ANALYTICS_PATH: &str = "/v1/nexusedge/ai/analytics";
pub const AI_METRICS_PATH: &str = "/v1/nexusedge/ai/metrics";

/// Multi-objective routing strategy supported by the AI Traffic Director.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoutingStrategy {
    #[default]
    Priority, // Tiered priority order with cost tie-break (Default baseline)
    Cost,     // Lowest spot cost per 1M tokens
    Latency,  // Lowest EWMA TTFT / response latency
    Balanced, // Multi-objective Pareto optimization (cost + TTFT)
}

impl RoutingStrategy {
    pub fn parse(s: &str) -> Self {
        match s.to_lowercase().trim() {
            "cost" | "lowest_cost" | "cheapest" | "spot" => RoutingStrategy::Cost,
            "latency" | "lowest_latency" | "fastest" | "speed" => RoutingStrategy::Latency,
            "balanced" | "optimal" | "pareto" => RoutingStrategy::Balanced,
            "priority" | "tier" => RoutingStrategy::Priority,
            _ => RoutingStrategy::Priority,
        }
    }
}

/// Returns true if the path and method correspond to an OpenAI/vLLM AI inference endpoint.
pub fn is_ai_inference_request(path: &str, method: &Method) -> bool {
    if method == Method::GET
        && (path == AI_MODELS_PATH || path == AI_METRICS_PATH || path == AI_ANALYTICS_PATH)
    {
        return true;
    }
    if method == Method::POST {
        return path == AI_CHAT_COMPLETIONS_PATH
            || path == AI_COMPLETIONS_PATH
            || path == AI_EMBEDDINGS_PATH;
    }
    false
}

/// Parsed metadata from an incoming AI inference request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiRequestMetadata {
    pub model: String,
    pub stream: bool,
    #[serde(default)]
    pub max_tokens: Option<u32>,
    #[serde(default)]
    pub temperature: Option<f32>,
    #[serde(default)]
    pub requested_jurisdiction: Option<String>,
    #[serde(default)]
    pub routing_strategy: RoutingStrategy,
}

/// Extracted candidate AI upstream compute provider.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AiProvider {
    pub id: String,
    pub name: String,
    pub endpoint: String,
    pub provider_type: String, // "openai", "azure", "coreweave", "vllm", "onprem"
    pub api_key: Option<String>,
    pub cost_per_m_tokens: f64,
    pub priority: u32,
    pub sovereignty_jurisdiction: Option<String>,
    pub failover_cooldown_secs: u64,
}

/// Runtime health state for an AI provider candidate.
#[derive(Debug)]
pub struct ProviderRuntimeState {
    pub provider: AiProvider,
    pub backoff_until: RwLock<Option<Instant>>,
    pub total_requests: AtomicU64,
    pub successful_requests: AtomicU64,
    pub rate_limited_429_count: AtomicU64,
    pub error_count: AtomicU64,
    pub failovers_triggered: AtomicU64,
    pub total_ttft_ms: AtomicU64,
    pub ttft_samples: AtomicU64,
}

impl ProviderRuntimeState {
    pub fn new(provider: AiProvider) -> Self {
        Self {
            provider,
            backoff_until: RwLock::new(None),
            total_requests: AtomicU64::new(0),
            successful_requests: AtomicU64::new(0),
            rate_limited_429_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
            failovers_triggered: AtomicU64::new(0),
            total_ttft_ms: AtomicU64::new(0),
            ttft_samples: AtomicU64::new(0),
        }
    }

    pub fn is_available(&self) -> bool {
        let backoff = self.backoff_until.read().unwrap();
        match *backoff {
            Some(until) => Instant::now() >= until,
            None => true,
        }
    }

    pub fn trigger_backoff(&self, duration: Duration) {
        let mut backoff = self.backoff_until.write().unwrap();
        *backoff = Some(Instant::now() + duration);
        self.rate_limited_429_count.fetch_add(1, Ordering::Relaxed);
        self.failovers_triggered.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_success(&self, ttft_ms: Option<u64>) {
        self.successful_requests.fetch_add(1, Ordering::Relaxed);
        if let Some(ttft) = ttft_ms {
            self.total_ttft_ms.fetch_add(ttft, Ordering::Relaxed);
            self.ttft_samples.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_error(&self) {
        self.error_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn avg_ttft_ms(&self) -> f64 {
        let samples = self.ttft_samples.load(Ordering::Relaxed);
        if samples == 0 {
            0.0
        } else {
            self.total_ttft_ms.load(Ordering::Relaxed) as f64 / samples as f64
        }
    }
}

/// Thread-safe AI Traffic Director & Routing Pool.
#[derive(Clone)]
pub struct AiTrafficDirector {
    providers: Arc<RwLock<Vec<Arc<ProviderRuntimeState>>>>,
    total_prompt_tokens: Arc<AtomicU64>,
    total_completion_tokens: Arc<AtomicU64>,
    total_tokens_routed: Arc<AtomicU64>,
    total_cost_spent_micros: Arc<AtomicU64>,
    total_cost_saved_micros: Arc<AtomicU64>,
}

impl AiTrafficDirector {
    pub fn new(providers: Vec<AiProvider>) -> Self {
        let runtime_states = providers
            .into_iter()
            .map(|p| Arc::new(ProviderRuntimeState::new(p)))
            .collect();
        Self {
            providers: Arc::new(RwLock::new(runtime_states)),
            total_prompt_tokens: Arc::new(AtomicU64::new(0)),
            total_completion_tokens: Arc::new(AtomicU64::new(0)),
            total_tokens_routed: Arc::new(AtomicU64::new(0)),
            total_cost_spent_micros: Arc::new(AtomicU64::new(0)),
            total_cost_saved_micros: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Atomically updates or replaces the provider pool from Control Plane dynamic sync.
    /// Preserves existing runtime stats and health history for providers that remain in the pool.
    pub fn update_providers(&self, new_providers: Vec<AiProvider>) {
        let mut guard = self.providers.write().unwrap();
        let existing_map: std::collections::HashMap<String, Arc<ProviderRuntimeState>> = guard
            .drain(..)
            .map(|s| (s.provider.id.clone(), s))
            .collect();

        let updated_states: Vec<Arc<ProviderRuntimeState>> = new_providers
            .into_iter()
            .map(|p| {
                if let Some(existing) = existing_map.get(&p.id) {
                    Arc::new(ProviderRuntimeState {
                        provider: p,
                        backoff_until: RwLock::new(*existing.backoff_until.read().unwrap()),
                        total_requests: AtomicU64::new(
                            existing.total_requests.load(Ordering::Relaxed),
                        ),
                        successful_requests: AtomicU64::new(
                            existing.successful_requests.load(Ordering::Relaxed),
                        ),
                        rate_limited_429_count: AtomicU64::new(
                            existing.rate_limited_429_count.load(Ordering::Relaxed),
                        ),
                        error_count: AtomicU64::new(existing.error_count.load(Ordering::Relaxed)),
                        failovers_triggered: AtomicU64::new(
                            existing.failovers_triggered.load(Ordering::Relaxed),
                        ),
                        total_ttft_ms: AtomicU64::new(
                            existing.total_ttft_ms.load(Ordering::Relaxed),
                        ),
                        ttft_samples: AtomicU64::new(existing.ttft_samples.load(Ordering::Relaxed)),
                    })
                } else {
                    Arc::new(ProviderRuntimeState::new(p))
                }
            })
            .collect();

        *guard = updated_states;
    }

    /// Returns the baseline cost per 1M tokens (the maximum cost among active providers or $2.50 hyperscaler default)
    pub fn get_baseline_cost_per_m(&self) -> f64 {
        let guard = self.providers.read().unwrap();
        guard
            .iter()
            .map(|s| s.provider.cost_per_m_tokens)
            .fold(2.50f64, f64::max)
    }

    /// Records token consumption economics, updating cumulative tokens routed, spent USD, and saved USD.
    pub fn record_token_usage(
        &self,
        prompt_tokens: u64,
        completion_tokens: u64,
        actual_cost_per_m: f64,
        baseline_cost_per_m: f64,
    ) -> (u64, f64) {
        let total = prompt_tokens.saturating_add(completion_tokens);
        self.total_prompt_tokens
            .fetch_add(prompt_tokens, Ordering::Relaxed);
        self.total_completion_tokens
            .fetch_add(completion_tokens, Ordering::Relaxed);
        self.total_tokens_routed.fetch_add(total, Ordering::Relaxed);

        let actual_micros = (actual_cost_per_m * total as f64) as u64;
        self.total_cost_spent_micros
            .fetch_add(actual_micros, Ordering::Relaxed);

        let baseline_micros = (baseline_cost_per_m * total as f64) as u64;
        let savings_micros = baseline_micros.saturating_sub(actual_micros);
        self.total_cost_saved_micros
            .fetch_add(savings_micros, Ordering::Relaxed);

        (total, savings_micros as f64 / 1_000_000.0)
    }

    /// Selects ordered candidate providers matching request constraints using default strategy.
    pub fn select_candidates(
        &self,
        requested_jurisdiction: Option<&str>,
    ) -> Vec<Arc<ProviderRuntimeState>> {
        self.select_candidates_with_strategy(requested_jurisdiction, RoutingStrategy::Priority)
    }

    /// Multi-objective candidate selection: filters strictly by data sovereignty,
    /// then ranks providers based on the requested optimization strategy.
    pub fn select_candidates_with_strategy(
        &self,
        requested_jurisdiction: Option<&str>,
        strategy: RoutingStrategy,
    ) -> Vec<Arc<ProviderRuntimeState>> {
        let guard = self.providers.read().unwrap();
        let mut candidates: Vec<Arc<ProviderRuntimeState>> = guard
            .iter()
            .filter(|state| {
                if let Some(req_jur) = requested_jurisdiction {
                    match state.provider.sovereignty_jurisdiction.as_deref() {
                        Some(jur) => jur.eq_ignore_ascii_case(req_jur),
                        None => false,
                    }
                } else {
                    true
                }
            })
            .cloned()
            .collect();

        match strategy {
            RoutingStrategy::Cost => {
                // Cost-optimized: Available first, then cheapest cost per 1M tokens, then priority, then TTFT
                candidates.sort_by(|a, b| {
                    let a_avail = a.is_available();
                    let b_avail = b.is_available();
                    if a_avail != b_avail {
                        return b_avail.cmp(&a_avail);
                    }
                    if a.provider.cost_per_m_tokens != b.provider.cost_per_m_tokens {
                        return a
                            .provider
                            .cost_per_m_tokens
                            .partial_cmp(&b.provider.cost_per_m_tokens)
                            .unwrap_or(std::cmp::Ordering::Equal);
                    }
                    if a.provider.priority != b.provider.priority {
                        return a.provider.priority.cmp(&b.provider.priority);
                    }
                    a.avg_ttft_ms()
                        .partial_cmp(&b.avg_ttft_ms())
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            RoutingStrategy::Latency => {
                // Latency-optimized: Available first, then lowest EWMA TTFT, then priority, then cost
                candidates.sort_by(|a, b| {
                    let a_avail = a.is_available();
                    let b_avail = b.is_available();
                    if a_avail != b_avail {
                        return b_avail.cmp(&a_avail);
                    }
                    let a_ttft = a.avg_ttft_ms();
                    let b_ttft = b.avg_ttft_ms();
                    if (a_ttft > 0.0 || b_ttft > 0.0) && (a_ttft - b_ttft).abs() > 0.1 {
                        if a_ttft == 0.0 {
                            return std::cmp::Ordering::Less; // Optimistic exploration probe
                        }
                        if b_ttft == 0.0 {
                            return std::cmp::Ordering::Greater;
                        }
                        return a_ttft
                            .partial_cmp(&b_ttft)
                            .unwrap_or(std::cmp::Ordering::Equal);
                    }
                    if a.provider.priority != b.provider.priority {
                        return a.provider.priority.cmp(&b.provider.priority);
                    }
                    a.provider
                        .cost_per_m_tokens
                        .partial_cmp(&b.provider.cost_per_m_tokens)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
            RoutingStrategy::Balanced => {
                // Multi-objective Pareto optimization (50% Cost, 50% TTFT)
                let max_cost = candidates
                    .iter()
                    .map(|c| c.provider.cost_per_m_tokens)
                    .fold(0.01f64, f64::max);
                let max_ttft = candidates
                    .iter()
                    .map(|c| c.avg_ttft_ms())
                    .fold(1.0f64, f64::max);

                candidates.sort_by(|a, b| {
                    let a_avail = a.is_available();
                    let b_avail = b.is_available();
                    if a_avail != b_avail {
                        return b_avail.cmp(&a_avail);
                    }
                    let a_cost_norm = a.provider.cost_per_m_tokens / max_cost;
                    let b_cost_norm = b.provider.cost_per_m_tokens / max_cost;
                    let a_ttft_norm = if a.avg_ttft_ms() == 0.0 {
                        0.5
                    } else {
                        a.avg_ttft_ms() / max_ttft
                    };
                    let b_ttft_norm = if b.avg_ttft_ms() == 0.0 {
                        0.5
                    } else {
                        b.avg_ttft_ms() / max_ttft
                    };

                    let a_score = 0.5 * a_cost_norm + 0.5 * a_ttft_norm;
                    let b_score = 0.5 * b_cost_norm + 0.5 * b_ttft_norm;

                    if (a_score - b_score).abs() > 0.01 {
                        return a_score
                            .partial_cmp(&b_score)
                            .unwrap_or(std::cmp::Ordering::Equal);
                    }
                    a.provider.priority.cmp(&b.provider.priority)
                });
            }
            RoutingStrategy::Priority => {
                // Strict priority tiers with cost tie-break
                candidates.sort_by(|a, b| {
                    let a_avail = a.is_available();
                    let b_avail = b.is_available();
                    if a_avail != b_avail {
                        return b_avail.cmp(&a_avail);
                    }
                    if a.provider.priority != b.provider.priority {
                        return a.provider.priority.cmp(&b.provider.priority);
                    }
                    a.provider
                        .cost_per_m_tokens
                        .partial_cmp(&b.provider.cost_per_m_tokens)
                        .unwrap_or(std::cmp::Ordering::Equal)
                });
            }
        }

        candidates
    }

    pub fn get_metrics_summary(&self) -> serde_json::Value {
        self.get_analytics_summary()
    }

    /// Full enterprise economics, real-time token tracking, and per-provider telemetry.
    pub fn get_analytics_summary(&self) -> serde_json::Value {
        let guard = self.providers.read().unwrap();
        let total_tokens = self.total_tokens_routed.load(Ordering::Relaxed);
        let prompt_tokens = self.total_prompt_tokens.load(Ordering::Relaxed);
        let completion_tokens = self.total_completion_tokens.load(Ordering::Relaxed);
        let spent_micros = self.total_cost_spent_micros.load(Ordering::Relaxed);
        let saved_micros = self.total_cost_saved_micros.load(Ordering::Relaxed);
        let spent_usd = spent_micros as f64 / 1_000_000.0;
        let saved_usd = saved_micros as f64 / 1_000_000.0;
        let baseline_usd = spent_usd + saved_usd;
        let savings_pct = if baseline_usd > 0.0 {
            (saved_usd / baseline_usd) * 100.0
        } else {
            0.0
        };

        let summary: Vec<serde_json::Value> = guard
            .iter()
            .map(|state| {
                serde_json::json!({
                    "id": state.provider.id,
                    "name": state.provider.name,
                    "endpoint": state.provider.endpoint,
                    "type": state.provider.provider_type,
                    "jurisdiction": state.provider.sovereignty_jurisdiction,
                    "is_available": state.is_available(),
                    "total_requests": state.total_requests.load(Ordering::Relaxed),
                    "successful_requests": state.successful_requests.load(Ordering::Relaxed),
                    "rate_limited_429": state.rate_limited_429_count.load(Ordering::Relaxed),
                    "failovers_triggered": state.failovers_triggered.load(Ordering::Relaxed),
                    "avg_ttft_ms": (state.avg_ttft_ms() * 10.0).round() / 10.0,
                    "cost_per_m_tokens": state.provider.cost_per_m_tokens,
                })
            })
            .collect();

        serde_json::json!({
            "status": "active",
            "engine": "NexusEdge Universal Compute Director",
            "timestamp": Utc::now().to_rfc3339(),
            "routing_strategies_supported": ["cost", "latency", "balanced", "priority"],
            "economics": {
                "total_tokens_routed": total_tokens,
                "prompt_tokens": prompt_tokens,
                "completion_tokens": completion_tokens,
                "cost_spent_usd": spent_usd,
                "cost_saved_usd": saved_usd,
                "savings_percentage": (savings_pct * 10.0).round() / 10.0,
            },
            "providers_count": guard.len(),
            "providers": summary,
        })
    }
}

/// Extracted token usage from an upstream inference response payload.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractedTokenUsage {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub total_tokens: u64,
}

pub fn extract_token_usage(body: &[u8]) -> Option<ExtractedTokenUsage> {
    if body.is_empty() {
        return None;
    }
    // 1. Try standard JSON payload
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(usage) = v.get("usage") {
            let p = usage
                .get("prompt_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            let c = usage
                .get("completion_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            let total = usage
                .get("total_tokens")
                .and_then(|t| t.as_u64())
                .unwrap_or_else(|| p.saturating_add(c));
            if total > 0 {
                return Some(ExtractedTokenUsage {
                    prompt_tokens: p,
                    completion_tokens: c,
                    total_tokens: total,
                });
            }
        }
    }
    // 2. Try SSE chunks if payload is streaming SSE
    if let Ok(s) = std::str::from_utf8(body) {
        if s.contains("data:") {
            for line in s.lines().rev() {
                let trimmed = line.trim();
                if let Some(json_str) = trimmed.strip_prefix("data:") {
                    let json_str = json_str.trim();
                    if json_str.is_empty() || json_str == "[DONE]" {
                        continue;
                    }
                    if let Ok(v) = serde_json::from_str::<serde_json::Value>(json_str) {
                        if let Some(usage) = v.get("usage") {
                            let p = usage
                                .get("prompt_tokens")
                                .and_then(|t| t.as_u64())
                                .unwrap_or(0);
                            let c = usage
                                .get("completion_tokens")
                                .and_then(|t| t.as_u64())
                                .unwrap_or(0);
                            let total = usage
                                .get("total_tokens")
                                .and_then(|t| t.as_u64())
                                .unwrap_or_else(|| p.saturating_add(c));
                            if total > 0 {
                                return Some(ExtractedTokenUsage {
                                    prompt_tokens: p,
                                    completion_tokens: c,
                                    total_tokens: total,
                                });
                            }
                        }
                    }
                }
            }
        }
    }
    None
}

/// Parses high-level metadata from an incoming AI inference payload.
pub fn parse_ai_request_metadata(
    body: &[u8],
    req_headers: &hyper::HeaderMap,
) -> Result<AiRequestMetadata, String> {
    let jurisdiction_header = req_headers
        .get("x-nexusedge-jurisdiction")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());

    let header_strategy = req_headers
        .get("x-nexusedge-routing-strategy")
        .and_then(|v| v.to_str().ok())
        .map(RoutingStrategy::parse);

    if body.is_empty() {
        return Ok(AiRequestMetadata {
            model: "default".to_string(),
            stream: false,
            max_tokens: None,
            temperature: None,
            requested_jurisdiction: jurisdiction_header,
            routing_strategy: header_strategy.unwrap_or_default(),
        });
    }

    let json_val: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| format!("Invalid JSON AI inference payload: {}", e))?;

    let model = json_val
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("default")
        .to_string();

    let stream = json_val
        .get("stream")
        .and_then(|s| s.as_bool())
        .unwrap_or(false);

    let max_tokens = json_val
        .get("max_tokens")
        .and_then(|t| t.as_u64())
        .map(|t| t as u32);

    let temperature = json_val
        .get("temperature")
        .and_then(|t| t.as_f64())
        .map(|t| t as f32);

    let body_strategy = json_val
        .get("routing_strategy")
        .and_then(|s| s.as_str())
        .map(RoutingStrategy::parse);

    let routing_strategy = header_strategy.or(body_strategy).unwrap_or_default();

    Ok(AiRequestMetadata {
        model,
        stream,
        max_tokens,
        temperature,
        requested_jurisdiction: jurisdiction_header,
        routing_strategy,
    })
}

/// Dispatches an AI inference request with transparent 429/503 circuit-breaking failover.
pub async fn dispatch_ai_request_with_failover(
    client: &HttpClient,
    director: &AiTrafficDirector,
    path: &str,
    method: &Method,
    req_headers: &hyper::HeaderMap,
    body_bytes: Bytes,
    client_ip: std::net::IpAddr,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let start_time = Instant::now();

    // Check for metrics or analytics endpoint
    if path == AI_METRICS_PATH || path == AI_ANALYTICS_PATH {
        let metrics_json = director.get_analytics_summary();
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("Server", "NexusEdge-AI-Director/0.1.0")
            .body(Full::new(Bytes::from(metrics_json.to_string())))
            .unwrap();
        return Ok(resp);
    }

    let metadata = match parse_ai_request_metadata(&body_bytes, req_headers) {
        Ok(meta) => meta,
        Err(err) => {
            let body = serde_json::json!({
                "error": {
                    "message": err,
                    "type": "invalid_request_error",
                    "code": "invalid_payload"
                }
            });
            let resp = Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge-AI-Director/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
    };

    let candidates = director.select_candidates_with_strategy(
        metadata.requested_jurisdiction.as_deref(),
        metadata.routing_strategy,
    );
    if candidates.is_empty() {
        warn!(
            jurisdiction = ?metadata.requested_jurisdiction,
            "No available AI compute providers satisfy sovereignty or capacity constraints"
        );
        let body = serde_json::json!({
            "error": {
                "message": "No available AI compute providers satisfy sovereignty or capacity constraints",
                "type": "insufficient_capacity_error",
                "code": "no_available_provider"
            }
        });
        let resp = Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Content-Type", "application/json")
            .header("Server", "NexusEdge-AI-Director/0.1.0")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        return Ok(resp);
    }

    let mut failover_count = 0u32;
    let mut last_error_status = StatusCode::BAD_GATEWAY;

    for candidate_state in candidates {
        candidate_state
            .total_requests
            .fetch_add(1, Ordering::Relaxed);
        let provider = &candidate_state.provider;

        // Construct target dispatch URL
        let target_url = format!(
            "{}{}",
            provider.endpoint.trim_end_matches('/'),
            if path.starts_with("/v1/") {
                &path["/v1".len()..]
            } else {
                path
            }
        );

        let mut req_builder = client.request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
            &target_url,
        );

        // Forward standard client headers, omitting hop-by-hop
        for (name, value) in req_headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if name_str == "host"
                || name_str == "authorization"
                || name_str == "connection"
                || name_str == "transfer-encoding"
            {
                continue;
            }
            if let (Ok(hn), Ok(hv)) = (
                reqwest::header::HeaderName::from_bytes(name.as_str().as_bytes()),
                reqwest::header::HeaderValue::from_bytes(value.as_bytes()),
            ) {
                req_builder = req_builder.header(hn, hv);
            }
        }

        // Dynamically inject provider credentials (Key Vault Injection)
        if let Some(ref key) = provider.api_key {
            if provider.provider_type == "azure" {
                req_builder = req_builder.header("api-key", key);
            } else {
                req_builder = req_builder.header("Authorization", format!("Bearer {}", key));
            }
        } else if let Some(client_auth) = req_headers.get("authorization") {
            // Pass through client's key if provider has no override
            if let Ok(val) = client_auth.to_str() {
                req_builder = req_builder.header("Authorization", val);
            }
        }

        // Add reverse proxy tracing headers
        req_builder = req_builder
            .header("X-Forwarded-For", client_ip.to_string())
            .header("X-NexusEdge-Selected-Provider", &provider.id)
            .header("X-NexusEdge-Model", &metadata.model);

        if !body_bytes.is_empty() {
            req_builder = req_builder.body(body_bytes.clone());
        }

        let send_start = Instant::now();
        match req_builder.send().await {
            Ok(upstream_resp) => {
                let status_code = upstream_resp.status();

                // Check for 429 Too Many Requests or 503 Overload (Trigger Transparent Failover)
                if status_code == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || status_code == reqwest::StatusCode::SERVICE_UNAVAILABLE
                {
                    warn!(
                        provider = %provider.id,
                        status = status_code.as_u16(),
                        "Upstream AI provider rate-limited or overloaded; triggering transparent failover"
                    );
                    candidate_state.trigger_backoff(Duration::from_secs(
                        provider.failover_cooldown_secs.max(5),
                    ));
                    failover_count += 1;
                    last_error_status = StatusCode::from_u16(status_code.as_u16())
                        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
                    continue; // Try next candidate!
                }

                // Successful or valid business response from upstream provider
                let ttft_ms = send_start.elapsed().as_millis() as u64;
                candidate_state.record_success(Some(ttft_ms));

                let resp_status = StatusCode::from_u16(status_code.as_u16())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

                let mut builder = Response::builder()
                    .status(resp_status)
                    .header("Server", "NexusEdge-Universal-Compute-Director/0.1.0")
                    .header("X-NexusEdge-Provider", &provider.id)
                    .header("X-NexusEdge-TTFT-Ms", ttft_ms.to_string())
                    .header("X-NexusEdge-Failover-Count", failover_count.to_string())
                    .header(
                        "X-NexusEdge-Total-Duration-Ms",
                        start_time.elapsed().as_millis().to_string(),
                    )
                    .header(
                        "X-NexusEdge-Routing-Strategy",
                        format!("{:?}", metadata.routing_strategy).to_lowercase(),
                    )
                    .header(
                        "X-NexusEdge-Cost-Per-MTokens",
                        format!("{:.2}", provider.cost_per_m_tokens),
                    );

                for (k, v) in upstream_resp.headers().iter() {
                    let k_str = k.as_str().to_lowercase();
                    if k_str == "connection"
                        || k_str == "transfer-encoding"
                        || k_str == "content-length"
                    {
                        continue;
                    }
                    if let (Ok(hn), Ok(hv)) = (
                        HeaderName::from_bytes(k.as_str().as_bytes()),
                        HeaderValue::from_bytes(v.as_bytes()),
                    ) {
                        builder = builder.header(hn, hv);
                    }
                }

                let resp_bytes = upstream_resp.bytes().await.unwrap_or_default();

                // Calculate real-time token economics & dollar savings
                let baseline_cost = director.get_baseline_cost_per_m();
                let usage_opt = extract_token_usage(&resp_bytes);
                let (tokens_total, savings_usd) = if let Some(ref usage) = usage_opt {
                    director.record_token_usage(
                        usage.prompt_tokens,
                        usage.completion_tokens,
                        provider.cost_per_m_tokens,
                        baseline_cost,
                    )
                } else {
                    (0, 0.0)
                };

                if tokens_total > 0 {
                    builder = builder
                        .header("X-NexusEdge-Tokens-Total", tokens_total.to_string())
                        .header(
                            "X-NexusEdge-Estimated-Savings-USD",
                            format!("{:.6}", savings_usd),
                        );
                }

                let resp = builder.body(Full::new(resp_bytes)).unwrap();
                return Ok(resp);
            }
            Err(e) => {
                warn!(
                    provider = %provider.id,
                    error = %e,
                    "Connection to AI compute provider failed; triggering failover"
                );
                candidate_state.record_error();
                candidate_state
                    .trigger_backoff(Duration::from_secs(provider.failover_cooldown_secs.max(5)));
                failover_count += 1;
                continue;
            }
        }
    }

    // All candidate compute nodes failed or exhausted
    let body = serde_json::json!({
        "error": {
            "message": "All upstream AI compute providers failed or rate-limited",
            "type": "provider_exhaustion_error",
            "code": "all_providers_failed",
            "failover_attempts": failover_count
        }
    });
    let resp = Response::builder()
        .status(last_error_status)
        .header("Content-Type", "application/json")
        .header("Server", "NexusEdge-AI-Director/0.1.0")
        .header("X-NexusEdge-Failover-Count", failover_count.to_string())
        .body(Full::new(Bytes::from(body.to_string())))
        .unwrap();
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_ai_inference_request() {
        assert!(is_ai_inference_request(
            "/v1/chat/completions",
            &Method::POST
        ));
        assert!(is_ai_inference_request("/v1/completions", &Method::POST));
        assert!(is_ai_inference_request("/v1/embeddings", &Method::POST));
        assert!(is_ai_inference_request("/v1/models", &Method::GET));
        assert!(is_ai_inference_request(
            "/v1/nexusedge/ai/metrics",
            &Method::GET
        ));

        assert!(!is_ai_inference_request(
            "/v1/chat/completions",
            &Method::GET
        ));
        assert!(!is_ai_inference_request("/api/users", &Method::POST));
        assert!(!is_ai_inference_request("/healthz", &Method::GET));
    }

    #[test]
    fn test_parse_ai_request_metadata() {
        let payload = br#"{"model": "llama-3.3-70b", "stream": true, "max_tokens": 1024}"#;
        let mut headers = hyper::HeaderMap::new();
        headers.insert("x-nexusedge-jurisdiction", HeaderValue::from_static("BD"));

        let meta = parse_ai_request_metadata(payload, &headers).unwrap();
        assert_eq!(meta.model, "llama-3.3-70b");
        assert!(meta.stream);
        assert_eq!(meta.max_tokens, Some(1024));
        assert_eq!(meta.requested_jurisdiction.as_deref(), Some("BD"));
    }

    #[test]
    fn test_sovereignty_and_priority_selection() {
        let providers = vec![
            AiProvider {
                id: "azure-us".to_string(),
                name: "Azure US East".to_string(),
                endpoint: "https://azure.example.com".to_string(),
                provider_type: "azure".to_string(),
                api_key: None,
                cost_per_m_tokens: 2.5,
                priority: 1,
                sovereignty_jurisdiction: Some("US".to_string()),
                failover_cooldown_secs: 10,
            },
            AiProvider {
                id: "onprem-dhaka".to_string(),
                name: "Dhaka On-Prem DGX".to_string(),
                endpoint: "http://10.0.0.5:8000".to_string(),
                provider_type: "vllm".to_string(),
                api_key: None,
                cost_per_m_tokens: 0.8,
                priority: 0,
                sovereignty_jurisdiction: Some("BD".to_string()),
                failover_cooldown_secs: 10,
            },
            AiProvider {
                id: "coreweave-spot".to_string(),
                name: "CoreWeave Spot".to_string(),
                endpoint: "https://coreweave.example.com".to_string(),
                provider_type: "coreweave".to_string(),
                api_key: None,
                cost_per_m_tokens: 0.6,
                priority: 2,
                sovereignty_jurisdiction: Some("US".to_string()),
                failover_cooldown_secs: 10,
            },
        ];

        let director = AiTrafficDirector::new(providers);

        // Test 1: Strict Bangladesh Sovereignty (NDMA 2026)
        let bd_candidates = director.select_candidates(Some("BD"));
        assert_eq!(bd_candidates.len(), 1);
        assert_eq!(bd_candidates[0].provider.id, "onprem-dhaka");

        // Test 2: Unconstrained Global Request (cheapest available / priority order)
        let global_candidates = director.select_candidates(None);
        assert_eq!(global_candidates.len(), 3);
        assert_eq!(global_candidates[0].provider.id, "onprem-dhaka"); // priority 0

        // Test 3: Circuit Breaker cooldown excludes rate-limited provider from top slot
        global_candidates[0].trigger_backoff(Duration::from_secs(60));
        let updated_candidates = director.select_candidates(None);
        assert_eq!(updated_candidates[0].provider.id, "azure-us"); // priority 1 takes over
        assert_eq!(updated_candidates[1].provider.id, "coreweave-spot"); // priority 2
        assert_eq!(updated_candidates[2].provider.id, "onprem-dhaka"); // backed off node pushed to end
    }
}
