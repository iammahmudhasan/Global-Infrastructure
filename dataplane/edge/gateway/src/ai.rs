use bytes::Bytes;
use chrono::Utc;
use http_body_util::Full;
use hyper::header::{HeaderName, HeaderValue};
use hyper::{Method, Response, StatusCode};
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use tracing::warn;

/// Authenticated client tenant identity and project scope for AI inference requests (Rule 1, 54, 55).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AiAuthIdentity {
    pub tenant_id: String,
    pub default_project_id: String,
    pub allowed_projects: HashSet<String>,
    pub allowed_jurisdictions: HashSet<String>,
    pub scopes: HashSet<String>,
}

impl Default for AiAuthIdentity {
    fn default() -> Self {
        let mut allowed_projects = HashSet::new();
        allowed_projects.insert("*".to_string());
        let mut allowed_jurisdictions = HashSet::new();
        allowed_jurisdictions.insert("*".to_string());
        let mut scopes = HashSet::new();
        scopes.insert("*".to_string());

        Self {
            tenant_id: "tenant-default".to_string(),
            default_project_id: "proj-default".to_string(),
            allowed_projects,
            allowed_jurisdictions,
            scopes,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AiAuthError {
    MissingCredentials,
    InvalidOrRevokedKey,
}

/// Dynamic tenant and client authentication registry for the AI Gateway (Rule 18, 54, 55).
/// Determines whether the gateway is running in an explicit development or testing mode.
pub fn is_dev_mode() -> bool {
    if let Ok(dev) = std::env::var("NEXUSEDGE_DEV_MODE") {
        let d = dev.trim().to_ascii_lowercase();
        if d == "true" || d == "1" || d == "yes" {
            return true;
        }
    }
    if let Ok(env) = std::env::var("NEXUSEDGE_ENV") {
        let e = env.trim().to_ascii_lowercase();
        if e == "development" || e == "dev" || e == "test" {
            return true;
        }
    }
    false
}

#[derive(Clone, Debug)]
pub struct AiGatewayAuthRegistry {
    identities: Arc<RwLock<HashMap<String, AiAuthIdentity>>>,
}

impl Default for AiGatewayAuthRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl AiGatewayAuthRegistry {
    /// Creates an empty auth registry with zero registered keys.
    pub fn new_empty() -> Self {
        Self {
            identities: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Creates an auth registry pre-populated with standard dev/testing fixture keys.
    /// Strictly intended for local test suites and unit testing.
    pub fn new_development_fixtures() -> Self {
        let mut map = HashMap::new();
        let default_identity = AiAuthIdentity::default();
        map.insert("dev-fixture-key-01".to_string(), default_identity.clone());
        map.insert("test-client-token".to_string(), default_identity.clone());
        map.insert("anthropic-client-key".to_string(), default_identity.clone());
        map.insert("test-key".to_string(), default_identity);
        Self {
            identities: Arc::new(RwLock::new(map)),
        }
    }

    /// Creates an auth registry strictly for production environments.
    /// Fails closed if NEXUSEDGE_AI_API_KEYS is missing, empty, or contains invalid policies.
    /// Never loads development fixture keys.
    pub fn new_production() -> Result<Self, String> {
        let env_keys = std::env::var("NEXUSEDGE_AI_API_KEYS").map_err(|_| {
            "NEXUSEDGE_AI_API_KEYS environment variable is required in production mode".to_string()
        })?;

        let trimmed = env_keys.trim();
        if trimmed.is_empty() {
            return Err("NEXUSEDGE_AI_API_KEYS cannot be empty in production mode".to_string());
        }

        let mut map = HashMap::new();
        for entry in trimmed.split(';') {
            let entry_trimmed = entry.trim();
            if entry_trimmed.is_empty() {
                continue;
            }
            let parts: Vec<&str> = entry_trimmed.split(':').collect();
            if parts.len() < 3 {
                return Err(format!(
                    "Invalid AI API key definition '{}': format must be key:tenant_id:default_project_id[:allowed_projs_csv][:scopes_csv][:jurisdictions_csv]",
                    entry_trimmed
                ));
            }

            let key = parts[0].trim().to_string();
            let tenant = parts[1].trim().to_string();
            let def_proj = parts[2].trim().to_string();

            if key.is_empty() || tenant.is_empty() || def_proj.is_empty() {
                return Err(format!(
                    "Invalid AI key, tenant, or default_project in '{}'",
                    entry_trimmed
                ));
            }

            // 1. Projects Allowlist
            let mut allowed_projs = HashSet::new();
            if parts.len() >= 4 && !parts[3].trim().is_empty() {
                for p in parts[3].split(',') {
                    let pt = p.trim().to_string();
                    if !pt.is_empty() {
                        allowed_projs.insert(pt);
                    }
                }
            } else {
                allowed_projs.insert(def_proj.clone());
            }

            // 2. Scopes Allowlist (e.g. "inference", "analytics", or explicit "*")
            let mut scopes = HashSet::new();
            if parts.len() >= 5 && !parts[4].trim().is_empty() {
                for s in parts[4].split(',') {
                    let st = s.trim().to_ascii_lowercase();
                    if !st.is_empty() {
                        scopes.insert(st);
                    }
                }
            } else {
                // In production, default scope is "inference" only; wildcard "*" must be explicitly configured
                scopes.insert("inference".to_string());
            }

            // 3. Jurisdictions Allowlist (e.g. "BD", "EU", "SG", or explicit "*")
            let mut allowed_jurisdictions = HashSet::new();
            if parts.len() >= 6 && !parts[5].trim().is_empty() {
                for j in parts[5].split(',') {
                    let jt = j.trim().to_ascii_uppercase();
                    if !jt.is_empty() {
                        allowed_jurisdictions.insert(jt);
                    }
                }
            } else {
                // In production, default jurisdiction is GLOBAL only; wildcard "*" must be explicitly configured
                allowed_jurisdictions.insert("GLOBAL".to_string());
            }

            map.insert(
                key,
                AiAuthIdentity {
                    tenant_id: tenant,
                    default_project_id: def_proj,
                    allowed_projects: allowed_projs,
                    allowed_jurisdictions,
                    scopes,
                },
            );
        }

        if map.is_empty() {
            return Err("No valid AI API keys were loaded from NEXUSEDGE_AI_API_KEYS".to_string());
        }

        Ok(Self {
            identities: Arc::new(RwLock::new(map)),
        })
    }

    /// Automatically selects production or development auth registry based on environment.
    pub fn new() -> Self {
        if is_dev_mode() {
            let registry = Self::new_development_fixtures();
            // In dev mode, optionally merge keys from NEXUSEDGE_AI_API_KEYS
            if let Ok(env_keys) = std::env::var("NEXUSEDGE_AI_API_KEYS") {
                for entry in env_keys.split(';') {
                    let parts: Vec<&str> = entry.trim().split(':').collect();
                    if parts.len() >= 3 {
                        let key = parts[0].trim().to_string();
                        let tenant = parts[1].trim().to_string();
                        let def_proj = parts[2].trim().to_string();
                        let mut allowed_projs = HashSet::new();
                        if parts.len() >= 4 && !parts[3].trim().is_empty() {
                            for p in parts[3].split(',') {
                                let pt = p.trim().to_string();
                                if !pt.is_empty() {
                                    allowed_projs.insert(pt);
                                }
                            }
                        } else {
                            allowed_projs.insert(def_proj.clone());
                        }

                        let mut scopes = HashSet::new();
                        if parts.len() >= 5 && !parts[4].trim().is_empty() {
                            for s in parts[4].split(',') {
                                let st = s.trim().to_ascii_lowercase();
                                if !st.is_empty() {
                                    scopes.insert(st);
                                }
                            }
                        } else {
                            scopes.insert("*".to_string());
                        }

                        let mut allowed_jurisdictions = HashSet::new();
                        if parts.len() >= 6 && !parts[5].trim().is_empty() {
                            for j in parts[5].split(',') {
                                let jt = j.trim().to_ascii_uppercase();
                                if !jt.is_empty() {
                                    allowed_jurisdictions.insert(jt);
                                }
                            }
                        } else {
                            allowed_jurisdictions.insert("*".to_string());
                        }

                        registry.register_key(
                            &key,
                            AiAuthIdentity {
                                tenant_id: tenant,
                                default_project_id: def_proj,
                                allowed_projects: allowed_projs,
                                allowed_jurisdictions,
                                scopes,
                            },
                        );
                    }
                }
            }
            registry
        } else {
            // Production mode: strict fail-closed
            match Self::new_production() {
                Ok(reg) => {
                    tracing::info!(
                        "Initialized production AI Gateway auth registry from environment"
                    );
                    reg
                }
                Err(err) => {
                    tracing::error!(
                        "FATAL/FAIL-CLOSED: Failed to initialize production AI Gateway auth registry: {}. Gateway will reject all incoming inference requests.",
                        err
                    );
                    Self::new_empty()
                }
            }
        }
    }

    pub fn register_key(&self, key: &str, identity: AiAuthIdentity) {
        let mut guard = self.identities.write().unwrap();
        guard.insert(key.trim().to_string(), identity);
    }

    pub fn revoke_key(&self, key: &str) {
        let mut guard = self.identities.write().unwrap();
        guard.remove(key.trim());
    }

    pub fn authenticate(&self, headers: &hyper::HeaderMap) -> Result<AiAuthIdentity, AiAuthError> {
        let token = Self::extract_credential(headers)?;
        let guard = self.identities.read().unwrap();
        guard
            .get(&token)
            .cloned()
            .ok_or(AiAuthError::InvalidOrRevokedKey)
    }

    fn extract_credential(headers: &hyper::HeaderMap) -> Result<String, AiAuthError> {
        if let Some(auth_hdr) = headers.get("authorization") {
            if let Ok(auth_str) = auth_hdr.to_str() {
                let trimmed = auth_str.trim();
                if trimmed.is_empty() {
                    return Err(AiAuthError::MissingCredentials);
                }
                if let Some(token) = trimmed.strip_prefix("Bearer ") {
                    let t = token.trim();
                    if !t.is_empty() {
                        return Ok(t.to_string());
                    }
                } else if !trimmed.is_empty() {
                    return Ok(trimmed.to_string());
                }
            }
        }

        if let Some(api_key_hdr) = headers.get("x-api-key") {
            if let Ok(key_str) = api_key_hdr.to_str() {
                let t = key_str.trim();
                if !t.is_empty() {
                    return Ok(t.to_string());
                }
            }
        }

        Err(AiAuthError::MissingCredentials)
    }
}

/// Standard endpoints recognized as OpenAI / Anthropic / vLLM compatible AI inference requests.
pub const AI_CHAT_COMPLETIONS_PATH: &str = "/v1/chat/completions";
pub const AI_COMPLETIONS_PATH: &str = "/v1/completions";
pub const AI_EMBEDDINGS_PATH: &str = "/v1/embeddings";
pub const AI_MODELS_PATH: &str = "/v1/models";
pub const AI_ANTHROPIC_MESSAGES_PATH: &str = "/v1/messages";
pub const AI_ANTHROPIC_COMPLETE_PATH: &str = "/v1/complete";

pub const AI_ANALYTICS_PATH: &str = "/v1/nexusedge/ai/analytics";
pub const AI_METRICS_PATH: &str = "/v1/nexusedge/ai/metrics";

/// Supported AI inference protocols across clients and providers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AiProtocol {
    OpenAi,
    Anthropic,
}

impl AiProtocol {
    pub fn from_path(path: &str) -> Self {
        if path.contains("/messages") || path.contains("/complete") {
            AiProtocol::Anthropic
        } else {
            AiProtocol::OpenAi
        }
    }

    pub fn from_provider_type(ptype: &str) -> Self {
        match ptype.to_lowercase().as_str() {
            "anthropic" | "bedrock" => AiProtocol::Anthropic,
            _ => AiProtocol::OpenAi,
        }
    }
}

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

/// Returns true if the path and method correspond to an OpenAI, Anthropic, or vLLM AI endpoint.
pub fn is_ai_inference_request(path: &str, method: &Method) -> bool {
    if method == Method::GET
        && (path == AI_MODELS_PATH || path == AI_METRICS_PATH || path == AI_ANALYTICS_PATH)
    {
        return true;
    }
    if method == Method::POST {
        return path == AI_CHAT_COMPLETIONS_PATH
            || path == AI_COMPLETIONS_PATH
            || path == AI_EMBEDDINGS_PATH
            || path == AI_ANTHROPIC_MESSAGES_PATH
            || path == AI_ANTHROPIC_COMPLETE_PATH;
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
    #[serde(default)]
    pub project_id: Option<String>,
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
    #[serde(default)]
    pub project_id: Option<String>,
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

    pub fn trigger_backoff(&self, duration: Duration, is_429: bool) {
        let mut backoff = self.backoff_until.write().unwrap();
        *backoff = Some(Instant::now() + duration);
        if is_429 {
            self.rate_limited_429_count.fetch_add(1, Ordering::Relaxed);
        } else {
            self.error_count.fetch_add(1, Ordering::Relaxed);
        }
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
    auth_registry: Arc<AiGatewayAuthRegistry>,
    total_prompt_tokens: Arc<AtomicU64>,
    total_completion_tokens: Arc<AtomicU64>,
    total_tokens_routed: Arc<AtomicU64>,
    total_cost_spent_micros: Arc<AtomicU64>,
    total_cost_saved_micros: Arc<AtomicU64>,
}

impl AiTrafficDirector {
    pub fn new(providers: Vec<AiProvider>) -> Self {
        Self::new_with_auth(providers, Arc::new(AiGatewayAuthRegistry::new()))
    }

    pub fn new_with_fixtures(providers: Vec<AiProvider>) -> Self {
        Self::new_with_auth(
            providers,
            Arc::new(AiGatewayAuthRegistry::new_development_fixtures()),
        )
    }

    pub fn new_empty() -> Self {
        Self::new_with_auth(vec![], Arc::new(AiGatewayAuthRegistry::new_empty()))
    }

    pub fn new_with_auth(
        providers: Vec<AiProvider>,
        auth_registry: Arc<AiGatewayAuthRegistry>,
    ) -> Self {
        let runtime_states = providers
            .into_iter()
            .map(|p| Arc::new(ProviderRuntimeState::new(p)))
            .collect();
        Self {
            providers: Arc::new(RwLock::new(runtime_states)),
            auth_registry,
            total_prompt_tokens: Arc::new(AtomicU64::new(0)),
            total_completion_tokens: Arc::new(AtomicU64::new(0)),
            total_tokens_routed: Arc::new(AtomicU64::new(0)),
            total_cost_spent_micros: Arc::new(AtomicU64::new(0)),
            total_cost_saved_micros: Arc::new(AtomicU64::new(0)),
        }
    }

    pub fn auth_registry(&self) -> &Arc<AiGatewayAuthRegistry> {
        &self.auth_registry
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
        self.select_candidates_with_strategy(
            requested_jurisdiction,
            RoutingStrategy::Priority,
            None,
        )
    }

    /// Multi-objective candidate selection: filters strictly by data sovereignty and tenant project scope,
    /// then ranks providers based on the requested optimization strategy.
    pub fn select_candidates_with_strategy(
        &self,
        requested_jurisdiction: Option<&str>,
        strategy: RoutingStrategy,
        target_project_id: Option<&str>,
    ) -> Vec<Arc<ProviderRuntimeState>> {
        let guard = self.providers.read().unwrap();
        let mut candidates: Vec<Arc<ProviderRuntimeState>> = guard
            .iter()
            .filter(|state| {
                if let Some(req_jur) = requested_jurisdiction {
                    let jur_match = match state.provider.sovereignty_jurisdiction.as_deref() {
                        Some(jur) => jur.eq_ignore_ascii_case(req_jur),
                        None => false,
                    };
                    if !jur_match {
                        return false;
                    }
                }

                // Enforce tenant project isolation:
                // If a target_project_id is provided, match that tenant's providers or global providers (project_id: None).
                // If NO target_project_id is provided, match only global providers (project_id: None) so tenant providers are never leaked.
                match (&state.provider.project_id, target_project_id) {
                    (Some(prov_proj), Some(target_proj)) => prov_proj == target_proj,
                    (Some(_), None) => false,
                    (None, _) => true,
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
                    "project_id": state.provider.project_id,
                    "jurisdiction": state.provider.sovereignty_jurisdiction,
                    "is_available": state.is_available(),
                    "total_requests": state.total_requests.load(Ordering::Relaxed),
                    "successful_requests": state.successful_requests.load(Ordering::Relaxed),
                    "rate_limited_429": state.rate_limited_429_count.load(Ordering::Relaxed),
                    "error_count": state.error_count.load(Ordering::Relaxed),
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
    // 1. Try standard JSON payload (OpenAI prompt_tokens / Anthropic input_tokens)
    if let Ok(v) = serde_json::from_slice::<serde_json::Value>(body) {
        if let Some(usage) = v.get("usage") {
            let p = usage
                .get("prompt_tokens")
                .or_else(|| usage.get("input_tokens"))
                .and_then(|t| t.as_u64())
                .unwrap_or(0);
            let c = usage
                .get("completion_tokens")
                .or_else(|| usage.get("output_tokens"))
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
                                .or_else(|| usage.get("input_tokens"))
                                .and_then(|t| t.as_u64())
                                .unwrap_or(0);
                            let c = usage
                                .get("completion_tokens")
                                .or_else(|| usage.get("output_tokens"))
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

/// Translates an OpenAI `/v1/chat/completions` JSON payload to an Anthropic `/v1/messages` JSON payload.
pub fn translate_openai_to_anthropic_payload(body: &[u8]) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        format!(
            "Failed to parse OpenAI payload for Anthropic translation: {}",
            e
        )
    })?;

    let mut system_prompt = String::new();
    let mut anthropic_messages = Vec::new();

    if let Some(messages) = v.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
            let content = match msg.get("content") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Array(arr)) => {
                    let mut text_acc = String::new();
                    for part in arr {
                        if let Some(t) = part.get("text").and_then(|s| s.as_str()) {
                            text_acc.push_str(t);
                        }
                    }
                    text_acc
                }
                _ => String::new(),
            };

            if role == "system" {
                if !system_prompt.is_empty() {
                    system_prompt.push('\n');
                }
                system_prompt.push_str(&content);
            } else {
                anthropic_messages.push(serde_json::json!({
                    "role": role,
                    "content": content
                }));
            }
        }
    }

    let mut anthropic_obj = serde_json::Map::new();
    let model = v
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("claude-3-5-sonnet-20241022");
    anthropic_obj.insert("model".to_string(), serde_json::json!(model));

    if !system_prompt.is_empty() {
        anthropic_obj.insert("system".to_string(), serde_json::json!(system_prompt));
    }

    anthropic_obj.insert(
        "messages".to_string(),
        serde_json::Value::Array(anthropic_messages),
    );

    let max_tokens = v.get("max_tokens").and_then(|t| t.as_u64()).unwrap_or(1024);
    anthropic_obj.insert("max_tokens".to_string(), serde_json::json!(max_tokens));

    if let Some(temp) = v.get("temperature") {
        anthropic_obj.insert("temperature".to_string(), temp.clone());
    }

    if let Some(stream) = v.get("stream") {
        anthropic_obj.insert("stream".to_string(), stream.clone());
    }

    serde_json::to_vec(&serde_json::Value::Object(anthropic_obj))
        .map_err(|e| format!("Failed to serialize translated Anthropic payload: {}", e))
}

/// Translates an Anthropic `/v1/messages` JSON payload to an OpenAI `/v1/chat/completions` JSON payload.
pub fn translate_anthropic_to_openai_payload(body: &[u8]) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(body).map_err(|e| {
        format!(
            "Failed to parse Anthropic payload for OpenAI translation: {}",
            e
        )
    })?;

    let mut openai_messages = Vec::new();

    if let Some(system) = v.get("system") {
        let system_str = match system {
            serde_json::Value::String(s) => s.clone(),
            serde_json::Value::Array(arr) => {
                let mut acc = String::new();
                for item in arr {
                    if let Some(text) = item.get("text").and_then(|t| t.as_str()) {
                        acc.push_str(text);
                    }
                }
                acc
            }
            _ => String::new(),
        };
        if !system_str.is_empty() {
            openai_messages.push(serde_json::json!({
                "role": "system",
                "content": system_str
            }));
        }
    }

    if let Some(messages) = v.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            let role = msg.get("role").and_then(|r| r.as_str()).unwrap_or("user");
            let content = match msg.get("content") {
                Some(serde_json::Value::String(s)) => s.clone(),
                Some(serde_json::Value::Array(arr)) => {
                    let mut acc = String::new();
                    for part in arr {
                        if let Some(text) = part.get("text").and_then(|t| t.as_str()) {
                            acc.push_str(text);
                        }
                    }
                    acc
                }
                _ => String::new(),
            };
            openai_messages.push(serde_json::json!({
                "role": role,
                "content": content
            }));
        }
    }

    let mut openai_obj = serde_json::Map::new();
    let model = v
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or("llama-3.3-70b");
    openai_obj.insert("model".to_string(), serde_json::json!(model));
    openai_obj.insert(
        "messages".to_string(),
        serde_json::Value::Array(openai_messages),
    );

    if let Some(max_tokens) = v.get("max_tokens") {
        openai_obj.insert("max_tokens".to_string(), max_tokens.clone());
    }
    if let Some(temp) = v.get("temperature") {
        openai_obj.insert("temperature".to_string(), temp.clone());
    }
    if let Some(stream) = v.get("stream") {
        openai_obj.insert("stream".to_string(), stream.clone());
    }

    serde_json::to_vec(&serde_json::Value::Object(openai_obj))
        .map_err(|e| format!("Failed to serialize translated OpenAI payload: {}", e))
}

/// Translates an OpenAI chat completion JSON response to an Anthropic message JSON response.
pub fn translate_openai_to_anthropic_response(
    resp_body: &[u8],
    requested_model: &str,
) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(resp_body).map_err(|e| {
        format!(
            "Failed to parse OpenAI response for Anthropic translation: {}",
            e
        )
    })?;

    let id = v
        .get("id")
        .and_then(|s| s.as_str())
        .unwrap_or("chatcmpl-unknown");
    let model = v
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or(requested_model);

    let content = v
        .get("choices")
        .and_then(|c| c.as_array())
        .and_then(|arr| arr.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|m| m.get("content"))
        .and_then(|c| c.as_str())
        .unwrap_or("");

    let usage = extract_token_usage(resp_body).unwrap_or_default();

    let anthropic_resp = serde_json::json!({
        "id": format!("msg_{}", id),
        "type": "message",
        "role": "assistant",
        "model": model,
        "content": [
            {
                "type": "text",
                "text": content
            }
        ],
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {
            "input_tokens": usage.prompt_tokens,
            "output_tokens": usage.completion_tokens
        }
    });

    serde_json::to_vec(&anthropic_resp)
        .map_err(|e| format!("Failed to serialize translated Anthropic response: {}", e))
}

/// Translates an Anthropic message JSON response to an OpenAI chat completion JSON response.
pub fn translate_anthropic_to_openai_response(
    resp_body: &[u8],
    requested_model: &str,
) -> Result<Vec<u8>, String> {
    let v: serde_json::Value = serde_json::from_slice(resp_body).map_err(|e| {
        format!(
            "Failed to parse Anthropic response for OpenAI translation: {}",
            e
        )
    })?;

    let id = v
        .get("id")
        .and_then(|s| s.as_str())
        .unwrap_or("msg-unknown");
    let model = v
        .get("model")
        .and_then(|m| m.as_str())
        .unwrap_or(requested_model);

    let mut text_acc = String::new();
    if let Some(content_arr) = v.get("content").and_then(|c| c.as_array()) {
        for block in content_arr {
            if let Some(text) = block.get("text").and_then(|t| t.as_str()) {
                text_acc.push_str(text);
            }
        }
    }

    let usage = extract_token_usage(resp_body).unwrap_or_default();

    let openai_resp = serde_json::json!({
        "id": format!("chatcmpl_{}", id),
        "object": "chat.completion",
        "created": chrono::Utc::now().timestamp(),
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {
                    "role": "assistant",
                    "content": text_acc
                },
                "finish_reason": "stop"
            }
        ],
        "usage": {
            "prompt_tokens": usage.prompt_tokens,
            "completion_tokens": usage.completion_tokens,
            "total_tokens": usage.total_tokens
        }
    });

    serde_json::to_vec(&openai_resp)
        .map_err(|e| format!("Failed to serialize translated OpenAI response: {}", e))
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

    let header_project_id = req_headers
        .get("x-nexusedge-project-id")
        .or_else(|| req_headers.get("x-project-id"))
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    if body.is_empty() {
        return Ok(AiRequestMetadata {
            model: "default".to_string(),
            stream: false,
            max_tokens: None,
            temperature: None,
            requested_jurisdiction: jurisdiction_header,
            routing_strategy: header_strategy.unwrap_or_default(),
            project_id: header_project_id,
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

    let body_project_id = json_val
        .get("project_id")
        .and_then(|p| p.as_str())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let routing_strategy = header_strategy.or(body_strategy).unwrap_or_default();
    let project_id = header_project_id.or(body_project_id);

    Ok(AiRequestMetadata {
        model,
        stream,
        max_tokens,
        temperature,
        requested_jurisdiction: jurisdiction_header,
        routing_strategy,
        project_id,
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

    // 1. Authenticate caller credential against verified identity registry (Finding 1)
    let identity = match director.auth_registry().authenticate(req_headers) {
        Ok(id) => id,
        Err(AiAuthError::MissingCredentials) => {
            let body = serde_json::json!({
                "error": {
                    "message": "Missing authentication credentials (Authorization: Bearer <token> or x-api-key required)",
                    "type": "authentication_error",
                    "code": "missing_credentials"
                }
            });
            let resp = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge-AI-Director/0.1.0")
                .header("WWW-Authenticate", "Bearer realm=\"NexusEdge-AI\"")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
        Err(AiAuthError::InvalidOrRevokedKey) => {
            let body = serde_json::json!({
                "error": {
                    "message": "Invalid or revoked authentication credentials",
                    "type": "authentication_error",
                    "code": "unauthorized"
                }
            });
            let resp = Response::builder()
                .status(StatusCode::UNAUTHORIZED)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge-AI-Director/0.1.0")
                .header("WWW-Authenticate", "Bearer realm=\"NexusEdge-AI\"")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
    };

    // 2. Protected metrics and analytics endpoints within auth boundary (Finding 1)
    if path == AI_METRICS_PATH || path == AI_ANALYTICS_PATH {
        if !identity.scopes.contains("*") && !identity.scopes.contains("analytics") {
            let body = serde_json::json!({
                "error": {
                    "message": "Forbidden: insufficient scope for analytics/metrics endpoint",
                    "type": "authorization_error",
                    "code": "insufficient_scope"
                }
            });
            let resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge-AI-Director/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }

        let metrics_json = director.get_analytics_summary();
        let resp = Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "application/json")
            .header("Server", "NexusEdge-AI-Director/0.1.0")
            .body(Full::new(Bytes::from(metrics_json.to_string())))
            .unwrap();
        return Ok(resp);
    }

    // 3. Enforce inference scope authorization (Finding 4)
    if !identity.scopes.contains("*") && !identity.scopes.contains("inference") {
        let body = serde_json::json!({
            "error": {
                "message": "Forbidden: insufficient scope for AI inference operations ('inference' scope required)",
                "type": "authorization_error",
                "code": "insufficient_scope"
            }
        });
        let resp = Response::builder()
            .status(StatusCode::FORBIDDEN)
            .header("Content-Type", "application/json")
            .header("Server", "NexusEdge-AI-Director/0.1.0")
            .body(Full::new(Bytes::from(body.to_string())))
            .unwrap();
        return Ok(resp);
    }

    // 4. Extract and validate inference request payload & metadata
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

    // 4. Multi-tenant project authorization and residency policy enforcement (Finding 1)
    let effective_project_id = if let Some(ref requested_project) = metadata.project_id {
        if !identity.allowed_projects.contains("*")
            && !identity.allowed_projects.contains(requested_project)
        {
            let body = serde_json::json!({
                "error": {
                    "message": format!(
                        "Cross-tenant access forbidden: tenant '{}' is not authorized for project '{}'",
                        identity.tenant_id, requested_project
                    ),
                    "type": "authorization_error",
                    "code": "cross_tenant_project_forbidden"
                }
            });
            let resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge-AI-Director/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
        Some(requested_project.clone())
    } else {
        Some(identity.default_project_id.clone())
    };

    if let Some(ref requested_jurisdiction) = metadata.requested_jurisdiction {
        if !identity.allowed_jurisdictions.contains("*")
            && !identity
                .allowed_jurisdictions
                .contains(requested_jurisdiction)
        {
            let body = serde_json::json!({
                "error": {
                    "message": format!(
                        "Residency constraint error: tenant '{}' is not authorized for jurisdiction '{}'",
                        identity.tenant_id, requested_jurisdiction
                    ),
                    "type": "authorization_error",
                    "code": "jurisdiction_forbidden"
                }
            });
            let resp = Response::builder()
                .status(StatusCode::FORBIDDEN)
                .header("Content-Type", "application/json")
                .header("Server", "NexusEdge-AI-Director/0.1.0")
                .body(Full::new(Bytes::from(body.to_string())))
                .unwrap();
            return Ok(resp);
        }
    }

    let candidates = director.select_candidates_with_strategy(
        metadata.requested_jurisdiction.as_deref(),
        metadata.routing_strategy,
        effective_project_id.as_deref(),
    );
    if candidates.is_empty() {
        warn!(
            jurisdiction = ?metadata.requested_jurisdiction,
            project = ?effective_project_id,
            "No available AI compute providers satisfy sovereignty, tenancy, or capacity constraints"
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

    let caller_protocol = AiProtocol::from_path(path);

    for candidate_state in candidates {
        candidate_state
            .total_requests
            .fetch_add(1, Ordering::Relaxed);
        let provider = &candidate_state.provider;
        let target_protocol = AiProtocol::from_provider_type(&provider.provider_type);

        // Construct target dispatch URL with protocol path adaptation
        let dispatch_path = match (caller_protocol, target_protocol) {
            (AiProtocol::OpenAi, AiProtocol::Anthropic) => "/messages",
            (AiProtocol::Anthropic, AiProtocol::OpenAi) => "/chat/completions",
            _ => {
                if path.starts_with("/v1/") {
                    &path["/v1".len()..]
                } else {
                    path
                }
            }
        };

        let target_url = format!(
            "{}{}",
            provider.endpoint.trim_end_matches('/'),
            dispatch_path
        );

        let mut req_builder = client.request(
            reqwest::Method::from_bytes(method.as_str().as_bytes()).unwrap(),
            &target_url,
        );

        // 5. Header Sanitization: Forward safe client headers, strictly stripping client credentials,
        // internal metadata, and hop-by-hop headers to prevent upstream leakage (Finding 8)
        for (name, value) in req_headers.iter() {
            let name_str = name.as_str().to_lowercase();
            if name_str == "host"
                || name_str == "authorization"
                || name_str == "x-api-key"
                || name_str == "api-key"
                || name_str == "x-project-id"
                || name_str == "cookie"
                || name_str == "set-cookie"
                || name_str == "connection"
                || name_str == "transfer-encoding"
                || name_str == "content-length"
                || name_str.starts_with("x-nexusedge-")
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
            match provider.provider_type.as_str() {
                "azure" => {
                    req_builder = req_builder.header("api-key", key);
                }
                "anthropic" | "bedrock" => {
                    req_builder = req_builder
                        .header("x-api-key", key)
                        .header("anthropic-version", "2023-06-01");
                }
                _ => {
                    req_builder = req_builder.header("Authorization", format!("Bearer {}", key));
                }
            }
        }

        // Add reverse proxy tracing headers
        req_builder = req_builder
            .header("X-Forwarded-For", client_ip.to_string())
            .header("X-NexusEdge-Selected-Provider", &provider.id)
            .header("X-NexusEdge-Model", &metadata.model);

        // Translate request payload if caller protocol differs from upstream provider protocol
        let dispatch_body = if !body_bytes.is_empty() {
            match (caller_protocol, target_protocol) {
                (AiProtocol::OpenAi, AiProtocol::Anthropic) => {
                    match translate_openai_to_anthropic_payload(&body_bytes) {
                        Ok(b) => Bytes::from(b),
                        Err(err) => {
                            let body = serde_json::json!({
                                "error": {
                                    "message": format!("Payload translation to Anthropic schema failed: {}", err),
                                    "type": "invalid_request_error",
                                    "code": "payload_translation_error"
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
                    }
                }
                (AiProtocol::Anthropic, AiProtocol::OpenAi) => {
                    match translate_anthropic_to_openai_payload(&body_bytes) {
                        Ok(b) => Bytes::from(b),
                        Err(err) => {
                            let body = serde_json::json!({
                                "error": {
                                    "message": format!("Payload translation to OpenAI schema failed: {}", err),
                                    "type": "invalid_request_error",
                                    "code": "payload_translation_error"
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
                    }
                }
                _ => body_bytes.clone(),
            }
        } else {
            body_bytes.clone()
        };

        if !dispatch_body.is_empty() {
            req_builder = req_builder.body(dispatch_body);
        }

        let send_start = Instant::now();
        match req_builder.send().await {
            Ok(upstream_resp) => {
                let status_code = upstream_resp.status();

                // Check for 429 Too Many Requests, 503 Overload, 502 Bad Gateway, or 504 Gateway Timeout (Trigger Transparent Failover)
                if status_code == reqwest::StatusCode::TOO_MANY_REQUESTS
                    || status_code == reqwest::StatusCode::SERVICE_UNAVAILABLE
                    || status_code == reqwest::StatusCode::BAD_GATEWAY
                    || status_code == reqwest::StatusCode::GATEWAY_TIMEOUT
                {
                    let is_429 = status_code == reqwest::StatusCode::TOO_MANY_REQUESTS;
                    warn!(
                        provider = %provider.id,
                        status = status_code.as_u16(),
                        "Upstream AI provider returned transient error; triggering transparent failover"
                    );
                    candidate_state.trigger_backoff(
                        Duration::from_secs(provider.failover_cooldown_secs.max(5)),
                        is_429,
                    );
                    failover_count += 1;
                    last_error_status = StatusCode::from_u16(status_code.as_u16())
                        .unwrap_or(StatusCode::SERVICE_UNAVAILABLE);
                    continue; // Try next candidate!
                }

                // Upstream response received
                let ttft_ms = send_start.elapsed().as_millis() as u64;
                if status_code.is_success() {
                    candidate_state.record_success(Some(ttft_ms));
                } else {
                    candidate_state.record_error();
                }

                let resp_status = StatusCode::from_u16(status_code.as_u16())
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);

                let mut builder = Response::builder()
                    .status(resp_status)
                    .header("Server", "NexusEdge-Universal-Compute-Director/0.1.0")
                    .header("X-NexusEdge-Provider", &provider.id)
                    .header("X-NexusEdge-TTFT-Ms", ttft_ms.to_string())
                    .header(
                        "X-NexusEdge-Upstream-Header-Latency-Ms",
                        ttft_ms.to_string(),
                    )
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

                let resp_bytes = match upstream_resp.bytes().await {
                    Ok(b) => b,
                    Err(e) => {
                        let body = serde_json::json!({
                            "error": {
                                "message": format!("Failed to read upstream response body: {}", e),
                                "type": "bad_gateway_error",
                                "code": "upstream_read_error"
                            }
                        });
                        let resp = Response::builder()
                            .status(StatusCode::BAD_GATEWAY)
                            .header("Content-Type", "application/json")
                            .header("Server", "NexusEdge-AI-Director/0.1.0")
                            .body(Full::new(Bytes::from(body.to_string())))
                            .unwrap();
                        return Ok(resp);
                    }
                };

                // 6. Fail-closed response body translation across protocols (Finding 13)
                let final_resp_bytes = if !resp_bytes.is_empty() && resp_status == StatusCode::OK {
                    match (caller_protocol, target_protocol) {
                        (AiProtocol::OpenAi, AiProtocol::Anthropic) => {
                            match translate_anthropic_to_openai_response(
                                &resp_bytes,
                                &metadata.model,
                            ) {
                                Ok(b) => Bytes::from(b),
                                Err(err) => {
                                    let body = serde_json::json!({
                                        "error": {
                                            "message": format!("Upstream response translation from Anthropic failed: {}", err),
                                            "type": "bad_gateway_error",
                                            "code": "response_translation_error"
                                        }
                                    });
                                    let resp = Response::builder()
                                        .status(StatusCode::BAD_GATEWAY)
                                        .header("Content-Type", "application/json")
                                        .header("Server", "NexusEdge-AI-Director/0.1.0")
                                        .body(Full::new(Bytes::from(body.to_string())))
                                        .unwrap();
                                    return Ok(resp);
                                }
                            }
                        }
                        (AiProtocol::Anthropic, AiProtocol::OpenAi) => {
                            match translate_openai_to_anthropic_response(
                                &resp_bytes,
                                &metadata.model,
                            ) {
                                Ok(b) => Bytes::from(b),
                                Err(err) => {
                                    let body = serde_json::json!({
                                        "error": {
                                            "message": format!("Upstream response translation from OpenAI failed: {}", err),
                                            "type": "bad_gateway_error",
                                            "code": "response_translation_error"
                                        }
                                    });
                                    let resp = Response::builder()
                                        .status(StatusCode::BAD_GATEWAY)
                                        .header("Content-Type", "application/json")
                                        .header("Server", "NexusEdge-AI-Director/0.1.0")
                                        .body(Full::new(Bytes::from(body.to_string())))
                                        .unwrap();
                                    return Ok(resp);
                                }
                            }
                        }
                        _ => resp_bytes.clone(),
                    }
                } else {
                    resp_bytes.clone()
                };

                // Calculate real-time token economics & dollar savings
                let baseline_cost = director.get_baseline_cost_per_m();
                let usage_opt = extract_token_usage(&final_resp_bytes)
                    .or_else(|| extract_token_usage(&resp_bytes));
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

                let resp = builder.body(Full::new(final_resp_bytes)).unwrap();
                return Ok(resp);
            }
            Err(e) => {
                warn!(
                    provider = %provider.id,
                    error = %e,
                    "Connection to AI compute provider failed; triggering failover"
                );
                // trigger_backoff already increments error_count and failovers_triggered!
                // Prevent duplicate error count increment (Finding 13).
                candidate_state.trigger_backoff(
                    Duration::from_secs(provider.failover_cooldown_secs.max(5)),
                    false,
                );
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
                project_id: None,
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
                project_id: None,
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
                project_id: None,
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
        global_candidates[0].trigger_backoff(Duration::from_secs(60), true);
        let updated_candidates = director.select_candidates(None);
        assert_eq!(updated_candidates[0].provider.id, "azure-us"); // priority 1 takes over
        assert_eq!(updated_candidates[1].provider.id, "coreweave-spot"); // priority 2
        assert_eq!(updated_candidates[2].provider.id, "onprem-dhaka"); // backed off node pushed to end
    }

    #[test]
    fn test_tenant_project_isolation() {
        let providers = vec![
            AiProvider {
                id: "global-vllm".to_string(),
                name: "Global Shared vLLM".to_string(),
                endpoint: "https://global.example.com".to_string(),
                provider_type: "vllm".to_string(),
                api_key: None,
                cost_per_m_tokens: 1.0,
                priority: 2,
                sovereignty_jurisdiction: None,
                failover_cooldown_secs: 10,
                project_id: None,
            },
            AiProvider {
                id: "tenant-alpha-custom".to_string(),
                name: "Alpha Custom Fine-Tuned".to_string(),
                endpoint: "https://alpha.example.com".to_string(),
                provider_type: "openai".to_string(),
                api_key: Some("alpha-key".to_string()),
                cost_per_m_tokens: 0.5,
                priority: 0,
                sovereignty_jurisdiction: None,
                failover_cooldown_secs: 10,
                project_id: Some("proj-alpha".to_string()),
            },
            AiProvider {
                id: "tenant-beta-private".to_string(),
                name: "Beta Private Azure".to_string(),
                endpoint: "https://beta.example.com".to_string(),
                provider_type: "azure".to_string(),
                api_key: Some("beta-key".to_string()),
                cost_per_m_tokens: 0.4,
                priority: 0,
                sovereignty_jurisdiction: None,
                failover_cooldown_secs: 10,
                project_id: Some("proj-beta".to_string()),
            },
        ];

        let director = AiTrafficDirector::new(providers);

        // Alpha query: sees Alpha's custom model + shared global model, never Beta's model
        let alpha_candidates = director.select_candidates_with_strategy(
            None,
            RoutingStrategy::Priority,
            Some("proj-alpha"),
        );
        assert_eq!(alpha_candidates.len(), 2);
        assert_eq!(alpha_candidates[0].provider.id, "tenant-alpha-custom");
        assert_eq!(alpha_candidates[1].provider.id, "global-vllm");

        // Beta query: sees Beta's private model + shared global model, never Alpha's model
        let beta_candidates = director.select_candidates_with_strategy(
            None,
            RoutingStrategy::Priority,
            Some("proj-beta"),
        );
        assert_eq!(beta_candidates.len(), 2);
        assert_eq!(beta_candidates[0].provider.id, "tenant-beta-private");
        assert_eq!(beta_candidates[1].provider.id, "global-vllm");

        // Unscoped / public query: sees only global model, never private tenant models
        let unscoped_candidates =
            director.select_candidates_with_strategy(None, RoutingStrategy::Priority, None);
        assert_eq!(unscoped_candidates.len(), 1);
        assert_eq!(unscoped_candidates[0].provider.id, "global-vllm");
    }

    #[test]
    fn test_parse_ai_request_metadata_with_project_id() {
        let payload = br#"{"model": "llama-3.3-70b", "project_id": "proj-from-body"}"#;
        let mut headers = hyper::HeaderMap::new();
        headers.insert(
            "x-nexusedge-project-id",
            HeaderValue::from_static("proj-from-header"),
        );

        // Header takes precedence when both provided
        let meta = parse_ai_request_metadata(payload, &headers).unwrap();
        assert_eq!(meta.project_id.as_deref(), Some("proj-from-header"));

        // Fallback to body when header absent
        let meta_body = parse_ai_request_metadata(payload, &hyper::HeaderMap::new()).unwrap();
        assert_eq!(meta_body.project_id.as_deref(), Some("proj-from-body"));
    }
}
