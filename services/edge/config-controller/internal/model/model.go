package model

import "time"

type DomainStatus string

const (
	DomainStatusPendingVerification DomainStatus = "PENDING_VERIFICATION"
	DomainStatusActive              DomainStatus = "ACTIVE"
	DomainStatusSuspended           DomainStatus = "SUSPENDED"
)

type LBAlgorithm string

const (
	LBAlgorithmRoundRobin   LBAlgorithm = "ROUND_ROBIN"
	LBAlgorithmLeastLatency LBAlgorithm = "LEAST_LATENCY"
	LBAlgorithmWeighted     LBAlgorithm = "WEIGHTED"
)

type Protocol string

const (
	ProtocolHTTP  Protocol = "HTTP"
	ProtocolHTTPS Protocol = "HTTPS"
)

type Domain struct {
	ID                string       `json:"id"`
	ProjectID         string       `json:"project_id"`
	Hostname          string       `json:"hostname"`
	Status            DomainStatus `json:"status"`
	OnboardingType    string       `json:"onboarding_type"` // "CNAME" or "NAMESERVER"
	CNAMETarget       string       `json:"cname_target"`    // e.g. "cname-d101.edge.nexusedge.net"
	VerificationToken string       `json:"verification_token,omitempty"`
	AllowedPoPs       []string     `json:"allowed_pops,omitempty"` // empty means global / all PoPs
	CreatedAt         time.Time    `json:"created_at"`
	UpdatedAt         time.Time    `json:"updated_at"`
}

type DomainVerification struct {
	ID               string    `json:"id"`
	DomainID         string    `json:"domain_id"`
	Token            string    `json:"token"`
	VerificationType string    `json:"verification_type"` // "DNS_CNAME", "DNS_TXT"
	IsVerified       bool      `json:"is_verified"`
	VerifiedAt       time.Time `json:"verified_at,omitempty"`
}

type HealthCheckProtocol string

const (
	HealthCheckProtocolHTTP  HealthCheckProtocol = "HTTP"
	HealthCheckProtocolHTTPS HealthCheckProtocol = "HTTPS"
	HealthCheckProtocolTCP   HealthCheckProtocol = "TCP"
)

type HealthMonitor struct {
	ID                  string              `json:"id"`
	PoolID              string              `json:"pool_id"`
	Protocol            HealthCheckProtocol `json:"protocol"`
	Path                string              `json:"path"` // default "/healthz"
	Port                int                 `json:"port"`
	IntervalSeconds     int                 `json:"interval_seconds"`      // default 10s
	TimeoutSeconds      int                 `json:"timeout_seconds"`       // default 2s
	HealthyThreshold    int                 `json:"healthy_threshold"`     // consecutive passes, default 2
	UnhealthyThreshold  int                 `json:"unhealthy_threshold"`   // consecutive failures, default 3
	ExpectedStatusCodes []int               `json:"expected_status_codes"` // default [200]
}

type OriginEndpointState struct {
	OriginID            string    `json:"origin_id"`
	PoolID              string    `json:"pool_id"`
	Address             string    `json:"address"`
	Port                int       `json:"port"`
	Healthy             bool      `json:"healthy"`
	ConsecutivePasses   int       `json:"consecutive_passes"`
	ConsecutiveFailures int       `json:"consecutive_failures"`
	EWMALatencyMs       float64   `json:"ewma_latency_ms"`
	LastStatusCode      int       `json:"last_status_code"`
	LastChecked         time.Time `json:"last_checked"`
	LastError           string    `json:"last_error,omitempty"`
}

type RoutingDecision struct {
	SelectedOriginID string  `json:"selected_origin_id"`
	OriginAddress    string  `json:"origin_address"`
	OriginPort       int     `json:"origin_port"`
	PoolID           string  `json:"pool_id"`
	Reason           string  `json:"reason"` // "LOWEST_EWMA_LATENCY", "FAILOVER", "ROUND_ROBIN"
	LatencyMs        float64 `json:"latency_ms"`
}

type OriginPool struct {
	ID            string         `json:"id"`
	ProjectID     string         `json:"project_id"`
	Name          string         `json:"name"`
	LBAlgorithm   LBAlgorithm    `json:"lb_algorithm"`
	HealthMonitor *HealthMonitor `json:"health_monitor,omitempty"`
	Origins       []Origin       `json:"origins"`
	AllowedPoPs   []string       `json:"allowed_pops,omitempty"` // empty means global / all PoPs
}

type Origin struct {
	ID           string   `json:"id"`
	PoolID       string   `json:"pool_id"`
	Address      string   `json:"address"` // FQDN or IP
	Port         int      `json:"port"`
	Protocol     Protocol `json:"protocol"` // "HTTP" or "HTTPS"
	SNI          string   `json:"sni,omitempty"`
	CABundlePath string   `json:"ca_bundle_path,omitempty"`
	Weight       int      `json:"weight"`
	Healthy      bool     `json:"healthy"`
	AllowedPoPs  []string `json:"allowed_pops,omitempty"` // empty means global / all PoPs
}

type Route struct {
	ID         string `json:"id"`
	DomainID   string `json:"domain_id"`
	PoolID     string `json:"pool_id"`
	PathPrefix string `json:"path_prefix"`
	Priority   int    `json:"priority"`
	TimeoutMs  int    `json:"timeout_ms"`
}

type WAFAction string

const (
	WAFActionAllow     WAFAction = "ALLOW"
	WAFActionBlock     WAFAction = "BLOCK"
	WAFActionLog       WAFAction = "LOG"
	WAFActionChallenge WAFAction = "CHALLENGE"
)

type WAFMatchType string

const (
	WAFMatchIPCIDR     WAFMatchType = "IP_CIDR"
	WAFMatchPathPrefix WAFMatchType = "PATH_PREFIX"
	WAFMatchHeader     WAFMatchType = "HEADER"
	WAFMatchQueryParam WAFMatchType = "QUERY_PARAM"
	WAFMatchOWASPCRS   WAFMatchType = "OWASP_CRS"
)

type WAFRule struct {
	ID          string       `json:"id"`
	DomainID    string       `json:"domain_id"`
	Name        string       `json:"name"`
	Description string       `json:"description"`
	MatchType   WAFMatchType `json:"match_type"`
	Pattern     string       `json:"pattern"`
	Action      WAFAction    `json:"action"`
	Priority    int          `json:"priority"`
	Enabled     bool         `json:"enabled"`
}

type RateLimitRule struct {
	ID                string `json:"id"`
	DomainID          string `json:"domain_id"`
	PathPrefix        string `json:"path_prefix"`
	RequestsPerMinute int    `json:"requests_per_minute"`
	BurstSize         int    `json:"burst_size"`
	KeyType           string `json:"key_type"` // "CLIENT_IP", "HEADER"
	HeaderName        string `json:"header_name,omitempty"`
	Enabled           bool   `json:"enabled"`
}

type SecurityEvent struct {
	ID            string    `json:"id"`
	DomainID      string    `json:"domain_id"`
	Timestamp     time.Time `json:"timestamp"`
	ClientIP      string    `json:"client_ip"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	UserAgent     string    `json:"user_agent"`
	RuleTriggered string    `json:"rule_triggered"`
	Action        WAFAction `json:"action"`
	Details       string    `json:"details"`
}

type SecurityPolicy struct {
	ID               string          `json:"id"`
	DomainID         string          `json:"domain_id"`
	WAFEnabled       bool            `json:"waf_enabled"`
	WAFMode          string          `json:"waf_mode"` // "BLOCK", "LOG"
	OWASPProtection  bool            `json:"owasp_protection"`
	WAFRules         []WAFRule       `json:"waf_rules"`
	RateLimitEnabled bool            `json:"rate_limit_enabled"`
	RateLimitRPM     int             `json:"rate_limit_rpm"`
	RateLimitRules   []RateLimitRule `json:"rate_limit_rules"`
}

type QueryStringHandling string

const (
	QueryStringIncludeAll      QueryStringHandling = "INCLUDE_ALL"
	QueryStringIgnoreAll       QueryStringHandling = "IGNORE_ALL"
	QueryStringIgnoreSelected  QueryStringHandling = "IGNORE_SELECTED"
	QueryStringIncludeSelected QueryStringHandling = "INCLUDE_SELECTED"
)

type CacheRule struct {
	ID                     string              `json:"id"`
	DomainID               string              `json:"domain_id"`
	Name                   string              `json:"name"`
	PathPattern            string              `json:"path_pattern"` // e.g. "/static/*", "*.jpg"
	TTLSeconds             int                 `json:"ttl_seconds"`
	BypassCache            bool                `json:"bypass_cache"`
	QueryHandling          QueryStringHandling `json:"query_handling"`
	IgnoredParams          []string            `json:"ignored_params,omitempty"`
	IncludedParams         []string            `json:"included_params,omitempty"`
	CustomHeadersToInclude []string            `json:"custom_headers_to_include,omitempty"`
	ServeStale             bool                `json:"serve_stale"`
	Enabled                bool                `json:"enabled"`
}

type CachePolicy struct {
	ID                   string              `json:"id"`
	DomainID             string              `json:"domain_id"`
	CacheEnabled         bool                `json:"cache_enabled"`
	DefaultTTLSeconds    int                 `json:"default_ttl_seconds"`
	RespectOriginHeaders bool                `json:"respect_origin_headers"`
	QueryHandling        QueryStringHandling `json:"query_handling"`
	StripCookies         bool                `json:"strip_cookies"`
	CacheRules           []CacheRule         `json:"cache_rules"`
}

type CertificateStatus string

const (
	CertStatusPendingChallenge CertificateStatus = "PENDING_CHALLENGE"
	CertStatusChallengeReady   CertificateStatus = "CHALLENGE_READY"
	CertStatusIssuing          CertificateStatus = "ISSUING"
	CertStatusActive           CertificateStatus = "ACTIVE"
	CertStatusRenewing         CertificateStatus = "RENEWING"
	CertStatusExpired          CertificateStatus = "EXPIRED"
	CertStatusRevoked          CertificateStatus = "REVOKED"
)

type KeyType string

const (
	KeyTypeECDSA KeyType = "ECDSA_P256"
	KeyTypeRSA   KeyType = "RSA_2048"
)

type Certificate struct {
	ID                string            `json:"id"`
	DomainID          string            `json:"domain_id"`
	Domains           []string          `json:"domains"`
	Status            CertificateStatus `json:"status"`
	KeyType           KeyType           `json:"key_type"`
	CertPEM           string            `json:"cert_pem"`
	PrivateKeyPEM     string            `json:"-"`
	FingerprintSHA256 string            `json:"fingerprint_sha256"`
	SerialNumber      string            `json:"serial_number"`
	Issuer            string            `json:"issuer"`
	IssuedAt          time.Time         `json:"issued_at"`
	ExpiresAt         time.Time         `json:"expires_at"`
	AutoRenew         bool              `json:"auto_renew"`
}

type ChallengeStatus string

const (
	ChallengeStatusPending   ChallengeStatus = "PENDING"
	ChallengeStatusValidated ChallengeStatus = "VALIDATED"
	ChallengeStatusFailed    ChallengeStatus = "FAILED"
)

type ACMEChallenge struct {
	ID               string          `json:"id"`
	CertificateID    string          `json:"certificate_id"`
	DomainID         string          `json:"domain_id"`
	Hostname         string          `json:"hostname"`
	Type             string          `json:"type"` // "HTTP-01"
	Token            string          `json:"token"`
	KeyAuthorization string          `json:"key_authorization"`
	Status           ChallengeStatus `json:"status"`
	CreatedAt        time.Time       `json:"created_at"`
	ExpiresAt        time.Time       `json:"expires_at"`
}

type TLSSettings struct {
	EnforceHTTPS  bool   `json:"enforce_https"`   // 301 redirect HTTP to HTTPS
	MinTLSVersion string `json:"min_tls_version"` // "TLSv1.2", "TLSv1.3"
	HSTS          bool   `json:"hsts"`
	HSTSMaxAge    int    `json:"hsts_max_age"`
}

// TelemetryEvent represents an individual HTTP transaction recorded at the edge
type TelemetryEvent struct {
	DomainID      string    `json:"domain_id"`
	RequestID     string    `json:"request_id"`
	ClientIP      string    `json:"client_ip"`
	Method        string    `json:"method"`
	Path          string    `json:"path"`
	StatusCode    int       `json:"status_code"`
	LatencyMs     float64   `json:"latency_ms"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
	CacheStatus   string    `json:"cache_status"` // "HIT", "MISS", "BYPASS"
	WAFAction     string    `json:"waf_action"`   // "ALLOW", "BLOCK", "LOG"
	OriginID      string    `json:"origin_id,omitempty"`
	Timestamp     time.Time `json:"timestamp"`
}

// LatencyPercentiles represents latency distribution metrics
type LatencyPercentiles struct {
	P50 float64 `json:"p50"`
	P90 float64 `json:"p90"`
	P95 float64 `json:"p95"`
	P99 float64 `json:"p99"`
	Min float64 `json:"min"`
	Max float64 `json:"max"`
	Avg float64 `json:"avg"`
}

// AnalyticsSummary aggregates traffic metrics for a domain
type AnalyticsSummary struct {
	DomainID        string             `json:"domain_id"`
	TotalRequests   int64              `json:"total_requests"`
	Status2xx       int64              `json:"status_2xx"`
	Status3xx       int64              `json:"status_3xx"`
	Status4xx       int64              `json:"status_4xx"`
	Status5xx       int64              `json:"status_5xx"`
	ErrorRate       float64            `json:"error_rate"`     // (4xx + 5xx) / total
	CacheHitRate    float64            `json:"cache_hit_rate"` // HIT / total
	CacheHits       int64              `json:"cache_hits"`
	CacheMisses     int64              `json:"cache_misses"`
	BytesSent       int64              `json:"bytes_sent"`       // Egress
	BytesReceived   int64              `json:"bytes_received"`   // Ingress
	SecurityBlocked int64              `json:"security_blocked"` // WAF blocks
	Latency         LatencyPercentiles `json:"latency"`
	LastUpdated     time.Time          `json:"last_updated"`
}

// TimeSeriesPoint represents aggregated traffic metrics over a single time window
type TimeSeriesPoint struct {
	Timestamp     time.Time `json:"timestamp"`
	Requests      int64     `json:"requests"`
	BytesSent     int64     `json:"bytes_sent"`
	BytesReceived int64     `json:"bytes_received"`
	AvgLatencyMs  float64   `json:"avg_latency_ms"`
	ErrorCount    int64     `json:"error_count"`
}

// BillingUsage represents metered resource utilization for customer invoicing ($1M ARR Engine)
type BillingUsage struct {
	DomainID         string    `json:"domain_id"`
	BillingPeriod    string    `json:"billing_period"`
	TotalRequests    int64     `json:"total_requests"`
	EgressGB         float64   `json:"egress_gb"`
	IngressGB        float64   `json:"ingress_gb"`
	BaseFeeUSD       float64   `json:"base_fee_usd"`
	BandwidthCostUSD float64   `json:"bandwidth_cost_usd"`
	RequestCostUSD   float64   `json:"request_cost_usd"`
	TotalCostUSD     float64   `json:"total_cost_usd"`
	GeneratedAt      time.Time `json:"generated_at"`
}

type PoPStatus string

const (
	PoPStatusActive   PoPStatus = "POP_ACTIVE"
	PoPStatusDraining PoPStatus = "POP_DRAINING"
	PoPStatusDegraded PoPStatus = "POP_DEGRADED"
	PoPStatusOffline  PoPStatus = "POP_OFFLINE"
)

type BGPState string

const (
	BGPStateAnnounced BGPState = "ANNOUNCED"
	BGPStateWithdrawn BGPState = "WITHDRAWN"
	BGPStatePending   BGPState = "PENDING"
)

// EdgePoP represents an Edge Point of Presence in the topology mesh
type EdgePoP struct {
	ID               string    `json:"id"`      // e.g. "dhaka", "singapore", "frankfurt", "virginia"
	Name             string    `json:"name"`    // e.g. "Dhaka BDIX Edge 01 (Simulated)"
	Region           string    `json:"region"`  // e.g. "asia-south1"
	City             string    `json:"city"`    // e.g. "Dhaka"
	Country          string    `json:"country"` // e.g. "BD"
	Latitude         float64   `json:"latitude"`
	Longitude        float64   `json:"longitude"`
	ASN              int       `json:"asn"`          // RFC 6996 Private ASN for simulation: 64512
	AnycastIPv4      string    `json:"anycast_ipv4"` // RFC 5737 TEST-NET-2: "198.51.100.1"
	AnycastIPv6      string    `json:"anycast_ipv6"` // RFC 3849 Documentation Prefix: "2001:db8::1"
	BGPState         BGPState  `json:"bgp_state"`    // ANNOUNCED or WITHDRAWN
	Status           PoPStatus `json:"status"`
	Mode             string    `json:"mode"`         // "SIMULATION" or "PRODUCTION"
	Source           string    `json:"source"`       // "SIMULATED", "PROBE", or "OPERATOR"
	IsSimulated      bool      `json:"is_simulated"` // true for simulated testbeds
	NodeCount        int       `json:"node_count"`
	HealthyNodeCount int       `json:"healthy_node_count"`
	CreatedAt        time.Time `json:"created_at"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// EdgeNode represents an individual proxy/cache server within a PoP
type EdgeNode struct {
	ID                  string    `json:"id"`
	PoPID               string    `json:"pop_id"`
	Hostname            string    `json:"hostname"`
	IPAddress           string    `json:"ip_address"`
	ActiveConfigVersion string    `json:"active_config_version"`
	Status              string    `json:"status"` // "HEALTHY", "DEGRADED", "OFFLINE"
	CPUUsagePercent     float64   `json:"cpu_usage_percent"`
	MemoryUsageMB       int64     `json:"memory_usage_mb"`
	ActiveConnections   int       `json:"active_connections"`
	LastHeartbeat       time.Time `json:"last_heartbeat"`
}

// GatewayOriginSync models a validated and pinned upstream origin destination
type GatewayOriginSync struct {
	Address  string `json:"address"` // Resolved and pinned IP address
	Port     int    `json:"port"`
	Protocol string `json:"protocol"` // "HTTP" or "HTTPS"
	SNI      string `json:"sni,omitempty"`
	Weight   int    `json:"weight,omitempty"`
}

// GatewayPathRouteSync models a path-prefix matched routing table entry
type GatewayPathRouteSync struct {
	PathPrefix string              `json:"path_prefix"`
	Priority   int                 `json:"priority"`
	Origins    []GatewayOriginSync `json:"origins"`
	Targets    []string            `json:"targets,omitempty"`
}

// GatewaySecuritySync models tenant-level security shield rules
type GatewaySecuritySync struct {
	WAFEnabled         bool     `json:"waf_enabled"`
	BlockSQLi          bool     `json:"block_sqli"`
	BlockXSS           bool     `json:"block_xss"`
	BlockPathTraversal bool     `json:"block_path_traversal"`
	BlockedPaths       []string `json:"blocked_paths,omitempty"`
	RateLimitEnabled   bool     `json:"rate_limit_enabled"`
	RequestsPerSecond  uint32   `json:"requests_per_second"`
	BurstCapacity      uint32   `json:"burst_capacity"`
}

// GatewayCacheSync models tenant-level cache policy
type GatewayCacheSync struct {
	Enabled           bool     `json:"enabled"`
	DefaultTTLSeconds uint64   `json:"default_ttl_seconds"`
	BypassPaths       []string `json:"bypass_paths,omitempty"`
}

// GatewayRouteSync models declarative host-to-origin mapping for the Rust edge gateway
type GatewayRouteSync struct {
	Host       string                 `json:"host"`
	PathRoutes []GatewayPathRouteSync `json:"path_routes,omitempty"`
	Targets    []string               `json:"targets,omitempty"`
	Security   *GatewaySecuritySync   `json:"security,omitempty"`
	Cache      *GatewayCacheSync      `json:"cache,omitempty"`
}

// GatewayAIProviderSync models validated AI compute provider destination for edge gateway
type GatewayAIProviderSync struct {
	ID                      string  `json:"id"`
	Name                    string  `json:"name"`
	Endpoint                string  `json:"endpoint"`
	ProviderType            string  `json:"provider_type"`
	APIKey                  string  `json:"api_key,omitempty"`
	CostPerMTokens          float64 `json:"cost_per_m_tokens"`
	Priority                uint32  `json:"priority"`
	SovereigntyJurisdiction string  `json:"sovereignty_jurisdiction,omitempty"`
	FailoverCooldownSecs    uint64  `json:"failover_cooldown_secs"`
}

// PoPConfigSync delivers synchronized Envoy configuration tailored for a specific PoP
type PoPConfigSync struct {
	PoPID           string                  `json:"pop_id"`
	ConfigVersion   string                  `json:"config_version"`
	ChecksumSHA256  string                  `json:"checksum_sha256"`
	CanonicalSHA256 string                  `json:"canonical_sha256,omitempty"`
	CompiledAt      time.Time               `json:"compiled_at"`
	TopologiesCount int                     `json:"topologies_count"`
	EnvoyConfig     interface{}             `json:"envoy_config"`
	Routes          []GatewayRouteSync      `json:"routes,omitempty"`
	AIProviders     []GatewayAIProviderSync `json:"ai_providers,omitempty"`
}

type AIProviderType string

const (
	AIProviderTypeOpenAI    AIProviderType = "openai"
	AIProviderTypeAzure     AIProviderType = "azure"
	AIProviderTypeCoreWeave AIProviderType = "coreweave"
	AIProviderTypeVLLM      AIProviderType = "vllm"
	AIProviderTypeOnPrem    AIProviderType = "onprem"
	AIProviderTypeAWS       AIProviderType = "aws"
)

// AIProvider represents an external or on-prem AI inference compute provider
type AIProvider struct {
	ID                      string    `json:"id"`
	ProjectID               string    `json:"project_id"`
	Name                    string    `json:"name"`
	Endpoint                string    `json:"endpoint"`
	ProviderType            string    `json:"provider_type"` // "openai", "azure", "coreweave", "vllm", "onprem", "aws"
	APIKey                  string    `json:"api_key,omitempty"`
	CostPerMTokens          float64   `json:"cost_per_m_tokens"`
	Priority                uint32    `json:"priority"`
	SovereigntyJurisdiction string    `json:"sovereignty_jurisdiction,omitempty"` // e.g. "BD", "EU", "GLOBAL"
	FailoverCooldownSecs    uint64    `json:"failover_cooldown_secs"`
	Enabled                 bool      `json:"enabled"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

// AIProviderResponse masks API keys in public responses (Rules 18, 19)
type AIProviderResponse struct {
	ID                      string    `json:"id"`
	ProjectID               string    `json:"project_id"`
	Name                    string    `json:"name"`
	Endpoint                string    `json:"endpoint"`
	ProviderType            string    `json:"provider_type"`
	APIKeyRedacted          string    `json:"api_key_redacted"`
	CostPerMTokens          float64   `json:"cost_per_m_tokens"`
	Priority                uint32    `json:"priority"`
	SovereigntyJurisdiction string    `json:"sovereignty_jurisdiction,omitempty"`
	FailoverCooldownSecs    uint64    `json:"failover_cooldown_secs"`
	Enabled                 bool      `json:"enabled"`
	CreatedAt               time.Time `json:"created_at"`
	UpdatedAt               time.Time `json:"updated_at"`
}

func (p *AIProvider) ToResponse() AIProviderResponse {
	redacted := "[NONE]"
	if p.APIKey != "" {
		if len(p.APIKey) > 8 {
			redacted = p.APIKey[:3] + "..." + p.APIKey[len(p.APIKey)-4:]
		} else {
			redacted = "[REDACTED]"
		}
	}
	return AIProviderResponse{
		ID:                      p.ID,
		ProjectID:               p.ProjectID,
		Name:                    p.Name,
		Endpoint:                p.Endpoint,
		ProviderType:            p.ProviderType,
		APIKeyRedacted:          redacted,
		CostPerMTokens:          p.CostPerMTokens,
		Priority:                p.Priority,
		SovereigntyJurisdiction: p.SovereigntyJurisdiction,
		FailoverCooldownSecs:    p.FailoverCooldownSecs,
		Enabled:                 p.Enabled,
		CreatedAt:               p.CreatedAt,
		UpdatedAt:               p.UpdatedAt,
	}
}

// LatencyRoute models inter-PoP or PoP-to-Origin physical fiber RTT
type LatencyRoute struct {
	FromPoP   string  `json:"from_pop"`
	ToTarget  string  `json:"to_target"` // PoP ID or Origin Region
	LatencyMs float64 `json:"latency_ms"`
	Status    string  `json:"status"` // "ACTIVE", "CONGESTED"
}

// GeoSteeringDecision represents intelligent origin selection for a request at a specific PoP
type GeoSteeringDecision struct {
	ClientPoP        string  `json:"client_pop"`
	DomainID         string  `json:"domain_id"`
	SelectedOriginID string  `json:"selected_origin_id"`
	OriginAddress    string  `json:"origin_address"`
	OriginRegion     string  `json:"origin_region"`
	DirectLatencyMs  float64 `json:"direct_latency_ms"`
	Reason           string  `json:"reason"` // "LOWEST_RTT", "FAILOVER_CROSS_POP", "ROUND_ROBIN"
}
