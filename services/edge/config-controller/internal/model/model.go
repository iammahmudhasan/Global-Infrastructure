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

// Domain represents a customer application endpoint fronted by NexusEdge
type Domain struct {
	ID             string       `json:"id"`
	ProjectID      string       `json:"project_id"`
	Hostname       string       `json:"hostname"`
	Status         DomainStatus `json:"status"`
	OnboardingType string       `json:"onboarding_type"` // "CNAME" or "NAMESERVER"
	CNAMETarget    string       `json:"cname_target"`    // e.g. "cname-d101.edge.nexusedge.net"
	CreatedAt      time.Time    `json:"created_at"`
	UpdatedAt      time.Time    `json:"updated_at"`
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
	IntervalSeconds     int                 `json:"interval_seconds"`     // default 10s
	TimeoutSeconds      int                 `json:"timeout_seconds"`      // default 2s
	HealthyThreshold    int                 `json:"healthy_threshold"`    // consecutive passes, default 2
	UnhealthyThreshold  int                 `json:"unhealthy_threshold"`  // consecutive failures, default 3
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
}

type Origin struct {
	ID       string   `json:"id"`
	PoolID   string   `json:"pool_id"`
	Address  string   `json:"address"` // FQDN or IP
	Port     int      `json:"port"`
	Protocol Protocol `json:"protocol"` // "HTTP" or "HTTPS"
	Weight   int      `json:"weight"`
	Healthy  bool     `json:"healthy"`
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
	WAFMatchIPCIDR    WAFMatchType = "IP_CIDR"
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
	PrivateKeyPEM     string            `json:"private_key_pem,omitempty"`
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
	EnforceHTTPS  bool   `json:"enforce_https"`  // 301 redirect HTTP to HTTPS
	MinTLSVersion string `json:"min_tls_version"` // "TLSv1.2", "TLSv1.3"
	HSTS          bool   `json:"hsts"`
	HSTSMaxAge    int    `json:"hsts_max_age"`
}
