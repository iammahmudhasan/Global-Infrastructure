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

type OriginPool struct {
	ID          string      `json:"id"`
	ProjectID   string      `json:"project_id"`
	Name        string      `json:"name"`
	LBAlgorithm LBAlgorithm `json:"lb_algorithm"`
	Origins     []Origin    `json:"origins"`
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

type SecurityPolicy struct {
	ID               string `json:"id"`
	DomainID         string `json:"domain_id"`
	WAFEnabled       bool   `json:"waf_enabled"`
	WAFMode          string `json:"waf_mode"` // "BLOCK", "LOG"
	RateLimitEnabled bool   `json:"rate_limit_enabled"`
	RateLimitRPM     int    `json:"rate_limit_rpm"`
}

type CachePolicy struct {
	ID                    string `json:"id"`
	DomainID              string `json:"domain_id"`
	CacheEnabled          bool   `json:"cache_enabled"`
	DefaultTTLSeconds     int    `json:"default_ttl_seconds"`
	RespectOriginHeaders  bool   `json:"respect_origin_headers"`
}

type Certificate struct {
	ID        string    `json:"id"`
	DomainID  string    `json:"domain_id"`
	Status    string    `json:"status"` // "PENDING_ISSUANCE", "ACTIVE"
	Issuer    string    `json:"issuer"`
	ExpiresAt time.Time `json:"expires_at"`
}
