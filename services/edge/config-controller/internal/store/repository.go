package store

import (
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

// Repository defines the complete storage and persistence contract for the Control Plane.
// Implemented by in-memory Store and durable PostgreSQL repository backends.
type Repository interface {
	// Quotas
	SetProjectQuota(projectID string, quota ProjectQuota) error
	GetProjectQuota(projectID string) ProjectQuota

	// Domains
	SaveDomain(d *model.Domain) error
	GetDomain(id string) (*model.Domain, error)
	GetDomainByHost(hostname string) (*model.Domain, error)
	ListDomainsByProject(projectID string) []*model.Domain
	ListDomains() []*model.Domain
	UpdateDomainStatus(id string, status model.DomainStatus) error
	DeleteDomain(domainID string) error
	SweepExpiredPendingDomains(maxAge time.Duration) int

	// Origin Pools & Endpoints
	SaveOriginPool(p *model.OriginPool) error
	SaveOriginPoolBypass(p *model.OriginPool) error
	AddOrigin(o *model.Origin) error
	GetOriginPool(poolID string) (*model.OriginPool, error)

	// Health Monitoring
	SaveHealthMonitor(hm *model.HealthMonitor) error
	GetHealthMonitor(poolID string) *model.HealthMonitor
	SaveOriginHealthState(st *model.OriginEndpointState) error
	GetOriginHealthState(originID string) *model.OriginEndpointState
	ListPoolHealthStates(poolID string) []*model.OriginEndpointState
	UpdateOriginHealthy(originID string, healthy bool) error

	// Routes
	SaveRoute(r *model.Route) error
	GetRoutes(domainID string) []*model.Route

	// Security Policy & WAF
	SaveSecurityPolicy(sp *model.SecurityPolicy) error
	GetSecurityPolicy(domainID string) *model.SecurityPolicy
	AddWAFRule(domainID string, rule model.WAFRule) error
	GetWAFRules(domainID string) []model.WAFRule
	DeleteWAFRule(domainID string, ruleID string) error
	SetRateLimitRules(domainID string, rules []model.RateLimitRule) error
	GetRateLimitRules(domainID string) []model.RateLimitRule
	RecordSecurityEvent(ev model.SecurityEvent) error
	GetSecurityEvents(domainID string, limit int) []model.SecurityEvent

	// Cache Policy & Rules
	SaveCachePolicy(cp *model.CachePolicy) error
	GetCachePolicy(domainID string) *model.CachePolicy
	AddCacheRule(domainID string, rule model.CacheRule) error
	GetCacheRules(domainID string) []model.CacheRule
	DeleteCacheRule(domainID string, ruleID string) error

	// Certificates & ACME
	SaveCertificate(cert *model.Certificate) error
	GetCertificate(domainID string) *model.Certificate
	GetPendingCertificate(domainID string) *model.Certificate
	SaveACMEChallenge(ch *model.ACMEChallenge) error
	GetACMEChallengeByToken(token string) *model.ACMEChallenge
	UpdateACMEChallengeStatus(token string, status model.ChallengeStatus) error
	SaveTLSSettings(domainID string, settings *model.TLSSettings) error
	GetTLSSettings(domainID string) *model.TLSSettings

	// Topologies (Compiled snapshots for Envoy and PoP Edge nodes)
	GetActiveTopologies() []*DomainTopology
	GetActiveTopologiesForPoP(popID string) []*DomainTopology

	// AI Compute Providers
	SaveAIProvider(p *model.AIProvider) error
	GetAIProvider(id string) (*model.AIProvider, error)
	ListAIProvidersByProject(projectID string) []*model.AIProvider
	ListAIProviders() []*model.AIProvider
	DeleteAIProvider(id string) error
}

// Ensure *Store satisfies Repository at compile time.
var _ Repository = (*Store)(nil)
