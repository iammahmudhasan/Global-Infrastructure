package store

import (
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

// Repository defines the complete storage and persistence contract for the Control Plane.
// Implemented by in-memory Store and durable PostgreSQL repository backends.
type Repository interface {
	// Quotas
	SetProjectQuota(projectID string, quota ProjectQuota)
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
	SaveOriginPoolBypass(p *model.OriginPool)
	AddOrigin(o *model.Origin) error
	GetOriginPool(poolID string) (*model.OriginPool, error)

	// Health Monitoring
	SaveHealthMonitor(hm *model.HealthMonitor)
	GetHealthMonitor(poolID string) *model.HealthMonitor
	SaveOriginHealthState(st *model.OriginEndpointState)
	GetOriginHealthState(originID string) *model.OriginEndpointState
	ListPoolHealthStates(poolID string) []*model.OriginEndpointState
	UpdateOriginHealthy(originID string, healthy bool)

	// Routes
	SaveRoute(r *model.Route)
	GetRoutes(domainID string) []*model.Route

	// Security Policy & WAF
	SaveSecurityPolicy(sp *model.SecurityPolicy)
	GetSecurityPolicy(domainID string) *model.SecurityPolicy
	AddWAFRule(domainID string, rule model.WAFRule) error
	GetWAFRules(domainID string) []model.WAFRule
	DeleteWAFRule(domainID string, ruleID string) error
	SetRateLimitRules(domainID string, rules []model.RateLimitRule) error
	GetRateLimitRules(domainID string) []model.RateLimitRule
	RecordSecurityEvent(ev model.SecurityEvent)
	GetSecurityEvents(domainID string, limit int) []model.SecurityEvent

	// Cache Policy & Rules
	SaveCachePolicy(cp *model.CachePolicy)
	GetCachePolicy(domainID string) *model.CachePolicy
	AddCacheRule(domainID string, rule model.CacheRule) error
	GetCacheRules(domainID string) []model.CacheRule
	DeleteCacheRule(domainID string, ruleID string) error

	// Certificates & ACME
	SaveCertificate(cert *model.Certificate)
	GetCertificate(domainID string) *model.Certificate
	GetPendingCertificate(domainID string) *model.Certificate
	SaveACMEChallenge(ch *model.ACMEChallenge)
	GetACMEChallengeByToken(token string) *model.ACMEChallenge
	UpdateACMEChallengeStatus(token string, status model.ChallengeStatus)
	SaveTLSSettings(domainID string, settings *model.TLSSettings)
	GetTLSSettings(domainID string) *model.TLSSettings

	// Topologies (Compiled snapshots for Envoy and PoP Edge nodes)
	GetActiveTopologies() []*DomainTopology
	GetActiveTopologiesForPoP(popID string) []*DomainTopology
}

// Ensure *Store satisfies Repository at compile time.
var _ Repository = (*Store)(nil)
