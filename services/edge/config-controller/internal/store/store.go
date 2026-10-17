package store

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

const (
	MaxOriginsPerPool           = 256
	MaxWAFRulesPerDomain        = 1000
	MaxRateLimitRulesPerDomain  = 500
	MaxCacheRulesPerDomain      = 1000
	DefaultMaxDomainsPerProject = 50 // Default per-project domain ceiling (Finding 2)
	MaxAIProvidersPerProject    = 100

	// WAF Rule Size Limits (Finding 2)
	MaxWAFRuleName        = 128
	MaxWAFRuleDescription = 1024
	MaxWAFRulePattern     = 4096

	// Cache Rule Size Limits (Finding 3)
	MaxCacheRuleName        = 128
	MaxCachePathPattern     = 4096
	MaxCacheRuleParamCount  = 64
	MaxCacheRuleParamLength = 128
	MaxCustomHeaderCount    = 32
	MaxCustomHeaderName     = 256

	// Rate Limit Rule Field Limits (P2 Finding 2)
	MaxRateLimitPathPrefix = 4096
	MaxRateLimitHeaderName = 256

	// Cache TTL Limits (P2 Finding 3)
	MaxCacheTTLSeconds = 7 * 24 * 60 * 60 // 7 days (604,800 seconds)

	// AllowedPoPs Bounds (P2 Finding 3)
	MaxAllowedPoPsPerResource = 16
	MaxPoPIDLength            = 64

	// Security Event Bounds (Finding 1)
	MaxSecurityEventsPerDomain          = 1000
	MaxSecurityEventByteBudgetPerDomain = 4 * 1024 * 1024 // 4 MiB cap per domain
)

var (
	ErrNotFound             = errors.New("entity not found")
	ErrAlreadyExists        = errors.New("entity already exists")
	ErrMixedOriginProtocols = errors.New("all origins in an origin pool must share the same protocol")
	ErrOriginPoolFull       = errors.New("origin pool limit reached (max 256)")
	ErrRuleLimitExceeded    = errors.New("rule limit exceeded for domain")
	ErrProjectQuotaExceeded = errors.New("project domain quota exceeded")
	ErrRuleSizeExceeded     = errors.New("rule field exceeds maximum allowed size")
)

type ProjectQuota struct {
	MaxDomains int
}

// ValidateAllowedPoPs validates and normalizes allowed PoP lists (P2 Finding 3)
// Enforces max 16 PoPs per resource, max 64 chars per token, no empty tokens, and case-insensitive deduplication.
func ValidateAllowedPoPs(pops []string) error {
	if len(pops) > MaxAllowedPoPsPerResource {
		return ErrRuleSizeExceeded
	}

	seen := make(map[string]struct{}, len(pops))
	for _, pop := range pops {
		pop = strings.TrimSpace(pop)
		if pop == "" || len(pop) > MaxPoPIDLength {
			return ErrRuleSizeExceeded
		}

		key := strings.ToLower(pop)
		if _, exists := seen[key]; exists {
			return ErrRuleSizeExceeded
		}
		seen[key] = struct{}{}
	}

	return nil
}

type Store struct {
	mu                  sync.RWMutex
	version             uint64
	popTopologyCache    map[string][]*DomainTopology
	activeTopologyCache []*DomainTopology
	domains             map[string]*model.Domain
	hostIndex           map[string]string // hostname -> domain ID
	projectQuotas       map[string]ProjectQuota
	projectDomainCount  map[string]int
	pools               map[string]*model.OriginPool
	origins             map[string]*model.Origin
	routes              map[string][]*model.Route             // domain ID -> routes
	security            map[string]*model.SecurityPolicy      // domain ID -> policy
	wafRules            map[string][]model.WAFRule            // domain ID -> WAF rules
	rateLimits          map[string][]model.RateLimitRule      // domain ID -> Rate limit rules
	events              map[string][]model.SecurityEvent      // domain ID -> Security events
	cache               map[string]*model.CachePolicy         // domain ID -> policy
	cacheRules          map[string][]model.CacheRule          // domain ID -> Cache rules
	monitors            map[string]*model.HealthMonitor       // pool ID -> HealthMonitor
	healthStates        map[string]*model.OriginEndpointState // origin ID -> OriginEndpointState
	certificates        map[string]*model.Certificate         // domain ID -> certificate
	pendingCertificates map[string]*model.Certificate         // domain ID -> pending renewal/issuance certificate
	challenges          map[string]*model.ACMEChallenge       // token -> ACMEChallenge
	tlsSettings         map[string]*model.TLSSettings         // domain ID -> TLSSettings
	aiProviders         map[string]*model.AIProvider          // provider ID -> AIProvider
	auditLogs           []*model.AuditLog
	auditLogMap         map[string]*model.AuditLog // id -> AuditLog
	outboxEvents        []*inMemoryOutboxEntry
}

type inMemoryOutboxEntry struct {
	event       OutboxEvent
	lockedBy    string
	lockedUntil time.Time
}

func NewStore() *Store {
	return &Store{
		popTopologyCache:    make(map[string][]*DomainTopology),
		domains:             make(map[string]*model.Domain),
		hostIndex:           make(map[string]string),
		projectQuotas:       make(map[string]ProjectQuota),
		projectDomainCount:  make(map[string]int),
		pools:               make(map[string]*model.OriginPool),
		origins:             make(map[string]*model.Origin),
		routes:              make(map[string][]*model.Route),
		security:            make(map[string]*model.SecurityPolicy),
		wafRules:            make(map[string][]model.WAFRule),
		rateLimits:          make(map[string][]model.RateLimitRule),
		events:              make(map[string][]model.SecurityEvent),
		cache:               make(map[string]*model.CachePolicy),
		cacheRules:          make(map[string][]model.CacheRule),
		monitors:            make(map[string]*model.HealthMonitor),
		healthStates:        make(map[string]*model.OriginEndpointState),
		certificates:        make(map[string]*model.Certificate),
		pendingCertificates: make(map[string]*model.Certificate),
		challenges:          make(map[string]*model.ACMEChallenge),
		tlsSettings:         make(map[string]*model.TLSSettings),
		aiProviders:         make(map[string]*model.AIProvider),
		auditLogs:           make([]*model.AuditLog, 0),
		auditLogMap:         make(map[string]*model.AuditLog),
		outboxEvents:        make([]*inMemoryOutboxEntry, 0),
	}
}

func (s *Store) invalidateCachesLocked() {
	s.version++
	s.popTopologyCache = make(map[string][]*DomainTopology)
	s.activeTopologyCache = nil
}

func (s *Store) SetProjectQuota(projectID string, quota ProjectQuota) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projectQuotas[projectID] = quota
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetProjectQuota(projectID string) ProjectQuota {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if q, ok := s.projectQuotas[projectID]; ok && q.MaxDomains > 0 {
		return q
	}
	return ProjectQuota{MaxDomains: DefaultMaxDomainsPerProject}
}

func (s *Store) SaveDomain(d *model.Domain) error {
	if err := ValidateAllowedPoPs(d.AllowedPoPs); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if existingID, exists := s.hostIndex[d.Hostname]; exists && existingID != d.ID {
		return ErrAlreadyExists
	}

	isNew := s.domains[d.ID] == nil
	if isNew {
		maxDomains := DefaultMaxDomainsPerProject
		if q, ok := s.projectQuotas[d.ProjectID]; ok && q.MaxDomains > 0 {
			maxDomains = q.MaxDomains
		}

		if d.ProjectID != "" && s.projectDomainCount[d.ProjectID] >= maxDomains {
			return ErrProjectQuotaExceeded
		}
	}

	cloned := cloneDomain(d)
	s.domains[d.ID] = cloned
	s.hostIndex[d.Hostname] = d.ID
	if isNew && d.ProjectID != "" {
		s.projectDomainCount[d.ProjectID]++
	}

	eventID := fmt.Sprintf("evt-cfg-%d-%s", time.Now().UnixNano(), d.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"domain_id":    d.ID,
		"project_id":   d.ProjectID,
		"hostname":     d.Hostname,
		"status":       string(d.Status),
		"allowed_pops": d.AllowedPoPs,
		"version":      d.Version,
		"updated_at":   time.Now().UTC().Format(time.RFC3339),
	})
	s.saveOutboxEventLocked(&OutboxEvent{
		EventID:       eventID,
		AggregateType: "domain",
		AggregateID:   d.ID,
		EventType:     "domain.config.changed",
		Payload:       payloadJSON,
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	s.invalidateCachesLocked()
	return nil
}

func cloneOrigin(o *model.Origin) *model.Origin {
	if o == nil {
		return nil
	}
	cp := *o
	cp.AllowedPoPs = append([]string(nil), o.AllowedPoPs...)
	return &cp
}

func cloneDomain(d *model.Domain) *model.Domain {
	if d == nil {
		return nil
	}
	cp := *d
	cp.AllowedPoPs = append([]string(nil), d.AllowedPoPs...)
	return &cp
}

func cloneOriginPool(p *model.OriginPool) *model.OriginPool {
	if p == nil {
		return nil
	}
	cp := *p
	cp.AllowedPoPs = append([]string(nil), p.AllowedPoPs...)
	cp.Origins = make([]model.Origin, len(p.Origins))
	for i, o := range p.Origins {
		cp.Origins[i] = o
		cp.Origins[i].AllowedPoPs = append([]string(nil), o.AllowedPoPs...)
	}
	if p.HealthMonitor != nil {
		hm := *p.HealthMonitor
		if hm.ExpectedStatusCodes != nil {
			hm.ExpectedStatusCodes = append([]int(nil), hm.ExpectedStatusCodes...)
		}
		cp.HealthMonitor = &hm
	}
	return &cp
}

func cloneHealthMonitor(hm *model.HealthMonitor) *model.HealthMonitor {
	if hm == nil {
		return nil
	}
	cp := *hm
	if hm.ExpectedStatusCodes != nil {
		cp.ExpectedStatusCodes = append([]int(nil), hm.ExpectedStatusCodes...)
	}
	return &cp
}

func cloneOriginEndpointState(st *model.OriginEndpointState) *model.OriginEndpointState {
	if st == nil {
		return nil
	}
	cp := *st
	return &cp
}

func cloneRoute(r *model.Route) *model.Route {
	if r == nil {
		return nil
	}
	cp := *r
	return &cp
}

func cloneSecurityPolicy(sp *model.SecurityPolicy) *model.SecurityPolicy {
	if sp == nil {
		return nil
	}
	cp := *sp
	cp.WAFRules = append([]model.WAFRule(nil), sp.WAFRules...)
	cp.RateLimitRules = append([]model.RateLimitRule(nil), sp.RateLimitRules...)
	return &cp
}

func cloneCacheRule(r model.CacheRule) model.CacheRule {
	cp := r
	cp.IgnoredParams = append([]string(nil), r.IgnoredParams...)
	cp.IncludedParams = append([]string(nil), r.IncludedParams...)
	cp.CustomHeadersToInclude = append([]string(nil), r.CustomHeadersToInclude...)
	return cp
}

func cloneCachePolicy(cp *model.CachePolicy) *model.CachePolicy {
	if cp == nil {
		return nil
	}
	cpc := *cp
	cpc.CacheRules = make([]model.CacheRule, len(cp.CacheRules))
	for i, rule := range cp.CacheRules {
		cpc.CacheRules[i] = cloneCacheRule(rule)
	}
	return &cpc
}

func cloneCertificate(cert *model.Certificate) *model.Certificate {
	if cert == nil {
		return nil
	}
	cp := *cert
	cp.Domains = append([]string(nil), cert.Domains...)
	return &cp
}

func cloneACMEChallenge(ch *model.ACMEChallenge) *model.ACMEChallenge {
	if ch == nil {
		return nil
	}
	cp := *ch
	return &cp
}

func cloneTLSSettings(st *model.TLSSettings) *model.TLSSettings {
	if st == nil {
		return nil
	}
	cp := *st
	return &cp
}

func (s *Store) GetDomain(id string) (*model.Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	d, exists := s.domains[id]
	if !exists {
		return nil, ErrNotFound
	}
	return cloneDomain(d), nil
}

func (s *Store) GetDomainByHost(hostname string) (*model.Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.hostIndex[hostname]
	if !exists {
		return nil, ErrNotFound
	}
	return cloneDomain(s.domains[id]), nil
}

func (s *Store) ListDomainsByProject(projectID string) []*model.Domain {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*model.Domain
	for _, d := range s.domains {
		if d.ProjectID == projectID {
			list = append(list, cloneDomain(d))
		}
	}
	return list
}

func (s *Store) ListDomains() []*model.Domain {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*model.Domain
	for _, d := range s.domains {
		list = append(list, cloneDomain(d))
	}
	return list
}

func (s *Store) UpdateDomainStatus(id string, status model.DomainStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, exists := s.domains[id]
	if !exists {
		return ErrNotFound
	}
	d.Status = status

	eventID := fmt.Sprintf("evt-status-%d-%s", time.Now().UnixNano(), id)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"domain_id": id,
		"status":    string(status),
	})
	s.saveOutboxEventLocked(&OutboxEvent{
		EventID:       eventID,
		AggregateType: "domain",
		AggregateID:   id,
		EventType:     "domain.status.changed",
		Payload:       payloadJSON,
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	s.invalidateCachesLocked()
	return nil
}

func (s *Store) deleteDomainLocked(domainID string) error {
	dom, ok := s.domains[domainID]
	if !ok {
		return ErrNotFound
	}

	delete(s.hostIndex, dom.Hostname)
	if dom.ProjectID != "" && s.projectDomainCount[dom.ProjectID] > 0 {
		s.projectDomainCount[dom.ProjectID]--
		if s.projectDomainCount[dom.ProjectID] == 0 {
			delete(s.projectDomainCount, dom.ProjectID)
		}
	}
	delete(s.domains, domainID)

	// Cascade delete routes & associated pools and origins (Finding 2)
	routes := s.routes[domainID]
	delete(s.routes, domainID)
	for _, rt := range routes {
		if rt != nil && rt.PoolID != "" {
			for origID, orig := range s.origins {
				if orig.PoolID == rt.PoolID {
					delete(s.origins, origID)
					delete(s.healthStates, origID)
				}
			}
			delete(s.pools, rt.PoolID)
			delete(s.monitors, rt.PoolID)
		}
	}

	delete(s.security, domainID)
	delete(s.wafRules, domainID)
	delete(s.rateLimits, domainID)
	delete(s.events, domainID)
	delete(s.cache, domainID)
	delete(s.cacheRules, domainID)
	delete(s.certificates, domainID)
	delete(s.pendingCertificates, domainID)
	delete(s.tlsSettings, domainID)

	eventID := fmt.Sprintf("evt-del-%d-%s", time.Now().UnixNano(), domainID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"domain_id":  domainID,
		"deleted_at": time.Now().UTC().Format(time.RFC3339),
	})
	s.saveOutboxEventLocked(&OutboxEvent{
		EventID:       eventID,
		AggregateType: "domain",
		AggregateID:   domainID,
		EventType:     "domain.deleted",
		Payload:       payloadJSON,
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	s.invalidateCachesLocked()
	return nil
}

func (s *Store) DeleteDomain(domainID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deleteDomainLocked(domainID)
}

func (s *Store) SweepExpiredPendingDomains(maxAge time.Duration) int {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var expiredIDs []string
	for id, dom := range s.domains {
		if dom.Status == model.DomainStatusPendingVerification && now.Sub(dom.CreatedAt) > maxAge {
			expiredIDs = append(expiredIDs, id)
		}
	}

	for _, id := range expiredIDs {
		_ = s.deleteDomainLocked(id)
	}

	return len(expiredIDs)
}

func (s *Store) SaveOriginPool(p *model.OriginPool) error {
	if err := ValidateAllowedPoPs(p.AllowedPoPs); err != nil {
		return err
	}
	for _, o := range p.Origins {
		if err := ValidateAllowedPoPs(o.AllowedPoPs); err != nil {
			return err
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 1; i < len(p.Origins); i++ {
		if p.Origins[i].Protocol != p.Origins[0].Protocol {
			return ErrMixedOriginProtocols
		}
	}

	s.pools[p.ID] = cloneOriginPool(p)

	eventID := fmt.Sprintf("evt-pool-%d-%s", time.Now().UnixNano(), p.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"pool_id":      p.ID,
		"project_id":   p.ProjectID,
		"name":         p.Name,
		"lb_algorithm": string(p.LBAlgorithm),
		"allowed_pops": p.AllowedPoPs,
		"origin_count": len(p.Origins),
		"updated_at":   time.Now().UTC().Format(time.RFC3339),
	})
	s.saveOutboxEventLocked(&OutboxEvent{
		EventID:       eventID,
		AggregateType: "pool",
		AggregateID:   p.ID,
		EventType:     "pool.config.changed",
		Payload:       payloadJSON,
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	s.invalidateCachesLocked()
	return nil
}

// SaveOriginPoolBypass saves an origin pool directly without validation (used in test fixtures)
func (s *Store) SaveOriginPoolBypass(p *model.OriginPool) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pools[p.ID] = cloneOriginPool(p)
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) AddOrigin(o *model.Origin) error {
	if err := ValidateAllowedPoPs(o.AllowedPoPs); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pool, exists := s.pools[o.PoolID]
	if !exists {
		return ErrNotFound
	}

	if len(pool.Origins) >= MaxOriginsPerPool {
		return ErrOriginPoolFull
	}

	for _, existing := range pool.Origins {
		if existing.Protocol != o.Protocol {
			return ErrMixedOriginProtocols
		}
	}

	cloned := cloneOrigin(o)
	s.origins[o.ID] = cloned
	pool.Origins = append(pool.Origins, *cloned)
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetOriginPool(poolID string) (*model.OriginPool, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.pools[poolID]
	if !exists {
		return nil, ErrNotFound
	}
	cp := cloneOriginPool(p)
	if hm := s.monitors[poolID]; hm != nil {
		cp.HealthMonitor = cloneHealthMonitor(hm)
	}
	return cp, nil
}

func (s *Store) SaveHealthMonitor(hm *model.HealthMonitor) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := cloneHealthMonitor(hm)
	s.monitors[cloned.PoolID] = cloned
	if pool, exists := s.pools[cloned.PoolID]; exists {
		pool.HealthMonitor = cloneHealthMonitor(cloned)
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetHealthMonitor(poolID string) *model.HealthMonitor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneHealthMonitor(s.monitors[poolID])
}

func (s *Store) SaveOriginHealthState(st *model.OriginEndpointState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := cloneOriginEndpointState(st)
	s.healthStates[cloned.OriginID] = cloned

	// Synchronize with origin entity healthy flag
	if orig, exists := s.origins[cloned.OriginID]; exists {
		orig.Healthy = cloned.Healthy
	}
	if pool, exists := s.pools[cloned.PoolID]; exists {
		for i := range pool.Origins {
			if pool.Origins[i].ID == cloned.OriginID {
				pool.Origins[i].Healthy = cloned.Healthy
			}
		}
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetOriginHealthState(originID string) *model.OriginEndpointState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneOriginEndpointState(s.healthStates[originID])
}

func (s *Store) ListPoolHealthStates(poolID string) []*model.OriginEndpointState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var states []*model.OriginEndpointState
	pool, exists := s.pools[poolID]
	if !exists {
		return states
	}

	for _, o := range pool.Origins {
		if st, exists := s.healthStates[o.ID]; exists {
			states = append(states, cloneOriginEndpointState(st))
		} else {
			// Return default initial state
			states = append(states, &model.OriginEndpointState{
				OriginID: o.ID,
				PoolID:   poolID,
				Address:  o.Address,
				Port:     o.Port,
				Healthy:  o.Healthy,
			})
		}
	}
	return states
}

func (s *Store) UpdateOriginHealthy(originID string, healthy bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if orig, exists := s.origins[originID]; exists {
		orig.Healthy = healthy
		if pool, exists := s.pools[orig.PoolID]; exists {
			for i := range pool.Origins {
				if pool.Origins[i].ID == originID {
					pool.Origins[i].Healthy = healthy
				}
			}
		}
	}
	if st, exists := s.healthStates[originID]; exists {
		st.Healthy = healthy
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) SaveRoute(r *model.Route) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[r.DomainID] = append(s.routes[r.DomainID], cloneRoute(r))

	eventID := fmt.Sprintf("evt-route-%d-%s", time.Now().UnixNano(), r.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"route_id":    r.ID,
		"domain_id":   r.DomainID,
		"pool_id":     r.PoolID,
		"path_prefix": r.PathPrefix,
		"priority":    r.Priority,
		"timeout_ms":  r.TimeoutMs,
		"updated_at":  time.Now().UTC().Format(time.RFC3339),
	})
	s.saveOutboxEventLocked(&OutboxEvent{
		EventID:       eventID,
		AggregateType: "route",
		AggregateID:   r.ID,
		EventType:     "route.config.changed",
		Payload:       payloadJSON,
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetRoutes(domainID string) []*model.Route {
	s.mu.RLock()
	defer s.mu.RUnlock()

	routes := s.routes[domainID]
	list := make([]*model.Route, len(routes))
	for i, r := range routes {
		list[i] = cloneRoute(r)
	}
	return list
}

func (s *Store) SaveSecurityPolicy(sp *model.SecurityPolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.security[sp.DomainID] = cloneSecurityPolicy(sp)
	if sp.WAFRules != nil {
		s.wafRules[sp.DomainID] = append([]model.WAFRule(nil), sp.WAFRules...)
	}
	if sp.RateLimitRules != nil {
		s.rateLimits[sp.DomainID] = append([]model.RateLimitRule(nil), sp.RateLimitRules...)
	}

	eventID := fmt.Sprintf("evt-sec-%d-%s", time.Now().UnixNano(), sp.DomainID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"domain_id":     sp.DomainID,
		"waf_enabled":   sp.WAFEnabled,
		"waf_mode":      string(sp.WAFMode),
		"rate_limit_en": sp.RateLimitEnabled,
		"updated_at":    time.Now().UTC().Format(time.RFC3339),
	})
	s.saveOutboxEventLocked(&OutboxEvent{
		EventID:       eventID,
		AggregateType: "security_policy",
		AggregateID:   sp.DomainID,
		EventType:     "security.policy.changed",
		Payload:       payloadJSON,
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetSecurityPolicy(domainID string) *model.SecurityPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneSecurityPolicy(s.security[domainID])
}

func (s *Store) AddWAFRule(domainID string, rule model.WAFRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.domains[domainID]; !exists {
		return ErrNotFound
	}
	if len(rule.Name) > MaxWAFRuleName || len(rule.Description) > MaxWAFRuleDescription || len(rule.Pattern) > MaxWAFRulePattern {
		return ErrRuleSizeExceeded
	}
	if len(s.wafRules[domainID]) >= MaxWAFRulesPerDomain {
		return ErrRuleLimitExceeded
	}
	s.wafRules[domainID] = append(s.wafRules[domainID], rule)
	if s.security[domainID] != nil {
		s.security[domainID].WAFRules = s.wafRules[domainID]
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetWAFRules(domainID string) []model.WAFRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.WAFRule(nil), s.wafRules[domainID]...)
}

func (s *Store) DeleteWAFRule(domainID string, ruleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rules, exists := s.wafRules[domainID]
	if !exists {
		return ErrNotFound
	}

	filtered := make([]model.WAFRule, 0, len(rules))
	found := false
	for _, r := range rules {
		if r.ID == ruleID {
			found = true
			continue
		}
		filtered = append(filtered, r)
	}

	if !found {
		return ErrNotFound
	}

	s.wafRules[domainID] = filtered
	if s.security[domainID] != nil {
		s.security[domainID].WAFRules = filtered
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) SetRateLimitRules(domainID string, rules []model.RateLimitRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.domains[domainID]; !exists {
		return ErrNotFound
	}
	if len(rules) > MaxRateLimitRulesPerDomain {
		return ErrRuleLimitExceeded
	}
	for _, r := range rules {
		if len(r.PathPrefix) > MaxRateLimitPathPrefix || len(r.HeaderName) > MaxRateLimitHeaderName {
			return ErrRuleSizeExceeded
		}
	}
	cloned := append([]model.RateLimitRule(nil), rules...)
	s.rateLimits[domainID] = cloned
	if s.security[domainID] != nil {
		s.security[domainID].RateLimitRules = append([]model.RateLimitRule(nil), rules...)
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetRateLimitRules(domainID string) []model.RateLimitRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.RateLimitRule(nil), s.rateLimits[domainID]...)
}

func securityEventSize(ev model.SecurityEvent) int {
	return len(ev.ID) + len(ev.DomainID) + len(ev.ClientIP) + len(ev.Method) +
		len(ev.Path) + len(ev.UserAgent) + len(ev.RuleTriggered) + len(ev.Action) + len(ev.Details) + 64
}

func (s *Store) RecordSecurityEvent(ev model.SecurityEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Truncate fields defensively to prevent individual oversized payloads (Finding 1)
	if len(ev.Path) > 2048 {
		ev.Path = ev.Path[:2048]
	}
	if len(ev.UserAgent) > 512 {
		ev.UserAgent = ev.UserAgent[:512]
	}
	if len(ev.Details) > 1024 {
		ev.Details = ev.Details[:1024]
	}

	events := append(s.events[ev.DomainID], ev)
	if len(events) > MaxSecurityEventsPerDomain {
		events = events[len(events)-MaxSecurityEventsPerDomain:]
	}

	// Enforce byte budget per domain (Finding 1)
	totalBytes := 0
	for _, e := range events {
		totalBytes += securityEventSize(e)
	}
	for totalBytes > MaxSecurityEventByteBudgetPerDomain && len(events) > 1 {
		totalBytes -= securityEventSize(events[0])
		events = events[1:]
	}

	s.events[ev.DomainID] = events
	return nil
}

func (s *Store) GetSecurityEvents(domainID string, limit int) []model.SecurityEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	events := s.events[domainID]
	if limit <= 0 || limit > len(events) {
		limit = len(events)
	}

	// Return most recent first
	result := make([]model.SecurityEvent, limit)
	for i := 0; i < limit; i++ {
		result[i] = events[len(events)-1-i]
	}
	return result
}

func (s *Store) SaveCachePolicy(cp *model.CachePolicy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := cloneCachePolicy(cp)
	if cloned != nil {
		if cloned.DefaultTTLSeconds < 0 {
			cloned.DefaultTTLSeconds = 0
		} else if cloned.DefaultTTLSeconds > MaxCacheTTLSeconds {
			cloned.DefaultTTLSeconds = MaxCacheTTLSeconds
		}
	}
	s.cache[cp.DomainID] = cloned
	if cp.CacheRules != nil {
		s.cacheRules[cp.DomainID] = append([]model.CacheRule(nil), cp.CacheRules...)
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetCachePolicy(domainID string) *model.CachePolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCachePolicy(s.cache[domainID])
}

func (s *Store) AddCacheRule(domainID string, rule model.CacheRule) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.domains[domainID]; !exists {
		return ErrNotFound
	}
	if len(rule.Name) > MaxCacheRuleName || len(rule.PathPattern) > MaxCachePathPattern {
		return ErrRuleSizeExceeded
	}
	if len(rule.IgnoredParams) > MaxCacheRuleParamCount || len(rule.IncludedParams) > MaxCacheRuleParamCount {
		return ErrRuleSizeExceeded
	}
	for _, p := range rule.IgnoredParams {
		if len(p) > MaxCacheRuleParamLength {
			return ErrRuleSizeExceeded
		}
	}
	for _, p := range rule.IncludedParams {
		if len(p) > MaxCacheRuleParamLength {
			return ErrRuleSizeExceeded
		}
	}
	if len(rule.CustomHeadersToInclude) > MaxCustomHeaderCount {
		return ErrRuleSizeExceeded
	}
	for _, h := range rule.CustomHeadersToInclude {
		if len(h) > MaxCustomHeaderName {
			return ErrRuleSizeExceeded
		}
	}
	if rule.TTLSeconds < 0 || rule.TTLSeconds > MaxCacheTTLSeconds {
		return ErrRuleSizeExceeded
	}

	if len(s.cacheRules[domainID]) >= MaxCacheRulesPerDomain {
		return ErrRuleLimitExceeded
	}
	s.cacheRules[domainID] = append(s.cacheRules[domainID], rule)
	if s.cache[domainID] != nil {
		s.cache[domainID].CacheRules = s.cacheRules[domainID]
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetCacheRules(domainID string) []model.CacheRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	rules := s.cacheRules[domainID]
	list := make([]model.CacheRule, len(rules))
	for i, r := range rules {
		list[i] = cloneCacheRule(r)
	}
	return list
}

func (s *Store) DeleteCacheRule(domainID string, ruleID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	rules, exists := s.cacheRules[domainID]
	if !exists {
		return ErrNotFound
	}

	filtered := make([]model.CacheRule, 0, len(rules))
	found := false
	for _, r := range rules {
		if r.ID == ruleID {
			found = true
			continue
		}
		filtered = append(filtered, r)
	}

	if !found {
		return ErrNotFound
	}

	s.cacheRules[domainID] = filtered
	if s.cache[domainID] != nil {
		s.cache[domainID].CacheRules = filtered
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) SaveCertificate(cert *model.Certificate) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cert.Status == model.CertStatusPendingChallenge {
		s.pendingCertificates[cert.DomainID] = cloneCertificate(cert)
	} else {
		s.certificates[cert.DomainID] = cloneCertificate(cert)
		delete(s.pendingCertificates, cert.DomainID)

		eventID := fmt.Sprintf("evt-cert-%d-%s", time.Now().UnixNano(), cert.ID)
		payloadJSON, _ := json.Marshal(map[string]interface{}{
			"cert_id":    cert.ID,
			"domain_id":  cert.DomainID,
			"status":     string(cert.Status),
			"expires_at": cert.ExpiresAt.Format(time.RFC3339),
			"updated_at": time.Now().UTC().Format(time.RFC3339),
		})
		s.saveOutboxEventLocked(&OutboxEvent{
			EventID:       eventID,
			AggregateType: "certificate",
			AggregateID:   cert.ID,
			EventType:     "certificate.changed",
			Payload:       payloadJSON,
			Status:        "PENDING",
			CreatedAt:     time.Now().UTC(),
		})
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetCertificate(domainID string) *model.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCertificate(s.certificates[domainID])
}

func (s *Store) GetPendingCertificate(domainID string) *model.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCertificate(s.pendingCertificates[domainID])
}

func (s *Store) SaveACMEChallenge(ch *model.ACMEChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[ch.Token] = cloneACMEChallenge(ch)
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetACMEChallengeByToken(token string) *model.ACMEChallenge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneACMEChallenge(s.challenges[token])
}

func (s *Store) UpdateACMEChallengeStatus(token string, status model.ChallengeStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, exists := s.challenges[token]; exists {
		ch.Status = status
	}
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) SaveTLSSettings(domainID string, settings *model.TLSSettings) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsSettings[domainID] = cloneTLSSettings(settings)
	s.invalidateCachesLocked()
	return nil
}

func (s *Store) GetTLSSettings(domainID string) *model.TLSSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st, exists := s.tlsSettings[domainID]; exists {
		return cloneTLSSettings(st)
	}
	return &model.TLSSettings{
		EnforceHTTPS:  true,
		MinTLSVersion: "TLSv1.2",
	}
}

type DomainTopology struct {
	Domain      *model.Domain
	Routes      []*model.Route
	Pools       map[string]*model.OriginPool // poolID -> OriginPool
	Security    *model.SecurityPolicy
	Cache       *model.CachePolicy
	Certificate *model.Certificate
	TLSSettings *model.TLSSettings
}

func (s *Store) buildActiveTopologiesLocked() []*DomainTopology {
	var topologies []*DomainTopology
	for _, d := range s.domains {
		if d.Status != model.DomainStatusActive {
			continue // Only compile active, verified domains (Rule 17)
		}

		routes := make([]*model.Route, 0, len(s.routes[d.ID]))
		for _, r := range s.routes[d.ID] {
			routes = append(routes, cloneRoute(r))
		}

		topo := &DomainTopology{
			Domain:      cloneDomain(d),
			Routes:      routes,
			Pools:       make(map[string]*model.OriginPool),
			Security:    cloneSecurityPolicy(s.security[d.ID]),
			Cache:       cloneCachePolicy(s.cache[d.ID]),
			Certificate: cloneCertificate(s.certificates[d.ID]),
			TLSSettings: cloneTLSSettings(s.tlsSettings[d.ID]),
		}

		for _, r := range topo.Routes {
			if pool, exists := s.pools[r.PoolID]; exists {
				topo.Pools[r.PoolID] = cloneOriginPool(pool)
			}
		}

		topologies = append(topologies, topo)
	}

	sort.Slice(topologies, func(i, j int) bool {
		if topologies[i].Domain == nil {
			return false
		}
		if topologies[j].Domain == nil {
			return true
		}

		left := strings.ToLower(topologies[i].Domain.Hostname)
		right := strings.ToLower(topologies[j].Domain.Hostname)

		if left != right {
			return left < right
		}

		return topologies[i].Domain.ID < topologies[j].Domain.ID
	})

	return topologies
}

func cloneDomainTopology(dt *DomainTopology) *DomainTopology {
	if dt == nil {
		return nil
	}
	routes := make([]*model.Route, len(dt.Routes))
	for i, r := range dt.Routes {
		routes[i] = cloneRoute(r)
	}
	pools := make(map[string]*model.OriginPool, len(dt.Pools))
	for k, p := range dt.Pools {
		pools[k] = cloneOriginPool(p)
	}
	return &DomainTopology{
		Domain:      cloneDomain(dt.Domain),
		Routes:      routes,
		Pools:       pools,
		Security:    cloneSecurityPolicy(dt.Security),
		Cache:       cloneCachePolicy(dt.Cache),
		Certificate: cloneCertificate(dt.Certificate),
		TLSSettings: cloneTLSSettings(dt.TLSSettings),
	}
}

func cloneTopologies(topos []*DomainTopology) []*DomainTopology {
	result := make([]*DomainTopology, len(topos))
	for i, t := range topos {
		result[i] = cloneDomainTopology(t)
	}
	return result
}

// GetActiveTopologies extracts all verified and active domains for Envoy compilation using snapshot caching (P2 Finding 7)
func (s *Store) GetActiveTopologies() []*DomainTopology {
	s.mu.RLock()
	if s.activeTopologyCache != nil {
		result := cloneTopologies(s.activeTopologyCache)
		s.mu.RUnlock()
		return result
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.activeTopologyCache != nil {
		return cloneTopologies(s.activeTopologyCache)
	}

	topos := s.buildActiveTopologiesLocked()
	s.activeTopologyCache = topos

	return cloneTopologies(topos)
}

func containsPoP(allowedPoPs []string, targetPoP string) bool {
	if len(allowedPoPs) == 0 {
		return true // Unrestricted / Global
	}
	target := strings.ToLower(strings.TrimSpace(targetPoP))
	for _, p := range allowedPoPs {
		if strings.EqualFold(strings.TrimSpace(p), target) {
			return true
		}
	}
	return false
}

func (s *Store) buildTopologiesForPoPLocked(targetPoP string) []*DomainTopology {
	var topologies []*DomainTopology

	for _, d := range s.domains {
		if d.Status != model.DomainStatusActive {
			continue // Only compile active, verified domains (Rule 17)
		}

		// Filter domains restricted to other PoPs (P1 Finding)
		if !containsPoP(d.AllowedPoPs, targetPoP) {
			continue
		}

		routes := make([]*model.Route, 0, len(s.routes[d.ID]))
		for _, r := range s.routes[d.ID] {
			routes = append(routes, cloneRoute(r))
		}

		topo := &DomainTopology{
			Domain:      cloneDomain(d),
			Routes:      routes,
			Pools:       make(map[string]*model.OriginPool),
			Security:    cloneSecurityPolicy(s.security[d.ID]),
			Cache:       cloneCachePolicy(s.cache[d.ID]),
			Certificate: cloneCertificate(s.certificates[d.ID]),
			TLSSettings: cloneTLSSettings(s.tlsSettings[d.ID]),
		}

		totalUsableOrigins := 0
		for _, r := range topo.Routes {
			if pool, exists := s.pools[r.PoolID]; exists {
				// Filter origin pools restricted to other PoPs
				if !containsPoP(pool.AllowedPoPs, targetPoP) {
					continue
				}

				clonedPool := cloneOriginPool(pool)
				// Filter individual origins restricted to other PoPs
				filteredOrigins := make([]model.Origin, 0, len(clonedPool.Origins))
				for _, o := range clonedPool.Origins {
					if containsPoP(o.AllowedPoPs, targetPoP) {
						filteredOrigins = append(filteredOrigins, o)
					}
				}
				if len(filteredOrigins) > 0 {
					clonedPool.Origins = filteredOrigins
					topo.Pools[r.PoolID] = clonedPool
					totalUsableOrigins += len(filteredOrigins)
				}
			}
		}

		// P2 Finding 8: If domain has configured routes, check that at least one route has usable origins at this PoP.
		// If 0 usable origins exist at this PoP, omit domain to prevent empty VirtualHost and routing blackholes.
		if len(topo.Routes) > 0 && totalUsableOrigins == 0 {
			continue
		}

		// Filter routes to only those pointing to usable pools
		if len(topo.Routes) > 0 {
			usableRoutes := make([]*model.Route, 0, len(topo.Routes))
			for _, r := range topo.Routes {
				if _, ok := topo.Pools[r.PoolID]; ok {
					usableRoutes = append(usableRoutes, r)
				}
			}
			topo.Routes = usableRoutes
		}

		topologies = append(topologies, topo)
	}

	sort.Slice(topologies, func(i, j int) bool {
		if topologies[i].Domain == nil {
			return false
		}
		if topologies[j].Domain == nil {
			return true
		}

		left := strings.ToLower(topologies[i].Domain.Hostname)
		right := strings.ToLower(topologies[j].Domain.Hostname)

		if left != right {
			return left < right
		}

		return topologies[i].Domain.ID < topologies[j].Domain.ID
	})

	return topologies
}

// GetActiveTopologiesForPoP extracts active domains and origin topologies allowed for a specific PoP using snapshot caching (P2 Finding 7)
func (s *Store) GetActiveTopologiesForPoP(popID string) []*DomainTopology {
	targetPoP := strings.ToLower(strings.TrimSpace(popID))

	s.mu.RLock()
	if cached, ok := s.popTopologyCache[targetPoP]; ok {
		result := cloneTopologies(cached)
		s.mu.RUnlock()
		return result
	}
	s.mu.RUnlock()

	s.mu.Lock()
	defer s.mu.Unlock()

	if cached, ok := s.popTopologyCache[targetPoP]; ok {
		return cloneTopologies(cached)
	}

	topos := s.buildTopologiesForPoPLocked(targetPoP)
	s.popTopologyCache[targetPoP] = topos

	return cloneTopologies(topos)
}

func (s *Store) SaveAIProvider(p *model.AIProvider) error {
	if p == nil {
		return errors.New("provider cannot be nil")
	}
	if strings.TrimSpace(p.ID) == "" {
		return errors.New("provider id is required")
	}
	if strings.TrimSpace(p.ProjectID) == "" {
		return errors.New("provider project_id is required")
	}
	if strings.TrimSpace(p.Name) == "" {
		return errors.New("provider name is required")
	}
	if strings.TrimSpace(p.Endpoint) == "" {
		return errors.New("provider endpoint is required")
	}
	switch p.ProviderType {
	case string(model.AIProviderTypeOpenAI), string(model.AIProviderTypeAzure),
		string(model.AIProviderTypeCoreWeave), string(model.AIProviderTypeVLLM),
		string(model.AIProviderTypeOnPrem), string(model.AIProviderTypeAWS),
		string(model.AIProviderTypeAnthropic), string(model.AIProviderTypeBedrock):
	default:
		return fmt.Errorf("unsupported provider_type '%s'", p.ProviderType)
	}
	if p.CostPerMTokens < 0 {
		return errors.New("cost_per_m_tokens cannot be negative")
	}
	if p.Priority == 0 {
		p.Priority = 10
	}
	if p.FailoverCooldownSecs == 0 {
		p.FailoverCooldownSecs = 60
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.aiProviders[p.ID]; !exists {
		count := 0
		for _, existing := range s.aiProviders {
			if existing.ProjectID == p.ProjectID {
				count++
			}
		}
		if count >= MaxAIProvidersPerProject {
			return errors.New("maximum AI providers per project exceeded")
		}
	}

	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now

	clone := *p
	s.aiProviders[p.ID] = &clone

	eventID := fmt.Sprintf("evt-aiprov-%d-%s", time.Now().UnixNano(), p.ID)
	payloadJSON, _ := json.Marshal(map[string]interface{}{
		"provider_id":   p.ID,
		"project_id":    p.ProjectID,
		"name":          p.Name,
		"provider_type": string(p.ProviderType),
		"enabled":       p.Enabled,
		"updated_at":    time.Now().UTC().Format(time.RFC3339),
	})
	s.saveOutboxEventLocked(&OutboxEvent{
		EventID:       eventID,
		AggregateType: "ai_provider",
		AggregateID:   p.ID,
		EventType:     "ai_provider.changed",
		Payload:       payloadJSON,
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	return nil
}

func (s *Store) GetAIProvider(id string) (*model.AIProvider, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	p, exists := s.aiProviders[id]
	if !exists {
		return nil, ErrNotFound
	}
	clone := *p
	return &clone, nil
}

func (s *Store) ListAIProvidersByProject(projectID string) []*model.AIProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*model.AIProvider
	for _, p := range s.aiProviders {
		if p.ProjectID == projectID {
			clone := *p
			list = append(list, &clone)
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Priority != list[j].Priority {
			return list[i].Priority < list[j].Priority
		}
		return list[i].Name < list[j].Name
	})
	return list
}

func (s *Store) ListAIProviders() []*model.AIProvider {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*model.AIProvider
	for _, p := range s.aiProviders {
		clone := *p
		list = append(list, &clone)
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Priority != list[j].Priority {
			return list[i].Priority < list[j].Priority
		}
		return list[i].Name < list[j].Name
	})
	return list
}

func (s *Store) DeleteAIProvider(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.aiProviders[id]; !exists {
		return ErrNotFound
	}
	delete(s.aiProviders, id)
	return nil
}

func (s *Store) SaveAuditLog(log *model.AuditLog) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if log == nil {
		return errors.New("audit log is nil")
	}
	clone := *log
	if existing, exists := s.auditLogMap[clone.ID]; exists {
		if existing.Hash == clone.Hash {
			// Idempotent duplicate replay: event already recorded with identical hash
			return nil
		}
		return fmt.Errorf("audit log conflict: ID %s exists with different hash", clone.ID)
	}

	s.auditLogs = append(s.auditLogs, &clone)
	s.auditLogMap[clone.ID] = &clone
	return nil
}

func (s *Store) ListAuditLogs(projectID string, limit int, offset int) ([]*model.AuditLog, int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var filtered []*model.AuditLog
	for i := len(s.auditLogs) - 1; i >= 0; i-- {
		l := s.auditLogs[i]
		if projectID == "" || l.ProjectID == projectID {
			clone := *l
			filtered = append(filtered, &clone)
		}
	}

	total := len(filtered)
	if offset < 0 {
		offset = 0
	}
	if offset > total {
		return []*model.AuditLog{}, total, nil
	}
	if limit <= 0 {
		limit = 50
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return filtered[offset:end], total, nil
}

func (s *Store) GetAuditLog(id string) (*model.AuditLog, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	log, exists := s.auditLogMap[id]
	if !exists {
		return nil, ErrNotFound
	}
	clone := *log
	return &clone, nil
}

func (s *Store) GetLastAuditHash() string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if len(s.auditLogs) == 0 {
		return "0000000000000000000000000000000000000000000000000000000000000000"
	}
	return s.auditLogs[len(s.auditLogs)-1].Hash
}

// -------------------------------------------------------------------------
// Transactional Outbox Events (In-Memory Implementation)
// -------------------------------------------------------------------------

var _ OutboxStore = (*Store)(nil)

func (s *Store) saveOutboxEventLocked(ev *OutboxEvent) {
	if ev == nil {
		return
	}
	s.outboxEvents = append(s.outboxEvents, &inMemoryOutboxEntry{
		event: *ev,
	})
}

// SaveOutboxEvent manually records an outbox event into the in-memory store.
func (s *Store) SaveOutboxEvent(ev *OutboxEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saveOutboxEventLocked(ev)
}

// GetPendingOutboxEvents retrieves unapplied outbox events ordered by creation timestamp.
func (s *Store) GetPendingOutboxEvents(ctx context.Context, limit int) ([]*OutboxEvent, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if limit <= 0 {
		limit = 100
	}
	var res []*OutboxEvent
	for _, entry := range s.outboxEvents {
		if entry.event.Status == "PENDING" {
			evClone := entry.event
			res = append(res, &evClone)
			if len(res) >= limit {
				break
			}
		}
	}
	return res, nil
}

// ClaimOutboxEvents claims up to limit unapplied outbox events with worker lease fencing.
func (s *Store) ClaimOutboxEvents(ctx context.Context, workerID string, limit int, leaseDuration time.Duration) ([]*OutboxEvent, error) {
	if strings.TrimSpace(workerID) == "" {
		return nil, errors.New("workerID is required to claim outbox events")
	}
	if limit <= 0 {
		limit = 100
	}
	if leaseDuration <= 0 {
		leaseDuration = 30 * time.Second
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	var claimed []*OutboxEvent
	for _, entry := range s.outboxEvents {
		isAvailable := entry.event.Status == "PENDING" || (entry.event.Status == "PROCESSING" && now.After(entry.lockedUntil))
		if isAvailable {
			tokenBytes := make([]byte, 16)
			_, _ = rand.Read(tokenBytes)
			leaseToken := fmt.Sprintf("lease-%d-%s", now.UnixNano(), hex.EncodeToString(tokenBytes))

			entry.event.Status = "PROCESSING"
			entry.lockedBy = workerID
			entry.event.LeaseToken = leaseToken
			entry.lockedUntil = now.Add(leaseDuration)
			entry.event.RetryCount++

			evClone := entry.event
			claimed = append(claimed, &evClone)
			if len(claimed) >= limit {
				break
			}
		}
	}
	return claimed, nil
}

// MarkOutboxEventProcessed marks an outbox event as PROCESSED under lease fencing.
func (s *Store) MarkOutboxEventProcessed(ctx context.Context, eventID string, workerID string, leaseToken string) error {
	if strings.TrimSpace(workerID) == "" {
		return errors.New("workerID is required for outbox lease fencing")
	}
	if strings.TrimSpace(leaseToken) == "" {
		return errors.New("leaseToken is required for outbox lease fencing")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for _, entry := range s.outboxEvents {
		if entry.event.EventID == eventID {
			if entry.event.Status == "PROCESSING" && entry.lockedBy == workerID && entry.event.LeaseToken == leaseToken && now.Before(entry.lockedUntil) {
				entry.event.Status = "PROCESSED"
				entry.event.ProcessedAt = &now
				entry.lockedBy = ""
				entry.event.LeaseToken = ""
				entry.lockedUntil = time.Time{}
				return nil
			}
			return ErrOutboxLeaseLost
		}
	}
	return ErrOutboxNotFound
}

// MarkOutboxEventFailed marks an outbox event as PENDING or DEAD_LETTER after repeated retry exhaustion.
func (s *Store) MarkOutboxEventFailed(ctx context.Context, eventID string, workerID string, leaseToken string, reason string) error {
	if strings.TrimSpace(workerID) == "" {
		return errors.New("workerID is required for outbox lease fencing")
	}
	if strings.TrimSpace(leaseToken) == "" {
		return errors.New("leaseToken is required for outbox lease fencing")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	for _, entry := range s.outboxEvents {
		if entry.event.EventID == eventID {
			if entry.event.Status == "PROCESSING" && entry.lockedBy == workerID && entry.event.LeaseToken == leaseToken && now.Before(entry.lockedUntil) {
				if entry.event.RetryCount >= 5 {
					entry.event.Status = "DEAD_LETTER"
				} else {
					entry.event.Status = "PENDING"
				}
				entry.lockedBy = ""
				entry.event.LeaseToken = ""
				entry.lockedUntil = time.Time{}
				return nil
			}
			return ErrOutboxLeaseLost
		}
	}
	return ErrOutboxNotFound
}
