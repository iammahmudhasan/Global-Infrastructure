package store

import (
	"errors"
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

type Store struct {
	mu                 sync.RWMutex
	domains            map[string]*model.Domain
	hostIndex          map[string]string // hostname -> domain ID
	projectQuotas      map[string]ProjectQuota
	projectDomainCount map[string]int
	pools              map[string]*model.OriginPool
	origins            map[string]*model.Origin
	routes             map[string][]*model.Route             // domain ID -> routes
	security           map[string]*model.SecurityPolicy      // domain ID -> policy
	wafRules           map[string][]model.WAFRule            // domain ID -> WAF rules
	rateLimits         map[string][]model.RateLimitRule      // domain ID -> Rate limit rules
	events             map[string][]model.SecurityEvent      // domain ID -> Security events
	cache              map[string]*model.CachePolicy         // domain ID -> policy
	cacheRules         map[string][]model.CacheRule          // domain ID -> Cache rules
	monitors           map[string]*model.HealthMonitor       // pool ID -> HealthMonitor
	healthStates       map[string]*model.OriginEndpointState // origin ID -> OriginEndpointState
	certificates       map[string]*model.Certificate         // domain ID -> certificate
	challenges         map[string]*model.ACMEChallenge       // token -> ACMEChallenge
	tlsSettings        map[string]*model.TLSSettings         // domain ID -> TLSSettings
}

func NewStore() *Store {
	return &Store{
		domains:            make(map[string]*model.Domain),
		hostIndex:          make(map[string]string),
		projectQuotas:      make(map[string]ProjectQuota),
		projectDomainCount: make(map[string]int),
		pools:              make(map[string]*model.OriginPool),
		origins:            make(map[string]*model.Origin),
		routes:             make(map[string][]*model.Route),
		security:           make(map[string]*model.SecurityPolicy),
		wafRules:           make(map[string][]model.WAFRule),
		rateLimits:         make(map[string][]model.RateLimitRule),
		events:             make(map[string][]model.SecurityEvent),
		cache:              make(map[string]*model.CachePolicy),
		cacheRules:         make(map[string][]model.CacheRule),
		monitors:           make(map[string]*model.HealthMonitor),
		healthStates:       make(map[string]*model.OriginEndpointState),
		certificates:       make(map[string]*model.Certificate),
		challenges:         make(map[string]*model.ACMEChallenge),
		tlsSettings:        make(map[string]*model.TLSSettings),
	}
}

func (s *Store) SetProjectQuota(projectID string, quota ProjectQuota) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.projectQuotas[projectID] = quota
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

func (s *Store) UpdateDomainStatus(id string, status model.DomainStatus) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	d, exists := s.domains[id]
	if !exists {
		return ErrNotFound
	}
	d.Status = status
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
	delete(s.tlsSettings, domainID)

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
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 1; i < len(p.Origins); i++ {
		if p.Origins[i].Protocol != p.Origins[0].Protocol {
			return ErrMixedOriginProtocols
		}
	}

	s.pools[p.ID] = cloneOriginPool(p)
	return nil
}

// SaveOriginPoolBypass saves an origin pool directly without validation (used in test fixtures)
func (s *Store) SaveOriginPoolBypass(p *model.OriginPool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pools[p.ID] = cloneOriginPool(p)
}

func (s *Store) AddOrigin(o *model.Origin) error {
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

func (s *Store) SaveHealthMonitor(hm *model.HealthMonitor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	cloned := cloneHealthMonitor(hm)
	s.monitors[cloned.PoolID] = cloned
	if pool, exists := s.pools[cloned.PoolID]; exists {
		pool.HealthMonitor = cloneHealthMonitor(cloned)
	}
}

func (s *Store) GetHealthMonitor(poolID string) *model.HealthMonitor {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneHealthMonitor(s.monitors[poolID])
}

func (s *Store) SaveOriginHealthState(st *model.OriginEndpointState) {
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

func (s *Store) UpdateOriginHealthy(originID string, healthy bool) {
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
}

func (s *Store) SaveRoute(r *model.Route) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.routes[r.DomainID] = append(s.routes[r.DomainID], cloneRoute(r))
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

func (s *Store) SaveSecurityPolicy(sp *model.SecurityPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.security[sp.DomainID] = cloneSecurityPolicy(sp)
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

func (s *Store) RecordSecurityEvent(ev model.SecurityEvent) {
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

func (s *Store) SaveCachePolicy(cp *model.CachePolicy) {
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
	return nil
}

func (s *Store) SaveCertificate(cert *model.Certificate) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.certificates[cert.DomainID] = cloneCertificate(cert)
}

func (s *Store) GetCertificate(domainID string) *model.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCertificate(s.certificates[domainID])
}

func (s *Store) SaveACMEChallenge(ch *model.ACMEChallenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[ch.Token] = cloneACMEChallenge(ch)
}

func (s *Store) GetACMEChallengeByToken(token string) *model.ACMEChallenge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneACMEChallenge(s.challenges[token])
}

func (s *Store) UpdateACMEChallengeStatus(token string, status model.ChallengeStatus) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if ch, exists := s.challenges[token]; exists {
		ch.Status = status
	}
}

func (s *Store) SaveTLSSettings(domainID string, settings *model.TLSSettings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tlsSettings[domainID] = cloneTLSSettings(settings)
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

// GetActiveTopologies extracts all verified and active domains for Envoy compilation
func (s *Store) GetActiveTopologies() []*DomainTopology {
	s.mu.RLock()
	defer s.mu.RUnlock()

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

// GetActiveTopologiesForPoP extracts active domains and origin topologies allowed for a specific PoP (P1 PoP Scoping)
func (s *Store) GetActiveTopologiesForPoP(popID string) []*DomainTopology {
	s.mu.RLock()
	defer s.mu.RUnlock()

	targetPoP := strings.ToLower(strings.TrimSpace(popID))
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
				clonedPool.Origins = filteredOrigins
				topo.Pools[r.PoolID] = clonedPool
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
