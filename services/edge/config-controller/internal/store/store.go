package store

import (
	"errors"
	"sync"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

var (
	ErrNotFound             = errors.New("entity not found")
	ErrAlreadyExists        = errors.New("entity already exists")
	ErrMixedOriginProtocols = errors.New("all origins in an origin pool must share the same protocol")
)

type Store struct {
	mu           sync.RWMutex
	domains      map[string]*model.Domain
	hostIndex    map[string]string // hostname -> domain ID
	pools        map[string]*model.OriginPool
	origins      map[string]*model.Origin
	routes       map[string][]*model.Route             // domain ID -> routes
	security     map[string]*model.SecurityPolicy      // domain ID -> policy
	wafRules     map[string][]model.WAFRule            // domain ID -> WAF rules
	rateLimits   map[string][]model.RateLimitRule      // domain ID -> Rate limit rules
	events       map[string][]model.SecurityEvent      // domain ID -> Security events
	cache        map[string]*model.CachePolicy         // domain ID -> policy
	cacheRules   map[string][]model.CacheRule          // domain ID -> Cache rules
	monitors     map[string]*model.HealthMonitor       // pool ID -> HealthMonitor
	healthStates map[string]*model.OriginEndpointState // origin ID -> OriginEndpointState
	certificates map[string]*model.Certificate         // domain ID -> certificate
	challenges   map[string]*model.ACMEChallenge       // token -> ACMEChallenge
	tlsSettings  map[string]*model.TLSSettings         // domain ID -> TLSSettings
}

func NewStore() *Store {
	return &Store{
		domains:      make(map[string]*model.Domain),
		hostIndex:    make(map[string]string),
		pools:        make(map[string]*model.OriginPool),
		origins:      make(map[string]*model.Origin),
		routes:       make(map[string][]*model.Route),
		security:     make(map[string]*model.SecurityPolicy),
		wafRules:     make(map[string][]model.WAFRule),
		rateLimits:   make(map[string][]model.RateLimitRule),
		events:       make(map[string][]model.SecurityEvent),
		cache:        make(map[string]*model.CachePolicy),
		cacheRules:   make(map[string][]model.CacheRule),
		monitors:     make(map[string]*model.HealthMonitor),
		healthStates: make(map[string]*model.OriginEndpointState),
		certificates: make(map[string]*model.Certificate),
		challenges:   make(map[string]*model.ACMEChallenge),
		tlsSettings:  make(map[string]*model.TLSSettings),
	}
}

func (s *Store) SaveDomain(d *model.Domain) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.hostIndex[d.Hostname]; exists {
		return ErrAlreadyExists
	}

	s.domains[d.ID] = d
	s.hostIndex[d.Hostname] = d.ID
	return nil
}

func cloneDomain(d *model.Domain) *model.Domain {
	if d == nil {
		return nil
	}
	cp := *d
	return &cp
}

func cloneOriginPool(p *model.OriginPool) *model.OriginPool {
	if p == nil {
		return nil
	}
	cp := *p
	cp.Origins = append([]model.Origin(nil), p.Origins...)
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

func (s *Store) SaveOriginPool(p *model.OriginPool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	for i := 1; i < len(p.Origins); i++ {
		if p.Origins[i].Protocol != p.Origins[0].Protocol {
			return ErrMixedOriginProtocols
		}
	}
	s.pools[p.ID] = p
	return nil
}

// SaveOriginPoolBypass saves an origin pool directly without validation (used in test fixtures)
func (s *Store) SaveOriginPoolBypass(p *model.OriginPool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pools[p.ID] = p
}

func (s *Store) AddOrigin(o *model.Origin) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	pool, exists := s.pools[o.PoolID]
	if !exists {
		return ErrNotFound
	}

	for _, existing := range pool.Origins {
		if existing.Protocol != o.Protocol {
			return ErrMixedOriginProtocols
		}
	}

	s.origins[o.ID] = o
	pool.Origins = append(pool.Origins, *o)
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
	s.monitors[hm.PoolID] = hm
	if pool, exists := s.pools[hm.PoolID]; exists {
		pool.HealthMonitor = hm
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
	s.healthStates[st.OriginID] = st

	// Synchronize with origin entity healthy flag
	if orig, exists := s.origins[st.OriginID]; exists {
		orig.Healthy = st.Healthy
	}
	if pool, exists := s.pools[st.PoolID]; exists {
		for i := range pool.Origins {
			if pool.Origins[i].ID == st.OriginID {
				pool.Origins[i].Healthy = st.Healthy
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
	s.routes[r.DomainID] = append(s.routes[r.DomainID], r)
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
	s.security[sp.DomainID] = sp
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
	s.rateLimits[domainID] = rules
	if s.security[domainID] != nil {
		s.security[domainID].RateLimitRules = rules
	}
	return nil
}

func (s *Store) GetRateLimitRules(domainID string) []model.RateLimitRule {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]model.RateLimitRule(nil), s.rateLimits[domainID]...)
}

func (s *Store) RecordSecurityEvent(ev model.SecurityEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Append and keep recent 1000 events per domain in memory
	events := append(s.events[ev.DomainID], ev)
	if len(events) > 1000 {
		events = events[len(events)-1000:]
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
	s.cache[cp.DomainID] = cp
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
	s.certificates[cert.DomainID] = cert
}

func (s *Store) GetCertificate(domainID string) *model.Certificate {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return cloneCertificate(s.certificates[domainID])
}

func (s *Store) SaveACMEChallenge(ch *model.ACMEChallenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[ch.Token] = ch
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
	s.tlsSettings[domainID] = settings
}

func (s *Store) GetTLSSettings(domainID string) *model.TLSSettings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if st, exists := s.tlsSettings[domainID]; exists {
		return cloneTLSSettings(st)
	}
	return &model.TLSSettings{
		EnforceHTTPS:  false,
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
	return topologies
}
