package store

import (
	"errors"
	"sync"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

var (
	ErrNotFound      = errors.New("entity not found")
	ErrAlreadyExists = errors.New("entity already exists")
)

type Store struct {
	mu           sync.RWMutex
	domains      map[string]*model.Domain
	hostIndex    map[string]string // hostname -> domain ID
	pools        map[string]*model.OriginPool
	origins      map[string]*model.Origin
	routes       map[string][]*model.Route          // domain ID -> routes
	security     map[string]*model.SecurityPolicy   // domain ID -> policy
	wafRules     map[string][]model.WAFRule         // domain ID -> WAF rules
	rateLimits   map[string][]model.RateLimitRule   // domain ID -> Rate limit rules
	events       map[string][]model.SecurityEvent   // domain ID -> Security events
	cache        map[string]*model.CachePolicy      // domain ID -> policy
	cacheRules   map[string][]model.CacheRule             // domain ID -> Cache rules
	monitors     map[string]*model.HealthMonitor          // pool ID -> HealthMonitor
	healthStates map[string]*model.OriginEndpointState    // origin ID -> OriginEndpointState
	certificates map[string]*model.Certificate            // domain ID -> certificate
	challenges   map[string]*model.ACMEChallenge          // token -> ACMEChallenge
	tlsSettings  map[string]*model.TLSSettings            // domain ID -> TLSSettings
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

func (s *Store) GetDomain(id string) (*model.Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	d, exists := s.domains[id]
	if !exists {
		return nil, ErrNotFound
	}
	return d, nil
}

func (s *Store) GetDomainByHost(hostname string) (*model.Domain, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	id, exists := s.hostIndex[hostname]
	if !exists {
		return nil, ErrNotFound
	}
	return s.domains[id], nil
}

func (s *Store) ListDomainsByProject(projectID string) []*model.Domain {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var list []*model.Domain
	for _, d := range s.domains {
		if d.ProjectID == projectID {
			list = append(list, d)
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

func (s *Store) SaveOriginPool(p *model.OriginPool) {
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
	p.HealthMonitor = s.monitors[poolID]
	return p, nil
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
	return s.monitors[poolID]
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
	return s.healthStates[originID]
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
			states = append(states, st)
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
	return s.routes[domainID]
}

func (s *Store) SaveSecurityPolicy(sp *model.SecurityPolicy) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.security[sp.DomainID] = sp
}

func (s *Store) GetSecurityPolicy(domainID string) *model.SecurityPolicy {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.security[domainID]
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
	return s.wafRules[domainID]
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
	return s.rateLimits[domainID]
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
	return s.cache[domainID]
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
	return s.cacheRules[domainID]
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
	return s.certificates[domainID]
}

func (s *Store) SaveACMEChallenge(ch *model.ACMEChallenge) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.challenges[ch.Token] = ch
}

func (s *Store) GetACMEChallengeByToken(token string) *model.ACMEChallenge {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.challenges[token]
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
		return st
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

		secPolicy := s.security[d.ID]
		if secPolicy != nil {
			// Ensure rules are attached
			secPolicy.WAFRules = s.wafRules[d.ID]
			secPolicy.RateLimitRules = s.rateLimits[d.ID]
		}

		cachePolicy := s.cache[d.ID]
		if cachePolicy != nil {
			cachePolicy.CacheRules = s.cacheRules[d.ID]
		}

		topo := &DomainTopology{
			Domain:      d,
			Routes:      s.routes[d.ID],
			Pools:       make(map[string]*model.OriginPool),
			Security:    secPolicy,
			Cache:       cachePolicy,
			Certificate: s.certificates[d.ID],
			TLSSettings: s.tlsSettings[d.ID],
		}

		for _, r := range topo.Routes {
			if pool, exists := s.pools[r.PoolID]; exists {
				pool.HealthMonitor = s.monitors[pool.ID]
				topo.Pools[r.PoolID] = pool
			}
		}

		topologies = append(topologies, topo)
	}
	return topologies
}
