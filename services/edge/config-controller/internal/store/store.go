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
	certificates map[string]*model.Certificate      // domain ID -> certificate
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
		certificates: make(map[string]*model.Certificate),
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
	return p, nil
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

type DomainTopology struct {
	Domain   *model.Domain
	Routes   []*model.Route
	Pools    map[string]*model.OriginPool // poolID -> OriginPool
	Security *model.SecurityPolicy
	Cache    *model.CachePolicy
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

		topo := &DomainTopology{
			Domain:   d,
			Routes:   s.routes[d.ID],
			Pools:    make(map[string]*model.OriginPool),
			Security: secPolicy,
			Cache:    s.cache[d.ID],
		}

		for _, r := range topo.Routes {
			if pool, exists := s.pools[r.PoolID]; exists {
				topo.Pools[r.PoolID] = pool
			}
		}

		topologies = append(topologies, topo)
	}
	return topologies
}
