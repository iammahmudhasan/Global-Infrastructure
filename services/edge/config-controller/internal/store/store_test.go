package store_test

import (
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestStore_DeepCloneMutationResistance(t *testing.T) {
	st := store.NewStore()

	// 1. Save domain and verify mutation resistance
	domain := &model.Domain{
		ID:        "dom-test-1",
		ProjectID: "prj-1",
		Hostname:  "api.test.com",
		Status:    model.DomainStatusActive,
	}
	if err := st.SaveDomain(domain); err != nil {
		t.Fatalf("failed to save domain: %v", err)
	}

	gotDomain, err := st.GetDomain("dom-test-1")
	if err != nil {
		t.Fatalf("failed to get domain: %v", err)
	}

	// Mutate the returned clone
	gotDomain.Status = model.DomainStatusPendingVerification
	gotDomain.Hostname = "mutated.test.com"

	// Fetch again from store -> must retain original values
	freshDomain, err := st.GetDomain("dom-test-1")
	if err != nil {
		t.Fatalf("failed to get fresh domain: %v", err)
	}
	if freshDomain.Status != model.DomainStatusActive {
		t.Errorf("store domain status was mutated! expected ACTIVE, got %s", freshDomain.Status)
	}
	if freshDomain.Hostname != "api.test.com" {
		t.Errorf("store domain hostname was mutated! expected api.test.com, got %s", freshDomain.Hostname)
	}

	// 2. Save pool and origins and verify deep copy of slice
	pool := &model.OriginPool{
		ID:          "pool-1",
		ProjectID:   "prj-1",
		Name:        "primary-pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
	}
	st.SaveOriginPool(pool)

	orig := &model.Origin{
		ID:       "orig-1",
		PoolID:   "pool-1",
		Address:  "198.51.100.10",
		Port:     443,
		Protocol: model.ProtocolHTTPS,
		Healthy:  true,
	}
	if err := st.AddOrigin(orig); err != nil {
		t.Fatalf("failed to add origin: %v", err)
	}

	gotPool, err := st.GetOriginPool("pool-1")
	if err != nil {
		t.Fatalf("failed to get pool: %v", err)
	}
	if len(gotPool.Origins) != 1 {
		t.Fatalf("expected 1 origin in pool, got %d", len(gotPool.Origins))
	}

	// Mutate origins slice on returned clone
	gotPool.Origins[0].Address = "mutated.address.com"
	gotPool.Origins = append(gotPool.Origins, model.Origin{ID: "orig-injected"})

	freshPool, err := st.GetOriginPool("pool-1")
	if err != nil {
		t.Fatalf("failed to get fresh pool: %v", err)
	}
	if len(freshPool.Origins) != 1 {
		t.Errorf("store pool origins slice was mutated! expected 1 origin, got %d", len(freshPool.Origins))
	}
	if freshPool.Origins[0].Address != "198.51.100.10" {
		t.Errorf("store origin address was mutated! expected 198.51.100.10, got %s", freshPool.Origins[0].Address)
	}
}

func TestStore_ConcurrentReadWrite(t *testing.T) {
	st := store.NewStore()

	domain := &model.Domain{
		ID:        "dom-concurrent",
		ProjectID: "prj-concurrent",
		Hostname:  "concurrent.example.com",
		Status:    model.DomainStatusActive,
	}
	_ = st.SaveDomain(domain)

	pool := &model.OriginPool{
		ID:        "pool-concurrent",
		ProjectID: "prj-concurrent",
		Name:      "pool-concurrent",
	}
	st.SaveOriginPool(pool)

	var wg sync.WaitGroup
	workers := 20
	iterations := 100

	// Concurrent readers
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				_, _ = st.GetDomain("dom-concurrent")
				_, _ = st.GetOriginPool("pool-concurrent")
				_ = st.GetActiveTopologies()
			}
		}()
	}

	// Concurrent writers
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for j := 0; j < iterations; j++ {
				st.SaveHealthMonitor(&model.HealthMonitor{
					ID:              fmt.Sprintf("hm-%d-%d", workerID, j),
					PoolID:          "pool-concurrent",
					IntervalSeconds: 5,
					TimeoutSeconds:  1,
				})
				st.SaveTLSSettings("dom-concurrent", &model.TLSSettings{
					EnforceHTTPS:  true,
					MinTLSVersion: "TLSv1.3",
				})
				time.Sleep(100 * time.Microsecond)
			}
		}(i)
	}

	wg.Wait()
}

func TestStore_TopologyRouteAndCacheDeepClone(t *testing.T) {
	st := store.NewStore()

	domain := &model.Domain{
		ID:        "dom-topo-1",
		ProjectID: "prj-topo",
		Hostname:  "topo.example.com",
		Status:    model.DomainStatusActive,
	}
	_ = st.SaveDomain(domain)

	route := &model.Route{
		ID:         "route-1",
		DomainID:   "dom-topo-1",
		PathPrefix: "/api",
		PoolID:     "pool-1",
		Priority:   10,
	}
	st.SaveRoute(route)

	rule := model.CacheRule{
		ID:                     "crule-1",
		DomainID:               "dom-topo-1",
		PathPattern:            "/static/*",
		TTLSeconds:             3600,
		IgnoredParams:          []string{"utm_source", "fbclid"},
		IncludedParams:         []string{"id"},
		CustomHeadersToInclude: []string{"X-Custom-Auth"},
	}
	_ = st.AddCacheRule("dom-topo-1", rule)

	rlRule := model.RateLimitRule{
		ID:                "rl-1",
		DomainID:          "dom-topo-1",
		PathPrefix:        "/login",
		RequestsPerMinute: 60,
		Enabled:           true,
	}
	_ = st.SetRateLimitRules("dom-topo-1", []model.RateLimitRule{rlRule})

	// 1. Verify Topology route pointer mutation resistance
	topos := st.GetActiveTopologies()
	if len(topos) != 1 || len(topos[0].Routes) != 1 {
		t.Fatalf("expected 1 topology with 1 route, got %d topos", len(topos))
	}
	topos[0].Routes[0].PathPrefix = "/mutated"
	topos[0].Routes[0].Priority = 999

	freshTopos := st.GetActiveTopologies()
	if freshTopos[0].Routes[0].PathPrefix != "/api" {
		t.Errorf("internal route was mutated via topology! expected /api, got %s", freshTopos[0].Routes[0].PathPrefix)
	}
	if freshTopos[0].Routes[0].Priority != 10 {
		t.Errorf("internal route priority was mutated! expected 10, got %d", freshTopos[0].Routes[0].Priority)
	}

	// 2. Verify nested CacheRule slice mutation resistance
	cacheRules := st.GetCacheRules("dom-topo-1")
	if len(cacheRules) != 1 {
		t.Fatalf("expected 1 cache rule, got %d", len(cacheRules))
	}
	cacheRules[0].IgnoredParams[0] = "mutated_param"
	cacheRules[0].IgnoredParams = append(cacheRules[0].IgnoredParams, "injected_param")

	freshCacheRules := st.GetCacheRules("dom-topo-1")
	if freshCacheRules[0].IgnoredParams[0] != "utm_source" {
		t.Errorf("internal cache rule IgnoredParams was mutated! expected utm_source, got %s", freshCacheRules[0].IgnoredParams[0])
	}
	if len(freshCacheRules[0].IgnoredParams) != 2 {
		t.Errorf("internal cache rule IgnoredParams length mutated! expected 2, got %d", len(freshCacheRules[0].IgnoredParams))
	}

	// 3. Verify RateLimitRule slice mutation resistance
	rlRules := st.GetRateLimitRules("dom-topo-1")
	if len(rlRules) != 1 {
		t.Fatalf("expected 1 rate limit rule, got %d", len(rlRules))
	}
	rlRules[0].RequestsPerMinute = 9999
	rlRules = append(rlRules, model.RateLimitRule{ID: "injected-rl"})

	freshRL := st.GetRateLimitRules("dom-topo-1")
	if freshRL[0].RequestsPerMinute != 60 {
		t.Errorf("internal rate limit RPM was mutated! expected 60, got %d", freshRL[0].RequestsPerMinute)
	}
	if len(freshRL) != 1 {
		t.Errorf("internal rate limit rules slice was mutated! expected 1, got %d", len(freshRL))
	}
}

func TestStore_SetterMutationResistance(t *testing.T) {
	st := store.NewStore()

	// 1. Caller mutates Domain pointer post-save
	domain := &model.Domain{
		ID:        "dom-postsave",
		ProjectID: "prj-1",
		Hostname:  "postsave.example.com",
		Status:    model.DomainStatusActive,
	}
	if err := st.SaveDomain(domain); err != nil {
		t.Fatalf("failed to save domain: %v", err)
	}
	// Caller mutates original pointer after save
	domain.Status = model.DomainStatusSuspended
	domain.Hostname = "evil-mutated.example.com"

	freshDom, err := st.GetDomain("dom-postsave")
	if err != nil {
		t.Fatalf("failed to get domain: %v", err)
	}
	if freshDom.Status != model.DomainStatusActive {
		t.Errorf("store domain was mutated post-save! Expected ACTIVE, got %s", freshDom.Status)
	}
	if freshDom.Hostname != "postsave.example.com" {
		t.Errorf("store domain hostname was mutated post-save! Expected postsave.example.com, got %s", freshDom.Hostname)
	}

	// 2. Caller mutates OriginPool and Origin post-save
	pool := &model.OriginPool{
		ID:          "pool-postsave",
		ProjectID:   "prj-1",
		Name:        "original-pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
	}
	st.SaveOriginPool(pool)
	pool.Name = "mutated-pool-name"

	freshPool, err := st.GetOriginPool("pool-postsave")
	if err != nil {
		t.Fatalf("failed to get pool: %v", err)
	}
	if freshPool.Name != "original-pool" {
		t.Errorf("store pool name mutated post-save! Expected original-pool, got %s", freshPool.Name)
	}

	orig := &model.Origin{
		ID:       "orig-postsave",
		PoolID:   "pool-postsave",
		Address:  "198.51.100.25",
		Port:     443,
		Protocol: model.ProtocolHTTPS,
		Healthy:  true,
	}
	if err := st.AddOrigin(orig); err != nil {
		t.Fatalf("failed to add origin: %v", err)
	}
	orig.Address = "198.51.100.99"
	orig.Port = 8080

	freshPoolWithOrig, _ := st.GetOriginPool("pool-postsave")
	if freshPoolWithOrig.Origins[0].Address != "198.51.100.25" {
		t.Errorf("store origin address mutated post-add! Expected 198.51.100.25, got %s", freshPoolWithOrig.Origins[0].Address)
	}
	if freshPoolWithOrig.Origins[0].Port != 443 {
		t.Errorf("store origin port mutated post-add! Expected 443, got %d", freshPoolWithOrig.Origins[0].Port)
	}

	// 3. Caller mutates Route post-save
	route := &model.Route{
		ID:         "route-postsave",
		DomainID:   "dom-postsave",
		PoolID:     "pool-postsave",
		PathPrefix: "/api",
		Priority:   5,
	}
	st.SaveRoute(route)
	route.PathPrefix = "/mutated-path"
	route.Priority = 999

	freshRoutes := st.GetRoutes("dom-postsave")
	if freshRoutes[0].PathPrefix != "/api" || freshRoutes[0].Priority != 5 {
		t.Errorf("store route mutated post-save! Expected /api and 5, got %s and %d",
			freshRoutes[0].PathPrefix, freshRoutes[0].Priority)
	}

	// 4. Caller mutates SecurityPolicy post-save
	secPolicy := &model.SecurityPolicy{
		DomainID:         "dom-postsave",
		WAFEnabled:       true,
		RateLimitEnabled: true,
	}
	st.SaveSecurityPolicy(secPolicy)
	secPolicy.WAFEnabled = false

	freshSec := st.GetSecurityPolicy("dom-postsave")
	if !freshSec.WAFEnabled {
		t.Errorf("store security policy mutated post-save! Expected WAFEnabled true")
	}

	// 5. Caller mutates CachePolicy post-save
	cachePol := &model.CachePolicy{
		DomainID:          "dom-postsave",
		DefaultTTLSeconds: 300,
	}
	st.SaveCachePolicy(cachePol)
	cachePol.DefaultTTLSeconds = 0

	freshCache := st.GetCachePolicy("dom-postsave")
	if freshCache.DefaultTTLSeconds != 300 {
		t.Errorf("store cache policy mutated post-save! Expected 300, got %d", freshCache.DefaultTTLSeconds)
	}
}

func TestStore_ProjectDomainQuota(t *testing.T) {
	st := store.NewStore()
	projectID := "prj-quota-test"
	st.SetProjectQuota(projectID, store.ProjectQuota{MaxDomains: 2})

	d1 := &model.Domain{ID: "dom-q1", ProjectID: projectID, Hostname: "q1.example.com", Status: model.DomainStatusPendingVerification}
	d2 := &model.Domain{ID: "dom-q2", ProjectID: projectID, Hostname: "q2.example.com", Status: model.DomainStatusPendingVerification}
	d3 := &model.Domain{ID: "dom-q3", ProjectID: projectID, Hostname: "q3.example.com", Status: model.DomainStatusPendingVerification}

	if err := st.SaveDomain(d1); err != nil {
		t.Fatalf("unexpected error saving d1: %v", err)
	}
	if err := st.SaveDomain(d2); err != nil {
		t.Fatalf("unexpected error saving d2: %v", err)
	}

	// 3rd domain must exceed quota
	err := st.SaveDomain(d3)
	if !errors.Is(err, store.ErrProjectQuotaExceeded) {
		t.Fatalf("expected ErrProjectQuotaExceeded, got %v", err)
	}

	// Deleting d1 should free up quota
	if err := st.DeleteDomain("dom-q1"); err != nil {
		t.Fatalf("failed to delete d1: %v", err)
	}

	if err := st.SaveDomain(d3); err != nil {
		t.Fatalf("expected d3 save to succeed after deleting d1, got %v", err)
	}
}

func TestStore_DeleteDomainCascade(t *testing.T) {
	st := store.NewStore()
	domainID := "dom-cascade-test"
	poolID := "pool-cascade-test"

	_ = st.SaveDomain(&model.Domain{ID: domainID, ProjectID: "p1", Hostname: "cascade.example.com"})
	_ = st.SaveOriginPool(&model.OriginPool{ID: poolID, ProjectID: "p1", Name: "pool-1"})
	_ = st.AddOrigin(&model.Origin{ID: "orig-1", PoolID: poolID, Address: "1.1.1.1", Port: 443, Protocol: model.ProtocolHTTPS})
	st.SaveRoute(&model.Route{ID: "rt-1", DomainID: domainID, PoolID: poolID, PathPrefix: "/"})
	st.SaveSecurityPolicy(&model.SecurityPolicy{ID: "sec-1", DomainID: domainID, WAFEnabled: true})
	st.SaveCachePolicy(&model.CachePolicy{ID: "c-1", DomainID: domainID, CacheEnabled: true})

	// Delete domain
	if err := st.DeleteDomain(domainID); err != nil {
		t.Fatalf("failed to delete domain: %v", err)
	}

	// Verify all cascades were deleted
	if _, err := st.GetDomain(domainID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("domain still exists after delete")
	}
	if _, err := st.GetDomainByHost("cascade.example.com"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("hostIndex still has domain after delete")
	}
	if len(st.GetRoutes(domainID)) != 0 {
		t.Errorf("routes still exist after delete")
	}
	if _, err := st.GetOriginPool(poolID); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("pool still exists after delete")
	}
	if st.GetSecurityPolicy(domainID) != nil {
		t.Errorf("security policy still exists after delete")
	}
	if st.GetCachePolicy(domainID) != nil {
		t.Errorf("cache policy still exists after delete")
	}
}

func TestStore_SweepExpiredPendingDomains(t *testing.T) {
	st := store.NewStore()

	// 1. Old pending domain (should be swept)
	st.SaveDomain(&model.Domain{
		ID:        "dom-old-pending",
		ProjectID: "p1",
		Hostname:  "old.example.com",
		Status:    model.DomainStatusPendingVerification,
		CreatedAt: time.Now().UTC().Add(-48 * time.Hour),
	})

	// 2. Fresh pending domain (should NOT be swept)
	st.SaveDomain(&model.Domain{
		ID:        "dom-fresh-pending",
		ProjectID: "p1",
		Hostname:  "fresh.example.com",
		Status:    model.DomainStatusPendingVerification,
		CreatedAt: time.Now().UTC().Add(-1 * time.Hour),
	})

	// 3. Old active domain (should NOT be swept)
	st.SaveDomain(&model.Domain{
		ID:        "dom-old-active",
		ProjectID: "p1",
		Hostname:  "active.example.com",
		Status:    model.DomainStatusActive,
		CreatedAt: time.Now().UTC().Add(-48 * time.Hour),
	})

	swept := st.SweepExpiredPendingDomains(24 * time.Hour)
	if swept != 1 {
		t.Fatalf("expected 1 swept domain, got %d", swept)
	}

	if _, err := st.GetDomain("dom-old-pending"); !errors.Is(err, store.ErrNotFound) {
		t.Errorf("expected old pending domain to be swept")
	}
	if _, err := st.GetDomain("dom-fresh-pending"); err != nil {
		t.Errorf("fresh pending domain should remain")
	}
	if _, err := st.GetDomain("dom-old-active"); err != nil {
		t.Errorf("old active domain should remain")
	}
}
