package store_test

import (
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
