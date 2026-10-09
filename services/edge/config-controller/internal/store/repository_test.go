package store_test

import (
	"os"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestRepository_InterfaceContract(t *testing.T) {
	// Assert compile-time satisfaction
	var inMemoryRepo store.Repository = store.NewStore()
	if inMemoryRepo == nil {
		t.Fatalf("expected non-nil in-memory repository")
	}

	var _ store.Repository = (*store.PostgresRepository)(nil)
}

func TestPostgresRepository_RestartRecovery(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("POSTGRES_TEST_URL")
	}
	if dbURL == "" {
		t.Skip("skipping PostgresRepository restart recovery test: NEXUSEDGE_TEST_DATABASE_URL is not set")
	}

	// 1. Initial process instance: Save tenant domain, origin pool, route, and certificate
	repo1, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize first repository instance: %v", err)
	}

	testDomainID := "dom-restart-recovery-" + time.Now().Format("150405")
	dom := &model.Domain{
		ID:             testDomainID,
		ProjectID:      "prj-recovery",
		Hostname:       testDomainID + ".example.com",
		Status:         model.DomainStatusActive,
		OnboardingType: "CNAME",
		CNAMETarget:    "edge.nexusedge.net",
		AllowedPoPs:    []string{"singapore", "dhaka"},
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}
	if err := repo1.SaveDomain(dom); err != nil {
		t.Fatalf("failed to save domain: %v", err)
	}

	pool := &model.OriginPool{
		ID:          "pool-recovery-" + testDomainID,
		ProjectID:   "prj-recovery",
		Name:        "recovery-pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		Origins: []model.Origin{
			{
				ID:          "orig-recovery-" + testDomainID,
				PoolID:      "pool-recovery-" + testDomainID,
				Address:     "198.51.100.20",
				Port:        443,
				Protocol:    model.ProtocolHTTPS,
				Weight:      100,
				Healthy:     true,
				AllowedPoPs: []string{"singapore", "dhaka"},
			},
		},
	}
	if err := repo1.SaveOriginPool(pool); err != nil {
		t.Fatalf("failed to save origin pool: %v", err)
	}

	rt := &model.Route{
		ID:         "route-recovery-" + testDomainID,
		DomainID:   dom.ID,
		PoolID:     pool.ID,
		PathPrefix: "/api",
		Priority:   10,
		TimeoutMs:  5000,
	}
	repo1.SaveRoute(rt)

	cert := &model.Certificate{
		ID:                "cert-recovery-" + testDomainID,
		DomainID:          dom.ID,
		Domains:           []string{dom.Hostname},
		Status:            model.CertStatusActive,
		KeyType:           model.KeyTypeECDSA,
		CertPEM:           "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		PrivateKeyPEM:     "-----BEGIN EC PRIVATE KEY-----\nMHc...\n-----END EC PRIVATE KEY-----",
		FingerprintSHA256: "AA:BB:CC:DD",
		Issuer:            "Let's Encrypt Authority",
		IssuedAt:          time.Now().UTC(),
		ExpiresAt:         time.Now().UTC().Add(90 * 24 * time.Hour),
		AutoRenew:         true,
	}
	repo1.SaveCertificate(cert)

	_ = repo1.Close()

	// 2. Simulated process restart: Create second independent repository instance from database
	repo2, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize restarted repository instance: %v", err)
	}
	defer func() {
		_ = repo2.DeleteDomain(dom.ID)
		_ = repo2.Close()
	}()

	// 3. Verify all entities survived process restart and are present in warm-up cache
	recoveredDom, err := repo2.GetDomain(dom.ID)
	if err != nil || recoveredDom == nil {
		t.Fatalf("failed to recover domain after restart: %v", err)
	}
	if recoveredDom.Hostname != dom.Hostname {
		t.Fatalf("domain hostname mismatch: expected %s, got %s", dom.Hostname, recoveredDom.Hostname)
	}

	recoveredPool, err := repo2.GetOriginPool(pool.ID)
	if err != nil || recoveredPool == nil {
		t.Fatalf("failed to recover origin pool after restart: %v", err)
	}
	if len(recoveredPool.Origins) != 1 || recoveredPool.Origins[0].Address != "198.51.100.20" {
		t.Fatalf("origin pool origins not recovered correctly: %+v", recoveredPool)
	}

	recoveredRoutes := repo2.GetRoutes(dom.ID)
	if len(recoveredRoutes) != 1 || recoveredRoutes[0].PathPrefix != "/api" {
		t.Fatalf("routes not recovered correctly: %+v", recoveredRoutes)
	}

	recoveredCert := repo2.GetCertificate(dom.ID)
	if recoveredCert == nil || recoveredCert.Status != model.CertStatusActive || recoveredCert.ID != cert.ID {
		t.Fatalf("certificate not recovered correctly: %+v", recoveredCert)
	}

	// 4. Verify compiled topology generation across restart
	topologies := repo2.GetActiveTopologies()
	var foundTopo *store.DomainTopology
	for _, topo := range topologies {
		if topo.Domain != nil && topo.Domain.ID == dom.ID {
			foundTopo = topo
			break
		}
	}
	if foundTopo == nil {
		t.Fatalf("recovered domain not found in active topologies after restart")
	}
	if len(foundTopo.Routes) != 1 || foundTopo.Pools[pool.ID] == nil {
		t.Fatalf("recovered topology routes/pools incomplete: %+v", foundTopo)
	}
}
