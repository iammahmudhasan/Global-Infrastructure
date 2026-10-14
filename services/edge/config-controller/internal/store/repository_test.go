package store_test

import (
	"fmt"
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

	testDomainID := fmt.Sprintf("dom-restart-recovery-%d", time.Now().UnixNano())
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
	if err := repo1.SaveRoute(rt); err != nil {
		t.Fatalf("failed to save route: %v", err)
	}

	cert := &model.Certificate{
		ID:                "cert-recovery-" + testDomainID,
		DomainID:          dom.ID,
		Domains:           []string{dom.Hostname},
		Status:            model.CertStatusActive,
		KeyType:           model.KeyTypeECDSA,
		SerialNumber:      "1122334455",
		CertPEM:           "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		PrivateKeyPEM:     "-----BEGIN EC PRIVATE KEY-----\nMHc...\n-----END EC PRIVATE KEY-----",
		FingerprintSHA256: "AA:BB:CC:DD",
		Issuer:            "Let's Encrypt Authority",
		IssuedAt:          time.Now().UTC(),
		ExpiresAt:         time.Now().UTC().Add(90 * 24 * time.Hour),
		AutoRenew:         true,
	}
	if err := repo1.SaveCertificate(cert); err != nil {
		t.Fatalf("failed to save initial certificate: %v", err)
	}

	// Finding 3: Simulate certificate renewal with new certificate ID & updated serial number.
	// Saving this active certificate must supersede the previous active certificate in DB.
	renewedCert := &model.Certificate{
		ID:                "cert-renewed-" + testDomainID,
		DomainID:          dom.ID,
		Domains:           []string{dom.Hostname},
		Status:            model.CertStatusActive,
		KeyType:           model.KeyTypeECDSA,
		SerialNumber:      "9988776655",
		CertPEM:           "-----BEGIN CERTIFICATE-----\nMIIB-RENEWED...\n-----END CERTIFICATE-----",
		PrivateKeyPEM:     "-----BEGIN EC PRIVATE KEY-----\nMHc-RENEWED...\n-----END EC PRIVATE KEY-----",
		FingerprintSHA256: "EE:FF:00:11",
		Issuer:            "Let's Encrypt Authority",
		IssuedAt:          time.Now().UTC().Add(10 * time.Second),
		ExpiresAt:         time.Now().UTC().Add(90 * 24 * time.Hour),
		AutoRenew:         true,
	}
	if err := repo1.SaveCertificate(renewedCert); err != nil {
		t.Fatalf("failed to save renewed certificate: %v", err)
	}

	// 1.5 Additional durable models: TLS settings, WAF rule, Cache rule, Health monitor, AI provider
	tlsSettings := &model.TLSSettings{
		EnforceHTTPS:  true,
		MinTLSVersion: "TLSv1.3",
		HSTS:          true,
		HSTSMaxAge:    31536000,
	}
	if err := repo1.SaveTLSSettings(dom.ID, tlsSettings); err != nil {
		t.Fatalf("failed to save TLS settings: %v", err)
	}

	secPolicy := &model.SecurityPolicy{
		ID:               "sec-rec-" + testDomainID,
		DomainID:         dom.ID,
		WAFEnabled:       true,
		WAFMode:          "BLOCK",
		OWASPProtection:  true,
		RateLimitEnabled: true,
		RateLimitRPM:     6000,
	}
	if err := repo1.SaveSecurityPolicy(secPolicy); err != nil {
		t.Fatalf("failed to save security policy: %v", err)
	}

	wafRule := model.WAFRule{
		ID:          "waf-rec-" + testDomainID,
		DomainID:    dom.ID,
		Name:        "Block Admin",
		Description: "Block administrative uri access",
		MatchType:   model.WAFMatchPathPrefix,
		Pattern:     "/admin",
		Action:      model.WAFActionBlock,
		Priority:    10,
		Enabled:     true,
	}
	if err := repo1.AddWAFRule(dom.ID, wafRule); err != nil {
		t.Fatalf("failed to save WAF rule: %v", err)
	}

	cachePolicy := &model.CachePolicy{
		ID:                   "cp-rec-" + testDomainID,
		DomainID:             dom.ID,
		CacheEnabled:         true,
		DefaultTTLSeconds:    3600,
		RespectOriginHeaders: true,
		QueryHandling:        model.QueryStringIgnoreAll,
	}
	if err := repo1.SaveCachePolicy(cachePolicy); err != nil {
		t.Fatalf("failed to save cache policy: %v", err)
	}

	cacheRule := model.CacheRule{
		ID:          "cache-rec-" + testDomainID,
		DomainID:    dom.ID,
		Name:        "Static Cache",
		PathPattern: "/static/*",
		TTLSeconds:  86400,
		Enabled:     true,
	}
	if err := repo1.AddCacheRule(dom.ID, cacheRule); err != nil {
		t.Fatalf("failed to save Cache rule: %v", err)
	}

	hm := &model.HealthMonitor{
		ID:                  "hm-rec-" + testDomainID,
		PoolID:              pool.ID,
		Protocol:            model.HealthCheckProtocolHTTP,
		Path:                "/healthz",
		Port:                443,
		IntervalSeconds:     10,
		TimeoutSeconds:      2,
		UnhealthyThreshold:  3,
		HealthyThreshold:    2,
		ExpectedStatusCodes: []int{200, 204},
	}
	if err := repo1.SaveHealthMonitor(hm); err != nil {
		t.Fatalf("failed to save health monitor: %v", err)
	}

	aiProvider := &model.AIProvider{
		ID:                      "ai-rec-" + testDomainID,
		ProjectID:               "prj-recovery",
		Name:                    "Recovery Anthropic Provider",
		Endpoint:                "https://api.anthropic.com/v1",
		ProviderType:            "anthropic",
		APIKey:                  "sk-ant-test-recovery-key-12345",
		CostPerMTokens:          15.0,
		Priority:                1,
		FailoverCooldownSecs:    30,
		Enabled:                 true,
		SovereigntyJurisdiction: "GLOBAL",
	}
	if err := repo1.SaveAIProvider(aiProvider); err != nil {
		t.Fatalf("failed to save AI provider: %v", err)
	}

	_ = repo1.Close()

	// 2. Simulated process restart: Create second independent repository instance from database
	repo2, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize restarted repository instance: %v", err)
	}
	defer func() {
		_ = repo2.DeleteDomain(dom.ID)
		_ = repo2.DeleteAIProvider(aiProvider.ID)
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
	if recoveredCert == nil || recoveredCert.Status != model.CertStatusActive || recoveredCert.ID != renewedCert.ID {
		t.Fatalf("certificate not recovered correctly: expected renewed ID %s, got %+v", renewedCert.ID, recoveredCert)
	}
	if recoveredCert.SerialNumber != renewedCert.SerialNumber {
		t.Fatalf("expected renewed serial number %s, got %s", renewedCert.SerialNumber, recoveredCert.SerialNumber)
	}

	// 3.1 Verify TLS settings persistence across restart
	recoveredTLS := repo2.GetTLSSettings(dom.ID)
	if recoveredTLS == nil || recoveredTLS.MinTLSVersion != "TLSv1.3" || !recoveredTLS.HSTS || recoveredTLS.HSTSMaxAge != 31536000 {
		t.Fatalf("TLS settings not recovered correctly across restart: %+v", recoveredTLS)
	}

	// 3.2 Verify WAF rules persistence across restart
	recoveredWAF := repo2.GetWAFRules(dom.ID)
	if len(recoveredWAF) != 1 || recoveredWAF[0].Pattern != "/admin" {
		t.Fatalf("WAF rules not recovered correctly across restart: %+v", recoveredWAF)
	}

	recoveredSec := repo2.GetSecurityPolicy(dom.ID)
	if recoveredSec == nil || !recoveredSec.WAFEnabled || recoveredSec.WAFMode != "BLOCK" {
		t.Fatalf("Security policy not recovered correctly across restart: %+v", recoveredSec)
	}

	// 3.3 Verify Cache rules persistence across restart
	recoveredCache := repo2.GetCacheRules(dom.ID)
	if len(recoveredCache) != 1 || recoveredCache[0].PathPattern != "/static/*" || recoveredCache[0].TTLSeconds != 86400 {
		t.Fatalf("Cache rules not recovered correctly across restart: %+v", recoveredCache)
	}

	recoveredCP := repo2.GetCachePolicy(dom.ID)
	if recoveredCP == nil || !recoveredCP.CacheEnabled || recoveredCP.DefaultTTLSeconds != 3600 {
		t.Fatalf("Cache policy not recovered correctly across restart: %+v", recoveredCP)
	}

	// 3.4 Verify Health Monitor persistence across restart
	recoveredHM := repo2.GetHealthMonitor(pool.ID)
	if recoveredHM == nil || recoveredHM.Path != "/healthz" || len(recoveredHM.ExpectedStatusCodes) != 2 {
		t.Fatalf("Health monitor not recovered correctly across restart: %+v", recoveredHM)
	}

	// 3.5 Verify AI Provider persistence and key decryption across restart
	recoveredAI, err := repo2.GetAIProvider(aiProvider.ID)
	if err != nil || recoveredAI == nil || recoveredAI.APIKey != "sk-ant-test-recovery-key-12345" {
		t.Fatalf("AI provider not recovered correctly across restart: %+v, err: %v", recoveredAI, err)
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

func TestPostgresRepository_WriteFailureDoesNotCorruptCache(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("POSTGRES_TEST_URL")
	}
	if dbURL == "" {
		t.Skip("skipping PostgresRepository write failure test: NEXUSEDGE_TEST_DATABASE_URL is not set")
	}

	repo, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize repository: %v", err)
	}

	// Close underlying DB connection to force database write failures
	_ = repo.Close()

	unpersistedDomainID := fmt.Sprintf("dom-fail-%d", time.Now().UnixNano())
	badDom := &model.Domain{
		ID:             unpersistedDomainID,
		ProjectID:      "prj-fail",
		Hostname:       unpersistedDomainID + ".example.com",
		Status:         model.DomainStatusActive,
		OnboardingType: "CNAME",
		CNAMETarget:    "edge.nexusedge.net",
		AllowedPoPs:    []string{"singapore"},
		CreatedAt:      time.Now().UTC(),
		UpdatedAt:      time.Now().UTC(),
	}

	// Attempt write — MUST fail because DB is closed
	err = repo.SaveDomain(badDom)
	if err == nil {
		t.Fatalf("expected write error to closed database, got nil")
	}

	// Invariant: Failed write must NOT update or corrupt active in-memory cache
	recovered, err := repo.GetDomain(unpersistedDomainID)
	if err == nil && recovered != nil {
		t.Fatalf("cache was corrupted with unpersisted domain on DB write failure")
	}
}
