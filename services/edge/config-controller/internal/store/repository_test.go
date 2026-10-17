package store_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/alert"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/events"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/security"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestRepository_InterfaceContract(t *testing.T) {
	// Assert compile-time satisfaction
	var inMemoryRepo store.Repository = store.NewStore()
	if inMemoryRepo == nil {
		t.Fatalf("expected non-nil in-memory repository")
	}

	var _ store.Repository = (*store.PostgresRepository)(nil)
	var _ store.OutboxStore = (*store.Store)(nil)
	var _ store.OutboxStore = (*store.PostgresRepository)(nil)
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

func TestValidateProductionDatabaseURL(t *testing.T) {
	testCases := []struct {
		name        string
		databaseURL string
		expectErr   bool
		errContains string
	}{
		{
			name:        "Empty URL rejected in production",
			databaseURL: "",
			expectErr:   true,
			errContains: "empty",
		},
		{
			name:        "sslmode=disable rejected in production URL",
			databaseURL: "postgres://user:pass@172.30.0.5:5432/db?sslmode=disable",
			expectErr:   true,
			errContains: "strictly mandates sslmode=verify-full",
		},
		{
			name:        "Omitted sslmode rejected in production URL",
			databaseURL: "postgres://user:pass@172.30.0.5:5432/db",
			expectErr:   true,
			errContains: "strictly mandates sslmode=verify-full",
		},
		{
			name:        "sslmode=allow rejected in production URL",
			databaseURL: "postgres://user:pass@172.30.0.5:5432/db?sslmode=allow",
			expectErr:   true,
			errContains: "strictly mandates sslmode=verify-full",
		},
		{
			name:        "sslmode=prefer rejected in production URL",
			databaseURL: "postgres://user:pass@172.30.0.5:5432/db?sslmode=prefer",
			expectErr:   true,
			errContains: "strictly mandates sslmode=verify-full",
		},
		{
			name:        "sslmode=disable rejected in DSN format",
			databaseURL: "host=172.30.0.5 port=5432 user=nexusedge password=pass dbname=db sslmode=disable",
			expectErr:   true,
			errContains: "strictly mandates sslmode=verify-full",
		},
		{
			name:        "sslmode=require rejected in production URL",
			databaseURL: "postgres://user:pass@172.30.0.5:5432/db?sslmode=require",
			expectErr:   true,
			errContains: "strictly mandates sslmode=verify-full",
		},
		{
			name:        "sslmode=verify-ca rejected in production URL",
			databaseURL: "postgres://user:pass@172.30.0.5:5432/db?sslmode=verify-ca&sslrootcert=/etc/ssl/certs/root.crt",
			expectErr:   true,
			errContains: "strictly mandates sslmode=verify-full",
		},
		{
			name:        "sslmode=verify-full without sslrootcert rejected in production URL",
			databaseURL: "postgres://user:pass@172.30.0.5:5432/db?sslmode=verify-full",
			expectErr:   true,
			errContains: "requires sslrootcert",
		},
		{
			name:        "sslmode=verify-full with sslrootcert permitted in production URL",
			databaseURL: "postgres://user:pass@172.30.0.5:5432/db?sslmode=verify-full&sslrootcert=/etc/ssl/certs/root.crt",
			expectErr:   false,
		},
		{
			name:        "sslmode=verify-full with sslrootcert permitted in DSN format",
			databaseURL: "host=172.30.0.5 port=5432 user=nexusedge dbname=db sslmode=verify-full sslrootcert=/etc/ssl/certs/root.crt",
			expectErr:   false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := store.ValidateProductionDatabaseURL(tc.databaseURL)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error for URL %q, got nil", tc.databaseURL)
				}
				if !strings.Contains(err.Error(), tc.errContains) {
					t.Fatalf("expected error to contain %q, got %q", tc.errContains, err.Error())
				}
			} else {
				if err != nil {
					t.Fatalf("unexpected error for URL %q: %v", tc.databaseURL, err)
				}
			}
		})
	}
}

func TestPostgresRepository_AuditPersistenceAndFencing(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("POSTGRES_TEST_URL")
	}
	if dbURL == "" {
		t.Skip("skipping PostgresRepository audit persistence and outbox fencing test: NEXUSEDGE_TEST_DATABASE_URL is not set")
	}

	repo1, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize repository: %v", err)
	}

	testKey := []byte("nexusedge-test-audit-key-2026")
	repo1.SetAuditHMACKey(testKey)

	testID := fmt.Sprintf("aud-test-%d", time.Now().UnixNano())
	now := time.Now().UTC()
	tsStr := now.Truncate(time.Microsecond).Format(time.RFC3339Nano)

	head := repo1.GetLastAuditHash()
	hash1, err := security.ComputeCanonicalPayloadHash(
		testKey, testID, tsStr, "admin", "org-1", "prj-audit-test",
		"domain.create", "domain", "dom-1", "127.0.0.1",
		map[string]interface{}{"note": "test"}, head,
	)
	if err != nil {
		t.Fatalf("failed to compute canonical hash: %v", err)
	}

	log1 := &model.AuditLog{
		ID:           testID,
		OrgID:        "org-1",
		ProjectID:    "prj-audit-test",
		Actor:        "admin",
		Action:       "domain.create",
		ResourceType: "domain",
		ResourceID:   "dom-1",
		ClientIP:     "127.0.0.1",
		Details:      map[string]interface{}{"note": "test"},
		PrevHash:     head,
		Hash:         hash1,
		CreatedAt:    now,
	}

	if err := repo1.SaveAuditLog(log1); err != nil {
		t.Fatalf("failed to save audit log: %v", err)
	}

	// 1. Idempotent replay: exact duplicate (same ID, same hash) must succeed
	if err := repo1.SaveAuditLog(log1); err != nil {
		t.Fatalf("idempotent replay of audit log failed: %v", err)
	}

	// 2. Conflict detection: duplicate ID with altered hash must fail
	conflictLog := *log1
	conflictLog.Hash = "tampered-hash-value"
	if err := repo1.SaveAuditLog(&conflictLog); err == nil {
		t.Fatalf("expected conflict error for altered hash with existing ID, got nil")
	}

	// 3. Atomic head re-linking: saving an audit log with stale prev_hash must atomically re-link to head
	testID2 := fmt.Sprintf("aud-relink-%d", time.Now().UnixNano())
	log2 := &model.AuditLog{
		ID:           testID2,
		OrgID:        "org-1",
		ProjectID:    "prj-audit-test",
		Actor:        "admin",
		Action:       "domain.update",
		ResourceType: "domain",
		ResourceID:   "dom-1",
		ClientIP:     "127.0.0.1",
		Details:      map[string]interface{}{"note": "relink-test"},
		PrevHash:     "stale-nonexistent-head", // intentional stale head
		Hash:         "initial-placeholder-hash",
		CreatedAt:    time.Now().UTC(),
	}
	if err := repo1.SaveAuditLog(log2); err != nil {
		t.Fatalf("failed to save and re-link audit log: %v", err)
	}
	if log2.PrevHash != log1.Hash {
		t.Fatalf("expected log2 to be atomically re-linked to prevHash %s, got %s", log1.Hash, log2.PrevHash)
	}

	// 4. Missing HMAC key when re-linking is required: must fail closed immediately (P1 Finding A)
	repoNoKey, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize repository without HMAC key: %v", err)
	}
	defer repoNoKey.Close()

	staleLogNoKey := &model.AuditLog{
		ID:           fmt.Sprintf("aud-fail-key-%d", time.Now().UnixNano()),
		OrgID:        "org-1",
		ProjectID:    "prj-audit-test",
		Actor:        "admin",
		Action:       "domain.delete",
		ResourceType: "domain",
		ResourceID:   "dom-1",
		ClientIP:     "127.0.0.1",
		Details:      map[string]interface{}{"note": "fail-key"},
		PrevHash:     "stale-head-requiring-relink",
		Hash:         "placeholder-hash",
		CreatedAt:    time.Now().UTC(),
	}
	if err := repoNoKey.SaveAuditLog(staleLogNoKey); err == nil {
		t.Fatalf("expected SaveAuditLog to fail closed when re-linking without HMAC key, got nil")
	}

	_ = repo1.Close()

	// 5. Restart recovery and durable reads
	repo2, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to restart repository: %v", err)
	}
	repo2.SetAuditHMACKey(testKey)
	defer repo2.Close()

	recoveredLog, err := repo2.GetAuditLog(testID)
	if err != nil || recoveredLog == nil {
		t.Fatalf("failed to get audit log from database after restart: %v", err)
	}
	if recoveredLog.Hash != hash1 {
		t.Fatalf("expected hash %s, got %s", hash1, recoveredLog.Hash)
	}

	logs, total, err := repo2.ListAuditLogs("prj-audit-test", 10, 0)
	if err != nil {
		t.Fatalf("failed to list audit logs from database: %v", err)
	}
	if total < 2 || len(logs) < 2 {
		t.Fatalf("expected at least 2 audit logs, got total=%d len=%d", total, len(logs))
	}

	// 6. Authoritative empty query results
	emptyDomains := repo2.ListDomainsByProject("non-existent-project-404")
	if len(emptyDomains) != 0 {
		t.Fatalf("expected empty slice for non-existent project, got %d domains", len(emptyDomains))
	}

	// 7. Outbox lease fencing with cryptographically unique lease token (P1 Finding)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	claimedEvents, err := repo2.ClaimOutboxEvents(ctx, "worker-primary", 5, 30*time.Second)
	if err != nil {
		t.Fatalf("failed to claim outbox events: %v", err)
	}
	if len(claimedEvents) > 0 {
		ev := claimedEvents[0]
		if ev.LeaseToken == "" {
			t.Fatalf("expected claimed event to have non-empty LeaseToken")
		}

		// A. Wrong worker attempt must fail with ErrOutboxLeaseLost
		if err := repo2.MarkOutboxEventProcessed(ctx, ev.EventID, "worker-stale", ev.LeaseToken); err != store.ErrOutboxLeaseLost {
			t.Fatalf("expected ErrOutboxLeaseLost for wrong worker, got %v", err)
		}

		// B. Stale lease token attempt (even with same workerID) must fail with ErrOutboxLeaseLost
		if err := repo2.MarkOutboxEventProcessed(ctx, ev.EventID, "worker-primary", "lease-stale-invalid-token"); err != store.ErrOutboxLeaseLost {
			t.Fatalf("expected ErrOutboxLeaseLost for stale lease token, got %v", err)
		}

		// C. Re-claim scenario: if lease expires or is reclaimed with a new lease token, the old lease token is rejected
		_, _ = repo2.DB().ExecContext(ctx, "UPDATE outbox_events SET status = 'PENDING', locked_until = NOW() - INTERVAL '1 second' WHERE event_id = $1", ev.EventID)
		reclaimedEvents, err := repo2.ClaimOutboxEvents(ctx, "worker-primary", 1, 30*time.Second)
		if err != nil {
			t.Fatalf("failed to reclaim outbox event: %v", err)
		}
		if len(reclaimedEvents) > 0 {
			newEv := reclaimedEvents[0]
			if newEv.LeaseToken == ev.LeaseToken {
				t.Fatalf("expected new claim to generate distinct lease token, got duplicate: %s", newEv.LeaseToken)
			}
			// Stale ack using previous token must fail even though workerID is identical ("worker-primary")
			if err := repo2.MarkOutboxEventProcessed(ctx, ev.EventID, "worker-primary", ev.LeaseToken); err != store.ErrOutboxLeaseLost {
				t.Fatalf("expected stale lease token from previous claim to be rejected with ErrOutboxLeaseLost, got %v", err)
			}
			// Authorized worker with current lease token must succeed
			if err := repo2.MarkOutboxEventProcessed(ctx, newEv.EventID, "worker-primary", newEv.LeaseToken); err != nil {
				t.Fatalf("authorized worker with new lease token failed to mark processed: %v", err)
			}
		}
	}

	// 8. Audit DB outage semantics: queries must fail closed and return error (never silent cache fallback)
	closedRepo, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to open repo for outage test: %v", err)
	}
	_ = closedRepo.Close() // simulate DB outage
	if _, _, err := closedRepo.ListAuditLogs("", 10, 0); err == nil {
		t.Fatalf("expected ListAuditLogs to return error on database outage, got nil")
	}
	if _, err := closedRepo.GetAuditLog(testID); err == nil {
		t.Fatalf("expected GetAuditLog to return error on database outage, got nil")
	}
}

func TestPostgresRepository_MultiReplicaCacheConsistencyAndRouteRevocation(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("POSTGRES_TEST_URL")
	}
	if dbURL == "" {
		t.Skip("skipping multi-replica cache consistency test: NEXUSEDGE_TEST_DATABASE_URL is not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// 1. Initialize two separate repository instances simulating two distinct control-plane replicas
	repo1, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize replica 1: %v", err)
	}
	defer repo1.Close()

	repo2, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize replica 2: %v", err)
	}
	defer repo2.Close()

	projectID := fmt.Sprintf("prj-multi-rep-%d", time.Now().UnixNano())
	domainID := fmt.Sprintf("dom-multi-%d", time.Now().UnixNano())
	hostname := fmt.Sprintf("sync-%d.nexusedge.net", time.Now().UnixNano())
	poolID := fmt.Sprintf("pool-multi-%d", time.Now().UnixNano())
	originID := fmt.Sprintf("orig-multi-%d", time.Now().UnixNano())
	routeID := fmt.Sprintf("route-multi-%d", time.Now().UnixNano())

	// 2. Replica 1 onboards a domain, origin pool, origin, and route
	dom := &model.Domain{
		ID:             domainID,
		ProjectID:      projectID,
		Hostname:       hostname,
		Status:         model.DomainStatusActive,
		OnboardingType: "CNAME",
		CNAMETarget:    "edge.nexusedge.net",
		AllowedPoPs:    []string{"dhaka", "singapore"},
	}
	if err := repo1.SaveDomain(dom); err != nil {
		t.Fatalf("replica 1 failed to save domain: %v", err)
	}

	pool := &model.OriginPool{
		ID:          poolID,
		ProjectID:   projectID,
		Name:        "primary-pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		AllowedPoPs: []string{"dhaka", "singapore"},
	}
	if err := repo1.SaveOriginPool(pool); err != nil {
		t.Fatalf("replica 1 failed to save origin pool: %v", err)
	}

	origin := &model.Origin{
		ID:          originID,
		PoolID:      poolID,
		Address:     "10.0.0.1",
		Port:        8080,
		Protocol:    model.ProtocolHTTP,
		Weight:      100,
		Healthy:     true,
		AllowedPoPs: []string{"dhaka", "singapore"},
	}
	if err := repo1.AddOrigin(origin); err != nil {
		t.Fatalf("replica 1 failed to add origin: %v", err)
	}

	route := &model.Route{
		ID:         routeID,
		DomainID:   domainID,
		PoolID:     poolID,
		PathPrefix: "/api",
		Priority:   10,
		TimeoutMs:  5000,
	}
	if err := repo1.SaveRoute(route); err != nil {
		t.Fatalf("replica 1 failed to save route: %v", err)
	}

	// 3. Replica 2 synchronizes and confirms active domain, versioning, and compiled route topology
	stats, err := repo2.ReconcileCache(ctx)
	if err != nil {
		t.Fatalf("replica 2 failed to reconcile cache: %v", err)
	}
	if stats.ActiveDomains == 0 {
		t.Fatalf("expected at least 1 active domain in reconciliation stats, got 0")
	}

	d2, err := repo2.GetDomain(domainID)
	if err != nil {
		t.Fatalf("replica 2 failed to get domain after sync: %v", err)
	}
	if d2.Hostname != hostname || d2.Version < 1 {
		t.Fatalf("expected hostname %s and version >= 1, got hostname=%s version=%d", hostname, d2.Hostname, d2.Version)
	}

	// Also sync pool/origin/route into replica 2's cache to verify topology compilation
	_ = repo2.Cache().SaveOriginPool(pool)
	_ = repo2.Cache().AddOrigin(origin)
	_ = repo2.Cache().SaveRoute(route)

	toposBefore := repo2.GetActiveTopologies()
	var foundTopoBefore bool
	for _, tp := range toposBefore {
		if tp.Domain != nil && tp.Domain.ID == domainID {
			foundTopoBefore = true
			if len(tp.Routes) == 0 {
				t.Fatalf("expected routes in compiled topology on replica 2, got 0")
			}
		}
	}
	if !foundTopoBefore {
		t.Fatalf("expected replica 2 to compile active topology for newly synced domain %s", domainID)
	}

	// 4. Replica 1 deletes the domain from PostgreSQL and its local cache
	if err := repo1.DeleteDomain(domainID); err != nil {
		t.Fatalf("replica 1 failed to delete domain: %v", err)
	}

	// 5. Point lookup eviction test on Replica 2:
	// Prior to full background reconciliation, calling GetDomain directly on Replica 2
	// must query PostgreSQL, detect ErrNotFound, evict the stale domain from Replica 2's local cache,
	// and return ErrNotFound (no stale cache serving).
	if _, err := repo2.GetDomain(domainID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected GetDomain on replica 2 to return ErrNotFound after DB deletion, got %v", err)
	}
	if _, err := repo2.Cache().GetDomain(domainID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected domain to be evicted from replica 2 cache, but still present")
	}

	// 6. Route Revocation Verification:
	// The compiled topology on Replica 2 must NO LONGER include the deleted domain or any routes to it.
	toposAfter := repo2.GetActiveTopologies()
	for _, tp := range toposAfter {
		if tp.Domain != nil && tp.Domain.ID == domainID {
			t.Fatalf("SECURITY VIOLATION: deleted domain %s is still present in compiled active topologies on replica 2", domainID)
		}
	}

	// 7. Full reconciliation pass on Replica 2:
	// Create another domain, sync to replica 2, delete on replica 1, then run ReconcileCache.
	domainID2 := fmt.Sprintf("dom-multi2-%d", time.Now().UnixNano())
	hostname2 := fmt.Sprintf("sync2-%d.nexusedge.net", time.Now().UnixNano())
	dom2 := &model.Domain{
		ID:             domainID2,
		ProjectID:      projectID,
		Hostname:       hostname2,
		Status:         model.DomainStatusActive,
		OnboardingType: "CNAME",
		CNAMETarget:    "edge.nexusedge.net",
	}
	if err := repo1.SaveDomain(dom2); err != nil {
		t.Fatalf("replica 1 failed to save domain 2: %v", err)
	}
	if _, err := repo2.ReconcileCache(ctx); err != nil {
		t.Fatalf("replica 2 failed to reconcile domain 2: %v", err)
	}
	if _, err := repo2.Cache().GetDomain(domainID2); err != nil {
		t.Fatalf("expected domain 2 in replica 2 cache, got %v", err)
	}

	// Delete domain 2 on replica 1
	if err := repo1.DeleteDomain(domainID2); err != nil {
		t.Fatalf("replica 1 failed to delete domain 2: %v", err)
	}

	// ReconcileCache on replica 2 must detect missing domain and evict it
	recStats, err := repo2.ReconcileCache(ctx)
	if err != nil {
		t.Fatalf("replica 2 failed to reconcile cache after deletion: %v", err)
	}
	if recStats.EvictedDomains == 0 {
		t.Fatalf("expected at least 1 evicted domain during reconciliation, got 0")
	}
	if _, err := repo2.Cache().GetDomain(domainID2); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected domain 2 to be evicted from replica 2 cache after ReconcileCache")
	}

	// 8. ListDomainsByProject cache pruning test:
	// Insert an unpersisted ghost domain directly into replica 2's cache.
	ghostID := fmt.Sprintf("dom-ghost-%d", time.Now().UnixNano())
	ghostDom := &model.Domain{
		ID:        ghostID,
		ProjectID: projectID,
		Hostname:  fmt.Sprintf("ghost-%d.example.com", time.Now().UnixNano()),
		Status:    model.DomainStatusActive,
	}
	_ = repo2.Cache().SaveDomain(ghostDom)
	if _, err := repo2.Cache().GetDomain(ghostID); err != nil {
		t.Fatalf("failed to insert ghost domain into cache: %v", err)
	}

	// Calling ListDomainsByProject must query DB and prune the ghost domain from cache
	list := repo2.ListDomainsByProject(projectID)
	for _, ld := range list {
		if ld.ID == ghostID {
			t.Fatalf("expected ghost domain to be omitted from ListDomainsByProject result")
		}
	}
	if _, err := repo2.Cache().GetDomain(ghostID); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ghost domain to be pruned from replica 2 cache by ListDomainsByProject, but still exists")
	}
}

func TestStore_OutboxStoreParityAndDispatcher(t *testing.T) {
	s := store.NewStore()
	var processed []string
	var mu sync.Mutex

	handler := events.OutboxEventHandlerFunc(func(ctx context.Context, ev *store.OutboxEvent) error {
		mu.Lock()
		defer mu.Unlock()
		processed = append(processed, ev.EventType)
		return nil
	})

	dispatcher, err := events.NewOutboxDispatcher(s, handler, events.OutboxDispatcherConfig{
		WorkerID:      "in-memory-worker",
		BatchSize:     10,
		PollInterval:  50 * time.Millisecond,
		LeaseDuration: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to create dispatcher: %v", err)
	}

	// 1. Create domain on Store -> generates domain.config.changed outbox event
	dom := &model.Domain{
		ID:        "dom-parity-01",
		ProjectID: "proj-parity",
		Hostname:  "parity.example.com",
		Status:    model.DomainStatusActive,
		Version:   1,
	}
	if err := s.SaveDomain(dom); err != nil {
		t.Fatalf("SaveDomain failed: %v", err)
	}

	// 2. Update status -> generates domain.status.changed outbox event
	if err := s.UpdateDomainStatus(dom.ID, model.DomainStatusSuspended); err != nil {
		t.Fatalf("UpdateDomainStatus failed: %v", err)
	}

	// 3. Delete domain -> generates domain.deleted outbox event
	if err := s.DeleteDomain(dom.ID); err != nil {
		t.Fatalf("DeleteDomain failed: %v", err)
	}

	// 4. Dispatch batch
	count, err := dispatcher.DispatchBatch(context.Background())
	if err != nil {
		t.Fatalf("DispatchBatch failed: %v", err)
	}
	if count != 3 {
		t.Fatalf("expected 3 outbox events dispatched, got %d", count)
	}

	mu.Lock()
	defer mu.Unlock()
	if len(processed) != 3 {
		t.Fatalf("expected 3 events processed by handler, got %d", len(processed))
	}
	expectedTypes := []string{"domain.config.changed", "domain.status.changed", "domain.deleted"}
	for i, exp := range expectedTypes {
		if processed[i] != exp {
			t.Errorf("event %d: expected type %s, got %s", i, exp, processed[i])
		}
	}
}

func TestPostgresRepository_OutboxDispatcherIntegration(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("POSTGRES_TEST_URL")
	}
	if dbURL == "" {
		t.Skip("skipping Postgres integration test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	repo, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test PostgreSQL database: %v", err)
	}
	defer repo.Close()

	var processed []string
	var mu sync.Mutex

	handler := events.OutboxEventHandlerFunc(func(ctx context.Context, ev *store.OutboxEvent) error {
		mu.Lock()
		defer mu.Unlock()
		processed = append(processed, ev.EventType)
		return nil
	})

	dispatcher, err := events.NewOutboxDispatcher(repo, handler, events.OutboxDispatcherConfig{
		WorkerID:      fmt.Sprintf("pg-worker-%d", time.Now().UnixNano()),
		BatchSize:     10,
		PollInterval:  50 * time.Millisecond,
		LeaseDuration: 10 * time.Second,
	})
	if err != nil {
		t.Fatalf("failed to initialize OutboxDispatcher for PostgresRepository: %v", err)
	}

	domID := fmt.Sprintf("dom-outbox-pg-%d", time.Now().UnixNano())
	dom := &model.Domain{
		ID:             domID,
		ProjectID:      "proj-pg-outbox",
		Hostname:       fmt.Sprintf("outbox-%d.nexusedge.net", time.Now().UnixNano()),
		Status:         model.DomainStatusActive,
		OnboardingType: "CNAME",
		CNAMETarget:    "edge.nexusedge.net",
	}

	if err := repo.SaveDomain(dom); err != nil {
		t.Fatalf("SaveDomain failed: %v", err)
	}

	count, err := dispatcher.DispatchBatch(context.Background())
	if err != nil {
		t.Fatalf("DispatchBatch against PostgreSQL failed: %v", err)
	}
	if count < 1 {
		t.Fatalf("expected at least 1 event dispatched, got %d", count)
	}

	stats := dispatcher.Stats()
	if stats.EventsClaimed < 1 || stats.EventsProcessed < 1 {
		t.Fatalf("invalid dispatcher stats: %+v", stats)
	}
}

func TestStore_MultiResourceOutboxEvents(t *testing.T) {
	s := store.NewStore()
	ctx := context.Background()

	// 1. Save Domain
	dom := &model.Domain{
		ID:        "dom-all-outbox",
		ProjectID: "proj-all",
		Hostname:  "all.example.com",
		Status:    model.DomainStatusActive,
		Version:   1,
	}
	if err := s.SaveDomain(dom); err != nil {
		t.Fatalf("SaveDomain failed: %v", err)
	}

	// 2. Save Origin Pool
	pool := &model.OriginPool{
		ID:          "pool-all-outbox",
		ProjectID:   "proj-all",
		Name:        "all-pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		Origins: []model.Origin{
			{
				ID:       "orig-01",
				PoolID:   "pool-all-outbox",
				Address:  "192.0.2.1",
				Port:     80,
				Protocol: model.ProtocolHTTP,
				Healthy:  true,
			},
		},
	}
	if err := s.SaveOriginPool(pool); err != nil {
		t.Fatalf("SaveOriginPool failed: %v", err)
	}

	// 3. Save Route
	rt := &model.Route{
		ID:         "route-all-outbox",
		DomainID:   dom.ID,
		PoolID:     pool.ID,
		PathPrefix: "/api",
		Priority:   1,
		TimeoutMs:  5000,
	}
	if err := s.SaveRoute(rt); err != nil {
		t.Fatalf("SaveRoute failed: %v", err)
	}

	// 4. Save Security Policy
	sec := &model.SecurityPolicy{
		ID:               "sec-all-outbox",
		DomainID:         dom.ID,
		WAFEnabled:       true,
		WAFMode:          "BLOCK",
		RateLimitEnabled: true,
	}
	if err := s.SaveSecurityPolicy(sec); err != nil {
		t.Fatalf("SaveSecurityPolicy failed: %v", err)
	}

	// 5. Save Certificate
	cert := &model.Certificate{
		ID:        "cert-all-outbox",
		DomainID:  dom.ID,
		Status:    model.CertStatusActive,
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	}
	if err := s.SaveCertificate(cert); err != nil {
		t.Fatalf("SaveCertificate failed: %v", err)
	}

	// 6. Save AI Provider
	provider := &model.AIProvider{
		ID:           "aiprov-all-outbox",
		ProjectID:    "proj-all",
		Name:         "OpenAI Production",
		ProviderType: string(model.AIProviderTypeOpenAI),
		Endpoint:     "https://api.openai.com/v1",
		APIKey:       "sk-test-mock-key",
	}
	if err := s.SaveAIProvider(provider); err != nil {
		t.Fatalf("SaveAIProvider failed: %v", err)
	}

	eventsList, err := s.GetPendingOutboxEvents(ctx, 100)
	if err != nil {
		t.Fatalf("GetPendingOutboxEvents failed: %v", err)
	}

	eventMap := make(map[string]bool)
	for _, ev := range eventsList {
		eventMap[ev.EventType] = true
	}

	requiredEvents := []string{
		"domain.config.changed",
		"pool.config.changed",
		"route.config.changed",
		"security.policy.changed",
		"certificate.changed",
		"ai_provider.changed",
	}

	for _, expected := range requiredEvents {
		if !eventMap[expected] {
			t.Errorf("expected outbox event type %s was not found in pending outbox events", expected)
		}
	}
}

func TestPostgresRepository_MultiReplicaTopologyReconciliation(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("POSTGRES_TEST_URL")
	}
	if dbURL == "" {
		t.Skip("skipping Postgres multi-replica reconciliation test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	repo1, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect repo1 to test database: %v", err)
	}
	defer repo1.Close()

	repo2, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect repo2 to test database: %v", err)
	}
	defer repo2.Close()

	ctx := context.Background()
	suffix := time.Now().UnixNano()
	domainID := fmt.Sprintf("dom-multi-%d", suffix)
	poolID := fmt.Sprintf("pool-multi-%d", suffix)
	routeID := fmt.Sprintf("route-multi-%d", suffix)
	hostname := fmt.Sprintf("multi-%d.nexusedge.net", suffix)

	// 1. Repo 1 creates Origin Pool with Origin
	pool := &model.OriginPool{
		ID:          poolID,
		ProjectID:   "proj-multi-rep",
		Name:        "Multi-Replica Origin Pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		AllowedPoPs: []string{"dhaka", "singapore"},
		Origins: []model.Origin{
			{
				ID:          fmt.Sprintf("orig-multi-%d", suffix),
				PoolID:      poolID,
				Address:     "10.200.1.5",
				Port:        8080,
				Protocol:    model.ProtocolHTTP,
				Weight:      100,
				Healthy:     true,
				AllowedPoPs: []string{"dhaka", "singapore"},
			},
		},
	}
	if err := repo1.SaveOriginPool(pool); err != nil {
		t.Fatalf("repo1.SaveOriginPool failed: %v", err)
	}

	// 2. Repo 1 creates Domain
	dom := &model.Domain{
		ID:             domainID,
		ProjectID:      "proj-multi-rep",
		Hostname:       hostname,
		Status:         model.DomainStatusActive,
		OnboardingType: "CNAME",
		CNAMETarget:    "edge.nexusedge.net",
		AllowedPoPs:    []string{"dhaka", "singapore"},
		Version:        1,
	}
	if err := repo1.SaveDomain(dom); err != nil {
		t.Fatalf("repo1.SaveDomain failed: %v", err)
	}

	// 3. Repo 1 creates Route
	rt := &model.Route{
		ID:         routeID,
		DomainID:   domainID,
		PoolID:     poolID,
		PathPrefix: "/api/v1",
		Priority:   10,
		TimeoutMs:  4000,
	}
	if err := repo1.SaveRoute(rt); err != nil {
		t.Fatalf("repo1.SaveRoute failed: %v", err)
	}

	// 4. Authoritative fallback on Repo 2: GetOriginPool should fetch from DB even before ReconcileCache
	fetchedPool, err := repo2.GetOriginPool(poolID)
	if err != nil || fetchedPool == nil {
		t.Fatalf("repo2.GetOriginPool fallback failed: %v", err)
	}
	if len(fetchedPool.Origins) != 1 || fetchedPool.Origins[0].Address != "10.200.1.5" {
		t.Fatalf("repo2.GetOriginPool returned unexpected origins: %+v", fetchedPool.Origins)
	}

	// 5. Authoritative fallback on Repo 2: GetRoutes should fetch from DB even before ReconcileCache
	fetchedRoutes := repo2.GetRoutes(domainID)
	if len(fetchedRoutes) != 1 || fetchedRoutes[0].ID != routeID {
		t.Fatalf("repo2.GetRoutes fallback failed: %+v", fetchedRoutes)
	}

	// 6. Full Cache Reconciliation on Repo 2: pulls domains, routes, origin pools, security policies, certs
	if _, err := repo2.ReconcileCache(ctx); err != nil {
		t.Fatalf("repo2.ReconcileCache failed: %v", err)
	}

	// 7. Verify compiled Envoy topologies on Repo 2 now compile the full graph
	topos := repo2.GetActiveTopologies()
	var foundTopology *store.DomainTopology
	for _, dt := range topos {
		if dt.Domain.ID == domainID {
			foundTopology = dt
			break
		}
	}
	if foundTopology == nil {
		t.Fatalf("domain %s not found in repo2 compiled active topologies", domainID)
	}
	if len(foundTopology.Routes) != 1 || foundTopology.Routes[0].ID != routeID {
		t.Fatalf("expected compiled route %s in topology, got %+v", routeID, foundTopology.Routes)
	}
	compiledPool, exists := foundTopology.Pools[poolID]
	if !exists || compiledPool == nil {
		t.Fatalf("expected compiled pool %s in topology, got %+v", poolID, foundTopology.Pools)
	}
	if len(compiledPool.Origins) != 1 || compiledPool.Origins[0].Address != "10.200.1.5" {
		t.Fatalf("expected origin 10.200.1.5 in compiled pool, got %+v", compiledPool.Origins)
	}
}

func TestStore_ConcurrentAuditChain(t *testing.T) {
	s := store.NewStore()
	testKey := []byte("01234567890123456789012345678901")
	s.SetAuditHMACKey(testKey)

	const goroutines = 10
	const logsPerGoroutine = 5
	var wg sync.WaitGroup

	errCh := make(chan error, goroutines*logsPerGoroutine)

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gID int) {
			defer wg.Done()
			for i := 0; i < logsPerGoroutine; i++ {
				logID := fmt.Sprintf("aud-inmem-conc-%d-%d", gID, i)
				now := time.Now().UTC()
				tsStr := now.Truncate(time.Microsecond).Format(time.RFC3339Nano)
				hash, err := security.ComputeCanonicalPayloadHash(
					testKey, logID, tsStr, "actor-conc", "org-conc", "prj-conc",
					"domain.create", "domain", "dom-1", "127.0.0.1",
					map[string]interface{}{"idx": i}, security.GenesisHash,
				)
				if err != nil {
					errCh <- err
					return
				}
				auditLog := &model.AuditLog{
					ID:           logID,
					OrgID:        "org-conc",
					ProjectID:    "prj-conc",
					Actor:        "actor-conc",
					Action:       "domain.create",
					ResourceType: "domain",
					ResourceID:   "dom-1",
					ClientIP:     "127.0.0.1",
					Details:      map[string]interface{}{"idx": i},
					PrevHash:     security.GenesisHash,
					Hash:         hash,
					CreatedAt:    now,
				}
				if err := s.SaveAuditLog(auditLog); err != nil {
					errCh <- err
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent save audit log error: %v", err)
	}

	logs, total, err := s.ListAuditLogs("prj-conc", 100, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs failed: %v", err)
	}
	expectedTotal := goroutines * logsPerGoroutine
	if total != expectedTotal || len(logs) != expectedTotal {
		t.Fatalf("expected %d audit logs, got total=%d len=%d", expectedTotal, total, len(logs))
	}

	// Verify unbroken sequential continuity: logs are returned in descending chronological order
	for i := 0; i < len(logs)-1; i++ {
		if logs[i].PrevHash != logs[i+1].Hash {
			t.Errorf("chain break at index %d: log.PrevHash (%s) != next.Hash (%s)", i, logs[i].PrevHash, logs[i+1].Hash)
		}
	}
}

func TestPostgresRepository_ConcurrentAuditChainStress(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("POSTGRES_TEST_URL")
	}
	if dbURL == "" {
		t.Skip("skipping Postgres concurrent audit chain test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	testKey := []byte("01234567890123456789012345678901")
	repo, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect to test database: %v", err)
	}
	repo.SetAuditHMACKey(testKey)
	defer repo.Close()

	const goroutines = 10
	const logsPerGoroutine = 5
	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*logsPerGoroutine)

	projectID := fmt.Sprintf("prj-stress-%d", time.Now().UnixNano())

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(gID int) {
			defer wg.Done()
			for i := 0; i < logsPerGoroutine; i++ {
				logID := fmt.Sprintf("aud-pg-stress-%d-%d-%d", time.Now().UnixNano(), gID, i)
				now := time.Now().UTC()
				tsStr := now.Truncate(time.Microsecond).Format(time.RFC3339Nano)
				// Deliberately use genesis or arbitrary prevHash to force advisory lock & atomic re-linking under contention
				hash, err := security.ComputeCanonicalPayloadHash(
					testKey, logID, tsStr, "stress-actor", "org-stress", projectID,
					"route.create", "route", "rt-1", "127.0.0.1",
					map[string]interface{}{"gid": gID, "idx": i}, security.GenesisHash,
				)
				if err != nil {
					errCh <- err
					return
				}
				auditLog := &model.AuditLog{
					ID:           logID,
					OrgID:        "org-stress",
					ProjectID:    projectID,
					Actor:        "stress-actor",
					Action:       "route.create",
					ResourceType: "route",
					ResourceID:   "rt-1",
					ClientIP:     "127.0.0.1",
					Details:      map[string]interface{}{"gid": gID, "idx": i},
					PrevHash:     security.GenesisHash,
					Hash:         hash,
					CreatedAt:    now,
				}
				if err := repo.SaveAuditLog(auditLog); err != nil {
					errCh <- fmt.Errorf("concurrent SaveAuditLog (g=%d, i=%d): %w", gID, i, err)
					return
				}
			}
		}(g)
	}

	wg.Wait()
	close(errCh)

	for err := range errCh {
		t.Fatalf("concurrent audit log save failed: %v", err)
	}

	logs, total, err := repo.ListAuditLogs(projectID, 100, 0)
	if err != nil {
		t.Fatalf("ListAuditLogs failed: %v", err)
	}
	expectedTotal := goroutines * logsPerGoroutine
	if total != expectedTotal || len(logs) != expectedTotal {
		t.Fatalf("expected %d audit logs, got total=%d len=%d", expectedTotal, total, len(logs))
	}

	// Verify unbroken cryptographic chain: logs[i].PrevHash == logs[i+1].Hash
	for i := 0; i < len(logs)-1; i++ {
		if logs[i].PrevHash != logs[i+1].Hash {
			t.Fatalf("cryptographic chain broken at index %d: log.PrevHash (%s) != next.Hash (%s)", i, logs[i].PrevHash, logs[i+1].Hash)
		}
	}
}

func TestPostgresRepository_MultiReplicaStaleCacheRouteRevocation(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("POSTGRES_TEST_URL")
	}
	if dbURL == "" {
		t.Skip("skipping Postgres multi-replica route revocation test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	repo1, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect repo1: %v", err)
	}
	defer repo1.Close()

	repo2, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect repo2: %v", err)
	}
	defer repo2.Close()

	suffix := time.Now().UnixNano()
	domainID := fmt.Sprintf("dom-revoc-%d", suffix)
	poolID := fmt.Sprintf("pool-revoc-%d", suffix)
	routeID := fmt.Sprintf("route-revoc-%d", suffix)

	// 1. Repo 1 creates pool, domain, and route
	pool := &model.OriginPool{
		ID:          poolID,
		ProjectID:   "proj-revoc",
		Name:        "Revoc Pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		AllowedPoPs: []string{"dhaka"},
		Origins: []model.Origin{
			{
				ID:          fmt.Sprintf("orig-revoc-%d", suffix),
				PoolID:      poolID,
				Address:     "10.0.0.1",
				Port:        80,
				Protocol:    model.ProtocolHTTP,
				Healthy:     true,
				AllowedPoPs: []string{"dhaka"},
			},
		},
	}
	if err := repo1.SaveOriginPool(pool); err != nil {
		t.Fatalf("repo1.SaveOriginPool failed: %v", err)
	}

	dom := &model.Domain{
		ID:             domainID,
		ProjectID:      "proj-revoc",
		Hostname:       fmt.Sprintf("revoc-%d.nexusedge.net", suffix),
		Status:         model.DomainStatusActive,
		OnboardingType: "CNAME",
		AllowedPoPs:    []string{"dhaka"},
		Version:        1,
	}
	if err := repo1.SaveDomain(dom); err != nil {
		t.Fatalf("repo1.SaveDomain failed: %v", err)
	}

	rt := &model.Route{
		ID:         routeID,
		DomainID:   domainID,
		PoolID:     poolID,
		PathPrefix: "/api/test",
		Priority:   5,
		TimeoutMs:  3000,
	}
	if err := repo1.SaveRoute(rt); err != nil {
		t.Fatalf("repo1.SaveRoute failed: %v", err)
	}

	// 2. Repo 2 fetches and populates its local cache
	fetchedDom, err := repo2.GetDomain(domainID)
	if err != nil || fetchedDom == nil {
		t.Fatalf("repo2.GetDomain failed: %v", err)
	}
	fetchedRoutes := repo2.GetRoutes(domainID)
	if len(fetchedRoutes) != 1 || fetchedRoutes[0].ID != routeID {
		t.Fatalf("repo2.GetRoutes returned unexpected routes: %+v", fetchedRoutes)
	}

	// 3. Repo 1 deletes the domain from PostgreSQL
	if err := repo1.DeleteDomain(domainID); err != nil {
		t.Fatalf("repo1.DeleteDomain failed: %v", err)
	}

	// 4. Repo 2 (which hasn't run ReconcileCache yet) MUST immediately fail-closed:
	// Calling GetRoutes(domainID) checks authoritative DB, detects deletion, evicts cache, returns nil!
	routesAfterDelete := repo2.GetRoutes(domainID)
	if len(routesAfterDelete) != 0 {
		t.Fatalf("CRITICAL SECURITY HOLE: repo2 returned %d routes for deleted domain from stale cache!", len(routesAfterDelete))
	}

	// Calling GetDomain(domainID) on repo 2 returns ErrNotFound
	domAfterDelete, err := repo2.GetDomain(domainID)
	if !errors.Is(err, store.ErrNotFound) || domAfterDelete != nil {
		t.Fatalf("expected ErrNotFound from repo2 for deleted domain, got dom=%v err=%v", domAfterDelete, err)
	}
}

func TestStore_EdgeConvergencePersistence(t *testing.T) {
	s := store.NewStore()
	ctx := context.Background()

	// 1. Initial head is version 1
	v0, chk0, _, err := s.GetEdgeConvergenceHead(ctx)
	if err != nil || v0 != 1 || chk0 != "" {
		t.Fatalf("unexpected initial head: ver=%d chk=%s err=%v", v0, chk0, err)
	}

	// 2. Save new convergence head
	if err := s.SaveEdgeConvergenceHead(ctx, 42, "sha256-edge-head-42"); err != nil {
		t.Fatalf("SaveEdgeConvergenceHead failed: %v", err)
	}
	v1, chk1, _, err := s.GetEdgeConvergenceHead(ctx)
	if err != nil || v1 != 42 || chk1 != "sha256-edge-head-42" {
		t.Fatalf("GetEdgeConvergenceHead returned unexpected head: ver=%d chk=%s err=%v", v1, chk1, err)
	}

	// 3. Save gateway sync states
	rec1 := &model.GatewaySyncRecord{
		GatewayID:        "gw-test-01",
		PoPID:            "dhaka",
		AppliedVersion:   42,
		AppliedChecksum:  "sha256-edge-head-42",
		TargetVersion:    42,
		TargetChecksum:   "sha256-edge-head-42",
		Status:           model.SyncStatusInSync,
		LastAckAt:        time.Now().UTC(),
		ConvergenceLagMs: 15,
	}
	rec2 := &model.GatewaySyncRecord{
		GatewayID:        "gw-test-02",
		PoPID:            "singapore",
		AppliedVersion:   40,
		AppliedChecksum:  "sha256-edge-head-40",
		TargetVersion:    42,
		TargetChecksum:   "sha256-edge-head-42",
		VersionLag:       2,
		Status:           model.SyncStatusLagging,
		LastAckAt:        time.Now().UTC(),
		ConvergenceLagMs: 120,
	}
	if err := s.SaveGatewaySyncRecord(ctx, rec1); err != nil {
		t.Fatalf("SaveGatewaySyncRecord rec1 failed: %v", err)
	}
	if err := s.SaveGatewaySyncRecord(ctx, rec2); err != nil {
		t.Fatalf("SaveGatewaySyncRecord rec2 failed: %v", err)
	}

	// 4. Fetch specific gateway
	g1, err := s.GetGatewaySyncRecord(ctx, "gw-test-01")
	if err != nil || g1.Status != model.SyncStatusInSync || g1.AppliedVersion != 42 {
		t.Fatalf("GetGatewaySyncRecord gw-test-01 unexpected: %+v err=%v", g1, err)
	}

	// 5. List all gateways
	list, err := s.ListGatewaySyncRecords(ctx)
	if err != nil || len(list) != 2 {
		t.Fatalf("ListGatewaySyncRecords returned %d records, expected 2 (err=%v)", len(list), err)
	}
}

func TestStore_AllocateEdgeConvergenceHead(t *testing.T) {
	ctx := context.Background()
	s := store.NewStore()

	// Initial store starts at genesis version 1 with empty checksum
	v0, c0, _, _ := s.GetEdgeConvergenceHead(ctx)
	if v0 != 1 || c0 != "" {
		t.Fatalf("expected genesis version 1 with empty checksum, got ver=%d chk=%s", v0, c0)
	}

	// First configuration allocation advances from genesis 1 to 2
	v1, c1, err := s.AllocateEdgeConvergenceHead(ctx, "sha256-chk-1")
	if err != nil || v1 != 2 || c1 != "sha256-chk-1" {
		t.Fatalf("unexpected allocation 1: ver=%d chk=%s err=%v", v1, c1, err)
	}

	// Idempotent allocation with identical checksum does NOT advance version
	v2, c2, err := s.AllocateEdgeConvergenceHead(ctx, "sha256-chk-1")
	if err != nil || v2 != 2 || c2 != "sha256-chk-1" {
		t.Fatalf("unexpected idempotent allocation: ver=%d chk=%s err=%v", v2, c2, err)
	}

	// Distinct checksum advances version to 3
	v3, c3, err := s.AllocateEdgeConvergenceHead(ctx, "sha256-chk-2")
	if err != nil || v3 != 3 || c3 != "sha256-chk-2" {
		t.Fatalf("unexpected allocation 2: ver=%d chk=%s err=%v", v3, c3, err)
	}
}

func TestPostgresRepository_EdgeConvergencePersistence(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		t.Skip("skipping Postgres Edge Convergence Persistence test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	ctx := context.Background()
	repo1, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect repo1: %v", err)
	}
	defer repo1.Close()

	targetVer := time.Now().Unix()
	targetChk := fmt.Sprintf("sha256-pg-conv-%d", targetVer)

	// 1. Save authoritative target head in PostgreSQL
	if err := repo1.SaveEdgeConvergenceHead(ctx, targetVer, targetChk); err != nil {
		t.Fatalf("repo1.SaveEdgeConvergenceHead failed: %v", err)
	}

	// 2. Save gateway sync record
	gwID := fmt.Sprintf("gw-pg-%d", targetVer)
	rec := &model.GatewaySyncRecord{
		GatewayID:        gwID,
		PoPID:            "dhaka",
		AppliedVersion:   targetVer,
		AppliedChecksum:  targetChk,
		TargetVersion:    targetVer,
		TargetChecksum:   targetChk,
		Status:           model.SyncStatusInSync,
		LastAckAt:        time.Now().UTC(),
		ConvergenceLagMs: 22,
	}
	if err := repo1.SaveGatewaySyncRecord(ctx, rec); err != nil {
		t.Fatalf("repo1.SaveGatewaySyncRecord failed: %v", err)
	}

	// 3. Connect new repository instance to simulate control plane restart & multi-replica read
	repo2, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect repo2: %v", err)
	}
	defer repo2.Close()

	recVer, recChk, _, err := repo2.GetEdgeConvergenceHead(ctx)
	if err != nil || recVer != targetVer || recChk != targetChk {
		t.Fatalf("repo2 recovered unexpected convergence head: ver=%d (expected %d) chk=%s (expected %s) err=%v", recVer, targetVer, recChk, targetChk, err)
	}

	// 4. Cross-replica atomic generation allocation with row-lock in PostgreSQL
	chkAlloc1 := fmt.Sprintf("sha256-alloc-1-%d", targetVer)
	allocVer1, allocChk1, err := repo1.AllocateEdgeConvergenceHead(ctx, chkAlloc1)
	if err != nil || allocVer1 <= targetVer || allocChk1 != chkAlloc1 {
		t.Fatalf("repo1.AllocateEdgeConvergenceHead failed: ver=%d chk=%s err=%v", allocVer1, allocChk1, err)
	}

	// Replica 2 duplicate checksum allocation must be idempotent
	allocVer2, allocChk2, err := repo2.AllocateEdgeConvergenceHead(ctx, chkAlloc1)
	if err != nil || allocVer2 != allocVer1 || allocChk2 != chkAlloc1 {
		t.Fatalf("repo2 duplicate AllocateEdgeConvergenceHead failed: ver=%d (expected %d) chk=%s err=%v", allocVer2, allocVer1, allocChk2, err)
	}

	// Replica 2 new checksum allocation must advance version atomically
	chkAlloc2 := fmt.Sprintf("sha256-alloc-2-%d", targetVer)
	allocVer3, allocChk3, err := repo2.AllocateEdgeConvergenceHead(ctx, chkAlloc2)
	if err != nil || allocVer3 != allocVer1+1 || allocChk3 != chkAlloc2 {
		t.Fatalf("repo2 distinct AllocateEdgeConvergenceHead failed: ver=%d (expected %d) chk=%s err=%v", allocVer3, allocVer1+1, allocChk3, err)
	}

	fetchedGw, err := repo2.GetGatewaySyncRecord(ctx, gwID)
	if err != nil || fetchedGw.Status != model.SyncStatusInSync || fetchedGw.AppliedVersion != targetVer {
		t.Fatalf("repo2 recovered unexpected gateway sync record: %+v err=%v", fetchedGw, err)
	}

	list, err := repo2.ListGatewaySyncRecords(ctx)
	if err != nil || len(list) == 0 {
		t.Fatalf("repo2.ListGatewaySyncRecords returned empty or error: %v", err)
	}
	found := false
	for _, g := range list {
		if g.GatewayID == gwID && g.Status == model.SyncStatusInSync {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("repo2.ListGatewaySyncRecords did not contain %s", gwID)
	}
}

func TestPostgresRepository_ReconcileCache_QueryFailurePreservesWorkingCache(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		t.Skip("skipping Postgres ReconcileCache query failure test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	ctx := context.Background()
	repo, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect repo: %v", err)
	}
	defer repo.Close()

	// 1. Populate a test domain and route
	ts := time.Now().UnixNano()
	domID := fmt.Sprintf("dom-rec-fail-%d", ts)
	dom := &model.Domain{
		ID:        domID,
		ProjectID: "prj-test",
		Hostname:  fmt.Sprintf("rec-fail-%d.example.com", ts),
		Status:    model.DomainStatusActive,
		Version:   1,
	}
	if err := repo.SaveDomain(dom); err != nil {
		t.Fatalf("SaveDomain failed: %v", err)
	}

	rtID := fmt.Sprintf("rt-rec-fail-%d", ts)
	rt := &model.Route{
		ID:         rtID,
		DomainID:   domID,
		PoolID:     "pool-default",
		PathPrefix: "/api",
		Priority:   10,
		TimeoutMs:  5000,
	}
	if err := repo.SaveRoute(rt); err != nil {
		t.Fatalf("SaveRoute failed: %v", err)
	}

	// 2. Perform a successful reconciliation pass to ensure cache is populated
	if _, err := repo.ReconcileCache(ctx); err != nil {
		t.Fatalf("initial ReconcileCache failed: %v", err)
	}

	// Verify working cache has route
	cachedRoutesBefore := repo.GetRoutes(domID)
	if len(cachedRoutesBefore) == 0 {
		t.Fatalf("expected cached route before failure test, got 0")
	}

	// 3. Trigger reconciliation failure with canceled context (simulating query failure)
	canceledCtx, cancel := context.WithCancel(ctx)
	cancel() // canceled immediately before query execution

	stats, err := repo.ReconcileCache(canceledCtx)
	if err == nil {
		t.Fatalf("expected ReconcileCache to return error on query failure, got stats: %+v", stats)
	}

	// 4. Invariant Verification: Working cache must NOT have been wiped or mutated
	cachedRoutesAfter := repo.GetRoutes(domID)
	if len(cachedRoutesAfter) == 0 {
		t.Fatalf("CRITICAL BUG: ReconcileCache wiped working routes on query failure!")
	}
	if cachedRoutesAfter[0].ID != rtID {
		t.Fatalf("expected cached route %s, got %s", rtID, cachedRoutesAfter[0].ID)
	}

	cachedDom, err := repo.GetDomain(domID)
	if err != nil || cachedDom == nil {
		t.Fatalf("expected cached domain %s to remain present, err: %v", domID, err)
	}
}

func TestPostgresRepository_ReconcileCache_CorruptCiphertextFailsClosed(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		dbURL = os.Getenv("DATABASE_URL")
	}
	if dbURL == "" {
		t.Skip("skipping Postgres ReconcileCache corrupt ciphertext test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	ctx := context.Background()
	repo, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to connect repo: %v", err)
	}
	defer repo.Close()

	ts := time.Now().UnixNano()
	domID := fmt.Sprintf("dom-corrupt-cert-%d", ts)
	dom := &model.Domain{
		ID:        domID,
		ProjectID: "prj-test",
		Hostname:  fmt.Sprintf("corrupt-%d.example.com", ts),
		Status:    model.DomainStatusActive,
		Version:   1,
	}
	if err := repo.SaveDomain(dom); err != nil {
		t.Fatalf("SaveDomain failed: %v", err)
	}

	// Seed healthy domain into cache
	validDomID := fmt.Sprintf("dom-healthy-%d", ts)
	validDom := &model.Domain{
		ID:        validDomID,
		ProjectID: "prj-test",
		Hostname:  fmt.Sprintf("healthy-%d.example.com", ts),
		Status:    model.DomainStatusActive,
		Version:   1,
	}
	if err := repo.SaveDomain(validDom); err != nil {
		t.Fatalf("SaveDomain healthy failed: %v", err)
	}
	defer func() {
		_, _ = repo.DB().ExecContext(ctx, "DELETE FROM domains WHERE id = $1", validDomID)
	}()

	// Insert active certificate with corrupted ciphertext directly into DB
	certID := fmt.Sprintf("cert-corrupt-%d", ts)
	corruptedCiphertext := "enc:v1:this-is-corrupted-ciphertext-that-fails-decryption"
	_, err = repo.DB().ExecContext(ctx, `
		INSERT INTO certificates (id, domain_id, status, issuer, cert_sn, cert_pem, private_key_pem, fingerprint_sha256, key_type, domains, auto_renew, expires_at)
		VALUES ($1, $2, 'ACTIVE', 'Let''s Encrypt', '123456', '-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----', $3, 'fingerprint123', 'RSA', ARRAY[$4], false, NOW() + INTERVAL '30 days')
	`, certID, domID, corruptedCiphertext, dom.Hostname)
	if err != nil {
		t.Fatalf("failed to insert corrupt cert: %v", err)
	}
	defer func() {
		_, _ = repo.DB().ExecContext(ctx, "DELETE FROM certificates WHERE id = $1", certID)
		_, _ = repo.DB().ExecContext(ctx, "DELETE FROM domains WHERE id = $1", domID)
	}()

	// ReconcileCache must fail-closed with error
	stats, err := repo.ReconcileCache(ctx)
	if err == nil {
		t.Fatalf("expected ReconcileCache to fail due to corrupt ciphertext, but succeeded with stats: %+v", stats)
	}
	if !strings.Contains(err.Error(), "decrypt private key for certificate") {
		t.Fatalf("expected decryption error message, got: %v", err)
	}

	// Working cache must still retain healthy domain
	cachedHealthyAfter, err := repo.GetDomain(validDomID)
	if err != nil || cachedHealthyAfter == nil {
		t.Fatalf("expected healthy domain to remain in cache despite failed reconciliation: %v", err)
	}

	// GetCertificate must also fail-closed and return nil rather than returning ciphertext
	badCert := repo.GetCertificate(domID)
	if badCert != nil {
		t.Fatalf("expected GetCertificate to return nil for corrupt ciphertext, got %+v", badCert)
	}
}

func TestStore_ApplyReconciliationSnapshot_AtomicEviction(t *testing.T) {
	s := store.NewStore()

	// 1. Seed store with 2 items of each entity type
	dom1 := &model.Domain{ID: "dom-keep", ProjectID: "p1", Hostname: "keep.example.com", Status: model.DomainStatusActive}
	dom2 := &model.Domain{ID: "dom-stale", ProjectID: "p1", Hostname: "stale.example.com", Status: model.DomainStatusActive}
	_ = s.SaveDomain(dom1)
	_ = s.SaveDomain(dom2)

	pool1 := &model.OriginPool{ID: "pool-keep", ProjectID: "p1", Name: "keep-pool"}
	pool2 := &model.OriginPool{ID: "pool-stale", ProjectID: "p1", Name: "stale-pool"}
	_ = s.SaveOriginPool(pool1)
	_ = s.SaveOriginPool(pool2)

	orig1 := &model.Origin{ID: "orig-keep", PoolID: "pool-keep", Address: "1.1.1.1", Port: 80, Weight: 1}
	orig2 := &model.Origin{ID: "orig-stale", PoolID: "pool-stale", Address: "2.2.2.2", Port: 80, Weight: 1}
	_ = s.AddOrigin(orig1)
	_ = s.AddOrigin(orig2)

	cert1 := &model.Certificate{ID: "cert-keep", DomainID: "dom-keep", Domains: []string{"keep.example.com"}, Status: model.CertStatusActive}
	cert2 := &model.Certificate{ID: "cert-stale", DomainID: "dom-stale", Domains: []string{"stale.example.com"}, Status: model.CertStatusActive}
	_ = s.SaveCertificate(cert1)
	_ = s.SaveCertificate(cert2)

	sp1 := &model.SecurityPolicy{ID: "sp-keep", DomainID: "dom-keep"}
	sp2 := &model.SecurityPolicy{ID: "sp-stale", DomainID: "dom-stale"}
	_ = s.SaveSecurityPolicy(sp1)
	_ = s.SaveSecurityPolicy(sp2)

	versionBefore := s.GetVersion()

	// 2. Prepare candidate reconciliation snapshot containing ONLY the keep entities
	pool1WithOrigins := &model.OriginPool{
		ID:        "pool-keep",
		ProjectID: "p1",
		Name:      "keep-pool",
		Origins:   []model.Origin{*orig1},
	}
	snap := &store.ReconciliationSnapshot{
		Domains: map[string]*model.Domain{
			dom1.ID: dom1,
		},
		RoutesByDomain: map[string][]*model.Route{},
		Pools: map[string]*model.OriginPool{
			pool1WithOrigins.ID: pool1WithOrigins,
		},
		Certificates: map[string]*model.Certificate{
			cert1.DomainID: cert1,
		},
		SecurityPolicies: map[string]*model.SecurityPolicy{
			sp1.DomainID: sp1,
		},
	}

	// 3. Atomically apply snapshot
	if err := s.ApplyReconciliationSnapshot(snap); err != nil {
		t.Fatalf("ApplyReconciliationSnapshot failed: %v", err)
	}

	// 4. Invariant: Stale entities MUST be completely evicted
	if _, err := s.GetDomain("dom-stale"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for dom-stale, got %v", err)
	}
	if _, err := s.GetOriginPool("pool-stale"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("expected ErrNotFound for pool-stale, got %v", err)
	}
	if cert := s.GetCertificate("dom-stale"); cert != nil {
		t.Fatalf("expected nil certificate for dom-stale, got %+v", cert)
	}
	if sp := s.GetSecurityPolicy("dom-stale"); sp != nil {
		t.Fatalf("expected nil security policy for dom-stale, got %+v", sp)
	}

	// 5. Invariant: Kept entities MUST remain accessible
	if dom, err := s.GetDomain("dom-keep"); err != nil || dom == nil {
		t.Fatalf("expected dom-keep to be present, err: %v", err)
	}
	pool, err := s.GetOriginPool("pool-keep")
	if err != nil || pool == nil {
		t.Fatalf("expected pool-keep to be present, err: %v", err)
	}
	if len(pool.Origins) != 1 || pool.Origins[0].ID != "orig-keep" {
		t.Fatalf("expected pool-keep to have orig-keep, got %+v", pool.Origins)
	}
	if cert := s.GetCertificate("dom-keep"); cert == nil {
		t.Fatalf("expected cert for dom-keep to be present")
	}
	if sp := s.GetSecurityPolicy("dom-keep"); sp == nil {
		t.Fatalf("expected sp for dom-keep to be present")
	}

	// Version must increment
	if s.GetVersion() <= versionBefore {
		t.Fatalf("expected store version to increment from %d, got %d", versionBefore, s.GetVersion())
	}
}

func TestPostgresRepository_MultiReplicaPoPSnapshotHeadConcurrency(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("skipping Postgres MultiReplicaPoPSnapshotHeadConcurrency test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	repo1, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize replica 1: %v", err)
	}
	defer repo1.Close()

	repo2, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize replica 2: %v", err)
	}
	defer repo2.Close()

	popID := fmt.Sprintf("pop-concurrent-head-%d", time.Now().UnixNano())

	// 1. Concurrent Idempotent Write: Both replicas write version 10 with checksum "hash-v10"
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for _, r := range []*store.PostgresRepository{repo1, repo2} {
		wg.Add(1)
		go func(repo *store.PostgresRepository) {
			defer wg.Done()
			errs <- repo.SavePoPSnapshotHead(ctx, popID, 10, "hash-v10")
		}(r)
	}
	wg.Wait()
	close(errs)

	for e := range errs {
		if e != nil {
			t.Fatalf("concurrent idempotent SavePoPSnapshotHead failed: %v", e)
		}
	}

	// Verify authoritative head in DB is v10 / "hash-v10"
	ver1, chk1, _, err := repo1.GetPoPSnapshotHead(ctx, popID)
	if err != nil {
		t.Fatalf("repo1.GetPoPSnapshotHead failed: %v", err)
	}
	ver2, chk2, _, err := repo2.GetPoPSnapshotHead(ctx, popID)
	if err != nil {
		t.Fatalf("repo2.GetPoPSnapshotHead failed: %v", err)
	}
	if ver1 != 10 || chk1 != "hash-v10" || ver2 != 10 || chk2 != "hash-v10" {
		t.Fatalf("expected head v10/hash-v10 on both replicas, got r1=(%d,%s) r2=(%d,%s)", ver1, chk1, ver2, chk2)
	}

	// 2. Monotonic Advancement: Replica 1 advances to version 15
	if err := repo1.SavePoPSnapshotHead(ctx, popID, 15, "hash-v15"); err != nil {
		t.Fatalf("replica 1 failed to advance to v15: %v", err)
	}

	// 3. Stale Version Rejection: Replica 2 attempts to write stale version 12
	staleErr := repo2.SavePoPSnapshotHead(ctx, popID, 12, "hash-v12")
	if staleErr == nil {
		t.Fatalf("expected stale version 12 to be rejected by repo2, got nil error")
	}
	if !strings.Contains(staleErr.Error(), "stale snapshot version 12 rejected") {
		t.Fatalf("expected stale rejection message, got: %v", staleErr)
	}

	// 4. Conflicting Checksum Rejection: Replica 2 attempts to write version 15 with differing checksum "hash-v15-conflict"
	conflictErr := repo2.SavePoPSnapshotHead(ctx, popID, 15, "hash-v15-conflict")
	if conflictErr == nil {
		t.Fatalf("expected checksum conflict on version 15 to be rejected, got nil error")
	}
	if !strings.Contains(conflictErr.Error(), "checksum mismatch conflict") {
		t.Fatalf("expected checksum mismatch error, got: %v", conflictErr)
	}

	// 5. Invariant: Authoritative state remains v15 / "hash-v15" on both replicas
	verFinal, chkFinal, _, err := repo2.GetPoPSnapshotHead(ctx, popID)
	if err != nil || verFinal != 15 || chkFinal != "hash-v15" {
		t.Fatalf("expected authoritative head to remain v15/hash-v15, got ver=%d chk=%s err=%v", verFinal, chkFinal, err)
	}
}

func TestPostgresRepository_SavePoPSnapshotHead_CanceledContext(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("skipping Postgres SavePoPSnapshotHead CanceledContext test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	repo, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize repository: %v", err)
	}
	defer repo.Close()

	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel() // canceled immediately to simulate connection/outage failure

	err = repo.SavePoPSnapshotHead(canceledCtx, "pop-outage", 1, "chk-1")
	if err == nil {
		t.Fatalf("expected error when saving snapshot head with canceled context, got nil")
	}
}

type mockReconcileAlerter struct {
	mu     sync.Mutex
	events []alert.Event
}

func (m *mockReconcileAlerter) SendAlert(ctx context.Context, event alert.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockReconcileAlerter) IsConfigured() bool {
	return true
}

func (m *mockReconcileAlerter) getEvents() []alert.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]alert.Event, len(m.events))
	copy(copied, m.events)
	return copied
}

func TestPostgresRepository_ReconcileCache_RepeatedFailuresThresholdTracking(t *testing.T) {
	dbURL := os.Getenv("NEXUSEDGE_TEST_DATABASE_URL")
	if dbURL == "" {
		t.Skip("skipping Postgres ReconcileCache repeated failures test: NEXUSEDGE_TEST_DATABASE_URL not set")
	}

	repo, err := store.NewPostgresRepository(dbURL)
	if err != nil {
		t.Fatalf("failed to initialize repository: %v", err)
	}
	defer repo.Close()

	mockAlert := &mockReconcileAlerter{}
	repo.SetAlerter(mockAlert)

	// Initial consecutive failures count must be 0
	if fails := repo.ConsecutiveReconcileFailures(); fails != 0 {
		t.Fatalf("expected 0 initial failures, got %d", fails)
	}

	// 1. Simulate repeated reconciliation failures with canceled context
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()

	for i := 1; i <= 3; i++ {
		_, recErr := repo.ReconcileCache(canceledCtx)
		if recErr == nil {
			t.Fatalf("iteration %d: expected error on canceled context, got nil", i)
		}
		if fails := repo.ConsecutiveReconcileFailures(); fails != int64(i) {
			t.Fatalf("iteration %d: expected consecutive failures = %d, got %d", i, i, fails)
		}
	}

	// Check that threshold (>= 3) was reached and last error was recorded
	if lastErr := repo.LastReconcileError(); lastErr == nil {
		t.Fatalf("expected recorded last reconcile error, got nil")
	}
	if dur := repo.LastReconcileDuration(); dur <= 0 {
		t.Fatalf("expected recorded reconcile duration > 0, got %v", dur)
	}

	// Invariant: Alerter MUST have received RECONCILER_THRESHOLD_EXCEEDED event
	time.Sleep(100 * time.Millisecond) // allow goroutine dispatch
	events := mockAlert.getEvents()
	var thresholdAlertFound bool
	for _, ev := range events {
		if ev.Type == alert.EventTypeReconcilerThresholdExceeded {
			thresholdAlertFound = true
			if ev.Severity != alert.SeverityCritical {
				t.Fatalf("expected CRITICAL severity, got %v", ev.Severity)
			}
			if ev.Details["consecutive_failures"] != "3" {
				t.Fatalf("expected consecutive_failures=3, got %v", ev.Details["consecutive_failures"])
			}
			break
		}
	}
	if !thresholdAlertFound {
		t.Fatalf("expected RECONCILER_THRESHOLD_EXCEEDED alert event, got %v", events)
	}

	// 2. Successful reconciliation resets failure counter to 0
	testStart := time.Now().UTC()
	ctx, cancelTimeout := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelTimeout()

	stats, recErr := repo.ReconcileCache(ctx)
	if recErr != nil {
		t.Fatalf("expected healthy ReconcileCache to succeed, got %v", recErr)
	}
	if stats == nil {
		t.Fatalf("expected non-nil stats from successful ReconcileCache")
	}

	if fails := repo.ConsecutiveReconcileFailures(); fails != 0 {
		t.Fatalf("expected consecutive failures to reset to 0 after success, got %d", fails)
	}
	if lastErr := repo.LastReconcileError(); lastErr != nil {
		t.Fatalf("expected last error to reset to nil after success, got %v", lastErr)
	}
	if lastSuccess := repo.LastReconcileSuccess(); lastSuccess.Before(testStart) {
		t.Fatalf("expected last reconcile success timestamp (%v) to be after testStart (%v)", lastSuccess, testStart)
	}
}
