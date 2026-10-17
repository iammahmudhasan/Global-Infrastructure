package store_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

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
