package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/api"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func setupTestServer() http.Handler {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	comp := compiler.NewCompiler(9901, 80, 443)
	return api.NewAPIHandler(st, svc, comp)
}

func TestAPIWorkflow(t *testing.T) {
	handler := setupTestServer()

	// 1. Health check
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 from /healthz, got %d", w.Code)
	}

	// 2. Onboard Domain
	body, _ := json.Marshal(map[string]interface{}{
		"hostname":        "api.customer.com",
		"origin_address":  "origin.customer.internal",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/projects/prj-alpha/domains", bytes.NewReader(body))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from onboard domain, got %d: %s", w.Code, w.Body.String())
	}

	var onboardResp struct {
		DomainID    string `json:"domain_id"`
		CNAMETarget string `json:"cname_target"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &onboardResp); err != nil {
		t.Fatalf("failed to decode onboard response: %v", err)
	}
	if onboardResp.DomainID == "" || onboardResp.CNAMETarget == "" {
		t.Fatalf("expected valid domain ID and CNAME target, got %+v", onboardResp)
	}

	// 3. Before verification, Envoy config should have 0 clusters
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/envoy-config", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	var envoyCfg compiler.EnvoyConfig
	_ = json.Unmarshal(w.Body.Bytes(), &envoyCfg)
	if len(envoyCfg.StaticResources.Clusters) != 0 {
		t.Errorf("expected 0 clusters before domain verification, got %d", len(envoyCfg.StaticResources.Clusters))
	}

	// 4. Verify Domain
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+onboardResp.DomainID+"/verify", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from verify domain, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Add a secondary origin to the pool
	addOriginBody, _ := json.Marshal(map[string]interface{}{
		"address":  "secondary-origin.customer.internal",
		"port":     443,
		"protocol": "HTTPS",
		"weight":   50,
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+onboardResp.DomainID+"/origins", bytes.NewReader(addOriginBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from add origin, got %d: %s", w.Code, w.Body.String())
	}

	// 6. After verification & secondary origin, Envoy config should have 1 cluster with 2 endpoints!
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/envoy-config", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from envoy-config, got %d", w.Code)
	}

	_ = json.Unmarshal(w.Body.Bytes(), &envoyCfg)
	if len(envoyCfg.StaticResources.Clusters) != 1 {
		t.Fatalf("expected 1 cluster in Envoy config, got %d", len(envoyCfg.StaticResources.Clusters))
	}

	endpoints := envoyCfg.StaticResources.Clusters[0].LoadAssignment.Endpoints[0].LbEndpoints
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints in cluster, got %d", len(endpoints))
	}

	// 7. Add Custom WAF Rule
	wafRuleBody, _ := json.Marshal(map[string]interface{}{
		"name":       "block-admin-path",
		"match_type": "PATH_PREFIX",
		"pattern":    "/admin",
		"action":     "BLOCK",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+onboardResp.DomainID+"/waf/rules", bytes.NewReader(wafRuleBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from add WAF rule, got %d: %s", w.Code, w.Body.String())
	}

	// 8. Configure Rate Limit Rule
	rateLimitBody, _ := json.Marshal(map[string]interface{}{
		"rules": []map[string]interface{}{
			{
				"path_prefix":          "/api/",
				"requests_per_minute": 500,
				"burst_size":          50,
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+onboardResp.DomainID+"/rate-limits", bytes.NewReader(rateLimitBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from set rate limits, got %d", w.Code)
	}

	// 9. Evaluate simulated clean request
	cleanEvalBody, _ := json.Marshal(map[string]interface{}{
		"domain_id":  onboardResp.DomainID,
		"client_ip":  "192.0.2.1",
		"method":     "GET",
		"path":       "/api/items",
		"user_agent": "Mozilla/5.0",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/evaluate", bytes.NewReader(cleanEvalBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var cleanResult struct {
		Blocked bool `json:"blocked"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &cleanResult)
	if cleanResult.Blocked {
		t.Errorf("clean request should not be blocked")
	}

	// 10. Evaluate simulated SQL Injection Attack -> MUST BE BLOCKED
	attackEvalBody, _ := json.Marshal(map[string]interface{}{
		"domain_id":  onboardResp.DomainID,
		"client_ip":  "203.0.113.19",
		"method":     "POST",
		"path":       "/login",
		"query":      "user=' OR 1=1--",
		"user_agent": "sqlmap/1.5",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/evaluate", bytes.NewReader(attackEvalBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var attackResult struct {
		Blocked       bool   `json:"blocked"`
		StatusCode    int    `json:"status_code"`
		RuleTriggered string `json:"rule_triggered"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &attackResult)
	if !attackResult.Blocked || attackResult.StatusCode != http.StatusForbidden {
		t.Fatalf("expected SQL injection attack to be blocked (403), got %+v", attackResult)
	}

	// 11. Verify Security Event is recorded in domain security audit stream
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+onboardResp.DomainID+"/security/events", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from get security events, got %d", w.Code)
	}
	var eventsResp struct {
		Count  int                   `json:"count"`
		Events []model.SecurityEvent `json:"events"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &eventsResp)
	if eventsResp.Count == 0 {
		t.Errorf("expected at least 1 security event logged from blocked attack, got 0")
	}

	// 12. Add Cache Rule for static assets
	cacheRuleBody, _ := json.Marshal(map[string]interface{}{
		"name":         "cache-static-images",
		"path_pattern": "/images/*",
		"ttl_seconds":  86400,
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+onboardResp.DomainID+"/cache/rules", bytes.NewReader(cacheRuleBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from add cache rule, got %d: %s", w.Code, w.Body.String())
	}

	// 13. Edge Cache Lookup Miss -> Store Origin Response
	lookupMissBody, _ := json.Marshal(map[string]interface{}{
		"domain_id": onboardResp.DomainID,
		"method":    "GET",
		"path":      "/images/logo.png",
		"origin_response": map[string]interface{}{
			"status_code": 200,
			"headers": map[string]string{
				"Content-Type":  "image/png",
				"Cache-Control": "public, max-age=86400",
			},
			"body": "fake-png-binary-data",
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/cache-lookup", bytes.NewReader(lookupMissBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var missResult struct {
		CacheStatus string `json:"cache_status"`
		CacheStored bool   `json:"cache_stored"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &missResult)
	if missResult.CacheStatus != "MISS" || !missResult.CacheStored {
		t.Fatalf("expected initial lookup to be MISS and stored=true, got %+v", missResult)
	}

	// 14. Edge Cache Lookup -> Cache HIT
	lookupHitBody, _ := json.Marshal(map[string]interface{}{
		"domain_id": onboardResp.DomainID,
		"method":    "GET",
		"path":      "/images/logo.png",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/cache-lookup", bytes.NewReader(lookupHitBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var hitResult struct {
		CacheStatus string `json:"cache_status"`
		Body        string `json:"body"`
		AgeSeconds  int    `json:"age_seconds"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &hitResult)
	if hitResult.CacheStatus != "HIT" || hitResult.Body != "fake-png-binary-data" {
		t.Fatalf("expected cache HIT with body, got %+v", hitResult)
	}

	// 15. Purge Cache
	purgeBody, _ := json.Marshal(map[string]interface{}{
		"target": "/images/logo.png",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+onboardResp.DomainID+"/cache/purge", bytes.NewReader(purgeBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from purge, got %d", w.Code)
	}

	// 16. Lookup after purge -> Cache MISS
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/cache-lookup", bytes.NewReader(lookupHitBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var postPurgeResult struct {
		CacheStatus string `json:"cache_status"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &postPurgeResult)
	if postPurgeResult.CacheStatus != "MISS" {
		t.Fatalf("expected post-purge lookup to be MISS, got %s", postPurgeResult.CacheStatus)
	}

	// 17. Configure Health Monitor on Origin Pool
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/topologies", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from topologies: %s", w.Body.String())
	}
	var toposResp struct {
		Topologies []struct {
			Pools map[string]interface{} `json:"pools"`
		} `json:"topologies"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &toposResp)
	if len(toposResp.Topologies) == 0 || len(toposResp.Topologies[0].Pools) == 0 {
		t.Fatalf("expected active topology with pool, got %+v", toposResp)
	}

	var poolID string
	for pid := range toposResp.Topologies[0].Pools {
		poolID = pid
		break
	}

	hmBody, _ := json.Marshal(map[string]interface{}{
		"protocol":              "HTTP",
		"path":                  "/healthz",
		"interval_seconds":      5,
		"timeout_seconds":       1,
		"healthy_threshold":     2,
		"unhealthy_threshold":   3,
		"expected_status_codes": []int{200},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/pools/"+poolID+"/health-monitor", bytes.NewReader(hmBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated && w.Code != http.StatusOK {
		t.Fatalf("expected 201 Created or 200 OK from set health monitor, got %d: %s", w.Code, w.Body.String())
	}

	// 18. Retrieve configured Health Monitor
	req = httptest.NewRequest(http.MethodGet, "/v1/pools/"+poolID+"/health-monitor", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from get health monitor, got %d", w.Code)
	}
	var hmResp model.HealthMonitor
	_ = json.Unmarshal(w.Body.Bytes(), &hmResp)
	if hmResp.Path != "/healthz" || hmResp.IntervalSeconds != 5 {
		t.Errorf("unexpected health monitor returned: %+v", hmResp)
	}

	// 19. Check Pool Health Status
	req = httptest.NewRequest(http.MethodGet, "/v1/pools/"+poolID+"/health", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from get pool health, got %d", w.Code)
	}
	var poolHealthResp struct {
		PoolID           string                        `json:"pool_id"`
		TotalEndpoints   int                           `json:"total_endpoints"`
		HealthyEndpoints int                           `json:"healthy_endpoints"`
		Endpoints        []*model.OriginEndpointState `json:"endpoints"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &poolHealthResp)
	if poolHealthResp.TotalEndpoints != 2 {
		t.Errorf("expected 2 total endpoints in pool health, got %d", poolHealthResp.TotalEndpoints)
	}

	// 20. Smart Routing Request
	req = httptest.NewRequest(http.MethodPost, "/v1/pools/"+poolID+"/route", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from smart routing, got %d: %s", w.Code, w.Body.String())
	}
	var routingResp model.RoutingDecision
	_ = json.Unmarshal(w.Body.Bytes(), &routingResp)
	if routingResp.SelectedOriginID == "" || routingResp.OriginAddress == "" {
		t.Errorf("expected valid routing decision, got %+v", routingResp)
	}

	// 21. Order Certificate via ACME HTTP-01 Flow
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+onboardResp.DomainID+"/certificates/order", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from cert order, got %d: %s", w.Code, w.Body.String())
	}
	var orderResult struct {
		Certificate model.Certificate   `json:"certificate"`
		Challenge   model.ACMEChallenge `json:"challenge"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &orderResult)
	if orderResult.Certificate.Status != model.CertStatusPendingChallenge || orderResult.Challenge.Token == "" {
		t.Fatalf("expected pending cert and challenge token, got %+v", orderResult)
	}

	// 22. Probe ACME Challenge via HTTP-01 Endpoint
	req = httptest.NewRequest(http.MethodGet, "/.well-known/acme-challenge/"+orderResult.Challenge.Token, nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from ACME challenge endpoint, got %d", w.Code)
	}
	if w.Body.String() != orderResult.Challenge.KeyAuthorization {
		t.Errorf("expected key auth %s, got %s", orderResult.Challenge.KeyAuthorization, w.Body.String())
	}

	// 23. Validate Challenge & Issue x509 Certificate
	validateBody, _ := json.Marshal(map[string]interface{}{
		"token": orderResult.Challenge.Token,
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/acme/validate", bytes.NewReader(validateBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from acme validate, got %d: %s", w.Code, w.Body.String())
	}
	var validateResult struct {
		Status      string            `json:"status"`
		Certificate model.Certificate `json:"certificate"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &validateResult)
	if validateResult.Status != "VALIDATED" || validateResult.Certificate.Status != model.CertStatusActive {
		t.Fatalf("expected VALIDATED status and active certificate, got %+v", validateResult)
	}
	if validateResult.Certificate.CertPEM == "" {
		t.Errorf("expected non-empty certificate PEM")
	}

	// 24. Inspect Current Certificate & Expiration Tracking
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+onboardResp.DomainID+"/certificates/current", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from get current certificate, got %d", w.Code)
	}
	var currentCertResp struct {
		Certificate         model.Certificate `json:"certificate"`
		IsExpiringSoon      bool              `json:"is_expiring_soon"`
		DaysUntilExpiration int               `json:"days_until_expiration"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &currentCertResp)
	if currentCertResp.IsExpiringSoon {
		t.Errorf("freshly issued certificate should not be expiring soon")
	}
	if currentCertResp.DaysUntilExpiration < 85 {
		t.Errorf("expected ~90 days remaining, got %d", currentCertResp.DaysUntilExpiration)
	}

	// 25. Update TLS Settings (Enforce HTTPS)
	tlsBody, _ := json.Marshal(map[string]interface{}{
		"enforce_https":   true,
		"min_tls_version": "TLSv1.3",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+onboardResp.DomainID+"/tls", bytes.NewReader(tlsBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from update TLS settings, got %d: %s", w.Code, w.Body.String())
	}

	// 26. Verify Envoy Config has Downstream TLS Context and SNI matching
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/envoy-config", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from envoy-config, got %d", w.Code)
	}
	envoyJSONStr := w.Body.String()
	if !strings.Contains(envoyJSONStr, "DownstreamTlsContext") {
		t.Errorf("expected Envoy config to contain DownstreamTlsContext after cert issuance")
	}
	if !strings.Contains(envoyJSONStr, "api.customer.com") {
		t.Errorf("expected Envoy config to contain customer SNI hostname")
	}
}
