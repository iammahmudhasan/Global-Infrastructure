package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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

	// 27. Ingest Edge Telemetry Batch (POST /v1/edge/telemetry)
	now := time.Now().UTC()
	telemetryBatch := []model.TelemetryEvent{
		{
			DomainID:      onboardResp.DomainID,
			RequestID:     "req-edge-001",
			ClientIP:      "203.0.113.10",
			Method:        "GET",
			Path:          "/api/v1/users",
			StatusCode:    200,
			LatencyMs:     14.2,
			BytesSent:     5242880, // 5 MB
			BytesReceived: 1024,
			CacheStatus:   "HIT",
			WAFAction:     "ALLOW",
			Timestamp:     now,
		},
		{
			DomainID:      onboardResp.DomainID,
			RequestID:     "req-edge-002",
			ClientIP:      "203.0.113.11",
			Method:        "GET",
			Path:          "/api/v1/orders",
			StatusCode:    200,
			LatencyMs:     48.5,
			BytesSent:     10485760, // 10 MB
			BytesReceived: 2048,
			CacheStatus:   "MISS",
			WAFAction:     "ALLOW",
			Timestamp:     now,
		},
		{
			DomainID:      onboardResp.DomainID,
			RequestID:     "req-edge-003",
			ClientIP:      "198.51.100.22",
			Method:        "GET",
			Path:          "/admin/config",
			StatusCode:    403,
			LatencyMs:     1.1,
			BytesSent:     450,
			BytesReceived: 350,
			CacheStatus:   "BYPASS",
			WAFAction:     "BLOCK",
			Timestamp:     now,
		},
		{
			DomainID:      onboardResp.DomainID,
			RequestID:     "req-edge-004",
			ClientIP:      "203.0.113.12",
			Method:        "POST",
			Path:          "/api/v1/payments",
			StatusCode:    502,
			LatencyMs:     125.0,
			BytesSent:     800,
			BytesReceived: 1500,
			CacheStatus:   "BYPASS",
			WAFAction:     "ALLOW",
			Timestamp:     now,
		},
	}

	batchBody, _ := json.Marshal(telemetryBatch)
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/telemetry", bytes.NewReader(batchBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from telemetry ingest, got %d: %s", w.Code, w.Body.String())
	}
	var ingestResult struct {
		Status   string `json:"status"`
		Ingested int    `json:"ingested"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &ingestResult)
	if ingestResult.Status != "ingested" || ingestResult.Ingested != 4 {
		t.Fatalf("expected 4 ingested events, got %+v", ingestResult)
	}

	// 28. Query Domain Analytics Summary (GET /v1/domains/{domain_id}/analytics/summary)
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+onboardResp.DomainID+"/analytics/summary", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from analytics summary, got %d: %s", w.Code, w.Body.String())
	}
	var summary model.AnalyticsSummary
	_ = json.Unmarshal(w.Body.Bytes(), &summary)
	if summary.TotalRequests != 4 {
		t.Fatalf("expected 4 total requests, got %d", summary.TotalRequests)
	}
	if summary.Status2xx != 2 || summary.Status4xx != 1 || summary.Status5xx != 1 {
		t.Errorf("unexpected status breakdown: 2xx=%d, 4xx=%d, 5xx=%d", summary.Status2xx, summary.Status4xx, summary.Status5xx)
	}
	if summary.ErrorRate != 0.50 {
		t.Errorf("expected error rate 0.50, got %f", summary.ErrorRate)
	}
	if summary.CacheHits != 1 || summary.CacheMisses != 1 {
		t.Errorf("expected 1 hit and 1 miss, got %d hits, %d misses", summary.CacheHits, summary.CacheMisses)
	}
	if summary.CacheHitRate != 0.50 {
		t.Errorf("expected cache hit rate 0.50, got %f", summary.CacheHitRate)
	}
	if summary.SecurityBlocked != 1 {
		t.Errorf("expected 1 security block, got %d", summary.SecurityBlocked)
	}
	if summary.Latency.P50 <= 0 || summary.Latency.P90 <= 0 {
		t.Errorf("expected calculated latency percentiles, got %+v", summary.Latency)
	}

	// 29. Query Domain TimeSeries (GET /v1/domains/{domain_id}/analytics/timeseries)
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+onboardResp.DomainID+"/analytics/timeseries?limit=5", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from analytics timeseries, got %d: %s", w.Code, w.Body.String())
	}
	var tsResp struct {
		DomainID    string                  `json:"domain_id"`
		PointsCount int                     `json:"points_count"`
		Points      []model.TimeSeriesPoint `json:"points"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &tsResp)
	if tsResp.PointsCount != 1 || len(tsResp.Points) != 1 {
		t.Fatalf("expected 1 time series point, got %d", tsResp.PointsCount)
	}
	if tsResp.Points[0].Requests != 4 {
		t.Errorf("expected 4 requests in time series point, got %d", tsResp.Points[0].Requests)
	}

	// 30. Query Billing Usage (GET /v1/domains/{domain_id}/billing/usage)
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+onboardResp.DomainID+"/billing/usage?period=2026-10", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from billing usage, got %d: %s", w.Code, w.Body.String())
	}
	var usage model.BillingUsage
	_ = json.Unmarshal(w.Body.Bytes(), &usage)
	if usage.DomainID != onboardResp.DomainID || usage.BillingPeriod != "2026-10" {
		t.Fatalf("unexpected billing metadata: %+v", usage)
	}
	if usage.TotalRequests != 4 {
		t.Errorf("expected 4 billed requests, got %d", usage.TotalRequests)
	}
	if usage.BaseFeeUSD != 20.00 {
		t.Errorf("expected base fee $20.00, got %f", usage.BaseFeeUSD)
	}
	if usage.TotalCostUSD < 20.00 {
		t.Errorf("expected total cost >= $20.00, got %f", usage.TotalCostUSD)
	}

	// 31. List Strategic Edge PoPs (GET /v1/edge/pops)
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/pops", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from list pops, got %d: %s", w.Code, w.Body.String())
	}
	var popsResp struct {
		TotalPoPs int             `json:"total_pops"`
		PoPs      []model.EdgePoP `json:"pops"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &popsResp)
	if popsResp.TotalPoPs != 4 || len(popsResp.PoPs) != 4 {
		t.Fatalf("expected 4 global PoPs, got %d", popsResp.TotalPoPs)
	}

	// 32. Register and Heartbeat an Edge Node in Dhaka PoP
	nodePayload, _ := json.Marshal(map[string]interface{}{
		"hostname":              "node-dhk-01.nexusedge.net",
		"ip_address":            "103.150.180.12",
		"active_config_version": "v1.0.0",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/nodes", bytes.NewReader(nodePayload))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from register node, got %d: %s", w.Code, w.Body.String())
	}
	var registeredNode model.EdgeNode
	_ = json.Unmarshal(w.Body.Bytes(), &registeredNode)
	if registeredNode.ID == "" || registeredNode.PoPID != "dhaka" {
		t.Fatalf("unexpected registered node: %+v", registeredNode)
	}

	heartbeatPayload, _ := json.Marshal(map[string]interface{}{
		"cpu_usage_percent":  24.5,
		"memory_usage_mb":    8192,
		"active_connections": 3500,
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/nodes/"+registeredNode.ID+"/heartbeat", bytes.NewReader(heartbeatPayload))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from heartbeat, got %d: %s", w.Code, w.Body.String())
	}

	// 33. Synchronize PoP-Specific Envoy Configuration (GET /v1/edge/pops/dhaka/config)
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/pops/dhaka/config", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from pop config sync, got %d: %s", w.Code, w.Body.String())
	}
	var popConfigSync model.PoPConfigSync
	_ = json.Unmarshal(w.Body.Bytes(), &popConfigSync)
	if popConfigSync.PoPID != "dhaka" || popConfigSync.ChecksumSHA256 == "" {
		t.Fatalf("unexpected pop config sync response: %+v", popConfigSync)
	}

	// 34. Trigger BGP Route Health Withdrawal for Failover (POST /v1/edge/pops/dhaka/bgp/withdraw)
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/bgp/withdraw", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from BGP withdraw, got %d: %s", w.Code, w.Body.String())
	}
	var bgpWithdrawnPoP model.EdgePoP
	_ = json.Unmarshal(w.Body.Bytes(), &bgpWithdrawnPoP)
	if bgpWithdrawnPoP.BGPState != model.BGPStateWithdrawn || bgpWithdrawnPoP.Status != model.PoPStatusDraining {
		t.Fatalf("expected WITHDRAWN and POP_DRAINING, got %+v", bgpWithdrawnPoP)
	}

	// 35. Re-announce Anycast BGP Prefix (POST /v1/edge/pops/dhaka/bgp/announce)
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/bgp/announce", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from BGP announce, got %d: %s", w.Code, w.Body.String())
	}
	var bgpAnnouncedPoP model.EdgePoP
	_ = json.Unmarshal(w.Body.Bytes(), &bgpAnnouncedPoP)
	if bgpAnnouncedPoP.BGPState != model.BGPStateAnnounced || bgpAnnouncedPoP.Status != model.PoPStatusActive {
		t.Fatalf("expected ANNOUNCED and POP_ACTIVE, got %+v", bgpAnnouncedPoP)
	}

	// 36. Query Latency Matrix & Origin Geo-Steering
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/routing/matrix", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from routing matrix, got %d: %s", w.Code, w.Body.String())
	}
	var matrixResp struct {
		RoutesCount int                  `json:"routes_count"`
		Routes      []model.LatencyRoute `json:"routes"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &matrixResp)
	if matrixResp.RoutesCount == 0 {
		t.Fatalf("expected non-empty latency matrix")
	}

	steerBody, _ := json.Marshal(map[string]interface{}{
		"client_pop": "dhaka",
		"domain_id":  onboardResp.DomainID,
		"origins": []model.Origin{
			{
				ID:      "orig-dhaka-primary",
				Address: "origin.dhaka.customer.internal",
				Healthy: true,
			},
			{
				ID:      "orig-singapore-secondary",
				Address: "origin.singapore.customer.internal",
				Healthy: true,
			},
		},
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/routing/steer", bytes.NewReader(steerBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK from routing steer, got %d: %s", w.Code, w.Body.String())
	}
	var steerDecision model.GeoSteeringDecision
	_ = json.Unmarshal(w.Body.Bytes(), &steerDecision)
	if steerDecision.SelectedOriginID != "orig-dhaka-primary" || steerDecision.Reason != "LOCAL_METRO_AFFINITY" {
		t.Fatalf("expected local Dhaka origin affinity, got %+v", steerDecision)
	}
}
