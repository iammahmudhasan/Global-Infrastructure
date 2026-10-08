package api_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/api"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/auth"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func setupTestServer() *api.APIHandler {
	os.Setenv("NEXUSEDGE_DEV_MODE", "true")
	os.Setenv("NEXUSEDGE_ENV", "test")
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
		"origin_address":  "origin.customer.com",
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
		"address":  "secondary-origin.customer.com",
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
	var customerCluster *compiler.Cluster
	var foundACME bool
	for i := range envoyCfg.StaticResources.Clusters {
		cl := &envoyCfg.StaticResources.Clusters[i]
		if cl.Name == "acme_challenge_service" {
			foundACME = true
		} else {
			customerCluster = cl
		}
	}
	if !foundACME {
		t.Fatalf("expected acme_challenge_service cluster to be present in Envoy config")
	}
	if customerCluster == nil {
		t.Fatalf("expected customer origin cluster in Envoy config")
	}
	endpoints := customerCluster.LoadAssignment.Endpoints[0].LbEndpoints
	if len(endpoints) != 2 {
		t.Fatalf("expected 2 endpoints in customer cluster, got %d", len(endpoints))
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
				"path_prefix":         "/api/",
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
		PoolID           string                       `json:"pool_id"`
		TotalEndpoints   int                          `json:"total_endpoints"`
		HealthyEndpoints int                          `json:"healthy_endpoints"`
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
		"ip_address":            "198.51.100.12",
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

func TestControlPlane_AuthenticationAndTenantIsolation(t *testing.T) {
	handler := setupTestServer()
	authEngine := auth.NewAuthenticator()
	authEngine.RegisterTenant("key-alpha-secret", "tenant-alpha", "proj-alpha")
	authEngine.RegisterTenant("key-beta-secret", "tenant-beta", "proj-beta")
	handler.SetAuthenticator(authEngine)

	// 1. Tenant Alpha successfully onboards domain under proj-alpha
	onboardPayload, _ := json.Marshal(map[string]interface{}{
		"hostname":        "portal.tenant-alpha.com",
		"origin_address":  "origin.tenant-alpha.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/proj-alpha/domains", bytes.NewReader(onboardPayload))
	req.Header.Set("X-API-Key", "key-alpha-secret")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for authenticated tenant-alpha onboarding, got %d: %s", w.Code, w.Body.String())
	}

	var alphaDomain struct {
		DomainID     string `json:"domain_id"`
		OriginPoolID string `json:"origin_pool_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &alphaDomain)
	if alphaDomain.DomainID == "" || alphaDomain.OriginPoolID == "" {
		t.Fatalf("expected valid domain ID and pool ID, got %+v", alphaDomain)
	}

	// 2. Tenant Alpha reads their own domain -> 200 OK
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+alphaDomain.DomainID, nil)
	req.Header.Set("X-API-Key", "key-alpha-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for tenant-alpha accessing their own domain, got %d: %s", w.Code, w.Body.String())
	}

	// 3. IDOR Defense: Tenant Beta attempts to access Tenant Alpha's domain -> 403 Forbidden
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+alphaDomain.DomainID, nil)
	req.Header.Set("X-API-Key", "key-beta-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when tenant-beta accesses tenant-alpha domain, got %d: %s", w.Code, w.Body.String())
	}

	// 4. IDOR Defense: Tenant Beta attempts to add origin to Tenant Alpha's domain -> 403 Forbidden
	addOriginBody, _ := json.Marshal(map[string]interface{}{
		"address": "evil-origin.beta.internal",
		"port":    443,
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+alphaDomain.DomainID+"/origins", bytes.NewReader(addOriginBody))
	req.Header.Set("X-API-Key", "key-beta-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when tenant-beta tries to add origin to tenant-alpha domain, got %d", w.Code)
	}

	// 5. Tenant Beta attempts to create domain in Tenant Alpha's project -> 403 Forbidden
	req = httptest.NewRequest(http.MethodPost, "/v1/projects/proj-alpha/domains", bytes.NewReader(onboardPayload))
	req.Header.Set("X-API-Key", "key-beta-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when tenant-beta tries to onboard into proj-alpha, got %d", w.Code)
	}

	// 6. Tenant Beta attempts to list Tenant Alpha's domains -> 403 Forbidden
	req = httptest.NewRequest(http.MethodGet, "/v1/projects/proj-alpha/domains", nil)
	req.Header.Set("X-API-Key", "key-beta-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when tenant-beta lists proj-alpha domains, got %d", w.Code)
	}

	// 7. Tenant Beta attempts to access Tenant Alpha's origin pool -> 403 Forbidden
	req = httptest.NewRequest(http.MethodGet, "/v1/pools/"+alphaDomain.OriginPoolID, nil)
	req.Header.Set("X-API-Key", "key-beta-secret")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when tenant-beta accesses tenant-alpha pool, got %d", w.Code)
	}

	// 8. Tenant Spoofing Defense: Key belongs to Alpha, but header claims Tenant Beta -> 403 Forbidden
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+alphaDomain.DomainID, nil)
	req.Header.Set("X-API-Key", "key-alpha-secret")
	req.Header.Set("X-Tenant-ID", "tenant-beta")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on tenant ID mismatch, got %d", w.Code)
	}

	// 9. Asserting X-Tenant-ID without credentials -> 401 Unauthorized
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+alphaDomain.DomainID, nil)
	req.Header.Set("X-Tenant-ID", "tenant-alpha")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when asserting tenant ID without key, got %d", w.Code)
	}

	// 10. Strict Auth Mode: NEXUSEDGE_ENFORCE_AUTH=true -> 401 Unauthorized on unauthenticated request
	os.Setenv("NEXUSEDGE_ENFORCE_AUTH", "true")
	defer os.Unsetenv("NEXUSEDGE_ENFORCE_AUTH")

	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+alphaDomain.DomainID, nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized when NEXUSEDGE_ENFORCE_AUTH=true, got %d", w.Code)
	}
}

func TestControlPlane_CORSFailClosed(t *testing.T) {
	handler := setupTestServer()

	// 1. Empty Origin: No CORS headers should be returned
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "" {
		t.Errorf("expected empty CORS origin for requests with no Origin header, got %q", origin)
	}

	// 2. Unknown External Origin: In production or without allowlist, must fail closed (no wildcard)
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://unauthorized-external-site.com")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin == "*" || origin == "https://unauthorized-external-site.com" {
		t.Errorf("expected fail-closed CORS for unknown origin, got %q", origin)
	}

	// 3. Configured Allowed Origin: Matches exact origin
	os.Setenv("NEXUSEDGE_ALLOWED_ORIGINS", "https://console.nexusedge.net,https://api.nexusedge.net")
	defer os.Unsetenv("NEXUSEDGE_ALLOWED_ORIGINS")

	// 3a. Matching allowed origin
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://console.nexusedge.net")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "https://console.nexusedge.net" {
		t.Errorf("expected allowed origin reflection, got %q", origin)
	}

	// 3b. Non-matching origin fails closed
	req = httptest.NewRequest(http.MethodGet, "/healthz", nil)
	req.Header.Set("Origin", "https://attacker.evil.com")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if origin := w.Header().Get("Access-Control-Allow-Origin"); origin != "" {
		t.Errorf("expected fail-closed for non-matching origin when allowlist configured, got %q", origin)
	}
}

func TestCertificatesRoute_NeverLeaksPrivateKey(t *testing.T) {
	handler := setupTestServer()

	// 1. Onboard Domain
	body, _ := json.Marshal(map[string]interface{}{
		"hostname":        "secure.dev.example.com",
		"origin_address":  "origin.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/prj-alpha/domains", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("failed to onboard domain: %d - %s", w.Code, w.Body.String())
	}

	var onboardResp struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &onboardResp)
	domainID := onboardResp.DomainID

	// Verify domain so it's active
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/verify", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// Helper to check for private key material
	assertNoPrivateKey := func(t *testing.T, endpoint string, bodyStr string) {
		t.Helper()
		if strings.Contains(bodyStr, "EC PRIVATE KEY") {
			t.Fatalf("[%s] certificate API leaked private key material: found EC PRIVATE KEY in %s", endpoint, bodyStr)
		}
		if strings.Contains(bodyStr, "PRIVATE KEY") {
			t.Fatalf("[%s] certificate API leaked private key material: found PRIVATE KEY in %s", endpoint, bodyStr)
		}
	}

	// 2. Order Certificate (POST /v1/domains/{domain_id}/certificates/order)
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/certificates/order", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("failed to order certificate: %d - %s", w.Code, w.Body.String())
	}
	assertNoPrivateKey(t, "POST /certificates/order", w.Body.String())

	// 3. Get Certificate (GET /v1/domains/{domain_id}/certificates)
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+domainID+"/certificates", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to get certificate: %d - %s", w.Code, w.Body.String())
	}
	assertNoPrivateKey(t, "GET /certificates", w.Body.String())

	// 4. Current Certificate (GET /v1/domains/{domain_id}/certificates/current)
	req = httptest.NewRequest(http.MethodGet, "/v1/domains/"+domainID+"/certificates/current", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to get current certificate: %d - %s", w.Code, w.Body.String())
	}
	assertNoPrivateKey(t, "GET /certificates/current", w.Body.String())

	// 5. Renew Certificate (POST /v1/domains/{domain_id}/certificates/renew)
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/certificates/renew", nil)
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("failed to renew certificate: %d - %s", w.Code, w.Body.String())
	}
	assertNoPrivateKey(t, "POST /certificates/renew", w.Body.String())
}

func TestControlPlane_RoutingSteerTenantAuthorization(t *testing.T) {
	handler := setupTestServer()
	authEngine := auth.NewAuthenticator()
	authEngine.RegisterTenant("key-tenant-alpha", "tenant-alpha", "prj-alpha")
	authEngine.RegisterTenant("key-tenant-beta", "tenant-beta", "prj-beta")
	handler.SetAuthenticator(authEngine)

	// Setup domain and origin pool under prj-alpha via API
	body, _ := json.Marshal(map[string]interface{}{
		"hostname":        "alpha.example.com",
		"origin_address":  "198.51.100.20",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/prj-alpha/domains", bytes.NewReader(body))
	req.Header.Set("X-API-Key", "key-tenant-alpha")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("failed to onboard domain: %d - %s", w.Code, w.Body.String())
	}
	var domainResp struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &domainResp)

	steerPayload, _ := json.Marshal(map[string]interface{}{
		"client_pop": "dhaka",
		"domain_id":  domainResp.DomainID,
	})

	// 1. Authorized tenant (prj-alpha) -> 200 OK
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/routing/steer", bytes.NewReader(steerPayload))
	req.Header.Set("X-API-Key", "key-tenant-alpha")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for authorized tenant, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Unauthorized cross-tenant caller (prj-beta) -> 403 Forbidden
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/routing/steer", bytes.NewReader(steerPayload))
	req.Header.Set("X-API-Key", "key-tenant-beta")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for cross-tenant steer caller, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Non-existent domain -> 404 Not Found
	unknownPayload, _ := json.Marshal(map[string]interface{}{
		"client_pop": "dhaka",
		"domain_id":  "dom-nonexistent",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/routing/steer", bytes.NewReader(unknownPayload))
	req.Header.Set("X-API-Key", "key-tenant-alpha")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 Not Found for missing domain, got %d: %s", w.Code, w.Body.String())
	}
}

func TestControlPlane_GlobalBodySizeLimit(t *testing.T) {
	handler := setupTestServer()

	// Create payload exceeding 1 MiB (1.5 MiB of garbage padding)
	oversized := make([]byte, 1500*1024)
	for i := range oversized {
		oversized[i] = 'a'
	}

	req := httptest.NewRequest(http.MethodPost, "/v1/projects/prj-alpha/domains", bytes.NewReader(oversized))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	// http.MaxBytesReader will cause json decoder to fail or return 400 Bad Request
	if w.Code != http.StatusBadRequest {
		t.Errorf("expected oversized request (> 1MB) to fail with 400 Bad Request, got %d", w.Code)
	}
}

func TestAddOrigin_PortAndProtocolValidation(t *testing.T) {
	handler := setupTestServer()

	// 1. Onboard a domain with an HTTPS origin
	body, _ := json.Marshal(map[string]interface{}{
		"hostname":        "origin-val.example.com",
		"origin_address":  "primary.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/prj-alpha/domains", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created from onboard domain, got %d: %s", w.Code, w.Body.String())
	}

	var onboardResp struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &onboardResp)
	domainID := onboardResp.DomainID

	// 2. Reject invalid port (> 65535)
	badPortBody, _ := json.Marshal(map[string]interface{}{
		"address":  "backup.example.com",
		"port":     70000,
		"protocol": "HTTPS",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/origins", bytes.NewReader(badPortBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "origin port must be between 1 and 65535") {
		t.Fatalf("expected 400 with port error for port 70000, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Reject invalid protocol
	badProtoBody, _ := json.Marshal(map[string]interface{}{
		"address":  "backup.example.com",
		"port":     443,
		"protocol": "FTP",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/origins", bytes.NewReader(badProtoBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "origin protocol must be HTTP or HTTPS") {
		t.Fatalf("expected 400 with protocol error for FTP, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Reject mixed protocol (HTTP added to an HTTPS pool)
	mixedProtoBody, _ := json.Marshal(map[string]interface{}{
		"address":  "backup.example.com",
		"port":     80,
		"protocol": "HTTP",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/origins", bytes.NewReader(mixedProtoBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "all origins in an origin pool must share the same protocol") {
		t.Fatalf("expected 400 with mixed protocol error, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Accept valid secondary origin (HTTPS, port 8443)
	validBody, _ := json.Marshal(map[string]interface{}{
		"address":  "backup.example.com",
		"port":     8443,
		"protocol": "HTTPS",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/origins", bytes.NewReader(validBody))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for valid origin, got %d: %s", w.Code, w.Body.String())
	}
}

func TestTLSSettings_Validation(t *testing.T) {
	handler := setupTestServer()

	// 1. Onboard Domain
	body, _ := json.Marshal(map[string]interface{}{
		"hostname":        "tls-val.example.com",
		"origin_address":  "origin.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/prj-tls/domains", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("onboard failed: %d", w.Code)
	}
	var res struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)

	// 2. Reject unsupported TLS version (TLSv1.1)
	badTLS, _ := json.Marshal(map[string]interface{}{
		"min_tls_version": "TLSv1.1",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+res.DomainID+"/tls", bytes.NewReader(badTLS))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "min_tls_version must be TLSv1.2 or TLSv1.3") {
		t.Fatalf("expected 400 for TLSv1.1, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Accept TLSv1.3
	goodTLS, _ := json.Marshal(map[string]interface{}{
		"min_tls_version": "TLSv1.3",
		"hsts":            true,
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+res.DomainID+"/tls", bytes.NewReader(goodTLS))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for TLSv1.3, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHealthMonitor_ProtocolValidation(t *testing.T) {
	handler := setupTestServer()

	// 1. Onboard Domain
	body, _ := json.Marshal(map[string]interface{}{
		"hostname":        "tcp-gate.example.com",
		"origin_address":  "origin.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/prj-tcp/domains", bytes.NewReader(body))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var res struct {
		DomainID     string `json:"domain_id"`
		OriginPoolID string `json:"origin_pool_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)

	// 2. Reject TCP health monitor protocol
	tcpMonitor, _ := json.Marshal(map[string]interface{}{
		"protocol": "TCP",
		"port":     443,
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/pools/"+res.OriginPoolID+"/health-monitor", bytes.NewReader(tcpMonitor))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "health monitor protocol must be HTTP or HTTPS") {
		t.Fatalf("expected 400 for TCP monitor, got %d: %s", w.Code, w.Body.String())
	}
}

func TestDomainVerification_StatusCodes(t *testing.T) {
	handler := setupTestServer()

	// 1. Nonexistent domain returns 404
	req := httptest.NewRequest(http.MethodPost, "/v1/domains/nonexistent-dom-id/verify", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404 for nonexistent domain, got %d", w.Code)
	}

	// 2. Existing domain with failed verification under non-dev mode returns 422
	body, _ := json.Marshal(map[string]interface{}{
		"hostname":        "unverified-unique-test.example.com",
		"origin_address":  "origin.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req = httptest.NewRequest(http.MethodPost, "/v1/projects/prj-verify/domains", bytes.NewReader(body))
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var res struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)

	// Explicitly disable dev mode for verification check and authenticate request
	t.Setenv("NEXUSEDGE_DEV_MODE", "false")
	handler.Authenticator().RegisterTenantWithRole("key-verify-test", "tenant-verify", "prj-verify", auth.RolePlatformOperator, "*")

	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+res.DomainID+"/verify", nil)
	req.Header.Set("X-API-Key", "key-verify-test")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "domain verification failed") {
		t.Fatalf("expected 422 Unprocessable Entity for failed DNS proof, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEdgeNodeHeartbeat_IdentityBinding(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	comp := compiler.NewCompiler(9901, 80, 443)
	handler := api.NewAPIHandler(st, svc, comp)

	// Register test nodes in Dhaka PoP
	node1 := model.EdgeNode{
		ID:        "edge-node-01",
		PoPID:     "dhaka",
		Hostname:  "node-01.dhaka.nexusedge.net",
		IPAddress: "192.0.2.10",
	}
	node2 := model.EdgeNode{
		ID:        "edge-node-02",
		PoPID:     "dhaka",
		Hostname:  "node-02.dhaka.nexusedge.net",
		IPAddress: "192.0.2.20",
	}
	_, _ = handler.PoPManager().RegisterNode(node1)
	_, _ = handler.PoPManager().RegisterNode(node2)

	// Register specific EdgeNode credentials
	authInst := handler.Authenticator()
	authInst.RegisterNodeWithPoP("key-node-01", "tenant-infra", "proj-infra", "edge-node-01", "dhaka")
	authInst.RegisterTenantWithRole("key-operator", "tenant-sys", "proj-core", auth.RolePlatformOperator, "*")

	heartbeatPayload, _ := json.Marshal(map[string]interface{}{
		"cpu_usage_percent":  15.5,
		"memory_usage_mb":    512,
		"active_connections": 100,
	})

	// 1. edge-node-01 heartbeats its own node -> 200 OK
	req := httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/nodes/edge-node-01/heartbeat", bytes.NewReader(heartbeatPayload))
	req.Header.Set("X-API-Key", "key-node-01")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for node-01 self-heartbeat, got %d: %s", w.Code, w.Body.String())
	}

	// 2. edge-node-01 attempts to heartbeat edge-node-02 -> 403 Forbidden
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/nodes/edge-node-02/heartbeat", bytes.NewReader(heartbeatPayload))
	req.Header.Set("X-API-Key", "key-node-01")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "edge node credential cannot update another node") {
		t.Fatalf("expected 403 Forbidden for cross-node heartbeat, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Platform Operator can heartbeat edge-node-02 -> 200 OK
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/nodes/edge-node-02/heartbeat", bytes.NewReader(heartbeatPayload))
	req.Header.Set("X-API-Key", "key-operator")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 for operator heartbeat, got %d: %s", w.Code, w.Body.String())
	}
}

func TestPoPAndRoutingAccessControl(t *testing.T) {
	handler := setupTestServer()
	authInst := handler.Authenticator()

	authInst.RegisterTenantWithRole("key-tenant-user", "tenant-user", "proj-user", auth.RoleTenant, "proj-user")
	authInst.RegisterTenantWithRole("key-operator-user", "tenant-ops", "proj-core", auth.RolePlatformOperator, "*")
	authInst.RegisterNodeWithPoP("key-node-user", "tenant-infra", "proj-infra", "edge-node-01", "dhaka")

	endpoints := []string{
		"/v1/edge/pops",
		"/v1/edge/pops/dhaka",
		"/v1/edge/routing/matrix",
	}

	for _, ep := range endpoints {
		// 1. Regular tenant -> 403 Forbidden
		req := httptest.NewRequest(http.MethodGet, ep, nil)
		req.Header.Set("X-API-Key", "key-tenant-user")
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusForbidden {
			t.Errorf("expected 403 Forbidden for tenant on %s, got %d: %s", ep, w.Code, w.Body.String())
		}

		// 2. Platform operator -> 200 OK
		req = httptest.NewRequest(http.MethodGet, ep, nil)
		req.Header.Set("X-API-Key", "key-operator-user")
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Errorf("expected 200 OK for operator on %s, got %d: %s", ep, w.Code, w.Body.String())
		}

		// 3. Edge node access
		req = httptest.NewRequest(http.MethodGet, ep, nil)
		req.Header.Set("X-API-Key", "key-node-user")
		w = httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		if ep == "/v1/edge/routing/matrix" {
			if w.Code != http.StatusForbidden {
				t.Errorf("expected 403 Forbidden for edge node on %s, got %d: %s", ep, w.Code, w.Body.String())
			}
		} else {
			if w.Code != http.StatusOK {
				t.Errorf("expected 200 OK for edge node on %s, got %d: %s", ep, w.Code, w.Body.String())
			}
		}
	}
}

func TestNodeRegistration_OperatorOnly(t *testing.T) {
	handler := setupTestServer()
	authInst := handler.Authenticator()

	authInst.RegisterTenantWithRole("key-operator", "tenant-ops", "proj-core", auth.RolePlatformOperator, "*")
	authInst.RegisterNodeWithPoP("key-node", "tenant-infra", "proj-infra", "edge-node-01", "dhaka")
	authInst.RegisterTenantWithRole("key-tenant", "tenant-user", "proj-user", auth.RoleTenant, "proj-user")

	nodePayload, _ := json.Marshal(map[string]interface{}{
		"id":         "node-rogue-01",
		"hostname":   "rogue.dhaka.nexusedge.net",
		"ip_address": "203.0.113.50",
	})

	// 1. EdgeNode role attempts node registration -> 403 Forbidden
	req := httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/nodes", bytes.NewReader(nodePayload))
	req.Header.Set("X-API-Key", "key-node")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "operator role required for node registration") {
		t.Fatalf("expected 403 Forbidden for edge node registration attempt, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Tenant role attempts node registration -> 403 Forbidden
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/nodes", bytes.NewReader(nodePayload))
	req.Header.Set("X-API-Key", "key-tenant")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for tenant registration attempt, got %d", w.Code)
	}

	// 3. Platform Operator attempts node registration -> 201 Created
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/pops/dhaka/nodes", bytes.NewReader(nodePayload))
	req.Header.Set("X-API-Key", "key-operator")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for operator node registration, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEdgeNode_PoPAndTopologyIsolation(t *testing.T) {
	// P2 Finding 6 Verification: EdgeNode visibility bounded to its assigned PoP
	handler := setupTestServer()
	authInst := handler.Authenticator()

	authInst.RegisterTenantWithRole("key-operator", "tenant-ops", "proj-core", auth.RolePlatformOperator, "*")
	authInst.RegisterNodeWithPoP("key-node-dhaka", "tenant-infra", "proj-infra", "edge-node-01", "dhaka")

	// 1. Operator listing PoPs receives all global PoPs (4 default PoPs)
	reqOp := httptest.NewRequest(http.MethodGet, "/v1/edge/pops", nil)
	reqOp.Header.Set("X-API-Key", "key-operator")
	wOp := httptest.NewRecorder()
	handler.ServeHTTP(wOp, reqOp)
	if wOp.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator, got %d: %s", wOp.Code, wOp.Body.String())
	}
	var opResp struct {
		TotalPoPs int             `json:"total_pops"`
		PoPs      []model.EdgePoP `json:"pops"`
	}
	if err := json.Unmarshal(wOp.Body.Bytes(), &opResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if opResp.TotalPoPs != 4 {
		t.Fatalf("expected 4 global PoPs for operator, got %d", opResp.TotalPoPs)
	}

	// 2. Edge node assigned to 'dhaka' receives ONLY dhaka in /v1/edge/pops
	reqNode := httptest.NewRequest(http.MethodGet, "/v1/edge/pops", nil)
	reqNode.Header.Set("X-API-Key", "key-node-dhaka")
	wNode := httptest.NewRecorder()
	handler.ServeHTTP(wNode, reqNode)
	if wNode.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for edge node, got %d: %s", wNode.Code, wNode.Body.String())
	}
	var nodeResp struct {
		TotalPoPs int             `json:"total_pops"`
		PoPs      []model.EdgePoP `json:"pops"`
	}
	if err := json.Unmarshal(wNode.Body.Bytes(), &nodeResp); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if nodeResp.TotalPoPs != 1 || len(nodeResp.PoPs) != 1 || strings.ToLower(nodeResp.PoPs[0].ID) != "dhaka" {
		t.Fatalf("expected edge node to receive only its assigned 'dhaka' PoP, got %d PoPs: %+v",
			nodeResp.TotalPoPs, nodeResp.PoPs)
	}

	// 3. Edge node requesting global /v1/edge/topologies -> 403 Forbidden
	reqTopo := httptest.NewRequest(http.MethodGet, "/v1/edge/topologies", nil)
	reqTopo.Header.Set("X-API-Key", "key-node-dhaka")
	wTopo := httptest.NewRecorder()
	handler.ServeHTTP(wTopo, reqTopo)
	if wTopo.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for edge node on /v1/edge/topologies, got %d", wTopo.Code)
	}

	// 4. Operator requesting /v1/edge/topologies -> 200 OK
	reqTopoOp := httptest.NewRequest(http.MethodGet, "/v1/edge/topologies", nil)
	reqTopoOp.Header.Set("X-API-Key", "key-operator")
	wTopoOp := httptest.NewRecorder()
	handler.ServeHTTP(wTopoOp, reqTopoOp)
	if wTopoOp.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator on /v1/edge/topologies, got %d", wTopoOp.Code)
	}

	// 5. Edge node requesting /v1/edge/routing/matrix -> 403 Forbidden
	reqMatrix := httptest.NewRequest(http.MethodGet, "/v1/edge/routing/matrix", nil)
	reqMatrix.Header.Set("X-API-Key", "key-node-dhaka")
	wMatrix := httptest.NewRecorder()
	handler.ServeHTTP(wMatrix, reqMatrix)
	if wMatrix.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for edge node on /v1/edge/routing/matrix, got %d", wMatrix.Code)
	}
}

func TestCachePurge_CrossTenantAndGlobalScope(t *testing.T) {
	handler := setupTestServer()
	authInst := handler.Authenticator()
	authInst.RegisterTenantWithRole("key-tenant-a", "tenant-a", "proj-a", auth.RoleTenant, "proj-a")
	authInst.RegisterTenantWithRole("key-tenant-b", "tenant-b", "proj-b", auth.RoleTenant, "proj-b")
	authInst.RegisterTenantWithRole("key-operator", "operator", "proj-core", auth.RolePlatformOperator, "*")

	// Onboard domain A for tenant A
	bodyA, _ := json.Marshal(map[string]interface{}{
		"hostname":        "tenant-a.example.com",
		"origin_address":  "origin-a.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	reqA := httptest.NewRequest(http.MethodPost, "/v1/projects/proj-a/domains", bytes.NewReader(bodyA))
	reqA.Header.Set("X-API-Key", "key-tenant-a")
	wA := httptest.NewRecorder()
	handler.ServeHTTP(wA, reqA)
	if wA.Code != http.StatusCreated {
		t.Fatalf("failed to onboard domain A: %d %s", wA.Code, wA.Body.String())
	}
	var resA struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(wA.Body.Bytes(), &resA)

	// 1. Tenant A purges own URL -> 200 OK
	purgeOwn := []byte(`{"target":"https://tenant-a.example.com/api/v1/data"}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/domains/"+resA.DomainID+"/cache/purge", bytes.NewReader(purgeOwn))
	req.Header.Set("X-API-Key", "key-tenant-a")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for tenant purging own domain URL, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Tenant A purges victim URL -> 403 Forbidden
	purgeVictim := []byte(`{"target":"https://victim-b.example.com/secret"}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+resA.DomainID+"/cache/purge", bytes.NewReader(purgeVictim))
	req.Header.Set("X-API-Key", "key-tenant-a")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "outside domain scope") {
		t.Fatalf("expected 403 Forbidden for cross-domain victim purge, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Tenant A attempts global target "*" -> 403 Forbidden
	purgeGlobal := []byte(`{"target":"*"}`)
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+resA.DomainID+"/cache/purge", bytes.NewReader(purgeGlobal))
	req.Header.Set("X-API-Key", "key-tenant-a")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "requires platform operator role") {
		t.Fatalf("expected 403 Forbidden for non-operator global purge, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Operator purges global target "*" -> 200 OK
	req = httptest.NewRequest(http.MethodPost, "/v1/domains/"+resA.DomainID+"/cache/purge", bytes.NewReader(purgeGlobal))
	req.Header.Set("X-API-Key", "key-operator")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator global purge, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEdgeTelemetry_DomainValidationAndAuthorization(t *testing.T) {
	handler := setupTestServer()
	authInst := handler.Authenticator()
	authInst.RegisterNode("key-node-scoped", "tenant-infra", "proj-a", "edge-node-01") // Only authorized for proj-a
	authInst.RegisterTenantWithRole("key-tenant-a", "tenant-a", "proj-a", auth.RoleTenant, "proj-a")
	authInst.RegisterTenantWithRole("key-tenant-b", "tenant-b", "proj-b", auth.RoleTenant, "proj-b")

	// Domain A in proj-a
	bodyA, _ := json.Marshal(map[string]interface{}{
		"hostname":        "service-a.example.com",
		"origin_address":  "origin-a.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	reqA := httptest.NewRequest(http.MethodPost, "/v1/projects/proj-a/domains", bytes.NewReader(bodyA))
	reqA.Header.Set("X-API-Key", "key-tenant-a")
	wA := httptest.NewRecorder()
	handler.ServeHTTP(wA, reqA)
	var resA struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(wA.Body.Bytes(), &resA)

	// Domain B in proj-b
	bodyB, _ := json.Marshal(map[string]interface{}{
		"hostname":        "service-b.example.com",
		"origin_address":  "origin-b.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	reqB := httptest.NewRequest(http.MethodPost, "/v1/projects/proj-b/domains", bytes.NewReader(bodyB))
	reqB.Header.Set("X-API-Key", "key-tenant-b")
	wB := httptest.NewRecorder()
	handler.ServeHTTP(wB, reqB)
	var resB struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(wB.Body.Bytes(), &resB)

	now := time.Now().UTC()

	// 1. Non-existent domain ID -> 400 Bad Request
	badDomainEvent := []model.TelemetryEvent{
		{DomainID: "non-existent-domain", StatusCode: 200, BytesSent: 100, Timestamp: now},
	}
	bodyBad, _ := json.Marshal(badDomainEvent)
	req := httptest.NewRequest(http.MethodPost, "/v1/edge/telemetry", bytes.NewReader(bodyBad))
	req.Header.Set("X-API-Key", "key-node-scoped")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "domain not found") {
		t.Fatalf("expected 400 Bad Request for unverified domain, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Foreign domain ID (proj-b) from node scoped only to proj-a -> 403 Forbidden
	foreignDomainEvent := []model.TelemetryEvent{
		{DomainID: resB.DomainID, StatusCode: 200, BytesSent: 100, Timestamp: now},
	}
	bodyForeign, _ := json.Marshal(foreignDomainEvent)
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/telemetry", bytes.NewReader(bodyForeign))
	req.Header.Set("X-API-Key", "key-node-scoped")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "not authorized") {
		t.Fatalf("expected 403 Forbidden for unauthorized project domain, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Valid authorized domain ID (proj-a) -> 200 OK
	validEvent := []model.TelemetryEvent{
		{DomainID: resA.DomainID, StatusCode: 200, BytesSent: 100, Timestamp: now},
	}
	bodyValid, _ := json.Marshal(validEvent)
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/telemetry", bytes.NewReader(bodyValid))
	req.Header.Set("X-API-Key", "key-node-scoped")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for authorized telemetry, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Future timestamp (> 5m) -> 400 Bad Request (P2 Finding 8)
	futureEvent := []model.TelemetryEvent{
		{DomainID: resA.DomainID, StatusCode: 200, BytesSent: 100, Timestamp: now.Add(10 * time.Minute)},
	}
	bodyFuture, _ := json.Marshal(futureEvent)
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/telemetry", bytes.NewReader(bodyFuture))
	req.Header.Set("X-API-Key", "key-node-scoped")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "timestamp out of acceptable window") {
		t.Fatalf("expected 400 Bad Request for future timestamp, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Far past timestamp (> 24h) -> 400 Bad Request (P2 Finding 8)
	pastEvent := []model.TelemetryEvent{
		{DomainID: resA.DomainID, StatusCode: 200, BytesSent: 100, Timestamp: now.Add(-48 * time.Hour)},
	}
	bodyPast, _ := json.Marshal(pastEvent)
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/telemetry", bytes.NewReader(bodyPast))
	req.Header.Set("X-API-Key", "key-node-scoped")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "timestamp out of acceptable window") {
		t.Fatalf("expected 400 Bad Request for far-past timestamp, got %d: %s", w.Code, w.Body.String())
	}
}

func TestEdgeNode_PoPScopingAndCrossPoPIsolation(t *testing.T) {
	handler := setupTestServer()
	authInst := handler.Authenticator()

	// Register edge-node scoped specifically to "dhaka"
	authInst.RegisterNodeWithPoP("key-node-dhaka", "tenant-infra", "proj-infra", "edge-node-dhaka", "dhaka")
	authInst.RegisterTenantWithRole("key-operator", "tenant-sys", "proj-core", auth.RolePlatformOperator, "*")

	// 1. Authorized PoP access: dhaka node accessing dhaka PoP -> 200 OK
	req := httptest.NewRequest(http.MethodGet, "/v1/edge/pops/dhaka", nil)
	req.Header.Set("X-API-Key", "key-node-dhaka")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for dhaka node accessing dhaka pop, got %d: %s", w.Code, w.Body.String())
	}

	// 2. Cross-PoP unauthorized access: dhaka node accessing singapore PoP -> 403 Forbidden
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/pops/singapore", nil)
	req.Header.Set("X-API-Key", "key-node-dhaka")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "edge node is not authorized for this PoP") {
		t.Fatalf("expected 403 Forbidden for cross-PoP access, got %d: %s", w.Code, w.Body.String())
	}

	// 3. Edge node accessing global envoy-config -> 403 Forbidden (operator only)
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/envoy-config", nil)
	req.Header.Set("X-API-Key", "key-node-dhaka")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "operator role required") {
		t.Fatalf("expected 403 Forbidden for edge node on global envoy-config, got %d: %s", w.Code, w.Body.String())
	}

	// 4. Platform Operator can access global envoy-config -> 200 OK
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/envoy-config", nil)
	req.Header.Set("X-API-Key", "key-operator")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator on global envoy-config, got %d: %s", w.Code, w.Body.String())
	}

	// 5. Unbound edge node (PoPID == "") attempting to list PoPs -> 403 Forbidden (P2 Finding 5)
	authInst.RegisterNodeWithPoP("key-node-unbound", "tenant-infra", "proj-infra", "edge-node-unbound", "")
	req = httptest.NewRequest(http.MethodGet, "/v1/edge/pops", nil)
	req.Header.Set("X-API-Key", "key-node-unbound")
	w = httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "edge node is not bound to a PoP") {
		t.Fatalf("expected 403 Forbidden for unbound edge node listing pops, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHealthMonitor_InputBoundsValidation(t *testing.T) {
	handler := setupTestServer()
	authInst := handler.Authenticator()
	authInst.RegisterTenantWithRole("key-tenant", "tenant-user", "proj-user", auth.RoleTenant, "proj-user")

	// Create domain
	bodyDomain, _ := json.Marshal(map[string]interface{}{
		"hostname":        "hm-bounds.example.com",
		"origin_address":  "origin.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/proj-user/domains", bytes.NewReader(bodyDomain))
	req.Header.Set("X-API-Key", "key-tenant")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var res struct {
		DomainID     string `json:"domain_id"`
		OriginPoolID string `json:"origin_pool_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)

	testCases := []struct {
		name    string
		payload map[string]interface{}
		wantErr string
	}{
		{
			name: "interval seconds too high",
			payload: map[string]interface{}{
				"path":             "/healthz",
				"interval_seconds": 999999,
				"timeout_seconds":  2,
			},
			wantErr: "interval_seconds must be between 1 and 3600",
		},
		{
			name: "timeout seconds too high",
			payload: map[string]interface{}{
				"path":             "/healthz",
				"interval_seconds": 100,
				"timeout_seconds":  75,
			},
			wantErr: "timeout_seconds must be between 1 and 60",
		},
		{
			name: "timeout exceeds interval",
			payload: map[string]interface{}{
				"path":             "/healthz",
				"interval_seconds": 5,
				"timeout_seconds":  10,
			},
			wantErr: "timeout_seconds cannot exceed interval_seconds",
		},
		{
			name: "healthy threshold out of bounds",
			payload: map[string]interface{}{
				"path":              "/healthz",
				"interval_seconds":  10,
				"timeout_seconds":   2,
				"healthy_threshold": 99,
			},
			wantErr: "healthy_threshold must be between 1 and 10",
		},
		{
			name: "unhealthy threshold > 10",
			payload: map[string]interface{}{
				"path":                "/healthz",
				"interval_seconds":    10,
				"timeout_seconds":     2,
				"unhealthy_threshold": 25,
			},
			wantErr: "unhealthy_threshold must be between 1 and 10",
		},
		{
			name: "invalid status code",
			payload: map[string]interface{}{
				"path":                  "/healthz",
				"interval_seconds":      10,
				"timeout_seconds":       2,
				"expected_status_codes": []int{200, 999},
			},
			wantErr: "expected_status_codes must be valid HTTP status codes",
		},
	}

	for _, tc := range testCases {
		data, _ := json.Marshal(tc.payload)
		r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/pools/%s/health-monitor", res.OriginPoolID), bytes.NewReader(data))
		r.Header.Set("X-API-Key", "key-tenant")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)

		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.wantErr) {
			t.Errorf("[%s] expected 400 Bad Request containing '%s', got %d: %s", tc.name, tc.wantErr, rec.Code, rec.Body.String())
		}
	}
}

func TestRateLimits_InputBoundsValidation(t *testing.T) {
	handler := setupTestServer()
	authInst := handler.Authenticator()
	authInst.RegisterTenantWithRole("key-tenant", "tenant-user", "proj-user", auth.RoleTenant, "proj-user")

	bodyDomain, _ := json.Marshal(map[string]interface{}{
		"hostname":        "rl-bounds.example.com",
		"origin_address":  "origin.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/proj-user/domains", bytes.NewReader(bodyDomain))
	req.Header.Set("X-API-Key", "key-tenant")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var res struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)

	testCases := []struct {
		name    string
		rules   []map[string]interface{}
		wantErr string
	}{
		{
			name: "rpm 0 rejected",
			rules: []map[string]interface{}{
				{"requests_per_minute": 0, "burst_size": 10},
			},
			wantErr: "requests_per_minute must be between 1 and 10,000,000",
		},
		{
			name: "rpm excessive rejected",
			rules: []map[string]interface{}{
				{"requests_per_minute": 99_000_000, "burst_size": 10},
			},
			wantErr: "requests_per_minute must be between 1 and 10,000,000",
		},
		{
			name: "burst size negative rejected",
			rules: []map[string]interface{}{
				{"requests_per_minute": 100, "burst_size": -5},
			},
			wantErr: "burst_size must be between 0 and 1,000,000",
		},
		{
			name: "invalid key type",
			rules: []map[string]interface{}{
				{"requests_per_minute": 100, "burst_size": 10, "key_type": "COOKIE"},
			},
			wantErr: "invalid key_type: must be CLIENT_IP or HEADER",
		},
		{
			name: "header key type without header name",
			rules: []map[string]interface{}{
				{"requests_per_minute": 100, "burst_size": 10, "key_type": "HEADER", "header_name": ""},
			},
			wantErr: "header_name is required when key_type is HEADER",
		},
		{
			name: "path prefix missing leading slash",
			rules: []map[string]interface{}{
				{"requests_per_minute": 100, "burst_size": 10, "path_prefix": "no-slash"},
			},
			wantErr: "path_prefix must start with /",
		},
	}

	for _, tc := range testCases {
		payload, _ := json.Marshal(map[string]interface{}{
			"rules": tc.rules,
		})
		r := httptest.NewRequest(http.MethodPost, fmt.Sprintf("/v1/domains/%s/rate-limits", res.DomainID), bytes.NewReader(payload))
		r.Header.Set("X-API-Key", "key-tenant")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)

		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), tc.wantErr) {
			t.Errorf("[%s] expected 400 Bad Request containing '%s', got %d: %s", tc.name, tc.wantErr, rec.Code, rec.Body.String())
		}
	}
}

func TestEvaluate_ClientIPValidation(t *testing.T) {
	handler := setupTestServer()
	authInst := handler.Authenticator()
	authInst.RegisterTenantWithRole("key-tenant", "tenant-user", "proj-user", auth.RoleTenant, "proj-user")

	bodyDomain, _ := json.Marshal(map[string]interface{}{
		"hostname":        "eval-bounds.example.com",
		"origin_address":  "origin.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/proj-user/domains", bytes.NewReader(bodyDomain))
	req.Header.Set("X-API-Key", "key-tenant")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	var res struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)

	// 1. Empty or malformed client IP -> 400 Bad Request
	badIPs := []string{"", "not-an-ip", "999.999.999.999", "abc::xyz"}
	for _, badIP := range badIPs {
		evalPayload, _ := json.Marshal(map[string]interface{}{
			"domain_id": res.DomainID,
			"client_ip": badIP,
			"method":    "GET",
			"path":      "/",
		})
		r := httptest.NewRequest(http.MethodPost, "/v1/edge/evaluate", bytes.NewReader(evalPayload))
		r.Header.Set("X-API-Key", "key-tenant")
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, r)

		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "client_ip must be a valid IP address") {
			t.Errorf("expected 400 Bad Request for bad client_ip '%s', got %d: %s", badIP, rec.Code, rec.Body.String())
		}
	}

	// 2. Valid client IP -> 200 OK
	validPayload, _ := json.Marshal(map[string]interface{}{
		"domain_id": res.DomainID,
		"client_ip": "203.0.113.195",
		"method":    "GET",
		"path":      "/",
	})
	r := httptest.NewRequest(http.MethodPost, "/v1/edge/evaluate", bytes.NewReader(validPayload))
	r.Header.Set("X-API-Key", "key-tenant")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for valid client_ip, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestHandler_OriginPoolCapacityLimit(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	comp := compiler.NewCompiler(9901, 80, 443)
	handler := api.NewAPIHandler(st, svc, comp)

	onboardBody, _ := json.Marshal(map[string]interface{}{
		"hostname":        "origin-limit.example.com",
		"origin_address":  "origin.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/prj-alpha/domains", bytes.NewReader(onboardBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("onboard failed: %d: %s", w.Code, w.Body.String())
	}

	var res struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)

	// Fetch the origin pool created during onboarding
	routes := st.GetRoutes(res.DomainID)
	if len(routes) == 0 {
		t.Fatalf("no routes found for domain")
	}
	pool, err := st.GetOriginPool(routes[0].PoolID)
	if err != nil {
		t.Fatalf("failed to get origin pool: %v", err)
	}

	// Pool already has 1 origin. Add 255 more to reach MaxOriginsPerPool (256)
	for i := 2; i <= store.MaxOriginsPerPool; i++ {
		orig := &model.Origin{
			ID:       fmt.Sprintf("orig-%d", i),
			PoolID:   pool.ID,
			Address:  fmt.Sprintf("origin-%d.example.com", i),
			Port:     443,
			Protocol: "HTTPS",
			Weight:   10,
			Healthy:  true,
		}
		if err := st.AddOrigin(orig); err != nil {
			t.Fatalf("failed to add origin %d: %v", i, err)
		}
	}

	// Now pool has exactly 256 origins. Attempting to add 257th via API must fail with 409 Conflict
	addBody, _ := json.Marshal(map[string]interface{}{
		"address":  "overflow-origin.example.com",
		"port":     443,
		"protocol": "HTTPS",
		"weight":   10,
	})
	addReq := httptest.NewRequest(http.MethodPost, "/v1/domains/"+res.DomainID+"/origins", bytes.NewReader(addBody))
	addRec := httptest.NewRecorder()
	handler.ServeHTTP(addRec, addReq)

	if addRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when origin pool is full, got %d: %s", addRec.Code, addRec.Body.String())
	}
	if !strings.Contains(addRec.Body.String(), "origin pool limit reached (max 256)") {
		t.Errorf("expected error message to mention origin pool limit, got: %s", addRec.Body.String())
	}
}

func TestHandler_RuleCardinalityLimits(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	comp := compiler.NewCompiler(9901, 80, 443)
	handler := api.NewAPIHandler(st, svc, comp)

	onboardBody, _ := json.Marshal(map[string]interface{}{
		"hostname":        "cardinality.example.com",
		"origin_address":  "origin.example.com",
		"origin_port":     443,
		"origin_protocol": "HTTPS",
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/projects/prj-alpha/domains", bytes.NewReader(onboardBody))
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("onboard failed: %d: %s", w.Code, w.Body.String())
	}
	var res struct {
		DomainID string `json:"domain_id"`
	}
	_ = json.Unmarshal(w.Body.Bytes(), &res)
	domainID := res.DomainID

	// 1. WAF Rules Limit (MaxWAFRulesPerDomain = 1000)
	for i := 0; i < store.MaxWAFRulesPerDomain; i++ {
		rule := model.WAFRule{
			ID:        fmt.Sprintf("waf-%d", i),
			DomainID:  domainID,
			Name:      fmt.Sprintf("rule-%d", i),
			Pattern:   fmt.Sprintf("/pattern-%d", i),
			Action:    model.WAFActionBlock,
			MatchType: model.WAFMatchPathPrefix,
			Enabled:   true,
		}
		if err := st.AddWAFRule(domainID, rule); err != nil {
			t.Fatalf("failed to add pre-populated WAF rule %d: %v", i, err)
		}
	}

	// 1001st WAF rule via API -> 409 Conflict
	wafBody, _ := json.Marshal(map[string]interface{}{
		"name":       "overflow-rule",
		"pattern":    "/overflow",
		"action":     "BLOCK",
		"match_type": "PATH_PREFIX",
	})
	wafReq := httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/waf/rules", bytes.NewReader(wafBody))
	wafRec := httptest.NewRecorder()
	handler.ServeHTTP(wafRec, wafReq)

	if wafRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when WAF rule limit is exceeded, got %d: %s", wafRec.Code, wafRec.Body.String())
	}
	if !strings.Contains(wafRec.Body.String(), "waf rule limit reached for domain (max 1000)") {
		t.Errorf("unexpected WAF rule limit error message: %s", wafRec.Body.String())
	}

	// 2. Rate Limit Rules Limit (MaxRateLimitRulesPerDomain = 500)
	// Sending 501 rules via API -> 409 Conflict
	oversizedRL := make([]map[string]interface{}, store.MaxRateLimitRulesPerDomain+1)
	for i := range oversizedRL {
		oversizedRL[i] = map[string]interface{}{
			"requests_per_minute": 100,
			"burst_size":          10,
			"key_type":            "CLIENT_IP",
		}
	}
	rlPayload, _ := json.Marshal(map[string]interface{}{
		"rules": oversizedRL,
	})
	rlReq := httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/rate-limits", bytes.NewReader(rlPayload))
	rlRec := httptest.NewRecorder()
	handler.ServeHTTP(rlRec, rlReq)

	if rlRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when rate limit count exceeds 500, got %d: %s", rlRec.Code, rlRec.Body.String())
	}
	if !strings.Contains(rlRec.Body.String(), "rate limit rule limit reached for domain (max 500)") {
		t.Errorf("unexpected Rate Limit limit error message: %s", rlRec.Body.String())
	}

	// 3. Cache Rules Limit (MaxCacheRulesPerDomain = 1000)
	for i := 0; i < store.MaxCacheRulesPerDomain; i++ {
		cRule := model.CacheRule{
			ID:          fmt.Sprintf("cache-%d", i),
			DomainID:    domainID,
			Name:        fmt.Sprintf("crule-%d", i),
			PathPattern: fmt.Sprintf("/cache/%d/*", i),
			TTLSeconds:  3600,
			Enabled:     true,
		}
		if err := st.AddCacheRule(domainID, cRule); err != nil {
			t.Fatalf("failed to add pre-populated cache rule %d: %v", i, err)
		}
	}

	// 1001st Cache rule via API -> 409 Conflict
	cacheBody, _ := json.Marshal(map[string]interface{}{
		"name":         "overflow-cache",
		"path_pattern": "/overflow/*",
		"ttl_seconds":  3600,
	})
	cacheReq := httptest.NewRequest(http.MethodPost, "/v1/domains/"+domainID+"/cache/rules", bytes.NewReader(cacheBody))
	cacheRec := httptest.NewRecorder()
	handler.ServeHTTP(cacheRec, cacheReq)

	if cacheRec.Code != http.StatusConflict {
		t.Fatalf("expected 409 Conflict when cache rule limit is exceeded, got %d: %s", cacheRec.Code, cacheRec.Body.String())
	}
	if !strings.Contains(cacheRec.Body.String(), "cache rule limit reached for domain (max 1000)") {
		t.Errorf("unexpected Cache rule limit error message: %s", cacheRec.Body.String())
	}
}
