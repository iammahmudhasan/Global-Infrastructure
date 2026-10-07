package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
}
