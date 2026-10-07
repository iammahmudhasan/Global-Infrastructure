package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/api"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
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
}
