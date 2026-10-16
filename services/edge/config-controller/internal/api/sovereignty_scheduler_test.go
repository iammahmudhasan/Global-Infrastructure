package api_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/policy"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/scheduler"
)

func TestAPI_SovereignPolicyEvaluate(t *testing.T) {
	h := setupTestServer()

	// 1. Bangladesh NDMA 2026 CII breach (BD -> US)
	reqPayload := policy.SovereignEvaluationRequest{
		TenantID:           "tenant-fintech-bd",
		ProjectID:          "proj-core",
		WorkloadID:         "core-banking-01",
		DataClassification: policy.ClassificationCII,
		SourceJurisdiction: policy.JurisdictionBD,
		TargetJurisdiction: policy.JurisdictionUS,
		StrictSovereignty:  true,
	}

	body, _ := json.Marshal(reqPayload)
	req := httptest.NewRequest(http.MethodPost, "/v1/edge/policies/sovereignty/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var res policy.SovereignEvaluationResult
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if res.Allowed {
		t.Fatal("expected BD CII foreign transfer to be rejected")
	}
	if res.DecisionCode != "BD_NDMA_2026_CII_BREACH" {
		t.Fatalf("expected BD_NDMA_2026_CII_BREACH, got %s", res.DecisionCode)
	}

	// 2. Bangladesh NDMA 2026 Compliant (BD -> BD)
	reqPayload.TargetJurisdiction = policy.JurisdictionBD
	body, _ = json.Marshal(reqPayload)
	req = httptest.NewRequest(http.MethodPost, "/v1/edge/policies/sovereignty/evaluate", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")

	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected domestic BD transfer to be allowed, got: %s", res.Reason)
	}
}

func TestAPI_WorkloadSchedule(t *testing.T) {
	h := setupTestServer()

	// 1. Schedule Bangladesh banking API
	schedReq := scheduler.WorkloadRequirement{
		TenantID:             "tenant-fintech-bd",
		ProjectID:            "proj-core",
		WorkloadID:           "banking-tx-99",
		WorkloadType:         "BANKING_API",
		ClientOrigin:         "dhaka",
		RequiredJurisdiction: "BD",
		StrictSovereignty:    true,
		DataClassification:   policy.ClassificationCII,
		MaxLatencyP95MS:      20,
		MaxCostPerHour:       5.0,
		GPUsRequested:        1,
	}

	body, _ := json.Marshal(schedReq)
	req := httptest.NewRequest(http.MethodPost, "/v1/workloads/schedule", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var decision scheduler.SchedulingDecision
	if err := json.Unmarshal(w.Body.Bytes(), &decision); err != nil {
		t.Fatalf("failed to decode decision: %v", err)
	}
	if decision.Status != "SCHEDULED" {
		t.Fatalf("expected status SCHEDULED, got %s", decision.Status)
	}
	if decision.AssignedNode != "bd-dhaka-dgx01" {
		t.Fatalf("expected assigned node bd-dhaka-dgx01, got %s", decision.AssignedNode)
	}

	// 2. Schedule impossible latency workload
	schedReq.WorkloadID = "impossible-workload-01"
	schedReq.ClientOrigin = "frankfurt"
	schedReq.RequiredJurisdiction = "BD"
	schedReq.MaxLatencyP95MS = 10 // Frankfurt to Dhaka is 130ms

	body, _ = json.Marshal(schedReq)
	req = httptest.NewRequest(http.MethodPost, "/v1/workloads/schedule", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")

	w = httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected status 422 Unprocessable Entity, got %d", w.Code)
	}
}

func TestAPI_WorkloadNodes(t *testing.T) {
	h := setupTestServer()

	req := httptest.NewRequest(http.MethodGet, "/v1/workloads/nodes", nil)
	req.Header.Set("Authorization", "Bearer dev-fixture-key-01")

	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp struct {
		Nodes []*scheduler.ComputeNode `json:"nodes"`
		Count int                      `json:"count"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Count < 4 {
		t.Fatalf("expected at least 4 default nodes, got %d", resp.Count)
	}
}
