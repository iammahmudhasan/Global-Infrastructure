package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/auth"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/registry"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/scheduler"
)

func TestBackendsAPI_AccessControl(t *testing.T) {
	srv := NewServer()
	srv.auth.RegisterTenantWithRole("key-tenant", "tenant-user", "proj-user", auth.RoleTenant)
	srv.auth.RegisterTenantWithRole("key-operator", "tenant-operator", "proj-core", auth.RolePlatformOperator)

	handler := srv.auth.Middleware(srv.routes())

	backendPayload := registry.ComputeBackend{
		ID:            "test-operator-node",
		Provider:      "custom-cloud",
		Region:        "ap-south-2",
		Endpoint:      "https://internal-gpu.node.cluster/v1",
		GPUModel:      "H100",
		AvailableGPUs: 8,
		HourlyCost:    2.50,
		LatencyP95Ms:  15,
		Healthy:       true,
	}
	body, _ := json.Marshal(backendPayload)

	// 1. Unauthenticated POST -> 401 Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodPost, "/api/v1/backends/register", bytes.NewReader(body))
	recUnauth := httptest.NewRecorder()
	handler.ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for missing auth, got: %d", recUnauth.Code)
	}

	// 2. Tenant POST -> 403 Forbidden
	reqTenant := httptest.NewRequest(http.MethodPost, "/api/v1/backends/register", bytes.NewReader(body))
	reqTenant.Header.Set("Authorization", "Bearer key-tenant")
	recTenant := httptest.NewRecorder()
	handler.ServeHTTP(recTenant, reqTenant)
	if recTenant.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for tenant registering backend, got: %d", recTenant.Code)
	}

	// 3. Platform Operator POST -> 201 Created
	reqOperator := httptest.NewRequest(http.MethodPost, "/api/v1/backends/register", bytes.NewReader(body))
	reqOperator.Header.Set("Authorization", "Bearer key-operator")
	recOperator := httptest.NewRecorder()
	handler.ServeHTTP(recOperator, reqOperator)
	if recOperator.Code != http.StatusCreated {
		t.Fatalf("expected 201 Created for operator registering backend, got: %d (%s)", recOperator.Code, recOperator.Body.String())
	}

	// 4. Tenant GET -> 200 OK with sanitized/redacted endpoints
	reqGetTenant := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	reqGetTenant.Header.Set("Authorization", "Bearer key-tenant")
	recGetTenant := httptest.NewRecorder()
	handler.ServeHTTP(recGetTenant, reqGetTenant)
	if recGetTenant.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for tenant listing backends, got: %d", recGetTenant.Code)
	}
	var tenantResp struct {
		Backends []registry.ComputeBackend `json:"backends"`
	}
	_ = json.Unmarshal(recGetTenant.Body.Bytes(), &tenantResp)
	for _, b := range tenantResp.Backends {
		if b.Endpoint != "[REDACTED]" {
			t.Errorf("expected tenant backend endpoint to be [REDACTED], got: %s", b.Endpoint)
		}
	}

	// 5. Operator GET -> 200 OK with unredacted endpoints
	reqGetOperator := httptest.NewRequest(http.MethodGet, "/api/v1/backends", nil)
	reqGetOperator.Header.Set("Authorization", "Bearer key-operator")
	recGetOperator := httptest.NewRecorder()
	handler.ServeHTTP(recGetOperator, reqGetOperator)
	if recGetOperator.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator listing backends, got: %d", recGetOperator.Code)
	}
	var opResp struct {
		Backends []registry.ComputeBackend `json:"backends"`
	}
	_ = json.Unmarshal(recGetOperator.Body.Bytes(), &opResp)
	foundUnredacted := false
	for _, b := range opResp.Backends {
		if b.ID == "test-operator-node" && b.Endpoint == "https://internal-gpu.node.cluster/v1" {
			foundUnredacted = true
		}
	}
	if !foundUnredacted {
		t.Errorf("operator should see original unredacted endpoint for registered backend")
	}
}

func TestWorkloadDispatch_ProjectIDSpoofingProtection(t *testing.T) {
	srv := NewServer()
	// Register authenticated tenant with ProjectID "proj-finance-secure"
	srv.auth.RegisterTenantWithRole("key-tenant-auth", "tenant-cbr-banking", "proj-finance-secure", auth.RoleTenant)
	handler := srv.routes()

	// 1. Register backend so dispatch can be admitted
	srv.registry.Register(&registry.ComputeBackend{
		ID:            "backend-dgx-h100",
		Provider:      "baremetal",
		Region:        "ap-south-2",
		Endpoint:      "https://dgx01.internal/v1",
		GPUModel:      "H100",
		AvailableGPUs: 8,
		HourlyCost:    2.00,
		LatencyP95Ms:  5,
		Healthy:       true,
	})

	// 2. Caller sends body attempting to spoof ProjectID as "proj-victim-foreign"
	dispatchReqBody := map[string]interface{}{
		"workload_id":     "wl-dispatch-spoof-01",
		"tenant_id":       "tenant-cbr-banking",
		"project_id":      "proj-victim-foreign", // Attempted spoof!
		"name":            "High Security Banking Model",
		"required_gpu":    "H100",
		"gpus_requested":  1,
		"objective":       "LOW_LATENCY",
		"idempotency_key": "idem-spoof-test-01",
	}
	body, _ := json.Marshal(dispatchReqBody)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer key-tenant-auth")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for dispatch, got: %d (%s)", rec.Code, rec.Body.String())
	}

	var decision scheduler.DispatchDecision
	if err := json.Unmarshal(rec.Body.Bytes(), &decision); err != nil {
		t.Fatalf("failed to decode dispatch decision: %v", err)
	}

	// 3. Verify ProjectID is overridden with the authenticated project from context
	if decision.ProjectID != "proj-finance-secure" {
		t.Errorf("ProjectID spoofing vulnerability! Expected authoritative proj-finance-secure, got: %s", decision.ProjectID)
	}
	if decision.TenantID != "tenant-cbr-banking" {
		t.Errorf("TenantID mismatch! Expected tenant-cbr-banking, got: %s", decision.TenantID)
	}
}

func TestGlobalRouter_BodySizeLimit(t *testing.T) {
	srv := NewServer()
	srv.auth.RegisterTenantWithRole("key-tenant-auth", "tenant-cbr-banking", "proj-finance-secure", auth.RoleTenant)
	handler := srv.routes()

	// Create body larger than 1 MiB (1.5 MiB)
	largePayload := make([]byte, 1500*1024)
	for i := range largePayload {
		largePayload[i] = 'A'
	}

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(largePayload))
	req.Header.Set("Authorization", "Bearer key-tenant-auth")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	// MaxBytesReader should cause decoder to fail with BadRequest (or RequestEntityTooLarge)
	if rec.Code != http.StatusBadRequest {
		t.Errorf("expected 400 Bad Request for oversized payload exceeding 1 MiB, got: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "too large") && !strings.Contains(rec.Body.String(), "Invalid policy JSON") {
		t.Errorf("expected body to indicate payload error, got: %s", rec.Body.String())
	}
}

func TestWorkloadDispatch_EndpointRedaction(t *testing.T) {
	srv := NewServer()
	srv.auth.RegisterTenantWithRole("key-tenant-user", "tenant-cbr-banking", "proj-finance-secure", auth.RoleTenant)
	srv.auth.RegisterTenantWithRole("key-operator-user", "tenant-admin", "proj-core", auth.RolePlatformOperator)
	handler := srv.routes()

	srv.registry.Register(&registry.ComputeBackend{
		ID:            "backend-dgx-h100-dispatch",
		Provider:      "baremetal",
		Region:        "ap-south-2",
		Endpoint:      "https://dgx01.internal/v1",
		GPUModel:      "H100",
		AvailableGPUs: 8,
		HourlyCost:    2.00,
		LatencyP95Ms:  5,
		Healthy:       true,
	})

	dispatchPayload := map[string]interface{}{
		"workload_id":     "wl-dispatch-redact-01",
		"tenant_id":       "tenant-cbr-banking",
		"name":            "Inference Task",
		"required_gpu":    "H100",
		"gpus_requested":  1,
		"objective":       "LOW_LATENCY",
		"idempotency_key": "idem-redact-01",
	}
	body, _ := json.Marshal(dispatchPayload)

	// 1. Tenant Dispatch -> Endpoint must be [REDACTED]
	reqTenant := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body))
	reqTenant.Header.Set("Authorization", "Bearer key-tenant-user")
	recTenant := httptest.NewRecorder()
	handler.ServeHTTP(recTenant, reqTenant)

	if recTenant.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for tenant dispatch, got: %d", recTenant.Code)
	}

	var tenantDecision scheduler.DispatchDecision
	if err := json.Unmarshal(recTenant.Body.Bytes(), &tenantDecision); err != nil {
		t.Fatalf("failed to parse tenant decision: %v", err)
	}
	if tenantDecision.AssignedBackend == nil {
		t.Fatalf("expected assigned backend in decision")
	}
	if tenantDecision.AssignedBackend.Endpoint != "[REDACTED]" {
		t.Fatalf("tenant received internal backend endpoint: %s", tenantDecision.AssignedBackend.Endpoint)
	}

	// 2. Operator Dispatch -> Actual internal endpoint must be visible
	dispatchPayload["workload_id"] = "wl-dispatch-operator-01"
	dispatchPayload["idempotency_key"] = "idem-operator-01"
	bodyOp, _ := json.Marshal(dispatchPayload)

	reqOperator := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(bodyOp))
	reqOperator.Header.Set("Authorization", "Bearer key-operator-user")
	recOperator := httptest.NewRecorder()
	handler.ServeHTTP(recOperator, reqOperator)

	if recOperator.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for operator dispatch, got: %d", recOperator.Code)
	}

	var opDecision scheduler.DispatchDecision
	if err := json.Unmarshal(recOperator.Body.Bytes(), &opDecision); err != nil {
		t.Fatalf("failed to parse operator decision: %v", err)
	}
	if opDecision.AssignedBackend == nil {
		t.Fatalf("expected assigned backend in decision")
	}
	if opDecision.AssignedBackend.Endpoint != "https://dgx01.internal/v1" {
		t.Fatalf("operator should receive actual endpoint, got: %s", opDecision.AssignedBackend.Endpoint)
	}
}
