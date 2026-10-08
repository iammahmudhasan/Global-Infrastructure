package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/auth"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/circuitbreaker"
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

	var tenantDecision PublicDispatchDecision
	if err := json.Unmarshal(recTenant.Body.Bytes(), &tenantDecision); err != nil {
		t.Fatalf("failed to parse tenant decision: %v", err)
	}
	if tenantDecision.AssignedBackend == nil {
		t.Fatalf("expected assigned backend in decision")
	}
	if tenantDecision.AssignedBackend.ID != "backend-dgx-h100-dispatch" {
		t.Fatalf("unexpected backend ID: %s", tenantDecision.AssignedBackend.ID)
	}

	// Verify that internal fields (Endpoint, HourlyCost, Latency, AvailableGPUs) are NOT leaked (Finding 10)
	var rawMap map[string]interface{}
	_ = json.Unmarshal(recTenant.Body.Bytes(), &rawMap)
	rawBackend := rawMap["assigned_backend"].(map[string]interface{})
	if _, leaked := rawBackend["endpoint"]; leaked {
		t.Errorf("tenant response must not contain internal endpoint field")
	}
	if _, leaked := rawBackend["hourly_cost"]; leaked {
		t.Errorf("tenant response must not leak internal hourly_cost")
	}
	if _, leaked := rawBackend["available_gpus"]; leaked {
		t.Errorf("tenant response must not leak internal available_gpus")
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

func TestWorkload_CompleteAndReleaseLifecycle(t *testing.T) {
	// P1 Finding 2 Verification: Workload completion and release restore capacity
	srv := NewServer()
	defer srv.Close()

	srv.auth.RegisterTenantWithRole("key-tenant", "tenant-alpha", "proj-alpha", auth.RoleTenant)
	handler := srv.routes()

	backend := &registry.ComputeBackend{
		ID:            "backend-dgx-h100-life",
		Provider:      "baremetal",
		Region:        "ap-south-2",
		Endpoint:      "https://dgx-life.internal/v1",
		GPUModel:      "H100",
		AvailableGPUs: 8,
		HourlyCost:    2.00,
		LatencyP95Ms:  5,
		Healthy:       true,
	}
	srv.registry.Register(backend)

	// 1. Dispatch 2 GPUs
	dispatchPayload := map[string]interface{}{
		"workload_id":     "wl-lifecycle-01",
		"tenant_id":       "tenant-alpha",
		"name":            "Lifecycle Test",
		"required_gpu":    "H100",
		"gpus_requested":  2,
		"objective":       "LOW_LATENCY",
		"idempotency_key": "idem-life-01",
	}
	body, _ := json.Marshal(dispatchPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer key-tenant")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch failed: %d, body: %s", rec.Code, rec.Body.String())
	}

	b, _ := srv.registry.Get("backend-dgx-h100-life")
	if b.AvailableGPUs != 6 {
		t.Fatalf("expected 6 available GPUs after dispatch, got %d", b.AvailableGPUs)
	}

	// 2. Complete workload -> Capacity restored to 8
	completeBody, _ := json.Marshal(map[string]interface{}{
		"workload_id": "wl-lifecycle-01",
		"status":      "COMPLETED",
	})
	reqComp := httptest.NewRequest(http.MethodPost, "/api/v1/workload/complete", bytes.NewReader(completeBody))
	reqComp.Header.Set("Authorization", "Bearer key-tenant")
	recComp := httptest.NewRecorder()
	handler.ServeHTTP(recComp, reqComp)
	if recComp.Code != http.StatusOK {
		t.Fatalf("complete failed: %d, body: %s", recComp.Code, recComp.Body.String())
	}

	b, _ = srv.registry.Get("backend-dgx-h100-life")
	if b.AvailableGPUs != 8 {
		t.Fatalf("expected 8 available GPUs after completion, got %d", b.AvailableGPUs)
	}

	// 3. Dispatch workload 2 for 3 GPUs
	dispatchPayload2 := map[string]interface{}{
		"workload_id":     "wl-lifecycle-02",
		"tenant_id":       "tenant-alpha",
		"name":            "Lifecycle Test 2",
		"required_gpu":    "H100",
		"gpus_requested":  3,
		"objective":       "LOW_LATENCY",
		"idempotency_key": "idem-life-02",
	}
	body2, _ := json.Marshal(dispatchPayload2)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body2))
	req2.Header.Set("Authorization", "Bearer key-tenant")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("dispatch 2 failed: %d", rec2.Code)
	}

	b, _ = srv.registry.Get("backend-dgx-h100-life")
	if b.AvailableGPUs != 5 {
		t.Fatalf("expected 5 available GPUs after dispatch 2, got %d", b.AvailableGPUs)
	}

	// 4. Release workload 2 -> Capacity restored to 8
	releaseBody, _ := json.Marshal(map[string]interface{}{
		"workload_id": "wl-lifecycle-02",
	})
	reqRel := httptest.NewRequest(http.MethodPost, "/api/v1/workload/release", bytes.NewReader(releaseBody))
	reqRel.Header.Set("Authorization", "Bearer key-tenant")
	recRel := httptest.NewRecorder()
	handler.ServeHTTP(recRel, reqRel)
	if recRel.Code != http.StatusOK {
		t.Fatalf("release failed: %d, body: %s", recRel.Code, recRel.Body.String())
	}

	b, _ = srv.registry.Get("backend-dgx-h100-life")
	if b.AvailableGPUs != 8 {
		t.Fatalf("expected 8 available GPUs after release, got %d", b.AvailableGPUs)
	}

	// 5. Calling release again on released workload returns 404
	reqRelAgain := httptest.NewRequest(http.MethodPost, "/api/v1/workload/release", bytes.NewReader(releaseBody))
	reqRelAgain.Header.Set("Authorization", "Bearer key-tenant")
	recRelAgain := httptest.NewRecorder()
	handler.ServeHTTP(recRelAgain, reqRelAgain)
	if recRelAgain.Code != http.StatusNotFound {
		t.Fatalf("expected 404 on duplicate release, got %d", recRelAgain.Code)
	}
}

func TestWorkload_CrossTenantIDORProtection(t *testing.T) {
	// Finding 1 Verification: Prevent cross-tenant completion, release, or renewal IDOR
	srv := NewServer()
	defer srv.Close()

	srv.auth.RegisterTenantWithRole("key-tenant-a", "tenant-a", "proj-a", auth.RoleTenant)
	srv.auth.RegisterTenantWithRole("key-tenant-b", "tenant-b", "proj-b", auth.RoleTenant)
	handler := srv.routes()

	backend := &registry.ComputeBackend{
		ID:            "backend-dgx-h100-idor",
		Provider:      "baremetal",
		Region:        "ap-south-2",
		Endpoint:      "https://dgx-idor.internal/v1",
		GPUModel:      "H100",
		AvailableGPUs: 8,
		HourlyCost:    2.00,
		LatencyP95Ms:  5,
		Healthy:       true,
	}
	srv.registry.Register(backend)

	// 1. Tenant A dispatches workload W
	dispatchPayload := map[string]interface{}{
		"workload_id":     "wl-idor-01",
		"tenant_id":       "tenant-a",
		"project_id":      "proj-a",
		"name":            "Tenant A Sensitive Task",
		"required_gpu":    "H100",
		"gpus_requested":  4,
		"objective":       "LOW_LATENCY",
		"idempotency_key": "idem-idor-01",
	}
	body, _ := json.Marshal(dispatchPayload)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer key-tenant-a")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("dispatch by tenant A failed: %d, body: %s", rec.Code, rec.Body.String())
	}

	b, _ := srv.registry.Get("backend-dgx-h100-idor")
	if b.AvailableGPUs != 4 {
		t.Fatalf("expected 4 available GPUs after dispatch, got %d", b.AvailableGPUs)
	}

	// 2. Tenant B attempts release(W) -> 403 Forbidden
	releaseBody, _ := json.Marshal(map[string]interface{}{
		"workload_id": "wl-idor-01",
	})
	reqRelB := httptest.NewRequest(http.MethodPost, "/api/v1/workload/release", bytes.NewReader(releaseBody))
	reqRelB.Header.Set("Authorization", "Bearer key-tenant-b")
	recRelB := httptest.NewRecorder()
	handler.ServeHTTP(recRelB, reqRelB)
	if recRelB.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when Tenant B releases Tenant A workload, got: %d (%s)", recRelB.Code, recRelB.Body.String())
	}

	// GPU capacity unchanged
	b, _ = srv.registry.Get("backend-dgx-h100-idor")
	if b.AvailableGPUs != 4 {
		t.Fatalf("GPU capacity altered by unauthorized release! Got: %d", b.AvailableGPUs)
	}

	// 3. Tenant B attempts complete(W) with FAILED to sabotage circuit breaker -> 403 Forbidden
	completeBody, _ := json.Marshal(map[string]interface{}{
		"workload_id": "wl-idor-01",
		"status":      "FAILED",
	})
	reqCompB := httptest.NewRequest(http.MethodPost, "/api/v1/workload/complete", bytes.NewReader(completeBody))
	reqCompB.Header.Set("Authorization", "Bearer key-tenant-b")
	recCompB := httptest.NewRecorder()
	handler.ServeHTTP(recCompB, reqCompB)
	if recCompB.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when Tenant B completes Tenant A workload, got: %d (%s)", recCompB.Code, recCompB.Body.String())
	}

	// Circuit breaker and capacity unchanged
	if srv.registry.CircuitState("backend-dgx-h100-idor") != circuitbreaker.StateClosed {
		t.Fatalf("circuit breaker sabotaged by unauthorized tenant failure!")
	}
	b, _ = srv.registry.Get("backend-dgx-h100-idor")
	if b.AvailableGPUs != 4 {
		t.Fatalf("GPU capacity altered by unauthorized complete! Got: %d", b.AvailableGPUs)
	}

	// 4. Tenant B attempts renew(W) -> 403 Forbidden
	renewBody, _ := json.Marshal(map[string]interface{}{
		"workload_id":    "wl-idor-01",
		"extend_seconds": 600,
	})
	reqRenB := httptest.NewRequest(http.MethodPost, "/api/v1/workload/renew", bytes.NewReader(renewBody))
	reqRenB.Header.Set("Authorization", "Bearer key-tenant-b")
	recRenB := httptest.NewRecorder()
	handler.ServeHTTP(recRenB, reqRenB)
	if recRenB.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden when Tenant B renews Tenant A workload, got: %d (%s)", recRenB.Code, recRenB.Body.String())
	}

	// 5. Tenant A renew(W) -> 200 OK
	reqRenA := httptest.NewRequest(http.MethodPost, "/api/v1/workload/renew", bytes.NewReader(renewBody))
	reqRenA.Header.Set("Authorization", "Bearer key-tenant-a")
	recRenA := httptest.NewRecorder()
	handler.ServeHTTP(recRenA, reqRenA)
	if recRenA.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when Tenant A renews own workload, got: %d (%s)", recRenA.Code, recRenA.Body.String())
	}

	// 6. Tenant A release(W) -> 200 OK and capacity restored
	reqRelA := httptest.NewRequest(http.MethodPost, "/api/v1/workload/release", bytes.NewReader(releaseBody))
	reqRelA.Header.Set("Authorization", "Bearer key-tenant-a")
	recRelA := httptest.NewRecorder()
	handler.ServeHTTP(recRelA, reqRelA)
	if recRelA.Code != http.StatusOK {
		t.Fatalf("expected 200 OK when Tenant A releases own workload, got: %d (%s)", recRelA.Code, recRelA.Body.String())
	}

	b, _ = srv.registry.Get("backend-dgx-h100-idor")
	if b.AvailableGPUs != 8 {
		t.Fatalf("expected 8 available GPUs after authorized release, got %d", b.AvailableGPUs)
	}
}

func TestWorkload_IdempotencyReservationCoupling(t *testing.T) {
	// Finding 3 Verification: Swept or released reservation invalidates cached idempotency hit
	srv := NewServer()
	defer srv.Close()

	srv.auth.RegisterTenantWithRole("key-tenant", "tenant-idem", "proj-idem", auth.RoleTenant)
	handler := srv.routes()

	backend := &registry.ComputeBackend{
		ID:            "backend-dgx-h100-idem",
		Provider:      "baremetal",
		Region:        "ap-south-2",
		Endpoint:      "https://dgx-idem.internal/v1",
		GPUModel:      "H100",
		AvailableGPUs: 8,
		HourlyCost:    2.00,
		LatencyP95Ms:  5,
		Healthy:       true,
	}
	srv.registry.Register(backend)

	dispatchPayload := map[string]interface{}{
		"workload_id":     "wl-idem-coupling-01",
		"tenant_id":       "tenant-idem",
		"project_id":      "proj-idem",
		"name":            "Idempotency Coupling Task",
		"required_gpu":    "H100",
		"gpus_requested":  2,
		"objective":       "LOW_LATENCY",
		"idempotency_key": "idem-key-coupled-01",
	}
	body, _ := json.Marshal(dispatchPayload)

	// 1. First dispatch -> SCHEDULED
	req1 := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body))
	req1.Header.Set("Authorization", "Bearer key-tenant")
	rec1 := httptest.NewRecorder()
	handler.ServeHTTP(rec1, req1)
	if rec1.Code != http.StatusOK {
		t.Fatalf("first dispatch failed: %d", rec1.Code)
	}

	// 2. Immediate second dispatch with same key -> Idempotency HIT (cached decision)
	req2 := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body))
	req2.Header.Set("Authorization", "Bearer key-tenant")
	rec2 := httptest.NewRecorder()
	handler.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Fatalf("second dispatch failed: %d", rec2.Code)
	}

	// 3. Workload is released by owner -> Idempotency entry is invalidated
	relBody, _ := json.Marshal(map[string]interface{}{
		"workload_id": "wl-idem-coupling-01",
	})
	reqRel := httptest.NewRequest(http.MethodPost, "/api/v1/workload/release", bytes.NewReader(relBody))
	reqRel.Header.Set("Authorization", "Bearer key-tenant")
	recRel := httptest.NewRecorder()
	handler.ServeHTTP(recRel, reqRel)
	if recRel.Code != http.StatusOK {
		t.Fatalf("release failed: %d", recRel.Code)
	}

	// 4. Retry with same idempotency key -> Re-evaluates freshly rather than returning stale SCHEDULED!
	// (New reservation will be admitted with the available capacity)
	req3 := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body))
	req3.Header.Set("Authorization", "Bearer key-tenant")
	rec3 := httptest.NewRecorder()
	handler.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusOK {
		t.Fatalf("third dispatch failed: %d", rec3.Code)
	}
}

func TestWorkloadDispatch_FieldBoundsValidation(t *testing.T) {
	srv := NewServer()
	srv.auth.RegisterTenantWithRole("key-tenant", "tenant-user", "proj-user", auth.RoleTenant)
	handler := srv.auth.Middleware(srv.routes())

	longKey := strings.Repeat("A", 300) // MaxIdempotencyKey is 256
	dispatchPayload := map[string]interface{}{
		"workload_id":     "wl-bounds-01",
		"residency":       "ANY",
		"gpus_requested":  1,
		"objective":       "LOW_LATENCY",
		"idempotency_key": longKey,
	}
	body, _ := json.Marshal(dispatchPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer key-tenant")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 Unprocessable Entity for oversized idempotency key, got: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "idempotency_key exceeds maximum length") {
		t.Errorf("expected error message to mention idempotency_key limit, got: %s", rec.Body.String())
	}
}

func TestWorkloadDispatch_TenantQuotaEnforcement(t *testing.T) {
	srv := NewServer()
	srv.auth.RegisterTenantWithRole("key-tenant", "tenant-user", "proj-user", auth.RoleTenant)
	handler := srv.auth.Middleware(srv.routes())

	// Limit tenant-user to 2 GPUs
	srv.registry.SetTenantQuota("tenant-user", registry.TenantQuota{
		MaxGPUs:            2,
		MaxActiveWorkloads: 5,
	})

	dispatchPayload := map[string]interface{}{
		"workload_id":    "wl-quota-dispatch-01",
		"residency":      "ANY",
		"gpus_requested": 4, // Exceeds quota of 2
		"objective":      "LOW_LATENCY",
	}
	body, _ := json.Marshal(dispatchPayload)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/workload/dispatch", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer key-tenant")
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 Unprocessable Entity for quota exceeded, got: %d", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "tenant resource quota exceeded") {
		t.Errorf("expected error to mention tenant resource quota exceeded, got: %s", rec.Body.String())
	}
}
