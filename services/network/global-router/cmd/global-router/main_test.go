package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/auth"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/registry"
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
