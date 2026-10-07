package auth_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/auth"
)

func TestAuthenticationSuccess(t *testing.T) {
	authenticator := auth.NewAuthenticator()
	authenticator.RegisterTenant("test-key-mock-banking-01", "tenant-cbr-banking", "proj-fintech-prod")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workload/dispatch", nil)
	req.Header.Set("Authorization", "Bearer test-key-mock-banking-01")
	req.Header.Set("X-Tenant-ID", "tenant-cbr-banking")

	rr := httptest.NewRecorder()

	var passedTenant string
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		passedTenant, _ = r.Context().Value(auth.TenantContextKey).(string)
		w.WriteHeader(http.StatusOK)
	})

	handler := authenticator.Middleware(testHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got: %d", rr.Code)
	}

	if passedTenant != "tenant-cbr-banking" {
		t.Errorf("expected tenant 'tenant-cbr-banking', got: %s", passedTenant)
	}
}

func TestAuthenticationUnauthorized(t *testing.T) {
	authenticator := auth.NewAuthenticator()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workload/dispatch", nil)
	req.Header.Set("Authorization", "Bearer invalid-tampered-token")

	rr := httptest.NewRecorder()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := authenticator.Middleware(testHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized, got: %d", rr.Code)
	}
}

func TestTenantMismatchForbidden(t *testing.T) {
	authenticator := auth.NewAuthenticator()
	authenticator.RegisterTenant("test-key-mock-banking-01", "tenant-cbr-banking", "proj-fintech-prod")

	req := httptest.NewRequest(http.MethodGet, "/api/v1/workload/dispatch", nil)
	req.Header.Set("Authorization", "Bearer test-key-mock-banking-01")
	req.Header.Set("X-Tenant-ID", "attacker-impersonated-tenant")

	rr := httptest.NewRecorder()
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := authenticator.Middleware(testHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden on tenant spoofing, got: %d", rr.Code)
	}
}

func TestHealthCheckBypass(t *testing.T) {
	authenticator := auth.NewAuthenticator()

	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rr := httptest.NewRecorder()

	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	handler := authenticator.Middleware(testHandler)
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK without auth on healthz, got: %d", rr.Code)
	}
}
