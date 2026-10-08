package auth_test

import (
	"net/http"
	"net/http/httptest"
	"os"
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

func TestAuthorizeRole_TenantVsOperator(t *testing.T) {
	authenticator := auth.NewAuthenticator()
	authenticator.RegisterTenantWithRole("key-tenant", "tenant-1", "proj-1", auth.RoleTenant)
	authenticator.RegisterTenantWithRole("key-operator", "operator-1", "proj-core", auth.RolePlatformOperator)

	// 1. Tenant caller
	reqTenant := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqTenant.Header.Set("Authorization", "Bearer key-tenant")
	rr := httptest.NewRecorder()

	var tenantIsOperator bool
	var tenantIsTenant bool
	testHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tenantIsOperator = authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator)
		tenantIsTenant = authenticator.AuthorizeRole(r.Context(), auth.RoleTenant)
		w.WriteHeader(http.StatusOK)
	})

	handler := authenticator.Middleware(testHandler)
	handler.ServeHTTP(rr, reqTenant)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rr.Code)
	}
	if tenantIsOperator {
		t.Errorf("tenant should NOT be authorized as RolePlatformOperator")
	}
	if !tenantIsTenant {
		t.Errorf("tenant SHOULD be authorized as RoleTenant")
	}

	// 2. Operator caller
	reqOperator := httptest.NewRequest(http.MethodGet, "/test", nil)
	reqOperator.Header.Set("Authorization", "Bearer key-operator")
	rrOp := httptest.NewRecorder()

	var opIsOperator bool
	testHandlerOp := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		opIsOperator = authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator)
		w.WriteHeader(http.StatusOK)
	})

	handlerOp := authenticator.Middleware(testHandlerOp)
	handlerOp.ServeHTTP(rrOp, reqOperator)

	if rrOp.Code != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", rrOp.Code)
	}
	if !opIsOperator {
		t.Errorf("operator SHOULD be authorized as RolePlatformOperator")
	}
}

func TestDevMode_EnvironmentBinding(t *testing.T) {
	origDevMode := os.Getenv("NEXUSEDGE_DEV_MODE")
	origEnv := os.Getenv("NEXUSEDGE_ENV")
	origGeneralEnv := os.Getenv("ENV")
	defer func() {
		os.Setenv("NEXUSEDGE_DEV_MODE", origDevMode)
		os.Setenv("NEXUSEDGE_ENV", origEnv)
		os.Setenv("ENV", origGeneralEnv)
	}()

	// 1. DEV_MODE=true + ENV=development -> fixtures loaded
	os.Setenv("NEXUSEDGE_DEV_MODE", "true")
	os.Setenv("NEXUSEDGE_ENV", "development")
	authDev := auth.NewAuthenticator()
	if _, err := authDev.ValidateKey("dev-fixture-adminkey-mock-01"); err != nil {
		t.Errorf("expected dev fixture key to be loaded in development environment")
	}

	// 2. DEV_MODE=true + ENV=production -> fixtures NOT loaded
	os.Setenv("NEXUSEDGE_DEV_MODE", "true")
	os.Setenv("NEXUSEDGE_ENV", "production")
	authProd := auth.NewAuthenticator()
	if _, err := authProd.ValidateKey("dev-fixture-adminkey-mock-01"); err == nil {
		t.Errorf("dev fixture key MUST NOT be loaded in production environment")
	}

	// 3. DEV_MODE=true + ENV="" -> fixtures NOT loaded
	os.Setenv("NEXUSEDGE_DEV_MODE", "true")
	os.Setenv("NEXUSEDGE_ENV", "")
	os.Setenv("ENV", "")
	authEmptyEnv := auth.NewAuthenticator()
	if _, err := authEmptyEnv.ValidateKey("dev-fixture-adminkey-mock-01"); err == nil {
		t.Errorf("dev fixture key MUST NOT be loaded with empty environment")
	}

	// 4. DEV_MODE=false -> fixtures NOT loaded
	os.Setenv("NEXUSEDGE_DEV_MODE", "false")
	os.Setenv("NEXUSEDGE_ENV", "development")
	authNoDev := auth.NewAuthenticator()
	if _, err := authNoDev.ValidateKey("dev-fixture-adminkey-mock-01"); err == nil {
		t.Errorf("dev fixture key MUST NOT be loaded when DEV_MODE is false")
	}
}

