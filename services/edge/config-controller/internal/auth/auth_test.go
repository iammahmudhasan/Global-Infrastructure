package auth_test

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/auth"
)

func TestAuthenticator_ValidateKey(t *testing.T) {
	a := auth.NewAuthenticator()
	a.RegisterTenant("test-key-123", "tenant-alpha", "proj-alpha", "proj-shared")

	// 1. Valid key
	record, err := a.ValidateKey("test-key-123")
	if err != nil {
		t.Fatalf("expected valid key, got error: %v", err)
	}
	if record.TenantID != "tenant-alpha" {
		t.Errorf("expected tenant-alpha, got %s", record.TenantID)
	}

	// 2. Empty key
	_, err = a.ValidateKey("")
	if err != auth.ErrMissingAuth {
		t.Errorf("expected ErrMissingAuth, got %v", err)
	}

	// 3. Invalid key
	_, err = a.ValidateKey("wrong-key")
	if err != auth.ErrInvalidAuth {
		t.Errorf("expected ErrInvalidAuth, got %v", err)
	}
}

func TestAuthenticator_Middleware(t *testing.T) {
	a := auth.NewAuthenticator()
	a.RegisterTenant("valid-key-alpha", "tenant-alpha", "proj-alpha")
	a.RegisterTenant("valid-key-beta", "tenant-beta", "proj-beta")

	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tc, ok := auth.FromContext(r.Context())
		if !ok || tc == nil {
			w.WriteHeader(http.StatusOK)
			w.Write([]byte("public"))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok:" + tc.TenantID))
	})

	mw := a.Middleware(dummyHandler)

	// Case 1: Public endpoint bypass
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("expected 200 for /healthz, got %d", w.Code)
	}

	// Case 2: Valid API key via X-API-Key
	req = httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	req.Header.Set("X-API-Key", "valid-key-alpha")
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "ok:tenant-alpha" {
		t.Errorf("expected 200 and ok:tenant-alpha, got %d and %s", w.Code, w.Body.String())
	}

	// Case 3: Valid API key via Bearer token
	req = httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	req.Header.Set("Authorization", "Bearer valid-key-beta")
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusOK || w.Body.String() != "ok:tenant-beta" {
		t.Errorf("expected 200 and ok:tenant-beta, got %d and %s", w.Code, w.Body.String())
	}

	// Case 4: Invalid API key
	req = httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	req.Header.Set("X-API-Key", "invalid-fake-key")
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 for invalid key, got %d", w.Code)
	}

	// Case 5: Tenant spoofing prevention (Valid key for alpha, but X-Tenant-ID says beta)
	req = httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	req.Header.Set("X-API-Key", "valid-key-alpha")
	req.Header.Set("X-Tenant-ID", "tenant-beta")
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden on tenant spoofing attempt, got %d", w.Code)
	}

	// Case 6: Attempting to assert X-Tenant-ID without credentials in dev mode
	req = httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	req.Header.Set("X-Tenant-ID", "tenant-banking-unauthorized")
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when asserting unverified X-Tenant-ID without key, got %d", w.Code)
	}

	// Case 7: Strict auth enforcement when NEXUSEDGE_ENFORCE_AUTH=true
	os.Setenv("NEXUSEDGE_ENFORCE_AUTH", "true")
	defer os.Unsetenv("NEXUSEDGE_ENFORCE_AUTH")

	req = httptest.NewRequest(http.MethodGet, "/v1/domains", nil)
	w = httptest.NewRecorder()
	mw.ServeHTTP(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Errorf("expected 401 when auth is enforced and credentials missing, got %d", w.Code)
	}
}

func TestAuthenticator_AuthorizeProject(t *testing.T) {
	a := auth.NewAuthenticator()
	a.RegisterTenant("key-tenant-x", "tenant-x", "proj-x", "proj-shared")

	// Create authenticated request context
	req := httptest.NewRequest(http.MethodGet, "/v1/projects", nil)
	req.Header.Set("X-API-Key", "key-tenant-x")

	var capturedCtx *http.Request
	mw := a.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCtx = r
		w.WriteHeader(http.StatusOK)
	}))

	w := httptest.NewRecorder()
	mw.ServeHTTP(w, req)

	if capturedCtx == nil {
		t.Fatalf("failed to capture request context")
	}

	// 1. Authorized project (primary)
	if !a.AuthorizeProject(capturedCtx.Context(), "proj-x") {
		t.Errorf("expected proj-x to be authorized for tenant-x")
	}

	// 2. Authorized project (extra allowed)
	if !a.AuthorizeProject(capturedCtx.Context(), "proj-shared") {
		t.Errorf("expected proj-shared to be authorized for tenant-x")
	}

	// 3. Unauthorized project
	if a.AuthorizeProject(capturedCtx.Context(), "proj-y") {
		t.Errorf("expected proj-y to be forbidden for tenant-x")
	}
}
