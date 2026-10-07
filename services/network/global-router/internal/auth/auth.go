package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"sync"
)

type contextKey string

const (
	TenantContextKey  contextKey = "tenant_id"
	ProjectContextKey contextKey = "project_id"
)

var (
	ErrMissingAuth   = errors.New("missing authorization header or api key")
	ErrInvalidAuth   = errors.New("invalid or expired credentials")
	ErrMissingTenant = errors.New("missing X-Tenant-ID header")
)

// TenantRecord represents an authenticated organizational identity
type TenantRecord struct {
	TenantID  string
	ProjectID string
	APIKey    string
	Active    bool
}

// Authenticator validates API keys and enforces tenant isolation (Rules 17, 20, 54, 55)
type Authenticator struct {
	mu      sync.RWMutex
	tenants map[string]*TenantRecord // Keyed by APIKey
}

func NewAuthenticator() *Authenticator {
	a := &Authenticator{
		tenants: make(map[string]*TenantRecord),
	}
	// Bootstrap default system tenant and enterprise test tenant
	a.RegisterTenant("nexusedge-secret-adminkey-2026", "tenant-system", "proj-core")
	a.RegisterTenant("bank-dhaka-livekey-9812", "tenant-cbr-banking", "proj-fintech-prod")
	a.RegisterTenant("global-ai-partner-key-4401", "tenant-ai-labs", "proj-reasoning")
	return a
}

func (a *Authenticator) RegisterTenant(apiKey, tenantID, projectID string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.tenants[apiKey] = &TenantRecord{
		TenantID:  tenantID,
		ProjectID: projectID,
		APIKey:    apiKey,
		Active:    true,
	}
}

// ValidateKey verifies API key in constant time to prevent timing attacks (Rule 17)
func (a *Authenticator) ValidateKey(providedKey string) (*TenantRecord, error) {
	if providedKey == "" {
		return nil, ErrMissingAuth
	}

	a.mu.RLock()
	defer a.mu.RUnlock()

	for key, record := range a.tenants {
		if subtle.ConstantTimeCompare([]byte(key), []byte(providedKey)) == 1 {
			if !record.Active {
				return nil, ErrInvalidAuth
			}
			return record, nil
		}
	}

	return nil, ErrInvalidAuth
}

// Middleware enforces authentication, extracts tenant context, and fails closed (Rule 88)
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bypass health endpoints
		if r.URL.Path == "/healthz" || r.URL.Path == "/readyz" {
			next.ServeHTTP(w, r)
			return
		}

		rawKey := r.Header.Get("X-API-Key")
		if rawKey == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				rawKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		record, err := a.ValidateKey(rawKey)
		if err != nil {
			http.Error(w, `{"error":"Unauthorized: invalid or missing credentials"}`, http.StatusUnauthorized)
			return
		}

		// Enforce Tenant ID header matches record to prevent spoofing (Rule 54)
		headerTenant := r.Header.Get("X-Tenant-ID")
		if headerTenant != "" && headerTenant != record.TenantID {
			http.Error(w, `{"error":"Forbidden: tenant ID mismatch"}`, http.StatusForbidden)
			return
		}

		ctx := context.WithValue(r.Context(), TenantContextKey, record.TenantID)
		ctx = context.WithValue(ctx, ProjectContextKey, record.ProjectID)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
