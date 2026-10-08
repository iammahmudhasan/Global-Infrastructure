package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"os"
	"strings"
	"sync"
)

type contextKey string

const (
	TenantContextKey  contextKey = "tenant_id"
	ProjectContextKey contextKey = "project_id"
	RoleContextKey    contextKey = "role"
)

type Role string

const (
	RoleTenant           Role = "TENANT"
	RolePlatformOperator Role = "PLATFORM_OPERATOR"
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
	Role      Role
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
	a.loadFromEnv()
	return a
}

func isExplicitDevEnvironment() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("NEXUSEDGE_ENV")))
	if env == "" {
		env = strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	}
	return env == "development" || env == "test"
}

// loadFromEnv loads API keys from NEXUSEDGE_API_KEYS (format: key:tenant_id:project_id[:role],...)
// or loads clearly labeled development mock keys if NEXUSEDGE_DEV_MODE is enabled in an explicit dev environment.
func (a *Authenticator) loadFromEnv() {
	rawKeys := os.Getenv("NEXUSEDGE_API_KEYS")
	if rawKeys != "" {
		for _, entry := range strings.Split(rawKeys, ",") {
			parts := strings.Split(strings.TrimSpace(entry), ":")
			if len(parts) == 4 {
				a.RegisterTenantWithRole(parts[0], parts[1], parts[2], Role(strings.ToUpper(parts[3])))
			} else if len(parts) == 3 {
				a.RegisterTenant(parts[0], parts[1], parts[2])
			}
		}
		return
	}

	// In explicit local development mode, register synthetic mock fixtures
	if os.Getenv("NEXUSEDGE_DEV_MODE") == "true" && isExplicitDevEnvironment() {
		a.RegisterTenantWithRole("dev-fixture-adminkey-mock-01", "tenant-system", "proj-core", RolePlatformOperator)
		a.RegisterTenantWithRole("dev-fixture-banking-mock-01", "tenant-cbr-banking", "proj-fintech-prod", RoleTenant)
	}
}

func (a *Authenticator) RegisterTenant(apiKey, tenantID, projectID string) {
	a.RegisterTenantWithRole(apiKey, tenantID, projectID, RoleTenant)
}

func (a *Authenticator) RegisterTenantWithRole(apiKey, tenantID, projectID string, role Role) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if role == "" {
		role = RoleTenant
	}
	a.tenants[apiKey] = &TenantRecord{
		TenantID:  tenantID,
		ProjectID: projectID,
		APIKey:    apiKey,
		Role:      role,
		Active:    true,
	}
}

// AuthorizeRole checks whether the authenticated identity has one of the allowed roles
func (a *Authenticator) AuthorizeRole(ctx context.Context, allowedRoles ...Role) bool {
	r, ok := ctx.Value(RoleContextKey).(Role)
	if !ok || r == "" {
		return false
	}
	for _, req := range allowedRoles {
		if r == req {
			return true
		}
	}
	return false
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
		ctx = context.WithValue(ctx, RoleContextKey, record.Role)

		next.ServeHTTP(w, r.WithContext(ctx))
	})
}
