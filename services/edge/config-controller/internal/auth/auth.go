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
	TenantContextKey contextKey = "tenant_context"
)

var (
	ErrMissingAuth    = errors.New("missing authorization header or api key")
	ErrInvalidAuth    = errors.New("invalid or expired credentials")
	ErrTenantMismatch = errors.New("forbidden: tenant ID mismatch")
	ErrUnauthorized   = errors.New("unauthorized: access denied to requested resource")
)

type Role string

const (
	RoleTenant           Role = "TENANT"
	RolePlatformOperator Role = "PLATFORM_OPERATOR"
	RoleEdgeNode         Role = "EDGE_NODE"
)

func isExplicitDevEnvironment() bool {
	env := strings.ToLower(strings.TrimSpace(os.Getenv("NEXUSEDGE_ENV")))
	if env == "" {
		env = strings.ToLower(strings.TrimSpace(os.Getenv("ENV")))
	}
	return env == "development" || env == "test"
}

// TenantRecord represents an authenticated organizational identity
type TenantRecord struct {
	TenantID        string
	ProjectID       string
	Role            Role
	NodeID          string
	APIKey          string
	AllowedProjects map[string]bool
	Active          bool
}

// TenantContext carries authenticated tenant metadata in request context
type TenantContext struct {
	TenantID        string
	ProjectID       string
	Role            Role
	NodeID          string
	AllowedProjects map[string]bool
	IsDevBypass     bool
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

func (a *Authenticator) loadFromEnv() {
	rawKeys := os.Getenv("NEXUSEDGE_API_KEYS")
	if rawKeys != "" {
		for _, entry := range strings.Split(rawKeys, ",") {
			parts := strings.Split(strings.TrimSpace(entry), ":")
			if len(parts) >= 3 {
				role := RoleTenant
				nodeID := ""
				extra := []string{}
				if len(parts) > 3 {
					// Format: key:tenant:proj:role:extraProj1/nodeID...
					switch strings.ToUpper(parts[3]) {
					case "PLATFORM_OPERATOR", "OPERATOR", "ADMIN":
						role = RolePlatformOperator
					case "EDGE_NODE", "NODE":
						role = RoleEdgeNode
						if len(parts) > 4 {
							nodeID = parts[4]
						}
					default:
						extra = append(extra, parts[3])
					}
					if role != RoleEdgeNode && len(parts) > 4 {
						extra = append(extra, parts[4:]...)
					}
				}
				if role == RoleEdgeNode && nodeID != "" {
					a.RegisterNode(parts[0], parts[1], parts[2], nodeID)
				} else {
					a.RegisterTenantWithRole(parts[0], parts[1], parts[2], role, extra...)
				}
			}
		}
		return
	}

	// In explicit local development mode, register synthetic mock fixtures (positive allowlist)
	if os.Getenv("NEXUSEDGE_DEV_MODE") == "true" && isExplicitDevEnvironment() {
		a.RegisterTenantWithRole("dev-fixture-key-01", "tenant-system", "proj-core", RolePlatformOperator, "prj-enterprise-01")
		a.RegisterTenantWithRole("dev-fixture-key-banking", "tenant-cbr-banking", "proj-fintech-prod", RoleTenant)
		a.RegisterNode("dev-fixture-key-node", "tenant-edge-nodes", "proj-infra", "edge-node-01")
	}
}

func (a *Authenticator) RegisterTenant(apiKey, tenantID, projectID string, extraProjects ...string) {
	a.RegisterTenantWithRole(apiKey, tenantID, projectID, RoleTenant, extraProjects...)
}

func (a *Authenticator) RegisterTenantWithRole(apiKey, tenantID, projectID string, role Role, extraProjects ...string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	allowed := make(map[string]bool)
	allowed[projectID] = true
	for _, p := range extraProjects {
		if p != "" {
			allowed[p] = true
		}
	}

	a.tenants[apiKey] = &TenantRecord{
		TenantID:        tenantID,
		ProjectID:       projectID,
		Role:            role,
		APIKey:          apiKey,
		AllowedProjects: allowed,
		Active:          true,
	}
}

func (a *Authenticator) RegisterNode(apiKey, tenantID, projectID, nodeID string) {
	a.mu.Lock()
	defer a.mu.Unlock()

	allowed := make(map[string]bool)
	allowed[projectID] = true

	a.tenants[apiKey] = &TenantRecord{
		TenantID:        tenantID,
		ProjectID:       projectID,
		Role:            RoleEdgeNode,
		NodeID:          nodeID,
		APIKey:          apiKey,
		AllowedProjects: allowed,
		Active:          true,
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

// AuthorizeProject verifies that the authenticated tenant has ownership of projectID (Rules 54, 55)
func (a *Authenticator) AuthorizeProject(ctx context.Context, projectID string) bool {
	tc, ok := ctx.Value(TenantContextKey).(*TenantContext)
	if !ok || tc == nil {
		return false
	}
	if tc.IsDevBypass {
		return true
	}
	if tc.AllowedProjects["*"] {
		return true
	}
	return tc.AllowedProjects[projectID]
}

// AuthorizeRole verifies that the authenticated caller has one of the required roles (P0 RBAC boundary)
func (a *Authenticator) AuthorizeRole(ctx context.Context, requiredRoles ...Role) bool {
	tc, ok := ctx.Value(TenantContextKey).(*TenantContext)
	if !ok || tc == nil {
		return false
	}
	if tc.IsDevBypass {
		return true
	}
	for _, r := range requiredRoles {
		if tc.Role == r {
			return true
		}
	}
	return false
}

// FromContext extracts the TenantContext from request context
func FromContext(ctx context.Context) (*TenantContext, bool) {
	tc, ok := ctx.Value(TenantContextKey).(*TenantContext)
	return tc, ok && tc != nil
}

// Middleware enforces authentication, tenant context extraction, and fails closed (Rule 88)
func (a *Authenticator) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 1. Bypass public health and challenge verification endpoints
		path := r.URL.Path
		if path == "/healthz" || path == "/readyz" || strings.HasPrefix(path, "/.well-known/acme-challenge/") {
			next.ServeHTTP(w, r)
			return
		}

		// 2. Extract API Key from headers
		rawKey := r.Header.Get("X-API-Key")
		if rawKey == "" {
			authHeader := r.Header.Get("Authorization")
			if strings.HasPrefix(authHeader, "Bearer ") {
				rawKey = strings.TrimPrefix(authHeader, "Bearer ")
			}
		}

		if rawKey != "" {
			record, err := a.ValidateKey(rawKey)
			if err != nil {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(`{"error":"Unauthorized: invalid or expired credentials"}`))
				return
			}

			// Enforce Tenant ID header matches authenticated record to prevent spoofing (Rule 54)
			headerTenant := r.Header.Get("X-Tenant-ID")
			if headerTenant != "" && headerTenant != record.TenantID {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusForbidden)
				w.Write([]byte(`{"error":"Forbidden: tenant ID mismatch"}`))
				return
			}

			tc := &TenantContext{
				TenantID:        record.TenantID,
				ProjectID:       record.ProjectID,
				Role:            record.Role,
				NodeID:          record.NodeID,
				AllowedProjects: record.AllowedProjects,
				IsDevBypass:     false,
			}
			ctx := context.WithValue(r.Context(), TenantContextKey, tc)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}

		// 3. Reject unverified tenant header assertion without credentials
		claimedTenant := r.Header.Get("X-Tenant-ID")
		if claimedTenant != "" && claimedTenant != "dev-tenant" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Unauthorized: API key required to authenticate asserted tenant identity"}`))
			return
		}

		// 4. Reject unauthenticated requests if auth is explicitly enforced or in production
		if os.Getenv("NEXUSEDGE_ENFORCE_AUTH") == "true" ||
			os.Getenv("NEXUSEDGE_ENV") == "production" ||
			os.Getenv("ENV") == "production" {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"Unauthorized: missing required API key or credentials"}`))
			return
		}

		// 5. Strict Dev Bypass Gate (Finding 3): Only permitted when NEXUSEDGE_DEV_MODE=true AND in explicit dev/test environment
		if os.Getenv("NEXUSEDGE_DEV_MODE") == "true" && isExplicitDevEnvironment() {
			tc := &TenantContext{
				TenantID:        "dev-tenant",
				ProjectID:       "proj-default",
				Role:            RolePlatformOperator, // Permits testbed execution in local dev mode
				AllowedProjects: map[string]bool{"*": true},
				IsDevBypass:     true,
			}
			ctx := context.WithValue(r.Context(), TenantContextKey, tc)
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}


		// 6. Fail closed in all other environments (staging, preview, CI)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":"Unauthorized: missing required API key or credentials"}`))
	})
}
