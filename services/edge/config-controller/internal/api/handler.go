package api

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/analytics"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/auth"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/cache"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/certificate"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/health"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/pop"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/security"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

type APIHandler struct {
	store           *store.Store
	service         *onboarding.DomainService
	compiler        *compiler.Compiler
	wafEngine       *security.WAFEngine
	cacheEngine     *cache.CacheEngine
	monitor         *health.Monitor
	smartRouter     *health.SmartRouter
	certManager     *certificate.Manager
	analyticsEngine *analytics.Engine
	popManager      *pop.Manager
	authenticator   *auth.Authenticator
	handlerChain    http.Handler
	mux             *http.ServeMux
}

func NewAPIHandler(s *store.Store, svc *onboarding.DomainService, c *compiler.Compiler) *APIHandler {
	authenticator := auth.NewAuthenticator()
	mux := http.NewServeMux()
	h := &APIHandler{
		store:           s,
		service:         svc,
		compiler:        c,
		wafEngine:       security.NewWAFEngine(),
		cacheEngine:     cache.NewCacheEngine(100000),
		monitor:         health.NewMonitor(),
		smartRouter:     health.NewSmartRouter(),
		certManager:     certificate.NewManager(s),
		analyticsEngine: analytics.NewEngine(),
		popManager:      pop.NewManager(),
		authenticator:   authenticator,
		mux:             mux,
		handlerChain:    authenticator.Middleware(mux),
	}
	h.registerRoutes()
	return h
}

// SetAuthenticator allows overriding or updating the authenticator (e.g. for testing)
func (h *APIHandler) SetAuthenticator(a *auth.Authenticator) {
	h.authenticator = a
	h.handlerChain = a.Middleware(h.mux)
}

func (h *APIHandler) Authenticator() *auth.Authenticator {
	return h.authenticator
}

func (h *APIHandler) PoPManager() *pop.Manager {
	return h.popManager
}

func (h *APIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Global 1 MiB body size cap prevents unbounded memory exhaustion across all control plane JSON endpoints
	const maxControlPlaneBody = 1 << 20 // 1 MiB
	r.Body = http.MaxBytesReader(w, r.Body, maxControlPlaneBody)

	origin := r.Header.Get("Origin")
	allowedOrigin := h.resolveAllowedOrigin(origin)
	if allowedOrigin != "" {
		w.Header().Set("Access-Control-Allow-Origin", allowedOrigin)
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID, X-Tenant-ID, X-API-Key")
		w.Header().Set("Vary", "Origin")
	}

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	h.handlerChain.ServeHTTP(w, r)
}

// resolveAllowedOrigin implements strict fail-closed CORS defaults (P1 Security).
// Never returns a blanket wildcard "*" unless explicitly configured in allowed origins.
func (h *APIHandler) resolveAllowedOrigin(origin string) string {
	if origin == "" {
		return ""
	}
	allowedList := os.Getenv("NEXUSEDGE_ALLOWED_ORIGINS")
	if allowedList != "" {
		for _, o := range strings.Split(allowedList, ",") {
			if strings.TrimSpace(o) == origin {
				return origin
			}
		}
		return ""
	}
	// In development / prototype mode, permit localhost origins only. Fail closed for external origins.
	if os.Getenv("NEXUSEDGE_ENV") != "production" && os.Getenv("ENV") != "production" {
		if strings.HasPrefix(origin, "http://localhost:") ||
			strings.HasPrefix(origin, "https://localhost:") ||
			strings.HasPrefix(origin, "http://127.0.0.1:") ||
			strings.HasPrefix(origin, "https://127.0.0.1:") ||
			origin == "http://localhost" ||
			origin == "https://localhost" ||
			origin == "http://127.0.0.1" ||
			origin == "https://127.0.0.1" {
			return origin
		}
	}
	return ""
}

func (h *APIHandler) registerRoutes() {
	h.mux.HandleFunc("/healthz", h.handleHealthz)
	h.mux.HandleFunc("/v1/projects/", h.handleProjectsRoute)
	h.mux.HandleFunc("/v1/domains/", h.handleDomainsRoute)
	h.mux.HandleFunc("/v1/pools/", h.handlePoolsRoute)
	h.mux.HandleFunc("/v1/edge/envoy-config", h.handleEnvoyConfig)
	h.mux.HandleFunc("/v1/edge/topologies", h.handleTopologies)
	h.mux.HandleFunc("/v1/edge/evaluate", h.handleEvaluate)
	h.mux.HandleFunc("/v1/edge/cache-lookup", h.handleCacheLookup)
	h.mux.HandleFunc("/.well-known/acme-challenge/", h.handleACMEChallenge)
	h.mux.HandleFunc("/v1/edge/acme/validate", h.handleACMEValidate)
	h.mux.HandleFunc("/v1/edge/telemetry", h.handleEdgeTelemetry)
	h.mux.HandleFunc("/v1/edge/pops", h.handleListPoPs)
	h.mux.HandleFunc("/v1/edge/pops/", h.handlePoPsRoute)
	h.mux.HandleFunc("/v1/edge/routing/", h.handleRoutingRoute)
}

func (h *APIHandler) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"status":  "healthy",
		"service": "nexusedge-config-controller",
		"version": "1.0.0",
	})
}

// /v1/projects/{project_id}/domains
func (h *APIHandler) handleProjectsRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/projects/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 || parts[1] != "domains" {
		writeError(w, http.StatusNotFound, "route not found")
		return
	}

	projectID := parts[0]
	if projectID == "" {
		writeError(w, http.StatusBadRequest, "project_id is required")
		return
	}

	// Verify authenticated tenant has access to this project (Rules 54, 55)
	if !h.authenticator.AuthorizeProject(r.Context(), projectID) {
		writeError(w, http.StatusForbidden, "forbidden: caller not authorized for project "+projectID)
		return
	}

	switch r.Method {
	case http.MethodPost:
		h.handleCreateDomain(w, r, projectID)
	case http.MethodGet:
		h.handleListDomains(w, r, projectID)
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *APIHandler) handleCreateDomain(w http.ResponseWriter, r *http.Request, projectID string) {
	var req onboarding.OnboardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: must be valid JSON")
		return
	}
	req.ProjectID = projectID

	res, err := h.service.OnboardDomain(req)
	if err != nil {
		if errors.Is(err, store.ErrProjectQuotaExceeded) || strings.Contains(err.Error(), "quota exceeded") {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}
		if strings.Contains(err.Error(), "already exists") {
			writeError(w, http.StatusConflict, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, res)
}

func (h *APIHandler) handleListDomains(w http.ResponseWriter, r *http.Request, projectID string) {
	domains := h.store.ListDomainsByProject(projectID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domains": domains,
		"count":   len(domains),
	})
}

// /v1/domains/{domain_id}[/verify, /origins, /waf/rules, /rate-limits, /security/events, /cache/...]
func (h *APIHandler) handleDomainsRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/domains/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "domain_id is required")
		return
	}

	domainID := parts[0]

	// Enforce IDOR protection: lookup domain and verify project ownership against authenticated tenant (Rules 54, 55)
	domain, err := h.store.GetDomain(domainID)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	if !h.authenticator.AuthorizeProject(r.Context(), domain.ProjectID) {
		writeError(w, http.StatusForbidden, "forbidden: caller not authorized for domain "+domainID)
		return
	}

	if len(parts) == 1 {
		// /v1/domains/{domain_id}
		switch r.Method {
		case http.MethodGet:
			writeJSON(w, http.StatusOK, domain)
			return
		case http.MethodDelete:
			if err := h.store.DeleteDomain(domainID); err != nil {
				writeError(w, http.StatusInternalServerError, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"status":    "deleted",
				"domain_id": domainID,
			})
			return
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
	}

	action := parts[1]
	switch action {
	case "verify":
		// POST /v1/domains/{domain_id}/verify
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		h.handleVerifyDomain(w, r, domainID)
	case "origins":
		// POST or GET /v1/domains/{domain_id}/origins
		switch r.Method {
		case http.MethodPost:
			h.handleAddOrigin(w, r, domainID)
		case http.MethodGet:
			h.handleListOrigins(w, r, domainID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case "waf":
		// /v1/domains/{domain_id}/waf/rules[/{rule_id}]
		if len(parts) >= 3 && parts[2] == "rules" {
			if len(parts) == 4 && r.Method == http.MethodDelete {
				h.handleDeleteWAFRule(w, r, domainID, parts[3])
				return
			}
			switch r.Method {
			case http.MethodPost:
				h.handleAddWAFRule(w, r, domainID)
			case http.MethodGet:
				h.handleListWAFRules(w, r, domainID)
			default:
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			}
			return
		}
		writeError(w, http.StatusNotFound, "unknown WAF endpoint")
	case "rate-limits":
		// POST or GET /v1/domains/{domain_id}/rate-limits
		switch r.Method {
		case http.MethodPost:
			h.handleSetRateLimits(w, r, domainID)
		case http.MethodGet:
			h.handleGetRateLimits(w, r, domainID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
	case "security":
		// GET /v1/domains/{domain_id}/security/events
		if len(parts) >= 3 && parts[2] == "events" {
			if r.Method == http.MethodGet {
				h.handleGetSecurityEvents(w, r, domainID)
				return
			}
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		writeError(w, http.StatusNotFound, "unknown security endpoint")
	case "cache":
		// /v1/domains/{domain_id}/cache/[policy, rules, purge]
		if len(parts) >= 3 {
			switch parts[2] {
			case "policy":
				if r.Method == http.MethodGet {
					h.handleGetCachePolicy(w, r, domainID)
					return
				}
				if r.Method == http.MethodPatch || r.Method == http.MethodPut {
					h.handleUpdateCachePolicy(w, r, domainID)
					return
				}
			case "rules":
				if len(parts) == 4 && r.Method == http.MethodDelete {
					h.handleDeleteCacheRule(w, r, domainID, parts[3])
					return
				}
				if r.Method == http.MethodPost {
					h.handleAddCacheRule(w, r, domainID)
					return
				}
				if r.Method == http.MethodGet {
					h.handleListCacheRules(w, r, domainID)
					return
				}
			case "purge":
				if r.Method == http.MethodPost {
					h.handlePurgeCache(w, r, domainID)
					return
				}
			}
		}
		writeError(w, http.StatusNotFound, "unknown cache endpoint")
	case "certificates":
		h.handleCertificatesRoute(w, r, domainID, parts)
		return
	case "tls":
		h.handleTLSSettingsRoute(w, r, domainID)
		return
	case "analytics":
		h.handleAnalyticsRoute(w, r, domainID, parts)
		return
	case "billing":
		h.handleBillingRoute(w, r, domainID, parts)
		return
	default:
		writeError(w, http.StatusNotFound, "unknown domain action")
	}
}

type CertificateResponse struct {
	ID                string                  `json:"id"`
	DomainID          string                  `json:"domain_id"`
	Domains           []string                `json:"domains"`
	Status            model.CertificateStatus `json:"status"`
	KeyType           model.KeyType           `json:"key_type"`
	CertPEM           string                  `json:"cert_pem"`
	Issuer            string                  `json:"issuer"`
	IssuedAt          time.Time               `json:"issued_at"`
	ExpiresAt         time.Time               `json:"expires_at"`
	AutoRenew         bool                    `json:"auto_renew"`
	FingerprintSHA256 string                  `json:"fingerprint_sha256"`
	SerialNumber      string                  `json:"serial_number"`
}

func publicCertificate(cert *model.Certificate) *CertificateResponse {
	if cert == nil {
		return nil
	}
	return &CertificateResponse{
		ID:                cert.ID,
		DomainID:          cert.DomainID,
		Domains:           cert.Domains,
		Status:            cert.Status,
		KeyType:           cert.KeyType,
		CertPEM:           cert.CertPEM,
		Issuer:            cert.Issuer,
		IssuedAt:          cert.IssuedAt,
		ExpiresAt:         cert.ExpiresAt,
		AutoRenew:         cert.AutoRenew,
		FingerprintSHA256: cert.FingerprintSHA256,
		SerialNumber:      cert.SerialNumber,
	}
}

func (h *APIHandler) handleCertificatesRoute(w http.ResponseWriter, r *http.Request, domainID string, parts []string) {
	if len(parts) == 2 {
		if r.Method == http.MethodGet {
			cert := h.store.GetCertificate(domainID)
			if cert == nil {
				writeError(w, http.StatusNotFound, "no certificate found for domain")
				return
			}
			writeJSON(w, http.StatusOK, publicCertificate(cert))
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	action := parts[2]
	switch action {
	case "order":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		cert, challenge, err := h.certManager.OrderCertificate(domainID)
		if err != nil {
			if errors.Is(err, certificate.ErrRateLimitExceeded) {
				writeError(w, http.StatusTooManyRequests, err.Error())
				return
			}
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]interface{}{
			"certificate": publicCertificate(cert),
			"challenge":   challenge,
		})

	case "current":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		cert := h.store.GetCertificate(domainID)
		if cert == nil {
			writeError(w, http.StatusNotFound, "no active certificate for domain")
			return
		}
		daysRemaining := 0
		if !cert.ExpiresAt.IsZero() {
			daysRemaining = int(time.Until(cert.ExpiresAt).Hours() / 24)
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"certificate":           publicCertificate(cert),
			"is_expiring_soon":      h.certManager.IsExpiringSoon(cert),
			"days_until_expiration": daysRemaining,
		})

	case "renew":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		renewedCert, err := h.certManager.RenewCertificate(domainID)
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to renew certificate: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, publicCertificate(renewedCert))

	default:
		writeError(w, http.StatusNotFound, "unknown certificate action: "+action)
	}
}

func (h *APIHandler) handleTLSSettingsRoute(w http.ResponseWriter, r *http.Request, domainID string) {
	switch r.Method {
	case http.MethodGet:
		settings := h.store.GetTLSSettings(domainID)
		writeJSON(w, http.StatusOK, settings)

	case http.MethodPost, http.MethodPut, http.MethodPatch:
		var settings model.TLSSettings
		if err := json.NewDecoder(r.Body).Decode(&settings); err != nil {
			writeError(w, http.StatusBadRequest, "invalid tls settings payload")
			return
		}
		switch settings.MinTLSVersion {
		case "", "TLSv1.2", "TLSv1.3":
		default:
			writeError(w, http.StatusBadRequest, "min_tls_version must be TLSv1.2 or TLSv1.3")
			return
		}
		if settings.MinTLSVersion == "" {
			settings.MinTLSVersion = "TLSv1.2"
		}
		h.store.SaveTLSSettings(domainID, &settings)
		writeJSON(w, http.StatusOK, settings)

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *APIHandler) handleACMEChallenge(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	token := strings.TrimPrefix(r.URL.Path, "/.well-known/acme-challenge/")
	if token == "" {
		writeError(w, http.StatusBadRequest, "challenge token required")
		return
	}

	challenge := h.store.GetACMEChallengeByToken(token)
	if challenge == nil {
		writeError(w, http.StatusNotFound, "acme challenge not found or expired")
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(challenge.KeyAuthorization))
}

func (h *APIHandler) handleACMEValidate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		writeError(w, http.StatusBadRequest, "valid challenge token is required")
		return
	}

	cert, err := h.certManager.ValidateAndIssueCertificate(req.Token)
	if err != nil {
		if errors.Is(err, certificate.ErrRateLimitExceeded) {
			writeError(w, http.StatusTooManyRequests, err.Error())
			return
		}
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":      "VALIDATED",
		"certificate": cert,
	})
}

// /v1/pools/{pool_id}[/health-monitor, /health, /probe, /route]
func (h *APIHandler) handlePoolsRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/pools/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "pool_id is required")
		return
	}

	poolID := parts[0]
	pool, err := h.store.GetOriginPool(poolID)
	if err != nil {
		writeError(w, http.StatusNotFound, "origin pool not found")
		return
	}

	// Verify project ownership of pool against authenticated tenant (Rules 54, 55 - IDOR Defense)
	if !h.authenticator.AuthorizeProject(r.Context(), pool.ProjectID) {
		writeError(w, http.StatusForbidden, "forbidden: caller not authorized for pool "+poolID)
		return
	}

	if len(parts) == 1 {
		writeJSON(w, http.StatusOK, pool)
		return
	}

	action := parts[1]
	switch action {
	case "health-monitor":
		if r.Method == http.MethodPost {
			h.handleSetHealthMonitor(w, r, pool)
			return
		}
		if r.Method == http.MethodGet {
			h.handleGetHealthMonitor(w, r, pool)
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	case "health":
		if r.Method == http.MethodGet {
			h.handleGetPoolHealth(w, r, pool)
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	case "probe":
		if r.Method == http.MethodPost {
			h.handleProbePool(w, r, pool)
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	case "route":
		if r.Method == http.MethodPost {
			h.handleSmartRoute(w, r, pool)
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	default:
		writeError(w, http.StatusNotFound, "unknown pool action")
	}
}

func (h *APIHandler) handleSetHealthMonitor(w http.ResponseWriter, r *http.Request, pool *model.OriginPool) {
	var hm model.HealthMonitor
	if err := json.NewDecoder(r.Body).Decode(&hm); err != nil {
		writeError(w, http.StatusBadRequest, "invalid health monitor payload")
		return
	}

	hm.ID = "hm-" + generateHex(4)
	hm.PoolID = pool.ID
	switch hm.Protocol {
	case "", model.HealthCheckProtocolHTTP, model.HealthCheckProtocolHTTPS:
	default:
		writeError(w, http.StatusBadRequest, "health monitor protocol must be HTTP or HTTPS")
		return
	}
	if hm.Protocol == "" {
		hm.Protocol = model.HealthCheckProtocolHTTP
	}

	if hm.Path == "" {
		hm.Path = "/healthz"
	}
	if len(hm.Path) > 1024 || !strings.HasPrefix(hm.Path, "/") || strings.ContainsAny(hm.Path, "\r\n\t") {
		writeError(w, http.StatusBadRequest, "health check path must be a valid path starting with / (max 1024 characters, no control characters)")
		return
	}

	// Bounds validation (Finding 6)
	if hm.IntervalSeconds == 0 {
		hm.IntervalSeconds = 10
	} else if hm.IntervalSeconds < 1 || hm.IntervalSeconds > 3600 {
		writeError(w, http.StatusBadRequest, "interval_seconds must be between 1 and 3600 seconds")
		return
	}

	if hm.TimeoutSeconds == 0 {
		hm.TimeoutSeconds = 2
	} else if hm.TimeoutSeconds < 1 || hm.TimeoutSeconds > 60 {
		writeError(w, http.StatusBadRequest, "timeout_seconds must be between 1 and 60 seconds")
		return
	}

	if hm.TimeoutSeconds > hm.IntervalSeconds {
		writeError(w, http.StatusBadRequest, "timeout_seconds cannot exceed interval_seconds")
		return
	}

	if hm.HealthyThreshold == 0 {
		hm.HealthyThreshold = 2
	} else if hm.HealthyThreshold < 1 || hm.HealthyThreshold > 10 {
		writeError(w, http.StatusBadRequest, "healthy_threshold must be between 1 and 10")
		return
	}

	if hm.UnhealthyThreshold == 0 {
		hm.UnhealthyThreshold = 3
	} else if hm.UnhealthyThreshold < 1 || hm.UnhealthyThreshold > 10 {
		writeError(w, http.StatusBadRequest, "unhealthy_threshold must be between 1 and 10")
		return
	}

	if len(hm.ExpectedStatusCodes) == 0 {
		hm.ExpectedStatusCodes = []int{200}
	} else {
		for _, code := range hm.ExpectedStatusCodes {
			if code < 100 || code > 599 {
				writeError(w, http.StatusBadRequest, "expected_status_codes must be valid HTTP status codes between 100 and 599")
				return
			}
		}
	}

	h.store.SaveHealthMonitor(&hm)
	writeJSON(w, http.StatusCreated, hm)
}

func (h *APIHandler) handleGetHealthMonitor(w http.ResponseWriter, r *http.Request, pool *model.OriginPool) {
	hm := h.store.GetHealthMonitor(pool.ID)
	if hm == nil {
		writeError(w, http.StatusNotFound, "health monitor not configured for this pool")
		return
	}
	writeJSON(w, http.StatusOK, hm)
}

func (h *APIHandler) handleGetPoolHealth(w http.ResponseWriter, r *http.Request, pool *model.OriginPool) {
	states := h.store.ListPoolHealthStates(pool.ID)
	healthyCount := 0
	for _, st := range states {
		if st.Healthy {
			healthyCount++
		}
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pool_id":           pool.ID,
		"total_endpoints":   len(pool.Origins),
		"healthy_endpoints": healthyCount,
		"origins":           states,
		"endpoints":         states,
		"count":             len(states),
	})
}

func (h *APIHandler) handleProbePool(w http.ResponseWriter, r *http.Request, pool *model.OriginPool) {
	hm := h.store.GetHealthMonitor(pool.ID)
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := make([]*model.OriginEndpointState, 0, len(pool.Origins))

	// Finding 6 Fix 2: Limit active probe goroutine fanout to avoid socket/network starvation
	const maxProbeConcurrency = 32
	sem := make(chan struct{}, maxProbeConcurrency)

	for i := range pool.Origins {
		orig := pool.Origins[i]
		wg.Add(1)
		go func(o model.Origin) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			current := h.store.GetOriginHealthState(o.ID)
			newState := h.monitor.ProbeEndpoint(r.Context(), &o, hm, current)
			h.store.SaveOriginHealthState(newState)

			mu.Lock()
			results = append(results, newState)
			mu.Unlock()
		}(orig)
	}
	wg.Wait()

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"pool_id": pool.ID,
		"probed":  len(results),
		"results": results,
	})
}

func (h *APIHandler) handleSmartRoute(w http.ResponseWriter, r *http.Request, pool *model.OriginPool) {
	states := h.store.ListPoolHealthStates(pool.ID)
	decision, err := h.smartRouter.SelectOptimalOrigin(pool, states)
	if err != nil {
		writeError(w, http.StatusServiceUnavailable, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, decision)
}

func (h *APIHandler) handleGetDomain(w http.ResponseWriter, r *http.Request, domainID string) {
	domain, err := h.store.GetDomain(domainID)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	writeJSON(w, http.StatusOK, domain)
}

func (h *APIHandler) handleVerifyDomain(w http.ResponseWriter, r *http.Request, domainID string) {
	domain, err := h.service.VerifyDomain(domainID)
	if err != nil {
		if errors.Is(err, store.ErrNotFound) {
			writeError(w, http.StatusNotFound, "domain not found")
			return
		}
		writeError(w, http.StatusUnprocessableEntity, "domain verification failed: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "verified",
		"domain_id": domain.ID,
		"hostname":  domain.Hostname,
		"state":     domain.Status,
		"message":   "domain verified successfully; active on edge proxy",
	})
}

type AddOriginRequest struct {
	Address  string `json:"address"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
	Weight   int    `json:"weight"`
}

func (h *APIHandler) handleAddOrigin(w http.ResponseWriter, r *http.Request, domainID string) {
	routes := h.store.GetRoutes(domainID)
	if len(routes) == 0 {
		writeError(w, http.StatusNotFound, "no route/pool found for domain")
		return
	}

	pool, err := h.store.GetOriginPool(routes[0].PoolID)
	if err != nil {
		writeError(w, http.StatusNotFound, "origin pool not found")
		return
	}
	if len(pool.Origins) >= store.MaxOriginsPerPool {
		writeError(w, http.StatusConflict, "origin pool limit reached (max 256)")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	var req AddOriginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Address == "" {
		writeError(w, http.StatusBadRequest, "origin address is required")
		return
	}
	if err := onboarding.ValidateOriginAddress(req.Address); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.Port < 1 || req.Port > 65535 {
		writeError(w, http.StatusBadRequest, "origin port must be between 1 and 65535")
		return
	}
	if req.Protocol == "" {
		req.Protocol = "HTTPS"
	}
	req.Protocol = strings.ToUpper(strings.TrimSpace(req.Protocol))
	switch req.Protocol {
	case "HTTP", "HTTPS":
	default:
		writeError(w, http.StatusBadRequest, "origin protocol must be HTTP or HTTPS")
		return
	}
	if req.Weight == 0 {
		req.Weight = 100
	}

	originID := "orig-" + generateHex(4)
	origin := &model.Origin{
		ID:       originID,
		PoolID:   routes[0].PoolID,
		Address:  req.Address,
		Port:     req.Port,
		Protocol: model.Protocol(req.Protocol),
		Weight:   req.Weight,
		Healthy:  true,
	}

	if err := h.store.AddOrigin(origin); err != nil {
		if errors.Is(err, store.ErrOriginPoolFull) {
			writeError(w, http.StatusConflict, "origin pool limit reached (max 256)")
			return
		}
		if errors.Is(err, store.ErrMixedOriginProtocols) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, origin)
}

func (h *APIHandler) handleListOrigins(w http.ResponseWriter, r *http.Request, domainID string) {
	routes := h.store.GetRoutes(domainID)
	if len(routes) == 0 {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}
	pool, err := h.store.GetOriginPool(routes[0].PoolID)
	if err != nil {
		writeError(w, http.StatusNotFound, "origin pool not found")
		return
	}
	writeJSON(w, http.StatusOK, pool.Origins)
}

// POST /v1/domains/{domain_id}/waf/rules
func (h *APIHandler) handleAddWAFRule(w http.ResponseWriter, r *http.Request, domainID string) {
	var rule model.WAFRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid WAF rule payload")
		return
	}

	if rule.Name == "" || rule.Pattern == "" {
		writeError(w, http.StatusBadRequest, "name and pattern are required")
		return
	}
	if rule.Action == "" {
		rule.Action = model.WAFActionBlock
	}
	if rule.MatchType == "" {
		rule.MatchType = model.WAFMatchPathPrefix
	}
	rule.ID = "waf-rule-" + generateHex(4)
	rule.DomainID = domainID
	rule.Enabled = true

	if err := h.store.AddWAFRule(domainID, rule); err != nil {
		if errors.Is(err, store.ErrRuleLimitExceeded) {
			writeError(w, http.StatusConflict, "waf rule limit reached for domain (max 1000)")
			return
		}
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, rule)
}

// GET /v1/domains/{domain_id}/waf/rules
func (h *APIHandler) handleListWAFRules(w http.ResponseWriter, r *http.Request, domainID string) {
	rules := h.store.GetWAFRules(domainID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domain_id": domainID,
		"rules":     rules,
		"count":     len(rules),
	})
}

// DELETE /v1/domains/{domain_id}/waf/rules/{rule_id}
func (h *APIHandler) handleDeleteWAFRule(w http.ResponseWriter, r *http.Request, domainID, ruleID string) {
	if err := h.store.DeleteWAFRule(domainID, ruleID); err != nil {
		writeError(w, http.StatusNotFound, "rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "WAF rule deleted successfully",
		"rule_id": ruleID,
	})
}

// POST /v1/domains/{domain_id}/rate-limits
func (h *APIHandler) handleSetRateLimits(w http.ResponseWriter, r *http.Request, domainID string) {
	var body struct {
		Rules []model.RateLimitRule `json:"rules"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, http.StatusBadRequest, "invalid rate limits payload")
		return
	}

	// Finding 7: Validate rate limit rule cardinality per domain
	if len(body.Rules) > store.MaxRateLimitRulesPerDomain {
		writeError(w, http.StatusConflict, "rate limit rule limit reached for domain (max 500)")
		return
	}

	for i := range body.Rules {
		rule := &body.Rules[i]
		rule.ID = "rl-" + generateHex(4)
		rule.DomainID = domainID
		rule.Enabled = true

		// Rule parameter validation (Finding 7)
		if rule.RequestsPerMinute < 1 || rule.RequestsPerMinute > 10_000_000 {
			writeError(w, http.StatusBadRequest, "requests_per_minute must be between 1 and 10,000,000")
			return
		}
		if rule.BurstSize < 0 || rule.BurstSize > 1_000_000 {
			writeError(w, http.StatusBadRequest, "burst_size must be between 0 and 1,000,000")
			return
		}

		if rule.KeyType == "" {
			rule.KeyType = "CLIENT_IP"
		}
		switch rule.KeyType {
		case "CLIENT_IP":
		case "HEADER":
			if strings.TrimSpace(rule.HeaderName) == "" {
				writeError(w, http.StatusBadRequest, "header_name is required when key_type is HEADER")
				return
			}
		default:
			writeError(w, http.StatusBadRequest, "invalid key_type: must be CLIENT_IP or HEADER")
			return
		}

		if rule.PathPrefix != "" && !strings.HasPrefix(rule.PathPrefix, "/") {
			writeError(w, http.StatusBadRequest, "path_prefix must start with /")
			return
		}
	}

	if err := h.store.SetRateLimitRules(domainID, body.Rules); err != nil {
		if errors.Is(err, store.ErrRuleLimitExceeded) {
			writeError(w, http.StatusConflict, "rate limit rule limit reached for domain (max 500)")
			return
		}
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domain_id": domainID,
		"rules":     body.Rules,
	})
}

// GET /v1/domains/{domain_id}/rate-limits
func (h *APIHandler) handleGetRateLimits(w http.ResponseWriter, r *http.Request, domainID string) {
	rules := h.store.GetRateLimitRules(domainID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domain_id": domainID,
		"rules":     rules,
	})
}

// GET /v1/domains/{domain_id}/security/events
func (h *APIHandler) handleGetSecurityEvents(w http.ResponseWriter, r *http.Request, domainID string) {
	limit := 50
	if lStr := r.URL.Query().Get("limit"); lStr != "" {
		if l, err := strconv.Atoi(lStr); err == nil && l > 0 {
			limit = l
		}
	}

	events := h.store.GetSecurityEvents(domainID, limit)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domain_id": domainID,
		"events":    events,
		"count":     len(events),
	})
}

// GET /v1/domains/{domain_id}/cache/policy
func (h *APIHandler) handleGetCachePolicy(w http.ResponseWriter, r *http.Request, domainID string) {
	cp := h.store.GetCachePolicy(domainID)
	if cp == nil {
		writeError(w, http.StatusNotFound, "cache policy not found")
		return
	}
	cp.CacheRules = h.store.GetCacheRules(domainID)
	writeJSON(w, http.StatusOK, cp)
}

// PATCH /v1/domains/{domain_id}/cache/policy
func (h *APIHandler) handleUpdateCachePolicy(w http.ResponseWriter, r *http.Request, domainID string) {
	cp := h.store.GetCachePolicy(domainID)
	if cp == nil {
		writeError(w, http.StatusNotFound, "cache policy not found")
		return
	}

	var update struct {
		CacheEnabled         *bool                      `json:"cache_enabled"`
		DefaultTTLSeconds    *int                       `json:"default_ttl_seconds"`
		RespectOriginHeaders *bool                      `json:"respect_origin_headers"`
		QueryHandling        *model.QueryStringHandling `json:"query_handling"`
		StripCookies         *bool                      `json:"strip_cookies"`
	}

	if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if update.CacheEnabled != nil {
		cp.CacheEnabled = *update.CacheEnabled
	}
	if update.DefaultTTLSeconds != nil {
		cp.DefaultTTLSeconds = *update.DefaultTTLSeconds
	}
	if update.RespectOriginHeaders != nil {
		cp.RespectOriginHeaders = *update.RespectOriginHeaders
	}
	if update.QueryHandling != nil {
		cp.QueryHandling = *update.QueryHandling
	}
	if update.StripCookies != nil {
		cp.StripCookies = *update.StripCookies
	}

	h.store.SaveCachePolicy(cp)
	cp.CacheRules = h.store.GetCacheRules(domainID)
	writeJSON(w, http.StatusOK, cp)
}

// POST /v1/domains/{domain_id}/cache/rules
func (h *APIHandler) handleAddCacheRule(w http.ResponseWriter, r *http.Request, domainID string) {
	var rule model.CacheRule
	if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
		writeError(w, http.StatusBadRequest, "invalid cache rule payload")
		return
	}

	if rule.Name == "" || rule.PathPattern == "" {
		writeError(w, http.StatusBadRequest, "name and path_pattern are required")
		return
	}
	if rule.TTLSeconds <= 0 {
		rule.TTLSeconds = 3600
	}
	rule.ID = "cache-rule-" + generateHex(4)
	rule.DomainID = domainID
	rule.Enabled = true

	if err := h.store.AddCacheRule(domainID, rule); err != nil {
		if errors.Is(err, store.ErrRuleLimitExceeded) {
			writeError(w, http.StatusConflict, "cache rule limit reached for domain (max 1000)")
			return
		}
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	writeJSON(w, http.StatusCreated, rule)
}

// GET /v1/domains/{domain_id}/cache/rules
func (h *APIHandler) handleListCacheRules(w http.ResponseWriter, r *http.Request, domainID string) {
	rules := h.store.GetCacheRules(domainID)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"domain_id": domainID,
		"rules":     rules,
		"count":     len(rules),
	})
}

// DELETE /v1/domains/{domain_id}/cache/rules/{rule_id}
func (h *APIHandler) handleDeleteCacheRule(w http.ResponseWriter, r *http.Request, domainID, ruleID string) {
	if err := h.store.DeleteCacheRule(domainID, ruleID); err != nil {
		writeError(w, http.StatusNotFound, "cache rule not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"message": "cache rule deleted successfully",
		"rule_id": ruleID,
	})
}

// POST /v1/domains/{domain_id}/cache/purge
func (h *APIHandler) handlePurgeCache(w http.ResponseWriter, r *http.Request, domainID string) {
	var body struct {
		Target string `json:"target"` // URL, prefix, or "*" for everything
	}
	_ = json.NewDecoder(r.Body).Decode(&body)

	domain, _ := h.store.GetDomain(domainID)
	target := strings.TrimSpace(body.Target)

	if target == "*" {
		// Global cache purge requires Platform Operator role (P1 finding)
		if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator) {
			writeError(w, http.StatusForbidden, "global cache purge requires platform operator role")
			return
		}
	} else if target == "" {
		if domain != nil {
			target = domain.Hostname
		} else {
			target = domainID
		}
	} else {
		// Validate that the target does not target another domain outside this domain scope
		var targetHost string
		if strings.Contains(target, "://") {
			parsed, err := url.Parse(target)
			if err != nil {
				writeError(w, http.StatusBadRequest, "invalid purge target URL")
				return
			}
			targetHost = parsed.Hostname()
		} else {
			parts := strings.SplitN(target, "/", 2)
			if strings.Contains(parts[0], ".") {
				targetHost = parts[0]
			}
		}

		if targetHost != "" {
			if domain != nil && !strings.EqualFold(targetHost, domain.Hostname) {
				writeError(w, http.StatusForbidden, "purge target is outside domain scope")
				return
			}
		} else if domain != nil {
			target = domain.Hostname + "/" + strings.TrimPrefix(target, "/")
		}
	}

	purged := h.cacheEngine.Purge(target)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":       "purged",
		"domain_id":    domainID,
		"target":       target,
		"purged_count": purged,
		"invalidation": "immediate",
	})
}

type CacheLookupRequest struct {
	DomainID       string            `json:"domain_id"`
	Method         string            `json:"method"`
	Path           string            `json:"path"`
	Query          string            `json:"query"`
	Headers        map[string]string `json:"headers"`
	OriginResponse *OriginResponse   `json:"origin_response,omitempty"`
}

type OriginResponse struct {
	StatusCode int               `json:"status_code"`
	Headers    map[string]string `json:"headers"`
	Body       string            `json:"body"`
}

// POST /v1/edge/cache-lookup
func (h *APIHandler) handleCacheLookup(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req CacheLookupRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	domain, err := h.store.GetDomain(req.DomainID)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	if !h.authenticator.AuthorizeProject(r.Context(), domain.ProjectID) {
		writeError(w, http.StatusForbidden, "forbidden: caller not authorized for domain "+req.DomainID)
		return
	}

	policy := h.store.GetCachePolicy(req.DomainID)
	if policy == nil {
		writeError(w, http.StatusNotFound, "cache policy not found")
		return
	}
	rules := h.store.GetCacheRules(req.DomainID)
	matchingRule := cache.FindMatchingRule(req.Path, rules)

	// Enforce CacheRule.BypassCache: if matching customer rule specifies bypass, bypass immediately
	if matchingRule != nil && matchingRule.BypassCache {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"cache_status": cache.CacheStatusBypass,
			"reason":       "cache rule specifies bypass_cache",
			"cacheable":    false,
		})
		return
	}

	// Construct HTTP request for cacheability verification
	httpReq, _ := http.NewRequest(req.Method, req.Path, nil)
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	isCacheableReq, reqReason := cache.IsRequestCacheable(httpReq, policy)
	if !isCacheableReq {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"cache_status": cache.CacheStatusBypass,
			"reason":       reqReason,
			"cacheable":    false,
		})
		return
	}

	cacheKey := cache.GenerateCacheKey("https", domain.Hostname, req.Path, req.Query, httpReq.Header, policy, matchingRule)

	// Check if already in cache
	cached, status := h.cacheEngine.Lookup(cacheKey)
	if status == cache.CacheStatusHit {
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"cache_status": cache.CacheStatusHit,
			"cache_key":    cacheKey,
			"status_code":  cached.StatusCode,
			"headers":      cached.Headers,
			"body":         string(cached.Body),
			"age_seconds":  cached.Age(),
			"etag":         cached.ETag,
		})
		return
	}

	// Cache MISS: If origin response was provided, evaluate cacheability and store
	if req.OriginResponse != nil {
		originRespHeaders := make(http.Header)
		for k, v := range req.OriginResponse.Headers {
			originRespHeaders.Set(k, v)
		}

		isCacheableResp, ttl, respReason := cache.IsResponseCacheable(req.OriginResponse.StatusCode, originRespHeaders, policy)
		if isCacheableResp {
			if matchingRule != nil && matchingRule.TTLSeconds > 0 {
				ttl = matchingRule.TTLSeconds
			}

			headersToStore := make(map[string]string)
			for k, v := range req.OriginResponse.Headers {
				headersToStore[k] = v
			}

			newEntry := h.cacheEngine.Store(cacheKey, req.OriginResponse.StatusCode, headersToStore, []byte(req.OriginResponse.Body), ttl)
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"cache_status": cache.CacheStatusMiss,
				"cache_stored": true,
				"cache_key":    cacheKey,
				"ttl_seconds":  ttl,
				"etag":         newEntry.ETag,
			})
			return
		}

		writeJSON(w, http.StatusOK, map[string]interface{}{
			"cache_status": cache.CacheStatusMiss,
			"cache_stored": false,
			"cache_key":    cacheKey,
			"reason":       respReason,
		})
		return
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"cache_status": cache.CacheStatusMiss,
		"cache_key":    cacheKey,
	})
}

type EvaluateRequest struct {
	DomainID  string            `json:"domain_id"`
	ClientIP  string            `json:"client_ip"`
	Method    string            `json:"method"`
	Path      string            `json:"path"`
	Query     string            `json:"query"`
	UserAgent string            `json:"user_agent"`
	Headers   map[string]string `json:"headers"`
}

// POST /v1/edge/evaluate
func (h *APIHandler) handleEvaluate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DomainID == "" {
		writeError(w, http.StatusBadRequest, "domain_id is required")
		return
	}

	if req.ClientIP == "" || net.ParseIP(req.ClientIP) == nil {
		writeError(w, http.StatusBadRequest, "client_ip must be a valid IP address")
		return
	}

	domain, err := h.store.GetDomain(req.DomainID)
	if err != nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	if !h.authenticator.AuthorizeProject(r.Context(), domain.ProjectID) {
		writeError(w, http.StatusForbidden, "forbidden: caller not authorized for domain "+req.DomainID)
		return
	}

	secPolicy := h.store.GetSecurityPolicy(req.DomainID)
	if secPolicy == nil {
		writeError(w, http.StatusNotFound, "domain security policy not found")
		return
	}

	// Construct simulated HTTP request for evaluation
	rawURL := req.Path
	if req.Query != "" {
		rawURL += "?" + req.Query
	}
	parsedURL, _ := url.Parse(rawURL)
	if parsedURL == nil {
		parsedURL = &url.URL{Path: req.Path}
	}

	simulatedHTTPReq := &http.Request{
		Method:     req.Method,
		URL:        parsedURL,
		Header:     make(http.Header),
		RemoteAddr: req.ClientIP + ":12345",
	}

	if req.UserAgent != "" {
		simulatedHTTPReq.Header.Set("User-Agent", req.UserAgent)
	}
	for k, v := range req.Headers {
		simulatedHTTPReq.Header.Set(k, v)
	}

	tc, _ := auth.FromContext(r.Context())
	evalCtx := security.EvaluationContext{
		ClientIP: req.ClientIP,
	}
	// P2 Finding 3: Trust decision is strictly governed by authenticated caller context.
	// Client-supplied markers (e.g. X-Gateway-Identity-Verified) are ignored.
	if tc != nil && (tc.Role == auth.RoleEdgeNode || tc.Role == auth.RolePlatformOperator) {
		evalCtx.IdentityTrusted = true
		if trustedID, ok := req.Headers["X-Authenticated-User"]; ok && trustedID != "" {
			evalCtx.TrustedIdentity = trustedID
		}
	} else {
		evalCtx.IdentityTrusted = false
	}

	result := h.wafEngine.EvaluateRequestWithContext(simulatedHTTPReq, secPolicy, evalCtx)

	// Record security event if blocked
	if result.Blocked || result.Action == model.WAFActionLog {
		secEvent := model.SecurityEvent{
			ID:            security.GenerateEventID(),
			DomainID:      req.DomainID,
			Timestamp:     time.Now().UTC(),
			ClientIP:      req.ClientIP,
			Method:        req.Method,
			Path:          req.Path,
			UserAgent:     req.UserAgent,
			RuleTriggered: result.RuleTriggered,
			Action:        result.Action,
			Details:       result.Reason,
		}
		h.store.RecordSecurityEvent(secEvent)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"blocked":        result.Blocked,
		"status_code":    result.StatusCode,
		"action":         result.Action,
		"rule_triggered": result.RuleTriggered,
		"reason":         result.Reason,
	})
}

// GET /v1/edge/envoy-config
func (h *APIHandler) handleEnvoyConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// RBAC Boundary (Finding 9, Finding 3): Only Platform Operators can inspect global compiled Envoy configuration.
	// Edge nodes must retrieve their PoP-scoped configuration via /v1/edge/pops/{pop_id}/config.
	if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator) {
		writeError(w, http.StatusForbidden, "forbidden: operator role required for global envoy configuration")
		return
	}

	topologies := h.store.GetActiveTopologies()
	cfg, err := h.compiler.Compile(topologies)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to compile envoy configuration: "+err.Error())
		return
	}

	writeJSON(w, http.StatusOK, cfg)
}

// GET /v1/edge/topologies
func (h *APIHandler) handleTopologies(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// RBAC Boundary (Finding 6): Only Platform Operators can view global edge topologies
	if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator) {
		writeError(w, http.StatusForbidden, "forbidden: operator role required for global edge topologies")
		return
	}

	topologies := h.store.GetActiveTopologies()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active_topologies_count": len(topologies),
		"topologies":              topologies,
	})
}

// POST /v1/edge/telemetry
func (h *APIHandler) handleEdgeTelemetry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// RBAC Boundary (Finding 9): Only Edge Nodes or Platform Operators can submit edge telemetry
	if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator, auth.RoleEdgeNode) {
		writeError(w, http.StatusForbidden, "forbidden: operator or edge node role required")
		return
	}

	// Request Body Limit (Finding 19): Bounded to 1 MiB to prevent memory exhaustion
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		writeError(w, http.StatusBadRequest, "failed to read request body (max 1 MiB)")
		return
	}

	trimmed := strings.TrimSpace(string(bodyBytes))
	var events []model.TelemetryEvent
	if strings.HasPrefix(trimmed, "[") {
		if err := json.Unmarshal(bodyBytes, &events); err != nil {
			writeError(w, http.StatusBadRequest, "invalid telemetry events batch: "+err.Error())
			return
		}
	} else {
		var single model.TelemetryEvent
		if err := json.Unmarshal(bodyBytes, &single); err != nil {
			writeError(w, http.StatusBadRequest, "invalid telemetry event: "+err.Error())
			return
		}
		events = []model.TelemetryEvent{single}
	}

	// Pre-validate all events: ensure domain exists, caller is authorized for the project, and timestamp is within sanity window (P1/P2)
	now := time.Now().UTC()
	for i := range events {
		ev := &events[i]
		if ev.DomainID == "" {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("event [%d]: domain_id is required", i))
			return
		}
		domain, err := h.store.GetDomain(ev.DomainID)
		if err != nil || domain == nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("event [%d]: domain not found (%s)", i, ev.DomainID))
			return
		}
		if !h.authenticator.AuthorizeProject(r.Context(), domain.ProjectID) {
			writeError(w, http.StatusForbidden, fmt.Sprintf("event [%d]: forbidden, caller not authorized for domain %s", i, ev.DomainID))
			return
		}
		// P2 Finding 8: Validate timestamp against sanity window [now - 24h, now + 5m] to prevent telemetry skew and billing tampering
		if !ev.Timestamp.IsZero() {
			if ev.Timestamp.Before(now.Add(-24*time.Hour)) || ev.Timestamp.After(now.Add(5*time.Minute)) {
				writeError(w, http.StatusBadRequest, fmt.Sprintf("event [%d]: telemetry timestamp out of acceptable window", i))
				return
			}
		} else {
			ev.Timestamp = now
		}
	}

	count, err := h.analyticsEngine.IngestBatch(events)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"status":   "ingested",
		"ingested": count,
	})
}

func (h *APIHandler) handleAnalyticsRoute(w http.ResponseWriter, r *http.Request, domainID string, parts []string) {
	if len(parts) < 3 {
		writeError(w, http.StatusNotFound, "analytics sub-resource required")
		return
	}

	domain, err := h.store.GetDomain(domainID)
	if err != nil || domain == nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	switch parts[2] {
	case "summary":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		summary, err := h.analyticsEngine.GetSummary(domainID)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, summary)

	case "timeseries":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		limit := 60
		if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
			if l, err := strconv.Atoi(limitStr); err == nil && l > 0 {
				limit = l
			}
		}
		series, err := h.analyticsEngine.GetTimeSeries(domainID, limit)
		if err != nil {
			writeError(w, http.StatusInternalServerError, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"domain_id":    domainID,
			"points_count": len(series),
			"points":       series,
		})

	default:
		writeError(w, http.StatusNotFound, "unknown analytics sub-resource: "+parts[2])
	}
}

func (h *APIHandler) handleBillingRoute(w http.ResponseWriter, r *http.Request, domainID string, parts []string) {
	if len(parts) < 3 || parts[2] != "usage" {
		writeError(w, http.StatusNotFound, "billing usage endpoint required")
		return
	}

	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	domain, err := h.store.GetDomain(domainID)
	if err != nil || domain == nil {
		writeError(w, http.StatusNotFound, "domain not found")
		return
	}

	period := r.URL.Query().Get("period")
	usage, err := h.analyticsEngine.GetBillingUsage(domainID, period)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, usage)
}

// GET /v1/edge/pops
func (h *APIHandler) handleListPoPs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator, auth.RoleEdgeNode) {
		writeError(w, http.StatusForbidden, "forbidden: operator or edge node role required")
		return
	}
	pops := h.popManager.ListPoPs()

	// If caller is an edge node, restrict visibility to its assigned PoP only (Finding 5)
	if tc, ok := auth.FromContext(r.Context()); ok && tc.Role == auth.RoleEdgeNode && !tc.IsDevBypass {
		if tc.PoPID == "" {
			writeError(w, http.StatusForbidden, "edge node is not bound to a PoP")
			return
		}
		if tc.PoPID != "*" {
			filtered := make([]model.EdgePoP, 0)
			for _, p := range pops {
				if strings.EqualFold(p.ID, tc.PoPID) {
					filtered = append(filtered, p)
				}
			}
			pops = filtered
		}
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"total_pops": len(pops),
		"pops":       pops,
	})
}

// /v1/edge/pops/{pop_id}/...
func (h *APIHandler) handlePoPsRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/edge/pops/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		h.handleListPoPs(w, r)
		return
	}

	popID := strings.ToLower(parts[0])

	if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator, auth.RoleEdgeNode) {
		writeError(w, http.StatusForbidden, "forbidden: operator or edge node role required")
		return
	}

	if !h.authenticator.AuthorizePoP(r.Context(), popID) {
		writeError(w, http.StatusForbidden, "edge node is not authorized for this PoP")
		return
	}

	if len(parts) == 1 {
		if r.Method == http.MethodGet {
			pop, err := h.popManager.GetPoP(popID)
			if err != nil {
				writeError(w, http.StatusNotFound, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, pop)
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	action := parts[1]
	switch action {
	case "nodes":
		if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator, auth.RoleEdgeNode) {
			writeError(w, http.StatusForbidden, "forbidden: operator or edge node role required")
			return
		}
		if len(parts) == 2 {
			if r.Method == http.MethodGet {
				nodes := h.popManager.ListNodes(popID)
				writeJSON(w, http.StatusOK, map[string]interface{}{
					"pop_id":      popID,
					"total_nodes": len(nodes),
					"nodes":       nodes,
				})
				return
			}
			if r.Method == http.MethodPost {
				if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator) {
					writeError(w, http.StatusForbidden, "forbidden: platform operator role required for node registration")
					return
				}
				r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
				var node model.EdgeNode
				if err := json.NewDecoder(r.Body).Decode(&node); err != nil {
					writeError(w, http.StatusBadRequest, "invalid node payload: "+err.Error())
					return
				}
				node.PoPID = popID
				registered, err := h.popManager.RegisterNode(node)
				if err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
				writeJSON(w, http.StatusCreated, registered)
				return
			}
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}

		if len(parts) == 4 && parts[3] == "heartbeat" {
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			nodeID := parts[2]

			// Validate EdgeNode identity binding (P1 finding): EdgeNode callers can only heartbeat their own node
			tc, ok := auth.FromContext(r.Context())
			if !ok {
				writeError(w, http.StatusUnauthorized, "authentication context missing")
				return
			}
			if tc.Role == auth.RoleEdgeNode && (tc.NodeID == "" || tc.NodeID != nodeID) {
				writeError(w, http.StatusForbidden, "edge node credential cannot update another node")
				return
			}

			r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
			var payload struct {
				CPUUsagePercent   float64 `json:"cpu_usage_percent"`
				MemoryUsageMB     int64   `json:"memory_usage_mb"`
				ActiveConnections int     `json:"active_connections"`
			}
			_ = json.NewDecoder(r.Body).Decode(&payload)
			if err := h.popManager.HeartbeatNode(popID, nodeID, payload.CPUUsagePercent, payload.MemoryUsageMB, payload.ActiveConnections); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"status":  "heartbeat_acknowledged",
				"pop_id":  popID,
				"node_id": nodeID,
			})
			return
		}
		writeError(w, http.StatusNotFound, "unknown node route")

	case "bgp":
		if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator) {
			writeError(w, http.StatusForbidden, "forbidden: platform operator role required for BGP control")
			return
		}
		if len(parts) == 3 {
			bgpAction := parts[2]
			if r.Method != http.MethodPost {
				writeError(w, http.StatusMethodNotAllowed, "method not allowed")
				return
			}
			var updated *model.EdgePoP
			var err error
			if bgpAction == "announce" {
				updated, err = h.popManager.SetBGPState(popID, model.BGPStateAnnounced)
			} else if bgpAction == "withdraw" {
				updated, err = h.popManager.SetBGPState(popID, model.BGPStateWithdrawn)
			} else {
				writeError(w, http.StatusBadRequest, "invalid bgp action: must be announce or withdraw")
				return
			}
			if err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}
			writeJSON(w, http.StatusOK, updated)
			return
		}
		writeError(w, http.StatusNotFound, "unknown bgp route")

	case "config":
		if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator, auth.RoleEdgeNode) {
			writeError(w, http.StatusForbidden, "forbidden: operator or edge node role required")
			return
		}
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		pop, err := h.popManager.GetPoP(popID)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		topologies := h.store.GetActiveTopologies()
		envoyCfg, err := h.compiler.CompileForPoP(popID, topologies)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to compile pop config: "+err.Error())
			return
		}
		cfgJSON, _ := envoyCfg.ToJSON()
		hash := sha256.Sum256(cfgJSON)
		checksum := hex.EncodeToString(hash[:])
		syncResult := model.PoPConfigSync{
			PoPID:           pop.ID,
			ConfigVersion:   "v1.0.0-" + checksum[:8],
			ChecksumSHA256:  checksum,
			CompiledAt:      time.Now().UTC(),
			TopologiesCount: len(topologies),
			EnvoyConfig:     envoyCfg,
		}
		writeJSON(w, http.StatusOK, syncResult)

	default:
		writeError(w, http.StatusNotFound, "unknown pop action: "+action)
	}
}

// /v1/edge/routing/...
func (h *APIHandler) handleRoutingRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/edge/routing/")
	sub := strings.Trim(path, "/")

	switch sub {
	case "matrix":
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		// RBAC Boundary (Finding 6): Only Platform Operators can view the global latency matrix
		if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator) {
			writeError(w, http.StatusForbidden, "forbidden: operator role required for global latency matrix")
			return
		}
		matrix := h.popManager.GetLatencyMatrix()
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"routes_count": len(matrix),
			"routes":       matrix,
		})

	case "steer":
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		var req struct {
			ClientPoP string         `json:"client_pop"`
			DomainID  string         `json:"domain_id"`
			Origins   []model.Origin `json:"origins"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeError(w, http.StatusBadRequest, "invalid steer payload: "+err.Error())
			return
		}
		if req.DomainID == "" {
			writeError(w, http.StatusBadRequest, "domain_id is required")
			return
		}

		domain, err := h.store.GetDomain(req.DomainID)
		if err != nil {
			writeError(w, http.StatusNotFound, "domain not found: "+req.DomainID)
			return
		}

		// Enforce project-level tenant authorization boundary (Rules 54, 55 - IDOR Defense)
		if !h.authenticator.AuthorizeProject(r.Context(), domain.ProjectID) {
			writeError(w, http.StatusForbidden, "forbidden: caller not authorized for domain "+req.DomainID)
			return
		}

		origins := req.Origins
		if len(origins) == 0 {
			routes := h.store.GetRoutes(domain.ID)
			for _, r := range routes {
				if pool, err := h.store.GetOriginPool(r.PoolID); err == nil {
					origins = append(origins, pool.Origins...)
				}
			}
		}
		if len(origins) == 0 {
			writeError(w, http.StatusBadRequest, "no origins configured for domain: "+req.DomainID)
			return
		}

		decision, err := h.popManager.CalculateSteering(req.ClientPoP, req.DomainID, origins)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeJSON(w, http.StatusOK, decision)

	default:
		writeError(w, http.StatusNotFound, "unknown routing sub-resource: "+sub)
	}
}

func writeJSON(w http.ResponseWriter, code int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, message string) {
	writeJSON(w, code, map[string]interface{}{
		"error": message,
		"code":  code,
	})
}

func generateHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
