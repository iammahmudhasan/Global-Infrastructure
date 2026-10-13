package api

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
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
	store           store.Repository
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
	limiter         *ControlPlaneLimiter
	auditLogger     *security.AuditLogger
	handlerChain    http.Handler
	mux             *http.ServeMux
}

func NewAPIHandler(s store.Repository, svc *onboarding.DomainService, c *compiler.Compiler) *APIHandler {
	authenticator := auth.NewAuthenticator()
	mux := http.NewServeMux()

	auditKeyStr := os.Getenv("AUDIT_HMAC_KEY")
	if len(auditKeyStr) == 0 {
		if !onboarding.IsExplicitDevEnvironment() {
			panic("FATAL: AUDIT_HMAC_KEY environment variable is required in production mode for cryptographic audit logging")
		}
		auditKeyStr = "nexusedge-immutable-audit-key-2026"
	}
	auditKey := []byte(auditKeyStr)
	auditLogger := security.NewAuditLogger(auditKey)
	var allLogs []*model.AuditLog
	offset := 0
	batchSize := 1000
	for {
		batch, total, err := s.ListAuditLogs("", batchSize, offset)
		if err != nil || len(batch) == 0 {
			break
		}
		allLogs = append(allLogs, batch...)
		offset += len(batch)
		if offset >= total || len(batch) < batchSize {
			break
		}
	}
	if len(allLogs) > 0 {
		records := make([]*security.AuditRecord, len(allLogs))
		for i, l := range allLogs {
			idx := len(allLogs) - 1 - i
			records[idx] = &security.AuditRecord{
				ID:           l.ID,
				Timestamp:    l.CreatedAt.Format(time.RFC3339Nano),
				ActorID:      l.Actor,
				OrgID:        l.OrgID,
				ProjectID:    l.ProjectID,
				Action:       l.Action,
				ResourceType: l.ResourceType,
				ResourceID:   l.ResourceID,
				ClientIP:     l.ClientIP,
				Details:      l.Details,
				PrevHash:     l.PrevHash,
				Hash:         l.Hash,
			}
		}
		_ = auditLogger.LoadExistingRecords(records)
		if valid, err := auditLogger.VerifyChain(); !valid {
			log.Printf("[AUDIT WARNING] Historical audit chain verification failed at startup: %v", err)
		}
	}

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
		limiter:         NewControlPlaneLimiterWithClientConcurrency(100.0, 100, 200, 20),
		auditLogger:     auditLogger,
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

// SetLimiter allows overriding or configuring the control-plane limiter (e.g. for testing)
func (h *APIHandler) SetLimiter(l *ControlPlaneLimiter) {
	h.limiter = l
}

func (h *APIHandler) resolveClientKey(r *http.Request) string {
	if tc, ok := auth.FromContext(r.Context()); ok {
		if tc.ProjectID != "" {
			return "project:" + tc.ProjectID
		}
		if tc.TenantID != "" {
			return "tenant:" + tc.TenantID
		}
		if tc.NodeID != "" {
			return "node:" + tc.NodeID
		}
	}
	if apiKey := r.Header.Get("X-API-Key"); apiKey != "" {
		hash := sha256.Sum256([]byte(apiKey))
		return "apikey:" + hex.EncodeToString(hash[:16])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil && host != "" {
		return "ip:" + host
	}
	return "ip:" + r.RemoteAddr
}

func (h *APIHandler) acquireControlPlaneSlot(w http.ResponseWriter, r *http.Request) (func(), bool) {
	if h.limiter == nil {
		return func() {}, true
	}
	clientKey := h.resolveClientKey(r)
	release, err := h.limiter.Acquire(clientKey)
	if err != nil {
		w.Header().Set("Retry-After", "1")
		writeError(w, http.StatusTooManyRequests, err.Error())
		return nil, false
	}
	return release, true
}

func (h *APIHandler) Authenticator() *auth.Authenticator {
	return h.authenticator
}

func (h *APIHandler) PoPManager() *pop.Manager {
	return h.popManager
}

func (h *APIHandler) Store() store.Repository {
	return h.store
}

func (h *APIHandler) CertManager() *certificate.Manager {
	return h.certManager
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
	h.mux.HandleFunc("/v1/pops/", h.handlePoPsRoute)
	h.mux.HandleFunc("/v1/edge/routing/", h.handleRoutingRoute)
	h.mux.HandleFunc("/v1/edge/ai-providers", h.handleEdgeAIProviders)
	h.mux.HandleFunc("/v1/ai/providers", h.handleAIProvidersRoute)
	h.mux.HandleFunc("/v1/ai/providers/", h.handleAIProviderByIDRoute)
	h.mux.HandleFunc("/v1/audit-logs", h.handleAuditLogsRoute)
	h.mux.HandleFunc("/v1/audit-logs/verify", h.handleAuditLogsVerifyRoute)
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

// /v1/projects/{project_id}/domains, /v1/projects/{project_id}/ai/providers, and /v1/projects/{project_id}/audit-logs
func (h *APIHandler) handleProjectsRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/projects/")
	parts := strings.Split(path, "/")
	if len(parts) < 2 {
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

	if parts[1] == "domains" {
		switch r.Method {
		case http.MethodPost:
			h.handleCreateDomain(w, r, projectID)
		case http.MethodGet:
			h.handleListDomains(w, r, projectID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	if parts[1] == "audit-logs" {
		switch r.Method {
		case http.MethodGet:
			h.handleListAuditLogs(w, r, projectID)
		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	if parts[1] == "ai" && len(parts) >= 3 && parts[2] == "providers" {
		providerID := ""
		if len(parts) >= 4 {
			providerID = parts[3]
		}
		h.handleProjectAIProvidersRoute(w, r, projectID, providerID)
		return
	}

	writeError(w, http.StatusNotFound, "route not found")
}

func (h *APIHandler) handleAuditLogsRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	tc, _ := auth.FromContext(r.Context())
	projectID := r.URL.Query().Get("project_id")
	if tc != nil && tc.ProjectID != "" {
		projectID = tc.ProjectID
	}

	h.handleListAuditLogs(w, r, projectID)
}

func (h *APIHandler) handleListAuditLogs(w http.ResponseWriter, r *http.Request, projectID string) {
	limit := 50
	offset := 0
	if l := r.URL.Query().Get("limit"); l != "" {
		if val, err := strconv.Atoi(l); err == nil && val > 0 && val <= 500 {
			limit = val
		}
	}
	if o := r.URL.Query().Get("offset"); o != "" {
		if val, err := strconv.Atoi(o); err == nil && val >= 0 {
			offset = val
		}
	}

	logs, total, err := h.store.ListAuditLogs(projectID, limit, offset)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "failed to list audit logs: "+err.Error())
		return
	}

	valid, _ := h.auditLogger.VerifyChain()
	lastHash := h.auditLogger.LastHash()

	resp := model.AuditLogListResponse{
		AuditLogs:  logs,
		Total:      total,
		Limit:      limit,
		Offset:     offset,
		ChainValid: valid,
		LastHash:   lastHash,
	}
	writeJSON(w, http.StatusOK, resp)
}

func (h *APIHandler) handleAuditLogsVerifyRoute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator) {
		writeError(w, http.StatusForbidden, "forbidden: operator role required for audit verification")
		return
	}

	valid, err := h.auditLogger.VerifyChain()
	records := h.auditLogger.GetRecords()
	lastHash := h.auditLogger.LastHash()

	status := map[string]interface{}{
		"chain_valid":   valid,
		"total_records": len(records),
		"last_hash":     lastHash,
		"algorithm":     "HMAC-SHA256",
		"genesis_hash":  security.GenesisHash,
		"verified_at":   time.Now().UTC().Format(time.RFC3339Nano),
	}
	if err != nil {
		status["verification_error"] = err.Error()
	}

	writeJSON(w, http.StatusOK, status)
}

func (h *APIHandler) recordAudit(r *http.Request, orgID, projectID, action, resourceType, resourceID string, details map[string]interface{}) error {
	if h.auditLogger == nil {
		return nil
	}

	actor := "system"
	clientIP := ""
	if r != nil {
		if tc, ok := auth.FromContext(r.Context()); ok {
			if tc.TenantID != "" {
				actor = tc.TenantID
				if orgID == "" {
					orgID = tc.TenantID
				}
			}
			if projectID == "" && tc.ProjectID != "" {
				projectID = tc.ProjectID
			}
		}
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err == nil {
			clientIP = host
		} else {
			clientIP = r.RemoteAddr
		}
		if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
			remoteIP := net.ParseIP(clientIP)
			if remoteIP != nil && (remoteIP.IsLoopback() || remoteIP.IsPrivate() || os.Getenv("NEXUSEDGE_TRUST_PROXY") == "true") {
				parts := strings.Split(xf, ",")
				forwarded := strings.TrimSpace(parts[0])
				if net.ParseIP(forwarded) != nil {
					clientIP = forwarded
				}
			}
		}
	}

	rec, err := h.auditLogger.Record(actor, orgID, projectID, action, resourceType, resourceID, clientIP, details)
	if err != nil {
		log.Printf("[AUDIT ERROR] failed to record audit event: %v", err)
		return err
	}

	t, parseErr := time.Parse(time.RFC3339Nano, rec.Timestamp)
	if parseErr != nil {
		t = time.Now().UTC()
	}

	auditLog := &model.AuditLog{
		ID:           rec.ID,
		OrgID:        rec.OrgID,
		ProjectID:    rec.ProjectID,
		Actor:        rec.ActorID,
		Action:       rec.Action,
		ResourceType: rec.ResourceType,
		ResourceID:   rec.ResourceID,
		ClientIP:     rec.ClientIP,
		Details:      rec.Details,
		PrevHash:     rec.PrevHash,
		Hash:         rec.Hash,
		CreatedAt:    t,
	}

	if err := h.store.SaveAuditLog(auditLog); err != nil {
		h.auditLogger.RollbackLastRecord(rec.ID)
		log.Printf("[AUDIT ERROR] failed to persist audit log %s, rolled back in-memory chain: %v", auditLog.ID, err)
		return err
	}

	return nil
}

func (h *APIHandler) handleCreateDomain(w http.ResponseWriter, r *http.Request, projectID string) {
	var req onboarding.OnboardRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: must be valid JSON")
		return
	}
	req.ProjectID = projectID

	if err := store.ValidateAllowedPoPs(req.AllowedPoPs); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

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

	h.recordAudit(r, "", projectID, "domain.created", "domain", res.DomainID, map[string]interface{}{
		"hostname":     res.Hostname,
		"cname_target": res.CNAMETarget,
	})

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
			h.recordAudit(r, "", domain.ProjectID, "domain.deleted", "domain", domainID, map[string]interface{}{
				"hostname": domain.Hostname,
			})
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
				cert = h.store.GetPendingCertificate(domainID)
			}
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
			if errors.Is(err, certificate.ErrProductionACMENotConfigured) {
				writeError(w, http.StatusNotImplemented, err.Error())
				return
			}
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
			cert = h.store.GetPendingCertificate(domainID)
		}
		if cert == nil {
			writeError(w, http.StatusNotFound, "no certificate for domain")
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
			if errors.Is(err, certificate.ErrProductionACMENotConfigured) {
				writeError(w, http.StatusNotImplemented, err.Error())
				return
			}
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
		if err := h.store.SaveTLSSettings(domainID, &settings); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to persist tls settings: "+err.Error())
			return
		}
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
		if errors.Is(err, certificate.ErrProductionACMENotConfigured) {
			writeError(w, http.StatusNotImplemented, err.Error())
			return
		}
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
	release, ok := h.acquireControlPlaneSlot(w, r)
	if !ok {
		return
	}
	defer release()

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
	Address     string   `json:"address"`
	Port        int      `json:"port"`
	Protocol    string   `json:"protocol"`
	Weight      int      `json:"weight"`
	AllowedPoPs []string `json:"allowed_pops,omitempty"`
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
		ID:          originID,
		PoolID:      routes[0].PoolID,
		Address:     req.Address,
		Port:        req.Port,
		Protocol:    model.Protocol(req.Protocol),
		Weight:      req.Weight,
		Healthy:     true,
		AllowedPoPs: req.AllowedPoPs,
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
	if len(rule.Name) > store.MaxWAFRuleName {
		writeError(w, http.StatusBadRequest, "waf rule name exceeds maximum length (128)")
		return
	}
	if len(rule.Description) > store.MaxWAFRuleDescription {
		writeError(w, http.StatusBadRequest, "waf rule description exceeds maximum length (1024)")
		return
	}
	if len(rule.Pattern) > store.MaxWAFRulePattern {
		writeError(w, http.StatusBadRequest, "waf rule pattern exceeds maximum length (4096)")
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
		if errors.Is(err, store.ErrRuleSizeExceeded) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	domain, _ := h.store.GetDomain(domainID)
	projID := ""
	if domain != nil {
		projID = domain.ProjectID
	}
	h.recordAudit(r, "", projID, "waf_rule.created", "waf_rule", rule.ID, map[string]interface{}{
		"domain_id": domainID,
		"rule_name": rule.Name,
		"pattern":   rule.Pattern,
		"action":    rule.Action,
	})

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

	domain, _ := h.store.GetDomain(domainID)
	projID := ""
	if domain != nil {
		projID = domain.ProjectID
	}
	h.recordAudit(r, "", projID, "waf_rule.deleted", "waf_rule", ruleID, map[string]interface{}{
		"domain_id": domainID,
	})

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
		if len(rule.PathPrefix) > store.MaxRateLimitPathPrefix {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("path_prefix length exceeds maximum allowed (%d characters)", store.MaxRateLimitPathPrefix))
			return
		}
		if len(rule.HeaderName) > store.MaxRateLimitHeaderName {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("header_name length exceeds maximum allowed (%d characters)", store.MaxRateLimitHeaderName))
			return
		}
	}

	if err := h.store.SetRateLimitRules(domainID, body.Rules); err != nil {
		if errors.Is(err, store.ErrRuleLimitExceeded) {
			writeError(w, http.StatusConflict, "rate limit rule limit reached for domain (max 500)")
			return
		}
		if errors.Is(err, store.ErrRuleSizeExceeded) {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		writeError(w, http.StatusNotFound, err.Error())
		return
	}

	domain, _ := h.store.GetDomain(domainID)
	projID := ""
	if domain != nil {
		projID = domain.ProjectID
	}
	h.recordAudit(r, "", projID, "rate_limit.updated", "rate_limit", domainID, map[string]interface{}{
		"domain_id":  domainID,
		"rule_count": len(body.Rules),
	})

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
		if *update.DefaultTTLSeconds < 0 || *update.DefaultTTLSeconds > store.MaxCacheTTLSeconds {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("default_ttl_seconds must be between 0 and %d", store.MaxCacheTTLSeconds))
			return
		}
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

	if err := h.store.SaveCachePolicy(cp); err != nil {
		writeError(w, http.StatusInternalServerError, "failed to persist cache policy: "+err.Error())
		return
	}
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
	if len(rule.Name) > store.MaxCacheRuleName {
		writeError(w, http.StatusBadRequest, "cache rule name exceeds maximum length (128)")
		return
	}
	if len(rule.PathPattern) > store.MaxCachePathPattern {
		writeError(w, http.StatusBadRequest, "cache rule path_pattern exceeds maximum length (4096)")
		return
	}
	if len(rule.IgnoredParams) > store.MaxCacheRuleParamCount {
		writeError(w, http.StatusBadRequest, "ignored_params count exceeds limit (64)")
		return
	}
	for _, p := range rule.IgnoredParams {
		if len(p) > store.MaxCacheRuleParamLength {
			writeError(w, http.StatusBadRequest, "ignored parameter exceeds max length (128)")
			return
		}
	}
	if len(rule.IncludedParams) > store.MaxCacheRuleParamCount {
		writeError(w, http.StatusBadRequest, "included_params count exceeds limit (64)")
		return
	}
	for _, p := range rule.IncludedParams {
		if len(p) > store.MaxCacheRuleParamLength {
			writeError(w, http.StatusBadRequest, "included parameter exceeds max length (128)")
			return
		}
	}
	if len(rule.CustomHeadersToInclude) > store.MaxCustomHeaderCount {
		writeError(w, http.StatusBadRequest, "custom_headers_to_include count exceeds limit (32)")
		return
	}
	for _, ch := range rule.CustomHeadersToInclude {
		if len(ch) > store.MaxCustomHeaderName {
			writeError(w, http.StatusBadRequest, "custom header name exceeds max length (256)")
			return
		}
	}
	if rule.TTLSeconds < 0 || rule.TTLSeconds > store.MaxCacheTTLSeconds {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("ttl_seconds must be between 0 and %d", store.MaxCacheTTLSeconds))
		return
	}
	if rule.TTLSeconds == 0 {
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
		if errors.Is(err, store.ErrRuleSizeExceeded) {
			writeError(w, http.StatusBadRequest, err.Error())
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
	release, ok := h.acquireControlPlaneSlot(w, r)
	if !ok {
		return
	}
	defer release()

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

const (
	maxEvalPath      = 4096
	maxEvalQuery     = 8192
	maxEvalUserAgent = 1024
	maxEvalHeaders   = 64
	maxEvalHeaderKey = 256
	maxEvalHeaderVal = 4096
)

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
	release, ok := h.acquireControlPlaneSlot(w, r)
	if !ok {
		return
	}
	defer release()

	var req EvaluateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.DomainID == "" {
		writeError(w, http.StatusBadRequest, "domain_id is required")
		return
	}

	if len(req.Path) > maxEvalPath || len(req.Query) > maxEvalQuery || len(req.UserAgent) > maxEvalUserAgent {
		writeError(w, http.StatusBadRequest, "evaluation input exceeds size limits")
		return
	}

	if len(req.Headers) > maxEvalHeaders {
		writeError(w, http.StatusBadRequest, "headers count exceeds limit (max 64)")
		return
	}
	for k, v := range req.Headers {
		if len(k) > maxEvalHeaderKey || len(v) > maxEvalHeaderVal {
			writeError(w, http.StatusBadRequest, "header key or value exceeds maximum allowed size")
			return
		}
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

	release, ok := h.acquireControlPlaneSlot(w, r)
	if !ok {
		return
	}
	defer release()

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
	aiProviders := h.store.ListAIProviders()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active_topologies_count": len(topologies),
		"topologies":              topologies,
		"ai_providers_count":      len(aiProviders),
		"ai_providers":            aiProviders,
	})
}

// GET /v1/edge/ai-providers
func (h *APIHandler) handleEdgeAIProviders(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}

	// RBAC Boundary: Platform Operators or Edge Nodes can retrieve dynamic AI providers for gateway routing
	if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator, auth.RoleEdgeNode) {
		writeError(w, http.StatusForbidden, "forbidden: operator or edge node role required")
		return
	}

	tc, _ := auth.FromContext(r.Context())
	popID := strings.TrimSpace(r.URL.Query().Get("pop_id"))
	if popID == "" && tc != nil && tc.PoPID != "" && tc.PoPID != "*" {
		popID = tc.PoPID
	}

	// Scope enforcement: If PoP ID is specified or node has designated PoPID, verify PoP authorization
	if popID != "" && !h.authenticator.AuthorizePoP(r.Context(), popID) {
		writeError(w, http.StatusForbidden, "forbidden: node not authorized for pop "+popID)
		return
	}

	all := h.store.ListAIProviders()
	var filtered []model.AIProviderResponse
	for _, p := range all {
		if !p.Enabled {
			continue
		}
		// If caller is an edge node with project constraints, restrict to authorized projects
		if tc != nil && tc.Role == auth.RoleEdgeNode && len(tc.AllowedProjects) > 0 && !tc.AllowedProjects["*"] {
			if !tc.AllowedProjects[p.ProjectID] && p.ProjectID != "proj-default" && p.ProjectID != "system" {
				continue
			}
		}
		filtered = append(filtered, p.ToResponse())
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"count":     len(filtered),
		"providers": filtered,
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

	release, ok := h.acquireControlPlaneSlot(w, r)
	if !ok {
		return
	}
	defer release()

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
	path = strings.TrimPrefix(path, "/v1/pops/")
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
		if !h.authenticator.AuthorizePoP(r.Context(), popID) {
			writeError(w, http.StatusForbidden, "forbidden: node is not authorized for target pop "+popID)
			return
		}
		if r.Method != http.MethodGet {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
			return
		}
		release, ok := h.acquireControlPlaneSlot(w, r)
		if !ok {
			return
		}
		defer release()

		pop, err := h.popManager.GetPoP(popID)
		if err != nil {
			writeError(w, http.StatusNotFound, err.Error())
			return
		}
		topologies := h.store.GetActiveTopologiesForPoP(popID)
		envoyCfg, err := h.compiler.CompileForPoP(popID, topologies)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to compile pop config: "+err.Error())
			return
		}
		cfgJSON, _ := envoyCfg.ToJSON()
		hash := sha256.Sum256(cfgJSON)
		checksum := hex.EncodeToString(hash[:])

		gatewayRoutes := h.buildGatewayRoutesForPoP(topologies)
		gatewayAIProviders := h.buildGatewayAIProvidersForPoP(pop, topologies)

		canonicalBytes, _ := json.Marshal(gatewayRoutes)
		canonicalSum := sha256.Sum256(canonicalBytes)
		canonicalHash := hex.EncodeToString(canonicalSum[:])

		syncResult := model.PoPConfigSync{
			PoPID:           pop.ID,
			ConfigVersion:   "v1.0.0-" + checksum[:8],
			ChecksumSHA256:  checksum,
			CanonicalSHA256: canonicalHash,
			CompiledAt:      time.Now().UTC(),
			TopologiesCount: len(topologies),
			EnvoyConfig:     envoyCfg,
			Routes:          gatewayRoutes,
			AIProviders:     gatewayAIProviders,
		}

		respBytes, err := json.Marshal(syncResult)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "failed to marshal pop config: "+err.Error())
			return
		}
		bodySum := sha256.Sum256(respBytes)
		bodyHash := hex.EncodeToString(bodySum[:])
		w.Header().Set("X-Snapshot-Checksum", bodyHash)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(respBytes)

	case "secrets":
		if !h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator, auth.RoleEdgeNode) {
			writeError(w, http.StatusForbidden, "forbidden: operator or edge node role required")
			return
		}
		if !h.authenticator.AuthorizePoP(r.Context(), popID) {
			writeError(w, http.StatusForbidden, "forbidden: node is not authorized for target pop "+popID)
			return
		}
		if len(parts) >= 3 && parts[2] != "retrieve" {
			writeError(w, http.StatusNotFound, "unknown secrets action: "+parts[2])
			return
		}
		if r.Method != http.MethodPost {
			writeError(w, http.StatusMethodNotAllowed, "method not allowed: must be POST")
			return
		}
		h.handleRetrieveSecretForPoP(w, r, popID)
		return

	default:
		writeError(w, http.StatusNotFound, "unknown pop action: "+action)
	}
}

func (h *APIHandler) handleRetrieveSecretForPoP(w http.ResponseWriter, r *http.Request, popID string) {
	release, ok := h.acquireControlPlaneSlot(w, r)
	if !ok {
		return
	}
	defer release()

	var req model.SecretRetrieveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body: must be valid JSON")
		return
	}

	req.SecretRef = strings.TrimSpace(req.SecretRef)
	req.ProjectID = strings.TrimSpace(req.ProjectID)
	req.ProviderID = strings.TrimSpace(req.ProviderID)

	if req.SecretRef == "" || req.ProjectID == "" || req.ProviderID == "" {
		writeError(w, http.StatusBadRequest, "secret_ref, project_id, and provider_id are required")
		return
	}

	expectedRef := fmt.Sprintf("vault://projects/%s/ai-providers/%s/key", req.ProjectID, req.ProviderID)
	if req.SecretRef != expectedRef {
		writeError(w, http.StatusBadRequest, fmt.Sprintf("invalid secret_ref: expected %q, got %q", expectedRef, req.SecretRef))
		return
	}

	// 1. Multi-tenant PoP Scope check:
	// Verify that popID hosts at least one active domain for req.ProjectID, OR req.ProjectID is a platform operator project.
	isOperator := h.isOperatorProject(req.ProjectID)
	if !isOperator {
		topologies := h.store.GetActiveTopologiesForPoP(popID)
		hasProject := false
		for _, topo := range topologies {
			if topo.Domain != nil && topo.Domain.ProjectID == req.ProjectID {
				hasProject = true
				break
			}
		}
		if !hasProject {
			writeError(w, http.StatusForbidden, fmt.Sprintf("forbidden: pop %q is not authorized to host or retrieve secrets for project %q", popID, req.ProjectID))
			return
		}
	}

	// 2. Project Authorization Check (Prevent Cross-Tenant / Cross-Project Secret Theft):
	if !h.authenticator.AuthorizeProject(r.Context(), req.ProjectID) {
		writeError(w, http.StatusForbidden, fmt.Sprintf("forbidden: caller is not authorized for project %q", req.ProjectID))
		return
	}

	// 3. Retrieve provider and verify identity, project ownership, and active/revocation state
	provider, err := h.store.GetAIProvider(req.ProviderID)
	if err != nil || provider == nil {
		writeError(w, http.StatusNotFound, fmt.Sprintf("provider not found: %s", req.ProviderID))
		return
	}

	if provider.ProjectID != req.ProjectID {
		writeError(w, http.StatusForbidden, "forbidden: provider does not belong to specified project")
		return
	}

	if !provider.Enabled {
		writeError(w, http.StatusForbidden, fmt.Sprintf("forbidden: provider %s is disabled or secret has been revoked", req.ProviderID))
		return
	}

	h.recordAudit(r, "", req.ProjectID, "ai_provider.secret_retrieved", "ai_provider_secret", req.ProviderID, map[string]interface{}{
		"pop_id":     popID,
		"secret_ref": req.SecretRef,
	})

	writeJSON(w, http.StatusOK, model.SecretRetrieveResponse{
		SecretRef:  req.SecretRef,
		ProjectID:  provider.ProjectID,
		ProviderID: provider.ID,
		APIKey:     provider.APIKey,
		KeyVersion: "v1",
		ExpiresAt:  time.Now().UTC().Add(24 * time.Hour),
	})
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

func (h *APIHandler) buildGatewayRoutesForPoP(topologies []*store.DomainTopology) []model.GatewayRouteSync {
	resolver := h.compiler.GetDNSResolver()
	pinOriginsForPool := func(pool *model.OriginPool) ([]model.GatewayOriginSync, []string) {
		if pool == nil {
			return nil, nil
		}
		var origins []model.GatewayOriginSync
		var targets []string

		for _, o := range pool.Origins {
			proto := strings.ToUpper(string(o.Protocol))
			if proto == "" {
				proto = "HTTP"
			}
			parsedIP := net.ParseIP(o.Address)
			if parsedIP != nil {
				if onboarding.IsPrivateOrReservedIP(parsedIP) {
					if os.Getenv("NEXUSEDGE_DEV_MODE") == "true" && onboarding.IsExplicitDevEnvironment() {
						// Permitted in isolated development/test profile for mock origins
					} else {
						continue
					}
				}
				sniHost := o.SNI
				if sniHost == "" {
					sniHost = o.Address
				}
				origins = append(origins, model.GatewayOriginSync{
					Address:  parsedIP.String(),
					Port:     o.Port,
					Protocol: proto,
					SNI:      sniHost,
					Weight:   o.Weight,
				})
				targets = append(targets, fmt.Sprintf("%s://%s:%d", strings.ToLower(proto), parsedIP.String(), o.Port))
			} else {
				if resolver == nil {
					continue
				}
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
				resolvedIPs, err := resolver(ctx, o.Address)
				cancel()
				if err != nil || len(resolvedIPs) == 0 {
					continue
				}
				hasUnsafeIP := false
				var safeIPs []net.IP
				for _, ip := range resolvedIPs {
					if onboarding.IsPrivateOrReservedIP(ip) {
						hasUnsafeIP = true
						break
					}
					safeIPs = append(safeIPs, ip)
				}
				if hasUnsafeIP || len(safeIPs) == 0 {
					continue
				}
				for _, ip := range safeIPs {
					origins = append(origins, model.GatewayOriginSync{
						Address:  ip.String(),
						Port:     o.Port,
						Protocol: proto,
						SNI:      o.Address,
						Weight:   o.Weight,
					})
					targets = append(targets, fmt.Sprintf("%s://%s", strings.ToLower(proto), net.JoinHostPort(ip.String(), strconv.Itoa(o.Port))))
				}
			}
		}
		return origins, targets
	}

	gatewayRoutes := make([]model.GatewayRouteSync, 0, len(topologies))
	for _, topo := range topologies {
		if topo == nil || topo.Domain == nil || topo.Domain.Status != model.DomainStatusActive {
			continue
		}

		var pathRoutes []model.GatewayPathRouteSync
		var allTargets []string
		seenTargets := make(map[string]bool)

		for _, r := range topo.Routes {
			pool := topo.Pools[r.PoolID]
			pinnedOrigins, tgts := pinOriginsForPool(pool)
			if len(pinnedOrigins) > 0 {
				pathRoutes = append(pathRoutes, model.GatewayPathRouteSync{
					PathPrefix: r.PathPrefix,
					Priority:   r.Priority,
					Origins:    pinnedOrigins,
					Targets:    tgts,
				})
				for _, t := range tgts {
					if !seenTargets[t] {
						seenTargets[t] = true
						allTargets = append(allTargets, t)
					}
				}
			}
		}

		if len(pathRoutes) == 0 {
			var fallbackOrigins []model.GatewayOriginSync
			for _, pool := range topo.Pools {
				pinned, tgts := pinOriginsForPool(pool)
				fallbackOrigins = append(fallbackOrigins, pinned...)
				for _, t := range tgts {
					if !seenTargets[t] {
						seenTargets[t] = true
						allTargets = append(allTargets, t)
					}
				}
			}
			if len(fallbackOrigins) > 0 {
				pathRoutes = append(pathRoutes, model.GatewayPathRouteSync{
					PathPrefix: "/",
					Priority:   0,
					Origins:    fallbackOrigins,
					Targets:    allTargets,
				})
			}
		}

		if len(pathRoutes) == 0 && len(allTargets) == 0 {
			continue
		}

		var secSync *model.GatewaySecuritySync
		if topo.Security != nil {
			secSync = &model.GatewaySecuritySync{
				WAFEnabled:         topo.Security.WAFEnabled,
				BlockSQLi:          topo.Security.WAFEnabled && (topo.Security.OWASPProtection || topo.Security.WAFMode == "BLOCK"),
				BlockXSS:           topo.Security.WAFEnabled && (topo.Security.OWASPProtection || topo.Security.WAFMode == "BLOCK"),
				BlockPathTraversal: topo.Security.WAFEnabled && (topo.Security.OWASPProtection || topo.Security.WAFMode == "BLOCK"),
				RateLimitEnabled:   topo.Security.RateLimitEnabled,
			}
			if topo.Security.RateLimitRPM > 0 {
				secSync.RequestsPerSecond = uint32((topo.Security.RateLimitRPM + 59) / 60)
				secSync.BurstCapacity = secSync.RequestsPerSecond * 2
			}
			for _, wr := range topo.Security.WAFRules {
				if wr.Enabled && wr.Action == model.WAFActionBlock && wr.MatchType == model.WAFMatchPathPrefix {
					secSync.BlockedPaths = append(secSync.BlockedPaths, wr.Pattern)
				}
			}
		}

		var cacheSync *model.GatewayCacheSync
		if topo.Cache != nil {
			cacheSync = &model.GatewayCacheSync{
				Enabled:           topo.Cache.CacheEnabled,
				DefaultTTLSeconds: uint64(topo.Cache.DefaultTTLSeconds),
			}
		}

		gatewayRoutes = append(gatewayRoutes, model.GatewayRouteSync{
			Host:       strings.ToLower(topo.Domain.Hostname),
			PathRoutes: pathRoutes,
			Targets:    allTargets,
			Security:   secSync,
			Cache:      cacheSync,
		})
	}
	return gatewayRoutes
}

func validateAIProviderEndpoint(rawEndpoint string, providerType string, isOperator bool) error {
	trimmed := strings.TrimSpace(rawEndpoint)
	parsedURL, err := url.Parse(trimmed)
	if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		return errors.New("endpoint must be a valid HTTP or HTTPS URL")
	}

	if parsedURL.User != nil {
		return errors.New("endpoint cannot contain userinfo or credentials")
	}
	if parsedURL.RawQuery != "" || parsedURL.Fragment != "" {
		return errors.New("endpoint cannot contain query parameters or fragments")
	}

	host := parsedURL.Hostname()
	if host == "" {
		return errors.New("endpoint host cannot be empty")
	}

	// Prohibit known cloud metadata and internal management domains
	lowerHost := strings.ToLower(host)
	if lowerHost == "169.254.169.254" ||
		lowerHost == "metadata.google.internal" ||
		lowerHost == "instance-data" ||
		lowerHost == "metadata" ||
		strings.HasSuffix(lowerHost, ".internal") ||
		strings.HasSuffix(lowerHost, ".local") {
		return errors.New("endpoint destination violates SSRF protection policy (cloud metadata or internal domain prohibited)")
	}

	// Public providers strictly require HTTPS
	switch providerType {
	case string(model.AIProviderTypeOpenAI), string(model.AIProviderTypeAnthropic),
		string(model.AIProviderTypeAzure), string(model.AIProviderTypeAWS),
		string(model.AIProviderTypeBedrock), string(model.AIProviderTypeCoreWeave):
		if parsedURL.Scheme != "https" {
			return errors.New("public AI provider endpoints must strictly use HTTPS")
		}
	}

	// IP Destination Checks
	ip := net.ParseIP(host)
	if ip != nil {
		if ip.IsLoopback() && !isOperator {
			return errors.New("loopback IP destinations are prohibited for non-operator tenants")
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return errors.New("link-local IP destinations are strictly prohibited")
		}
		if ip.IsPrivate() {
			// Private IPs only allowed for onprem/vllm by platform operators or explicit dev environment
			if providerType != string(model.AIProviderTypeOnPrem) && providerType != string(model.AIProviderTypeVLLM) {
				return errors.New("private RFC1918 IP addresses are not permitted for public cloud provider types")
			}
			if !isOperator && !(os.Getenv("NEXUSEDGE_DEV_MODE") == "true" && onboarding.IsExplicitDevEnvironment()) {
				return errors.New("private network destinations require platform operator authorization")
			}
		}
	} else {
		// Hostname destination resolution check (DNS SSRF prevention)
		if ips, err := net.LookupIP(host); err == nil && len(ips) > 0 {
			for _, resolvedIP := range ips {
				if resolvedIP.IsLinkLocalUnicast() || resolvedIP.IsLinkLocalMulticast() {
					return fmt.Errorf("endpoint hostname %q resolves to prohibited link-local IP %s", host, resolvedIP)
				}
				if resolvedIP.IsLoopback() && !isOperator {
					return fmt.Errorf("endpoint hostname %q resolves to prohibited loopback IP %s", host, resolvedIP)
				}
				if resolvedIP.IsPrivate() && providerType != string(model.AIProviderTypeOnPrem) && providerType != string(model.AIProviderTypeVLLM) && !(os.Getenv("NEXUSEDGE_DEV_MODE") == "true" && onboarding.IsExplicitDevEnvironment()) {
					return fmt.Errorf("endpoint hostname %q resolves to prohibited private IP %s for public cloud provider", host, resolvedIP)
				}
			}
		}
	}

	return nil
}

func validateAIProviderPayload(p *model.AIProvider, isOperator bool) error {
	if p == nil {
		return errors.New("provider payload cannot be nil")
	}

	trimmedType := strings.ToLower(strings.TrimSpace(p.ProviderType))
	switch trimmedType {
	case string(model.AIProviderTypeOpenAI),
		string(model.AIProviderTypeAzure),
		string(model.AIProviderTypeCoreWeave),
		string(model.AIProviderTypeVLLM),
		string(model.AIProviderTypeOnPrem),
		string(model.AIProviderTypeAWS),
		string(model.AIProviderTypeAnthropic),
		string(model.AIProviderTypeBedrock):
		p.ProviderType = trimmedType
	default:
		return fmt.Errorf("invalid provider_type %q: must be one of openai, azure, coreweave, vllm, onprem, aws, anthropic, bedrock", p.ProviderType)
	}

	if err := validateAIProviderEndpoint(p.Endpoint, p.ProviderType, isOperator); err != nil {
		return err
	}
	return nil
}

func (h *APIHandler) isOperatorProject(projectID string) bool {
	return projectID == "system" || projectID == "proj-default" || projectID == "proj-core" || projectID == "prj-ops" || projectID == "proj-infra"
}

func (h *APIHandler) buildGatewayAIProvidersForPoP(pop *model.EdgePoP, topologies []*store.DomainTopology) []model.GatewayAIProviderSync {
	all := h.store.ListAIProviders()
	var result []model.GatewayAIProviderSync
	activeProjects := make(map[string]bool)
	for _, topo := range topologies {
		if topo.Domain != nil && topo.Domain.ProjectID != "" {
			activeProjects[topo.Domain.ProjectID] = true
		}
	}

	for _, p := range all {
		if !p.Enabled {
			continue
		}
		// Multi-tenant PoP Scoping (Finding 2):
		// When active domain topologies exist on this PoP, strictly limit to providers owned by those active projects (or system/operator platform providers).
		// When NO active topologies exist on this PoP, strictly limit to system/operator platform providers only (never leak tenant providers into empty PoP topologies).
		isPlatform := h.isOperatorProject(p.ProjectID)
		if len(activeProjects) > 0 {
			if !activeProjects[p.ProjectID] && !isPlatform {
				continue
			}
		} else {
			if !isPlatform {
				continue
			}
		}

		// Jurisdiction Scoping: Filter sovereign providers if designated
		if p.SovereigntyJurisdiction != "" && pop != nil && pop.Country != "" {
			if !strings.EqualFold(p.SovereigntyJurisdiction, pop.Country) &&
				!strings.EqualFold(p.SovereigntyJurisdiction, "GLOBAL") {
				continue
			}
		}

		result = append(result, model.GatewayAIProviderSync{
			ID:                      p.ID,
			ProjectID:               p.ProjectID,
			Name:                    p.Name,
			Endpoint:                p.Endpoint,
			ProviderType:            p.ProviderType,
			SecretRef:               fmt.Sprintf("vault://projects/%s/ai-providers/%s/key", p.ProjectID, p.ID),
			CostPerMTokens:          p.CostPerMTokens,
			Priority:                p.Priority,
			SovereigntyJurisdiction: p.SovereigntyJurisdiction,
			FailoverCooldownSecs:    p.FailoverCooldownSecs,
		})
	}
	return result
}

func generateAIProviderID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "aip-" + hex.EncodeToString(b)
}

func (h *APIHandler) handleAIProvidersRoute(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		release, ok := h.acquireControlPlaneSlot(w, r)
		if !ok {
			return
		}
		defer release()

		var p model.AIProvider
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: must be valid JSON")
			return
		}

		if strings.TrimSpace(p.ProjectID) == "" {
			if tc, ok := auth.FromContext(r.Context()); ok && tc.ProjectID != "" {
				p.ProjectID = tc.ProjectID
			} else {
				writeError(w, http.StatusBadRequest, "project_id is required")
				return
			}
		}

		if !h.authenticator.AuthorizeProject(r.Context(), p.ProjectID) {
			writeError(w, http.StatusForbidden, "forbidden: caller not authorized for project "+p.ProjectID)
			return
		}

		isOperator := h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator)
		if err := validateAIProviderPayload(&p, isOperator); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		if p.ID == "" {
			p.ID = generateAIProviderID()
		}

		if err := h.store.SaveAIProvider(&p); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		h.recordAudit(r, "", p.ProjectID, "ai_provider.created", "ai_provider", p.ID, map[string]interface{}{
			"name":          p.Name,
			"provider_type": p.ProviderType,
			"endpoint":      p.Endpoint,
		})

		writeJSON(w, http.StatusCreated, p.ToResponse())

	case http.MethodGet:
		projectID := r.URL.Query().Get("project_id")
		var providers []*model.AIProvider
		if projectID != "" {
			if !h.authenticator.AuthorizeProject(r.Context(), projectID) {
				writeError(w, http.StatusForbidden, "forbidden: caller not authorized for project "+projectID)
				return
			}
			providers = h.store.ListAIProvidersByProject(projectID)
		} else {
			if h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator) {
				providers = h.store.ListAIProviders()
			} else if tc, ok := auth.FromContext(r.Context()); ok && tc.ProjectID != "" {
				providers = h.store.ListAIProvidersByProject(tc.ProjectID)
			} else {
				writeError(w, http.StatusBadRequest, "project_id query parameter is required")
				return
			}
		}

		resp := make([]model.AIProviderResponse, 0, len(providers))
		for _, item := range providers {
			resp = append(resp, item.ToResponse())
		}
		writeJSON(w, http.StatusOK, map[string]interface{}{
			"providers": resp,
			"count":     len(resp),
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *APIHandler) handleAIProviderByIDRoute(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimPrefix(r.URL.Path, "/v1/ai/providers/")
	id = strings.Trim(id, "/")
	if id == "" || strings.Contains(id, "/") {
		writeError(w, http.StatusBadRequest, "invalid provider id in path")
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, err := h.store.GetAIProvider(id)
		if err != nil {
			writeError(w, http.StatusNotFound, "provider not found: "+id)
			return
		}
		if !h.authenticator.AuthorizeProject(r.Context(), p.ProjectID) {
			writeError(w, http.StatusForbidden, "forbidden: caller not authorized for project "+p.ProjectID)
			return
		}
		writeJSON(w, http.StatusOK, p.ToResponse())

	case http.MethodPut:
		release, ok := h.acquireControlPlaneSlot(w, r)
		if !ok {
			return
		}
		defer release()

		existing, err := h.store.GetAIProvider(id)
		if err != nil {
			writeError(w, http.StatusNotFound, "provider not found: "+id)
			return
		}
		if !h.authenticator.AuthorizeProject(r.Context(), existing.ProjectID) {
			writeError(w, http.StatusForbidden, "forbidden: caller not authorized for project "+existing.ProjectID)
			return
		}

		var update model.AIProvider
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: must be valid JSON")
			return
		}

		update.ID = id
		update.ProjectID = existing.ProjectID
		if strings.TrimSpace(update.APIKey) == "" {
			update.APIKey = existing.APIKey
		}
		if strings.TrimSpace(update.Name) == "" {
			update.Name = existing.Name
		}
		if strings.TrimSpace(update.Endpoint) == "" {
			update.Endpoint = existing.Endpoint
		}
		if strings.TrimSpace(update.ProviderType) == "" {
			update.ProviderType = existing.ProviderType
		}

		isOperator := h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator)
		if err := validateAIProviderPayload(&update, isOperator); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		if err := h.store.SaveAIProvider(&update); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		h.recordAudit(r, "", update.ProjectID, "ai_provider.updated", "ai_provider", update.ID, map[string]interface{}{
			"name":          update.Name,
			"provider_type": update.ProviderType,
			"endpoint":      update.Endpoint,
		})

		writeJSON(w, http.StatusOK, update.ToResponse())

	case http.MethodDelete:
		existing, err := h.store.GetAIProvider(id)
		if err != nil {
			writeError(w, http.StatusNotFound, "provider not found: "+id)
			return
		}
		if !h.authenticator.AuthorizeProject(r.Context(), existing.ProjectID) {
			writeError(w, http.StatusForbidden, "forbidden: caller not authorized for project "+existing.ProjectID)
			return
		}

		if err := h.store.DeleteAIProvider(id); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to delete provider: "+err.Error())
			return
		}

		h.recordAudit(r, "", existing.ProjectID, "ai_provider.deleted", "ai_provider", id, map[string]interface{}{
			"name":          existing.Name,
			"provider_type": existing.ProviderType,
		})

		writeJSON(w, http.StatusOK, map[string]string{
			"status": "deleted",
			"id":     id,
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (h *APIHandler) handleProjectAIProvidersRoute(w http.ResponseWriter, r *http.Request, projectID string, providerID string) {
	if providerID == "" {
		switch r.Method {
		case http.MethodPost:
			release, ok := h.acquireControlPlaneSlot(w, r)
			if !ok {
				return
			}
			defer release()

			var p model.AIProvider
			if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
				writeError(w, http.StatusBadRequest, "invalid request body: must be valid JSON")
				return
			}
			p.ProjectID = projectID
			if p.ID == "" {
				p.ID = generateAIProviderID()
			}

			isOperator := h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator)
			if err := validateAIProviderPayload(&p, isOperator); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			if err := h.store.SaveAIProvider(&p); err != nil {
				writeError(w, http.StatusBadRequest, err.Error())
				return
			}

			h.recordAudit(r, "", p.ProjectID, "ai_provider.created", "ai_provider", p.ID, map[string]interface{}{
				"name":          p.Name,
				"provider_type": p.ProviderType,
				"endpoint":      p.Endpoint,
			})

			writeJSON(w, http.StatusCreated, p.ToResponse())

		case http.MethodGet:
			providers := h.store.ListAIProvidersByProject(projectID)
			resp := make([]model.AIProviderResponse, 0, len(providers))
			for _, item := range providers {
				resp = append(resp, item.ToResponse())
			}
			writeJSON(w, http.StatusOK, map[string]interface{}{
				"providers": resp,
				"count":     len(resp),
			})

		default:
			writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		}
		return
	}

	p, err := h.store.GetAIProvider(providerID)
	if err != nil || p.ProjectID != projectID {
		writeError(w, http.StatusNotFound, "provider not found: "+providerID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, p.ToResponse())

	case http.MethodPut:
		release, ok := h.acquireControlPlaneSlot(w, r)
		if !ok {
			return
		}
		defer release()

		var update model.AIProvider
		if err := json.NewDecoder(r.Body).Decode(&update); err != nil {
			writeError(w, http.StatusBadRequest, "invalid request body: must be valid JSON")
			return
		}
		update.ID = providerID
		update.ProjectID = projectID
		if strings.TrimSpace(update.APIKey) == "" {
			update.APIKey = p.APIKey
		}
		if strings.TrimSpace(update.Name) == "" {
			update.Name = p.Name
		}
		if strings.TrimSpace(update.Endpoint) == "" {
			update.Endpoint = p.Endpoint
		}
		if strings.TrimSpace(update.ProviderType) == "" {
			update.ProviderType = p.ProviderType
		}

		isOperator := h.authenticator.AuthorizeRole(r.Context(), auth.RolePlatformOperator)
		if err := validateAIProviderPayload(&update, isOperator); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		if err := h.store.SaveAIProvider(&update); err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}

		h.recordAudit(r, "", update.ProjectID, "ai_provider.updated", "ai_provider", update.ID, map[string]interface{}{
			"name":          update.Name,
			"provider_type": update.ProviderType,
			"endpoint":      update.Endpoint,
		})

		writeJSON(w, http.StatusOK, update.ToResponse())

	case http.MethodDelete:
		if err := h.store.DeleteAIProvider(providerID); err != nil {
			writeError(w, http.StatusInternalServerError, "failed to delete provider: "+err.Error())
			return
		}

		h.recordAudit(r, "", projectID, "ai_provider.deleted", "ai_provider", providerID, map[string]interface{}{
			"name":          p.Name,
			"provider_type": p.ProviderType,
		})

		writeJSON(w, http.StatusOK, map[string]string{
			"status": "deleted",
			"id":     providerID,
		})

	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}
