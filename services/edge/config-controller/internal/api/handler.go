package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/security"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

type APIHandler struct {
	store     *store.Store
	service   *onboarding.DomainService
	compiler  *compiler.Compiler
	wafEngine *security.WAFEngine
	mux       *http.ServeMux
}

func NewAPIHandler(s *store.Store, svc *onboarding.DomainService, c *compiler.Compiler) *APIHandler {
	h := &APIHandler{
		store:     s,
		service:   svc,
		compiler:  c,
		wafEngine: security.NewWAFEngine(),
		mux:       http.NewServeMux(),
	}
	h.registerRoutes()
	return h
}

func (h *APIHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Enable CORS for dashboard access
	w.Header().Set("Access-Control-Allow-Origin", "*")
	w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Request-ID")

	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	h.mux.ServeHTTP(w, r)
}

func (h *APIHandler) registerRoutes() {
	h.mux.HandleFunc("/healthz", h.handleHealthz)
	h.mux.HandleFunc("/v1/projects/", h.handleProjectsRoute)
	h.mux.HandleFunc("/v1/domains/", h.handleDomainsRoute)
	h.mux.HandleFunc("/v1/edge/envoy-config", h.handleEnvoyConfig)
	h.mux.HandleFunc("/v1/edge/topologies", h.handleTopologies)
	h.mux.HandleFunc("/v1/edge/evaluate", h.handleEvaluate)
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

// /v1/domains/{domain_id}[/verify, /origins, /waf/rules, /rate-limits, /security/events]
func (h *APIHandler) handleDomainsRoute(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/v1/domains/")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, http.StatusBadRequest, "domain_id is required")
		return
	}

	domainID := parts[0]

	if len(parts) == 1 {
		// /v1/domains/{domain_id}
		if r.Method == http.MethodGet {
			h.handleGetDomain(w, r, domainID)
			return
		}
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
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
	default:
		writeError(w, http.StatusNotFound, "unknown domain action")
	}
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
		writeError(w, http.StatusNotFound, "domain not found")
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

	var req AddOriginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	if req.Address == "" {
		writeError(w, http.StatusBadRequest, "origin address is required")
		return
	}
	if req.Port == 0 {
		req.Port = 443
	}
	if req.Protocol == "" {
		req.Protocol = "HTTPS"
	}
	if req.Weight == 0 {
		req.Weight = 100
	}

	originID := "orig-" + domainID[:min(len(domainID), 6)] + "-" + strings.ReplaceAll(req.Address, ".", "")[:min(len(req.Address), 6)]
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

	for i := range body.Rules {
		body.Rules[i].ID = "rl-" + generateHex(4)
		body.Rules[i].DomainID = domainID
		body.Rules[i].Enabled = true
		if body.Rules[i].KeyType == "" {
			body.Rules[i].KeyType = "CLIENT_IP"
		}
	}

	if err := h.store.SetRateLimitRules(domainID, body.Rules); err != nil {
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

	result := h.wafEngine.EvaluateRequest(simulatedHTTPReq, secPolicy)

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

	topologies := h.store.GetActiveTopologies()
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"active_topologies_count": len(topologies),
		"topologies":              topologies,
	})
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
