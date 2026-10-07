package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

type APIHandler struct {
	store     *store.Store
	service   *onboarding.DomainService
	compiler  *compiler.Compiler
	mux       *http.ServeMux
}

func NewAPIHandler(s *store.Store, svc *onboarding.DomainService, c *compiler.Compiler) *APIHandler {
	h := &APIHandler{
		store:    s,
		service:  svc,
		compiler: c,
		mux:      http.NewServeMux(),
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

// /v1/domains/{domain_id}[/verify, /origins]
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
