package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/auth"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/circuitbreaker"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/registry"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/scheduler"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/telemetry"
)

// BackendSummary minimizes metadata exposure for tenant callers (Finding 8)
type BackendSummary struct {
	ID           string               `json:"id"`
	Provider     string               `json:"provider"`
	Region       string               `json:"region"`
	GPUModel     string               `json:"gpu_model"`
	Endpoint     string               `json:"endpoint"`
	Healthy      bool                 `json:"healthy"`
	CircuitState circuitbreaker.State `json:"circuit_state"`
}

type Server struct {
	auth        *auth.Authenticator
	registry    *registry.Registry
	evaluator   *scheduler.Evaluator
	stopSweeper chan struct{}
}

func NewServer() *Server {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)
	authenticator := auth.NewAuthenticator()

	if os.Getenv("NEXUSEDGE_API_KEYS") == "" && os.Getenv("NEXUSEDGE_DEV_MODE") != "true" {
		log.Println("[INFO] Zero preconfigured API keys loaded. Configure NEXUSEDGE_API_KEYS or set NEXUSEDGE_DEV_MODE=true.")
	}

	s := &Server{
		auth:        authenticator,
		registry:    reg,
		evaluator:   eval,
		stopSweeper: make(chan struct{}),
	}
	s.StartSweeper(1*time.Minute, 15*time.Minute)
	return s
}

func (s *Server) StartSweeper(interval, ttl time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.registry.SweepExpiredReservations(ttl)
			case <-s.stopSweeper:
				return
			}
		}
	}()
}

func (s *Server) Close() {
	select {
	case <-s.stopSweeper:
	default:
		close(s.stopSweeper)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	// 1. Health Endpoints (Rules 41, 44)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"status":"HEALTHY","plane":"control-plane","version":"1.0.0"}`))
	})

	mux.HandleFunc("/readyz", func(w http.ResponseWriter, r *http.Request) {
		backends := s.registry.List()
		healthyCount := 0
		for _, b := range backends {
			if b.Healthy {
				healthyCount++
			}
		}

		if healthyCount == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			w.Write([]byte(`{"status":"NOT_READY","error":"no healthy backends available"}`))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(fmt.Sprintf(`{"status":"READY","healthy_backends":%d}`, healthyCount)))
	})

	// 2. Metrics Endpoint (Prometheus scraper) (Rule 42)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4")
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(telemetry.GlobalMetrics.ExportPrometheus()))
	})

	// 3. Compute Backends Registry API
	mux.HandleFunc("/api/v1/backends", func(w http.ResponseWriter, r *http.Request) {
		backends := s.registry.List()
		isOperator := s.auth.AuthorizeRole(r.Context(), auth.RolePlatformOperator)
		w.Header().Set("Content-Type", "application/json")

		if !isOperator {
			summaries := make([]BackendSummary, 0, len(backends))
			for _, b := range backends {
				summaries = append(summaries, BackendSummary{
					ID:           b.ID,
					Provider:     b.Provider,
					Region:       b.Region,
					GPUModel:     b.GPUModel,
					Endpoint:     "[REDACTED]",
					Healthy:      b.Healthy,
					CircuitState: b.CircuitState,
				})
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"count":    len(summaries),
				"backends": summaries,
			})
			return
		}

		json.NewEncoder(w).Encode(map[string]interface{}{
			"count":    len(backends),
			"backends": backends,
		})
	})

	mux.HandleFunc("/api/v1/backends/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
			return
		}

		if !s.auth.AuthorizeRole(r.Context(), auth.RolePlatformOperator) {
			http.Error(w, `{"error":"forbidden: platform operator role required"}`, http.StatusForbidden)
			return
		}

		var b registry.ComputeBackend
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"Invalid payload: %v"}`, err), http.StatusBadRequest)
			return
		}

		if err := s.registry.Register(&b); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"Registration failed: %v"}`, err), http.StatusConflict)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":  "REGISTERED",
			"backend": b.ID,
		})
	})

	// 4. Phase 0 Core Engine: Multi-Cloud & AI Compute Workload Dispatcher (Rules 110, 111, 112)
	mux.HandleFunc("/api/v1/workload/dispatch", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, `{"error":"Method not allowed. Use POST."}`, http.StatusMethodNotAllowed)
			return
		}

		var policy scheduler.DispatchPolicy
		if err := json.NewDecoder(r.Body).Decode(&policy); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"Invalid policy JSON: %v"}`, err), http.StatusBadRequest)
			return
		}

		// Inject authenticated tenant and project from context as authoritative source of truth (Rules 54, 55)
		tenantID, _ := r.Context().Value(auth.TenantContextKey).(string)
		projectID, _ := r.Context().Value(auth.ProjectContextKey).(string)
		if tenantID != "" {
			policy.TenantID = tenantID
		}
		if projectID != "" {
			policy.ProjectID = projectID
		}

		start := time.Now()
		decision, err := s.evaluator.Evaluate(policy)
		duration := time.Since(start)

		if err != nil {
			telemetry.GlobalMetrics.RecordDispatch(string(policy.Residency), "none", duration, false)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"status":      "DISPATCH_REJECTED",
				"workload_id": policy.WorkloadID,
				"error":       err.Error(),
			})
			return
		}

		telemetry.GlobalMetrics.RecordDispatch(
			string(decision.AssignedBackend.Jurisdiction),
			decision.AssignedBackend.Provider,
			duration,
			true,
		)

		isOperator := s.auth.AuthorizeRole(r.Context(), auth.RolePlatformOperator)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(publicDispatchDecision(decision, isOperator))
	})

	// 5. Workload Completion Lifecycle API (Finding 2)
	mux.HandleFunc("/api/v1/workload/complete", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			WorkloadID string `json:"workload_id"`
			Status     string `json:"status"` // "COMPLETED" or "FAILED"
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid complete request body"})
			return
		}
		if req.WorkloadID == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "workload_id is required"})
			return
		}

		success := !strings.EqualFold(req.Status, "FAILED")
		if err := s.registry.CompleteWorkload(req.WorkloadID, success); err != nil {
			if errors.Is(err, registry.ErrReservationNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": "workload reservation not found"})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "RELEASED",
			"workload_id": req.WorkloadID,
			"outcome":     req.Status,
		})
	})

	// 6. Workload Release API
	mux.HandleFunc("/api/v1/workload/release", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}

		var req struct {
			WorkloadID string `json:"workload_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid release request body"})
			return
		}
		if req.WorkloadID == "" {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "workload_id is required"})
			return
		}

		if err := s.registry.Release(req.WorkloadID); err != nil {
			if errors.Is(err, registry.ErrReservationNotFound) {
				w.WriteHeader(http.StatusNotFound)
				json.NewEncoder(w).Encode(map[string]string{"error": "workload reservation not found"})
				return
			}
			w.WriteHeader(http.StatusInternalServerError)
			json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":      "RELEASED",
			"workload_id": req.WorkloadID,
		})
	})

	// Wrap in middleware chain: Correlation -> BodySizeLimit -> Auth (Rule 6: Dependency Direction)
	handler := s.auth.Middleware(mux)
	handler = bodySizeLimitMiddleware(handler)
	return telemetry.RequestCorrelationMiddleware(handler)
}

func publicDispatchDecision(d *scheduler.DispatchDecision, operator bool) *scheduler.DispatchDecision {
	if d == nil {
		return nil
	}
	cp := *d
	if d.AssignedBackend != nil {
		backend := *d.AssignedBackend
		if !operator {
			backend.Endpoint = "[REDACTED]"
		}
		backend.Breaker = nil
		cp.AssignedBackend = &backend
	}
	if d.ReasonCodes != nil {
		cp.ReasonCodes = append([]string(nil), d.ReasonCodes...)
	}
	if d.Alternatives != nil {
		cp.Alternatives = append([]string(nil), d.Alternatives...)
	}
	return &cp
}

const maxRequestBody = 1 << 20 // 1 MiB

func bodySizeLimitMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil {
			r.Body = http.MaxBytesReader(w, r.Body, maxRequestBody)
		}
		next.ServeHTTP(w, r)
	})
}

func main() {
	server := NewServer()
	defer server.Close()

	port := 9090
	serverAddr := fmt.Sprintf(":%d", port)

	httpServer := &http.Server{
		Addr:         serverAddr,
		Handler:      server.routes(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	log.Printf("=================================================================")
	log.Printf(" NexusEdge Global AI & Compute Traffic Controller (Go Control Plane)")
	log.Printf(" Listening on %s", serverAddr)
	log.Printf(" Multi-Cloud Heterogeneous Placement: AWS, CoreWeave, GCP, Dhaka, IS")
	log.Printf(" Sovereign Enforcement: Bangladesh NDMA 2026, EU GDPR, US, SG")
	log.Printf(" Real-Time Telemetry & Prometheus Scraping at /metrics")
	log.Printf("=================================================================")

	// Graceful shutdown handling (Rule 41)
	shutdownChan := make(chan os.Signal, 1)
	signal.Notify(shutdownChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Control plane fatal server failure: %v", err)
		}
	}()

	<-shutdownChan
	log.Println("Received termination signal. Initiating graceful shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if err := httpServer.Shutdown(ctx); err != nil {
		log.Printf("Forced shutdown encountered error: %v", err)
	}

	log.Println("NexusEdge Control Plane cleanly terminated.")
}
