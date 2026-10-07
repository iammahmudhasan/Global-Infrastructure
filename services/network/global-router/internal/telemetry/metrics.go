package telemetry

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"
)

type contextKey string

const (
	RequestIDKey contextKey = "request_id"
	TraceIDKey   contextKey = "trace_id"
)

// MetricsCollector tracks operational metrics for Prometheus scraping (Rule 42)
type MetricsCollector struct {
	mu                sync.RWMutex
	TotalRequests     atomic.Uint64
	SuccessfulRoutes  atomic.Uint64
	FailedRoutes      atomic.Uint64
	TotalDispatchTime atomic.Uint64 // Cumulative ms
	JurisdictionHits  map[string]uint64
	ProviderHits      map[string]uint64
}

var GlobalMetrics = &MetricsCollector{
	JurisdictionHits: make(map[string]uint64),
	ProviderHits:     make(map[string]uint64),
}

func (m *MetricsCollector) RecordDispatch(jurisdiction, provider string, duration time.Duration, success bool) {
	m.TotalRequests.Add(1)
	m.TotalDispatchTime.Add(uint64(duration.Milliseconds()))

	if success {
		m.SuccessfulRoutes.Add(1)
	} else {
		m.FailedRoutes.Add(1)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	m.JurisdictionHits[jurisdiction]++
	m.ProviderHits[provider]++
}

func (m *MetricsCollector) ExportPrometheus() string {
	m.mu.RLock()
	defer m.mu.RUnlock()

	total := m.TotalRequests.Load()
	success := m.SuccessfulRoutes.Load()
	failed := m.FailedRoutes.Load()
	timeMs := m.TotalDispatchTime.Load()

	avgLat := float64(0)
	if total > 0 {
		avgLat = float64(timeMs) / float64(total)
	}

	out := "# HELP nexusedge_router_requests_total Total workload dispatch requests received\n"
	out += "# TYPE nexusedge_router_requests_total counter\n"
	out += fmt.Sprintf("nexusedge_router_requests_total %d\n", total)

	out += "# HELP nexusedge_router_dispatches_success_total Successful dispatches placed\n"
	out += "# TYPE nexusedge_router_dispatches_success_total counter\n"
	out += fmt.Sprintf("nexusedge_router_dispatches_success_total %d\n", success)

	out += "# HELP nexusedge_router_dispatches_failed_total Failed dispatches\n"
	out += "# TYPE nexusedge_router_dispatches_failed_total counter\n"
	out += fmt.Sprintf("nexusedge_router_dispatches_failed_total %d\n", failed)

	out += "# HELP nexusedge_router_dispatch_latency_ms Average dispatch evaluation latency in milliseconds\n"
	out += "# TYPE nexusedge_router_dispatch_latency_ms gauge\n"
	out += fmt.Sprintf("nexusedge_router_dispatch_latency_ms %.2f\n", avgLat)

	out += "# HELP nexusedge_router_jurisdiction_dispatches Total dispatches partitioned by jurisdiction\n"
	out += "# TYPE nexusedge_router_jurisdiction_dispatches counter\n"
	for jur, count := range m.JurisdictionHits {
		out += fmt.Sprintf("nexusedge_router_jurisdiction_dispatches{jurisdiction=\"%s\"} %d\n", jur, count)
	}

	out += "# HELP nexusedge_router_provider_dispatches Total dispatches partitioned by cloud provider\n"
	out += "# TYPE nexusedge_router_provider_dispatches counter\n"
	for prov, count := range m.ProviderHits {
		out += fmt.Sprintf("nexusedge_router_provider_dispatches{provider=\"%s\"} %d\n", prov, count)
	}

	return out
}

func generateID(prefix string) string {
	b := make([]byte, 8)
	rand.Read(b)
	return fmt.Sprintf("%s-%s", prefix, hex.EncodeToString(b))
}

// RequestCorrelationMiddleware injects request_id and trace_id and records latency (Rules 19, 43)
func RequestCorrelationMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = generateID("req")
		}

		traceID := r.Header.Get("X-Trace-ID")
		if traceID == "" {
			traceID = generateID("trace")
		}

		ctx := context.WithValue(r.Context(), RequestIDKey, reqID)
		ctx = context.WithValue(ctx, TraceIDKey, traceID)

		w.Header().Set("X-Request-ID", reqID)
		w.Header().Set("X-Trace-ID", traceID)

		start := time.Now()
		next.ServeHTTP(w, r.WithContext(ctx))
		duration := time.Since(start)

		// Structured log with zero secrets (Rule 19)
		log.Printf("[HTTP] %s %s | req_id=%s trace_id=%s duration=%s",
			r.Method, r.URL.Path, reqID, traceID, duration)
	})
}
