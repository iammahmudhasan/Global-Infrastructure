package test_test

import (
	"fmt"
	"math/rand"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/analytics"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/cache"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/health"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/pop"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/security"
)

// BenchmarkWAF_Inspection measures throughput of OWASP CRS rule matching and IP CIDR lookups
func BenchmarkWAF_Inspection(b *testing.B) {
	wafEngine := security.NewWAFEngine()
	domainID := "dom_bench_waf"

	policy := &model.SecurityPolicy{
		DomainID:        domainID,
		WAFEnabled:      true,
		WAFMode:         "BLOCK",
		OWASPProtection: true,
		WAFRules: []model.WAFRule{
			{
				ID:        "rule-ip-block",
				DomainID:  domainID,
				Name:      "Block Scanner IP",
				MatchType: model.WAFMatchIPCIDR,
				Pattern:   "198.51.100.0/24",
				Action:    model.WAFActionBlock,
				Enabled:   true,
			},
			{
				ID:        "rule-path-admin",
				DomainID:  domainID,
				Name:      "Block Admin Shell",
				MatchType: model.WAFMatchPathPrefix,
				Pattern:   "/admin/shell",
				Action:    model.WAFActionBlock,
				Enabled:   true,
			},
		},
	}

	reqs := []*http.Request{
		mustNewRequest("GET", "http://api.customer.com/api/v1/users?page=1", "203.0.113.1"),
		mustNewRequest("GET", "http://api.customer.com/admin/shell?exec=ls", "203.0.113.2"),
		mustNewRequest("GET", "http://api.customer.com/api/v1/search?q=normal", "198.51.100.5"),
		mustNewRequest("GET", "http://api.customer.com/login?u=' OR 1=1 --", "203.0.113.3"),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		idx := 0
		for pb.Next() {
			req := reqs[idx%len(reqs)]
			_ = wafEngine.EvaluateRequest(req, policy)
			idx++
		}
	})
}

// BenchmarkCache_KeyNormalization measures deterministic cache key hashing under concurrency
func BenchmarkCache_KeyNormalization(b *testing.B) {
	policy := model.CachePolicy{
		DomainID:             "dom_bench_cache",
		CacheEnabled:         true,
		DefaultTTLSeconds:    300,
		RespectOriginHeaders: true,
		StripCookies:         true,
		CacheRules: []model.CacheRule{
			{
				ID:            "rule-static",
				DomainID:      "dom_bench_cache",
				Name:          "Static Assets",
				PathPattern:   "/static/*",
				TTLSeconds:    86400,
				QueryHandling: model.QueryStringIgnoreSelected,
				IgnoredParams: []string{"utm_source", "utm_medium", "fbclid"},
				Enabled:       true,
			},
		},
	}

	req := mustNewRequest("GET", "http://api.customer.com/static/bundle.js?v=2.1&utm_source=twitter&utm_medium=cpc", "192.0.2.1")
	req.Header.Set("Accept-Encoding", "gzip, br")

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_ = cache.GenerateCacheKey("https", "api.customer.com", "/static/bundle.js", "v=2.1&utm_source=twitter", req.Header, &policy, &policy.CacheRules[0])
		}
	})
}

// BenchmarkHealth_SmartRouting measures EWMA lowest-latency origin selection throughput
func BenchmarkHealth_SmartRouting(b *testing.B) {
	router := health.NewSmartRouter()
	pool := &model.OriginPool{
		ID:          "pool-global",
		LBAlgorithm: model.LBAlgorithmLeastLatency,
		Origins: []model.Origin{
			{
				ID:      "origin-dhk-01",
				PoolID:  "pool-global",
				Address: "198.51.100.20",
				Port:    443,
				Healthy: true,
			},
			{
				ID:      "origin-sin-01",
				PoolID:  "pool-global",
				Address: "198.51.100.21",
				Port:    443,
				Healthy: true,
			},
			{
				ID:      "origin-fra-01",
				PoolID:  "pool-global",
				Address: "198.51.100.22",
				Port:    443,
				Healthy: true,
			},
		},
	}

	states := []*model.OriginEndpointState{
		{OriginID: "origin-dhk-01", Healthy: true, EWMALatencyMs: 14.5},
		{OriginID: "origin-sin-01", Healthy: true, EWMALatencyMs: 38.2},
		{OriginID: "origin-fra-01", Healthy: true, EWMALatencyMs: 130.0},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _ = router.SelectOptimalOrigin(pool, states)
		}
	})
}

// BenchmarkAnalytics_ReservoirSampling measures high-throughput latency percentile sampling
func BenchmarkAnalytics_ReservoirSampling(b *testing.B) {
	sampler := analytics.NewReservoirSampler(2048)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		for pb.Next() {
			sampler.Add(float64(r.Intn(200)))
		}
	})
}

// TestHighConcurrency_Pipeline runs an end-to-end multi-tenant stress test across 50 concurrent workers
func TestHighConcurrency_Pipeline(t *testing.T) {
	wafEngine := security.NewWAFEngine()
	analyticsEngine := analytics.NewEngine()
	popManager := pop.NewManager()

	domainID := "dom_concurrency_stress"
	policy := &model.SecurityPolicy{
		DomainID:   domainID,
		WAFEnabled: true,
		WAFMode:    "BLOCK",
	}

	numWorkers := 50
	requestsPerWorker := 400
	totalExpected := numWorkers * requestsPerWorker

	var wg sync.WaitGroup
	wg.Add(numWorkers)

	startTime := time.Now()

	for w := 0; w < numWorkers; w++ {
		workerID := w
		go func() {
			defer wg.Done()
			for r := 0; r < requestsPerWorker; r++ {
				status := 200
				cacheStatus := "HIT"
				if r%10 == 0 {
					status = 404
					cacheStatus = "MISS"
				}

				// 1. Evaluate WAF
				req := mustNewRequest("GET", fmt.Sprintf("/api/v1/items/%d", r), fmt.Sprintf("192.168.1.%d", workerID%250))
				_ = wafEngine.EvaluateRequest(req, policy)

				// 2. Ingest telemetry
				_ = analyticsEngine.Ingest(model.TelemetryEvent{
					DomainID:      domainID,
					RequestID:     fmt.Sprintf("req-%d-%d", workerID, r),
					StatusCode:    status,
					LatencyMs:     float64(5 + (r % 50)),
					BytesSent:     4096,
					BytesReceived: 512,
					CacheStatus:   cacheStatus,
					WAFAction:     "ALLOW",
					Timestamp:     time.Now().UTC(),
				})
			}
		}()
	}

	wg.Wait()
	duration := time.Since(startTime)

	// Verify Summary
	summary, err := analyticsEngine.GetSummary(domainID)
	if err != nil {
		t.Fatalf("failed to get analytics summary: %v", err)
	}
	if summary.TotalRequests != int64(totalExpected) {
		t.Fatalf("expected %d total requests, got %d", totalExpected, summary.TotalRequests)
	}

	// Verify PoP steering works concurrently
	origins := []model.Origin{
		{ID: "orig-dhk", Address: "app.dhaka.customer.internal", Healthy: true},
		{ID: "orig-sin", Address: "app.singapore.customer.internal", Healthy: true},
	}
	decision, err := popManager.CalculateSteering("dhaka", domainID, origins)
	if err != nil || decision.SelectedOriginID != "orig-dhk" {
		t.Fatalf("unexpected steering decision: %+v, err: %v", decision, err)
	}

	opsPerSec := float64(totalExpected) / duration.Seconds()
	t.Logf("High Concurrency Pipeline Processed %d transactions in %v (%.2f ops/sec)", totalExpected, duration, opsPerSec)
	if opsPerSec < 5000.0 {
		t.Errorf("expected throughput > 5000 ops/sec, achieved %.2f ops/sec", opsPerSec)
	}
}

func mustNewRequest(method, urlStr, clientIP string) *http.Request {
	req, _ := http.NewRequest(method, urlStr, nil)
	req.RemoteAddr = clientIP + ":54321"
	req.Header.Set("X-Forwarded-For", clientIP)
	return req
}
