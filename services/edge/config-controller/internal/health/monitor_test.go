package health_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/health"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

func TestMonitor_ProbeSuccessAndThreshold(t *testing.T) {
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	// Mock healthy server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(`{"status":"ok"}`))
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	u, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("failed to parse test server url: %v", err)
	}
	port, _ := strconv.Atoi(u.Port())

	origin := &model.Origin{
		ID:       "orig-1",
		PoolID:   "pool-1",
		Address:  u.Hostname(),
		Port:     port,
		Protocol: model.ProtocolHTTP,
		Healthy:  false, // initially unverified/unhealthy
	}

	monitorConfig := &model.HealthMonitor{
		ID:                  "hm-1",
		PoolID:              "pool-1",
		Protocol:            model.HealthCheckProtocolHTTP,
		Path:                "/healthz",
		Port:                port,
		TimeoutSeconds:      2,
		HealthyThreshold:    2,
		UnhealthyThreshold:  3,
		ExpectedStatusCodes: []int{200},
	}

	m := health.NewMonitor()
	ctx := context.Background()

	// 1st probe: pass 1/2 -> still Healthy: false
	state := m.ProbeEndpoint(ctx, origin, monitorConfig, nil)
	if state.ConsecutivePasses != 1 {
		t.Fatalf("expected 1 pass, got %d", state.ConsecutivePasses)
	}
	if state.Healthy {
		t.Fatalf("expected Healthy=false after only 1 pass (threshold=2)")
	}
	if state.EWMALatencyMs <= 0 {
		t.Errorf("expected EWMA latency to be recorded, got %f", state.EWMALatencyMs)
	}

	// 2nd probe: pass 2/2 -> transitions to Healthy: true!
	state2 := m.ProbeEndpoint(ctx, origin, monitorConfig, state)
	if state2.ConsecutivePasses != 2 {
		t.Fatalf("expected 2 passes, got %d", state2.ConsecutivePasses)
	}
	if !state2.Healthy {
		t.Fatalf("expected Healthy=true after reaching threshold 2")
	}
	if state2.LastStatusCode != 200 {
		t.Errorf("expected status code 200, got %d", state2.LastStatusCode)
	}
}

func TestMonitor_ProbeFailureAndFailoverThreshold(t *testing.T) {
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	// Mock failing server (returns 503)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	u, _ := url.Parse(server.URL)
	port, _ := strconv.Atoi(u.Port())

	origin := &model.Origin{
		ID:       "orig-flaky",
		PoolID:   "pool-1",
		Address:  u.Hostname(),
		Port:     port,
		Protocol: model.ProtocolHTTP,
		Healthy:  true, // initially healthy
	}

	monitorConfig := &model.HealthMonitor{
		ID:                  "hm-1",
		PoolID:              "pool-1",
		Protocol:            model.HealthCheckProtocolHTTP,
		Path:                "/healthz",
		Port:                port,
		TimeoutSeconds:      2,
		HealthyThreshold:    2,
		UnhealthyThreshold:  3,
		ExpectedStatusCodes: []int{200},
	}

	m := health.NewMonitor()
	ctx := context.Background()

	initialState := &model.OriginEndpointState{
		OriginID:      origin.ID,
		PoolID:        origin.PoolID,
		Address:       origin.Address,
		Port:          origin.Port,
		Healthy:       true,
		EWMALatencyMs: 15.0,
	}

	// 1st fail: consecutive failures = 1, still healthy (thresh = 3)
	st1 := m.ProbeEndpoint(ctx, origin, monitorConfig, initialState)
	if st1.ConsecutiveFailures != 1 || !st1.Healthy {
		t.Fatalf("expected 1 failure and Healthy=true, got failures=%d healthy=%v", st1.ConsecutiveFailures, st1.Healthy)
	}

	// 2nd fail: consecutive failures = 2, still healthy
	st2 := m.ProbeEndpoint(ctx, origin, monitorConfig, st1)
	if st2.ConsecutiveFailures != 2 || !st2.Healthy {
		t.Fatalf("expected 2 failures and Healthy=true, got failures=%d healthy=%v", st2.ConsecutiveFailures, st2.Healthy)
	}

	// 3rd fail: consecutive failures = 3, transitions to Healthy: false!
	st3 := m.ProbeEndpoint(ctx, origin, monitorConfig, st2)
	if st3.ConsecutiveFailures != 3 || st3.Healthy {
		t.Fatalf("expected 3 failures and Healthy=false, got failures=%d healthy=%v", st3.ConsecutiveFailures, st3.Healthy)
	}
	if st3.LastStatusCode != 503 {
		t.Errorf("expected last status code 503, got %d", st3.LastStatusCode)
	}
}

func TestSmartRouter_LowestLatencyAndFailover(t *testing.T) {
	router := health.NewSmartRouter()

	pool := &model.OriginPool{
		ID:          "pool-primary",
		ProjectID:   "prj-1",
		Name:        "api-backends",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		Origins: []model.Origin{
			{
				ID:      "orig-fast",
				PoolID:  "pool-primary",
				Address: "10.0.1.10",
				Port:    8080,
				Healthy: true,
			},
			{
				ID:      "orig-slow",
				PoolID:  "pool-primary",
				Address: "10.0.1.20",
				Port:    8080,
				Healthy: true,
			},
		},
	}

	states := []*model.OriginEndpointState{
		{
			OriginID:      "orig-fast",
			PoolID:        "pool-primary",
			Address:       "10.0.1.10",
			Port:          8080,
			Healthy:       true,
			EWMALatencyMs: 8.5,
			LastChecked:   time.Now(),
		},
		{
			OriginID:      "orig-slow",
			PoolID:        "pool-primary",
			Address:       "10.0.1.20",
			Port:          8080,
			Healthy:       true,
			EWMALatencyMs: 42.0,
			LastChecked:   time.Now(),
		},
	}

	// 1. Both healthy: must select lowest EWMA latency (orig-fast)
	decision, err := router.SelectOptimalOrigin(pool, states)
	if err != nil {
		t.Fatalf("unexpected routing error: %v", err)
	}
	if decision.SelectedOriginID != "orig-fast" {
		t.Errorf("expected orig-fast (8.5ms), got %s", decision.SelectedOriginID)
	}
	if decision.Reason != "LOWEST_EWMA_LATENCY" {
		t.Errorf("expected reason LOWEST_EWMA_LATENCY, got %s", decision.Reason)
	}

	// 2. orig-fast fails -> automatic failover to orig-slow
	states[0].Healthy = false
	decisionFailover, err := router.SelectOptimalOrigin(pool, states)
	if err != nil {
		t.Fatalf("unexpected failover routing error: %v", err)
	}
	if decisionFailover.SelectedOriginID != "orig-slow" {
		t.Errorf("expected automatic failover to orig-slow, got %s", decisionFailover.SelectedOriginID)
	}

	// 3. Both origins fail -> returns ErrNoHealthyOrigins
	states[1].Healthy = false
	_, err = router.SelectOptimalOrigin(pool, states)
	if err != health.ErrNoHealthyOrigins {
		t.Errorf("expected ErrNoHealthyOrigins when all backends down, got: %v", err)
	}
}

func TestMonitor_RuntimeSSRFBlocked(t *testing.T) {
	// Ensure dev mode is explicitly off
	t.Setenv("NEXUSEDGE_DEV_MODE", "false")

	m := health.NewMonitor()
	ctx := context.Background()

	blockedTargets := []string{
		"127.0.0.1",
		"169.254.169.254", // Cloud metadata
		"10.0.0.1",        // RFC 1918
	}

	for _, addr := range blockedTargets {
		origin := &model.Origin{
			ID:       "orig-ssrf-attack",
			PoolID:   "pool-1",
			Address:  addr,
			Port:     80,
			Protocol: model.ProtocolHTTP,
			Healthy:  true,
		}

		monitorConfig := &model.HealthMonitor{
			ID:                  "hm-1",
			PoolID:              "pool-1",
			Protocol:            model.HealthCheckProtocolHTTP,
			Path:                "/healthz",
			Port:                80,
			TimeoutSeconds:      1,
			HealthyThreshold:    2,
			UnhealthyThreshold:  1,
			ExpectedStatusCodes: []int{200},
		}

		st := m.ProbeEndpoint(ctx, origin, monitorConfig, nil)
		if st.Healthy {
			t.Errorf("expected origin with address %s to be blocked and marked unhealthy", addr)
		}
		if st.ConsecutiveFailures == 0 {
			t.Errorf("expected failure to be registered for blocked SSRF destination %s", addr)
		}
	}
}
