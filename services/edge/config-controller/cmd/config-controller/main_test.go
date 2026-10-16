package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/api"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestConfigController_AutomatedPoPWatchdogLifecycle(t *testing.T) {
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	t.Setenv("NEXUSEDGE_ENV", "test")

	memStore := store.NewStore()
	domainSvc := onboarding.NewDomainService(memStore)
	envoyCompiler := compiler.NewCompiler(9901, 80, 443)

	handler := api.NewAPIHandler(memStore, domainSvc, envoyCompiler)
	prober := handler.PoPProber()
	if prober == nil {
		t.Fatalf("expected initialized PoPProber on APIHandler")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start prober with fast interval
	prober.Start(ctx, 15*time.Millisecond)
	time.Sleep(50 * time.Millisecond)

	// Verify states are available via HTTP endpoint
	req := httptest.NewRequest(http.MethodGet, "/v1/edge/pops/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for /v1/edge/pops/health, got %d", w.Code)
	}

	prober.Stop()

	// Verify prober can be stopped cleanly without deadlock
	states := prober.GetHealthStates()
	if len(states) != 4 {
		t.Fatalf("expected 4 tracked PoPs, got %d", len(states))
	}
}
