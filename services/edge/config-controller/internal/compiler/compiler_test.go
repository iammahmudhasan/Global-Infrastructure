package compiler_test

import (
	"strings"
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestCompiler(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	comp := compiler.NewCompiler(9901, 80, 443)

	// 1. Initial compile: 0 domains -> default listeners, 0 clusters
	topologies := st.GetActiveTopologies()
	cfg, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("unexpected compilation error: %v", err)
	}
	if len(cfg.StaticResources.Listeners) != 2 {
		t.Errorf("expected 2 listeners (HTTP & HTTPS), got %d", len(cfg.StaticResources.Listeners))
	}
	if len(cfg.StaticResources.Clusters) != 0 {
		t.Errorf("expected 0 clusters for unverified store, got %d", len(cfg.StaticResources.Clusters))
	}

	// 2. Onboard domain: still PENDING_VERIFICATION -> should NOT be in active topologies
	res, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-test-01",
		Hostname:       "api.customer.com",
		OriginAddress:  "origin.customer.internal",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("onboard error: %v", err)
	}

	cfg, _ = comp.Compile(st.GetActiveTopologies())
	if len(cfg.StaticResources.Clusters) != 0 {
		t.Errorf("unverified domain should not generate upstream clusters")
	}

	// 3. Verify domain: now ACTIVE -> must generate virtual hosts & clusters
	_, err = svc.VerifyDomain(res.DomainID)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	cfg, err = comp.Compile(st.GetActiveTopologies())
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	if len(cfg.StaticResources.Clusters) != 1 {
		t.Fatalf("expected 1 upstream cluster, got %d", len(cfg.StaticResources.Clusters))
	}

	cluster := cfg.StaticResources.Clusters[0]
	if cluster.TransportSocket == nil {
		t.Errorf("expected HTTPS origin to have UpstreamTlsContext transport socket")
	}

	jsonBytes, err := cfg.ToJSON()
	if err != nil {
		t.Fatalf("failed to serialize Envoy config to JSON: %v", err)
	}

	jsonStr := string(jsonBytes)
	if !strings.Contains(jsonStr, "api.customer.com") {
		t.Errorf("expected JSON config to contain customer domain api.customer.com")
	}
	if !strings.Contains(jsonStr, "origin.customer.internal") {
		t.Errorf("expected JSON config to contain origin address origin.customer.internal")
	}
}
