package compiler_test

import (
	"strings"
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
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
	if !strings.Contains(jsonStr, "envoy.filters.http.local_ratelimit") {
		t.Errorf("expected JSON config to contain local_ratelimit HTTP filter")
	}
	if !strings.Contains(jsonStr, "envoy.filters.http.cache") {
		t.Errorf("expected JSON config to contain cache HTTP filter")
	}

	// 4. Add a custom WAF block rule and verify Envoy RBAC filter is generated
	_ = st.AddWAFRule(res.DomainID, model.WAFRule{
		ID:        "rule-admin-block",
		DomainID:  res.DomainID,
		Name:      "block-admin",
		MatchType: model.WAFMatchPathPrefix,
		Pattern:   "/admin",
		Action:    model.WAFActionBlock,
		Enabled:   true,
	})
	cfgWithWAF, err := comp.Compile(st.GetActiveTopologies())
	if err != nil {
		t.Fatalf("failed to compile topology with WAF rule: %v", err)
	}
	wafJsonBytes, _ := cfgWithWAF.ToJSON()
	if !strings.Contains(string(wafJsonBytes), "envoy.filters.http.rbac") {
		t.Errorf("expected JSON config to contain envoy.filters.http.rbac filter when WAF block rule is active")
	}

	// 5. Add HealthMonitor to origin pool and verify Envoy health_checks block
	routes := st.GetRoutes(res.DomainID)
	if len(routes) > 0 {
		poolID := routes[0].PoolID
		st.SaveHealthMonitor(&model.HealthMonitor{
			ID:                 "hm-pool-1",
			PoolID:             poolID,
			Protocol:           model.HealthCheckProtocolHTTP,
			Path:               "/healthz",
			IntervalSeconds:    5,
			TimeoutSeconds:     1,
			HealthyThreshold:   2,
			UnhealthyThreshold: 3,
		})

		cfgWithHC, err := comp.Compile(st.GetActiveTopologies())
		if err != nil {
			t.Fatalf("failed to compile with health monitor: %v", err)
		}
		if len(cfgWithHC.StaticResources.Clusters) == 0 {
			t.Fatalf("expected at least 1 cluster")
		}
		clusterHC := cfgWithHC.StaticResources.Clusters[0]
		if len(clusterHC.HealthChecks) == 0 {
			t.Fatalf("expected cluster to have health_checks configured")
		}
		hcJSON, _ := cfgWithHC.ToJSON()
		if !strings.Contains(string(hcJSON), "http_health_check") || !strings.Contains(string(hcJSON), "/healthz") {
			t.Errorf("expected JSON to contain http_health_check with /healthz")
		}
	}
}
