package compiler_test

import (
	"strings"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/compiler"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/onboarding"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestCompiler(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	comp := compiler.NewCompiler(9901, 80, 443)

	// 1. Initial compile: 0 domains -> only HTTP listener before TLS provisioning, 0 clusters
	topologies := st.GetActiveTopologies()
	cfg, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("unexpected compilation error: %v", err)
	}
	if len(cfg.StaticResources.Listeners) != 1 {
		t.Errorf("expected 1 listener (HTTP only before TLS certificates), got %d", len(cfg.StaticResources.Listeners))
	}
	if len(cfg.StaticResources.Clusters) != 0 {
		t.Errorf("expected 0 clusters for unverified store, got %d", len(cfg.StaticResources.Clusters))
	}

	// 2. Onboard domain: still PENDING_VERIFICATION -> should NOT be in active topologies
	res, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-test-01",
		Hostname:       "api.customer.com",
		OriginAddress:  "origin.customer.com",
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
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	_, err = svc.VerifyDomain(res.DomainID)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	cfg, err = comp.Compile(st.GetActiveTopologies())
	if err != nil {
		t.Fatalf("compile error: %v", err)
	}

	// Only 1 listener (HTTP :80) before active TLS certificates are provisioned
	if len(cfg.StaticResources.Listeners) != 1 {
		t.Fatalf("expected 1 listener (HTTP only before TLS certificates), got %d", len(cfg.StaticResources.Listeners))
	}

	var originCluster *compiler.Cluster
	var acmeCluster *compiler.Cluster
	for i := range cfg.StaticResources.Clusters {
		c := &cfg.StaticResources.Clusters[i]
		if strings.HasPrefix(c.Name, "cluster_") {
			originCluster = c
		} else if c.Name == "acme_challenge_service" {
			acmeCluster = c
		}
	}
	if originCluster == nil {
		t.Fatalf("expected customer origin cluster to be generated")
	}
	if acmeCluster == nil {
		t.Fatalf("expected acme_challenge_service cluster to be defined without dangling reference")
	}
	if originCluster.TransportSocket == nil {
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
	if !strings.Contains(jsonStr, "origin.customer.com") {
		t.Errorf("expected JSON config to contain origin address origin.customer.com")
	}
	if !strings.Contains(jsonStr, "vh_rate_limit_api_customer_com") {
		t.Errorf("expected JSON config to contain per-vhost rate limiter vh_rate_limit_api_customer_com")
	}
	if !strings.Contains(jsonStr, "envoy.access_loggers.file") || !strings.Contains(jsonStr, "bytes_sent") {
		t.Errorf("expected JSON config to contain structured access log configuration")
	}

	// 4. Add a custom WAF block rule and verify Envoy RBAC filter is generated with tenant isolation
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
	wafStr := string(wafJsonBytes)
	if !strings.Contains(wafStr, "envoy.filters.http.rbac") {
		t.Errorf("expected JSON config to contain envoy.filters.http.rbac filter when WAF block rule is active")
	}
	if !strings.Contains(wafStr, ":authority") || !strings.Contains(wafStr, "api.customer.com") {
		t.Errorf("expected RBAC filter to be tenant-scoped to :authority api.customer.com")
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
		var clusterHC *compiler.Cluster
		for i := range cfgWithHC.StaticResources.Clusters {
			if strings.HasPrefix(cfgWithHC.StaticResources.Clusters[i].Name, "cluster_") {
				clusterHC = &cfgWithHC.StaticResources.Clusters[i]
				break
			}
		}
		if clusterHC == nil {
			t.Fatalf("expected origin cluster to exist")
		}
		if len(clusterHC.HealthChecks) == 0 {
			t.Fatalf("expected cluster to have health_checks configured")
		}
		hcJSON, _ := cfgWithHC.ToJSON()
		if !strings.Contains(string(hcJSON), "http_health_check") || !strings.Contains(string(hcJSON), "/healthz") {
			t.Errorf("expected JSON to contain http_health_check with /healthz")
		}
	}

	// 6. Attach active TLS Certificate and verify DownstreamTlsContext + SNI filter chains
	st.SaveCertificate(&model.Certificate{
		ID:            "cert-active-1",
		DomainID:      res.DomainID,
		Domains:       []string{"api.customer.com"},
		Status:        model.CertStatusActive,
		KeyType:       model.KeyTypeECDSA,
		CertPEM:       "-----BEGIN CERTIFICATE-----\nMIIC...dummy-cert\n-----END CERTIFICATE-----",
		PrivateKeyPEM: "-----BEGIN EC PRIVATE KEY-----\nMHQC...dummy-key\n-----END EC PRIVATE KEY-----",
		ExpiresAt:     time.Now().Add(90 * 24 * time.Hour),
	})

	cfgWithTLS, err := comp.Compile(st.GetActiveTopologies())
	if err != nil {
		t.Fatalf("failed to compile with certificate: %v", err)
	}
	if len(cfgWithTLS.StaticResources.Listeners) != 2 {
		t.Fatalf("expected 2 listeners (HTTP & HTTPS) after TLS provisioned, got %d", len(cfgWithTLS.StaticResources.Listeners))
	}
	hasSDSCluster := false
	for _, c := range cfgWithTLS.StaticResources.Clusters {
		if c.Name == "sds-grpc-cluster" {
			hasSDSCluster = true
			if c.Http2ProtocolOptions == nil {
				t.Fatalf("expected sds-grpc-cluster to have HTTP/2 protocol options enabled for gRPC")
			}
			break
		}
	}
	if !hasSDSCluster {
		t.Fatalf("expected sds-grpc-cluster to be defined in clusters")
	}

	tlsJSON, _ := cfgWithTLS.ToJSON()
	tlsStr := string(tlsJSON)
	if !strings.Contains(tlsStr, "DownstreamTlsContext") {
		t.Errorf("expected JSON to contain DownstreamTlsContext")
	}
	if strings.Contains(tlsStr, "dummy-key") {
		t.Fatalf("CRITICAL SECURITY FLAW: Private key leaked in compiled Envoy configuration!")
	}
	if !strings.Contains(tlsStr, "tls_certificate_sds_secret_configs") {
		t.Errorf("expected SDS configuration in DownstreamTlsContext")
	}
	if !strings.Contains(tlsStr, "api.customer.com") {
		t.Errorf("expected JSON to contain SNI server_names for api.customer.com")
	}
	if !strings.Contains(tlsStr, "/.well-known/acme-challenge/") {
		t.Errorf("expected JSON to contain ACME challenge route bypass on port 80")
	}

	// 7. Verify CompileForPoP injects x-nexusedge-pop header
	popCfg, err := comp.CompileForPoP("dhaka", st.GetActiveTopologies())
	if err != nil {
		t.Fatalf("failed to compile for pop: %v", err)
	}
	popJSON, _ := popCfg.ToJSON()
	popStr := string(popJSON)
	if !strings.Contains(popStr, "x-nexusedge-pop") || !strings.Contains(popStr, "dhaka") {
		t.Errorf("expected pop config to contain x-nexusedge-pop: dhaka header")
	}
}
