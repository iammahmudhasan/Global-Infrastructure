package compiler_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net"
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
	t.Setenv("NEXUSEDGE_ENV", "test")
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

func TestCompiler_ExactRateLimitAndClusterTLS(t *testing.T) {
	comp := compiler.NewCompiler(9901, 80, 443)
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	t.Setenv("NEXUSEDGE_ENV", "test")

	res, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj_test",
		Hostname:       "ratelimit.example.com",
		OriginAddress:  "origin.example.com",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("onboard error: %v", err)
	}

	_, err = svc.VerifyDomain(res.DomainID)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	// Set Rate Limit to 1200 RPM
	secPolicy := &model.SecurityPolicy{
		DomainID:         res.DomainID,
		RateLimitEnabled: true,
		RateLimitRPM:     1200,
	}
	st.SaveSecurityPolicy(secPolicy)

	cfg, err := comp.Compile(st.GetActiveTopologies())
	if err != nil {
		t.Fatalf("compilation failed: %v", err)
	}

	cfgJSON, _ := cfg.ToJSON()
	cfgStr := string(cfgJSON)

	// Verify exact RPM math: max_tokens: 1200, tokens_per_fill: 1200, fill_interval: 60s
	if !strings.Contains(cfgStr, `"fill_interval": "60s"`) {
		t.Errorf("expected rate limit fill_interval to be exact '60s'")
	}
	if !strings.Contains(cfgStr, `"tokens_per_fill": 1200`) {
		t.Errorf("expected tokens_per_fill to be exactly 1200")
	}
	if !strings.Contains(cfgStr, `"max_tokens": 1200`) {
		t.Errorf("expected max_tokens to be exactly 1200")
	}

	// 2. Add an origin pool with mixed HTTP and HTTPS to verify cluster does NOT attach TransportSocket
	mixedPool := &model.OriginPool{
		ID:          "pool_mixed",
		ProjectID:   "prj_test",
		Name:        "mixed-pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		Origins: []model.Origin{
			{
				ID:       "orig_http",
				PoolID:   "pool_mixed",
				Address:  "192.0.2.1",
				Port:     80,
				Protocol: model.ProtocolHTTP,
				Healthy:  true,
			},
			{
				ID:       "orig_https",
				PoolID:   "pool_mixed",
				Address:  "192.0.2.2",
				Port:     443,
				Protocol: model.ProtocolHTTPS,
				Healthy:  true,
			},
		},
	}

	// Verify that store rejects saving mixed origin pool via standard SaveOriginPool
	if err := st.SaveOriginPool(mixedPool); err != store.ErrMixedOriginProtocols {
		t.Errorf("expected ErrMixedOriginProtocols when saving mixed pool, got: %v", err)
	}

	// Save via test fixture bypass to test compiler fallback defense
	st.SaveOriginPoolBypass(mixedPool)

	topologies := st.GetActiveTopologies()
	if len(topologies) > 0 && len(topologies[0].Routes) > 0 {
		topologies[0].Pools[mixedPool.ID] = mixedPool
		topologies[0].Routes[0].PoolID = mixedPool.ID
	}
	cfgMixed, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("compilation with mixed pool failed: %v", err)
	}
	for _, cl := range cfgMixed.StaticResources.Clusters {
		if cl.Name == "cluster_pool_mixed" {
			if cl.TransportSocket != nil {
				t.Fatalf("mixed HTTP/HTTPS pool must NOT attach cluster-level TransportSocket!")
			}
		}
	}
}

func TestCompiler_TLSSettingsAndHSTSIntegration(t *testing.T) {
	comp := compiler.NewCompiler(9901, 80, 443)
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	t.Setenv("NEXUSEDGE_ENV", "test")

	res, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj_tls_test",
		Hostname:       "secure.example.com",
		OriginAddress:  "origin.secure.example.com",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("onboard error: %v", err)
	}

	_, err = svc.VerifyDomain(res.DomainID)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	// Attach active certificate
	st.SaveCertificate(&model.Certificate{
		ID:        "cert-secure-1",
		DomainID:  res.DomainID,
		Status:    model.CertStatusActive,
		CertPEM:   "-----BEGIN CERTIFICATE-----\nMOCK_CERT\n-----END CERTIFICATE-----",
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	})

	// Configure TLSv1.3 and HSTS
	st.SaveTLSSettings(res.DomainID, &model.TLSSettings{
		MinTLSVersion: "TLSv1.3",
		HSTS:          true,
		HSTSMaxAge:    63072000,
	})

	cfg, err := comp.Compile(st.GetActiveTopologies())
	if err != nil {
		t.Fatalf("failed to compile topology with TLS settings: %v", err)
	}

	cfgJSON, _ := cfg.ToJSON()
	cfgStr := string(cfgJSON)

	// Verify TLSv1_3 in DownstreamTlsContext
	if !strings.Contains(cfgStr, `"tls_minimum_protocol_version": "TLSv1_3"`) {
		t.Errorf("expected compiled config to reflect TLSv1_3 minimum protocol version")
	}

	// Verify HSTS response header injection
	if !strings.Contains(cfgStr, "Strict-Transport-Security") || !strings.Contains(cfgStr, "max-age=63072000; includeSubDomains") {
		t.Errorf("expected VirtualHost to include Strict-Transport-Security response header")
	}
}

func TestCompiler_DeterministicOutput(t *testing.T) {
	comp := compiler.NewCompiler(9901, 80, 443)
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	t.Setenv("NEXUSEDGE_ENV", "test")

	// Create 5 different domains with origins and certificates
	hostnames := []string{"zeta.example.com", "alpha.example.com", "beta.example.com", "gamma.example.com", "delta.example.com"}
	for _, h := range hostnames {
		res, err := svc.OnboardDomain(onboarding.OnboardRequest{
			ProjectID:      "prj_determ",
			Hostname:       h,
			OriginAddress:  "origin." + h,
			OriginPort:     443,
			OriginProtocol: "HTTPS",
		})
		if err != nil {
			t.Fatalf("onboard error for %s: %v", h, err)
		}
		if _, err := svc.VerifyDomain(res.DomainID); err != nil {
			t.Fatalf("verify error for %s: %v", h, err)
		}
		st.SaveCertificate(&model.Certificate{
			ID:        "cert-" + res.DomainID,
			DomainID:  res.DomainID,
			Status:    model.CertStatusActive,
			CertPEM:   "-----BEGIN CERTIFICATE-----\nMOCK\n-----END CERTIFICATE-----",
			ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
		})
	}

	topologies := st.GetActiveTopologies()
	if len(topologies) != len(hostnames) {
		t.Fatalf("expected %d topologies, got %d", len(hostnames), len(topologies))
	}

	// Compile once to establish golden checksum and JSON
	firstCfg, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("initial compile failed: %v", err)
	}
	firstJSON, err := firstCfg.ToJSON()
	if err != nil {
		t.Fatalf("failed to marshal first json: %v", err)
	}
	firstHash := sha256.Sum256(firstJSON)
	firstChecksum := hex.EncodeToString(firstHash[:])

	// Compile 30 times and verify that every run produces the exact identical JSON and SHA-256 checksum
	for i := 0; i < 30; i++ {
		cfg, err := comp.Compile(topologies)
		if err != nil {
			t.Fatalf("compile run %d failed: %v", i, err)
		}
		jsonBytes, err := cfg.ToJSON()
		if err != nil {
			t.Fatalf("marshal run %d failed: %v", i, err)
		}
		hash := sha256.Sum256(jsonBytes)
		checksum := hex.EncodeToString(hash[:])

		if checksum != firstChecksum {
			t.Fatalf("non-deterministic compile detected on iteration %d: expected checksum %s, got %s", i, firstChecksum, checksum)
		}
		if string(jsonBytes) != string(firstJSON) {
			t.Fatalf("non-deterministic JSON content detected on iteration %d", i)
		}
	}
}

func TestCompiler_EnforceHTTPS_Behavior(t *testing.T) {
	comp := compiler.NewCompiler(9901, 80, 443)
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	t.Setenv("NEXUSEDGE_ENV", "test")

	// Domain 1: cert active + EnforceHTTPS = true
	res1, _ := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj_https_1",
		Hostname:       "redirect.example.com",
		OriginAddress:  "origin1.example.com",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	svc.VerifyDomain(res1.DomainID)
	st.SaveCertificate(&model.Certificate{
		ID:        "cert-1",
		DomainID:  res1.DomainID,
		Status:    model.CertStatusActive,
		CertPEM:   "-----BEGIN CERTIFICATE-----\nCERT1\n-----END CERTIFICATE-----",
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	})
	st.SaveTLSSettings(res1.DomainID, &model.TLSSettings{
		EnforceHTTPS:  true,
		MinTLSVersion: "TLSv1.2",
	})

	// Domain 2: cert active + EnforceHTTPS = false
	res2, _ := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj_https_2",
		Hostname:       "direct.example.com",
		OriginAddress:  "origin2.example.com",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	svc.VerifyDomain(res2.DomainID)
	st.SaveCertificate(&model.Certificate{
		ID:        "cert-2",
		DomainID:  res2.DomainID,
		Status:    model.CertStatusActive,
		CertPEM:   "-----BEGIN CERTIFICATE-----\nCERT2\n-----END CERTIFICATE-----",
		ExpiresAt: time.Now().Add(90 * 24 * time.Hour),
	})
	st.SaveTLSSettings(res2.DomainID, &model.TLSSettings{
		EnforceHTTPS:  false,
		MinTLSVersion: "TLSv1.2",
	})

	// Domain 3: no cert (HTTP direct)
	res3, _ := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj_https_3",
		Hostname:       "nocert.example.com",
		OriginAddress:  "origin3.example.com",
		OriginPort:     80,
		OriginProtocol: "HTTP",
	})
	svc.VerifyDomain(res3.DomainID)

	topologies := st.GetActiveTopologies()
	cfg, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	// Listeners: Port 80 HTTP listener and Port 443 HTTPS listener must both exist
	if len(cfg.StaticResources.Listeners) != 2 {
		t.Fatalf("expected 2 listeners (HTTP + HTTPS), got %d", len(cfg.StaticResources.Listeners))
	}

	var httpListener *compiler.Listener
	var httpsListener *compiler.Listener
	for i := range cfg.StaticResources.Listeners {
		l := &cfg.StaticResources.Listeners[i]
		if l.Address.SocketAddress.PortValue == 80 {
			httpListener = l
		} else if l.Address.SocketAddress.PortValue == 443 {
			httpsListener = l
		}
	}
	if httpListener == nil || httpsListener == nil {
		t.Fatalf("expected both HTTP (:80) and HTTPS (:443) listeners")
	}

	// Inspect HTTP listener virtual hosts
	httpHCM := httpListener.FilterChains[0].Filters[0].TypedConfig
	httpRouteCfg := httpHCM["route_config"].(map[string]interface{})
	httpVhosts := httpRouteCfg["virtual_hosts"].([]compiler.VirtualHost)

	vhostMap := make(map[string]compiler.VirtualHost)
	for _, vh := range httpVhosts {
		vhostMap[vh.Domains[0]] = vh
	}

	// Domain 1 (redirect.example.com):
	// Must have ACME challenge route first, then "/" HTTPS redirect
	vh1, ok := vhostMap["redirect.example.com"]
	if !ok {
		t.Fatalf("missing vhost for redirect.example.com")
	}
	if len(vh1.Routes) < 2 {
		t.Fatalf("expected at least 2 routes for redirect.example.com, got %d", len(vh1.Routes))
	}
	if vh1.Routes[0].Match.Prefix != "/.well-known/acme-challenge/" {
		t.Errorf("expected route 0 to be ACME challenge bypass, got %s", vh1.Routes[0].Match.Prefix)
	}
	if vh1.Routes[1].Redirect == nil || !vh1.Routes[1].Redirect.HttpsRedirect {
		t.Errorf("expected route 1 to have HttpsRedirect: true for redirect.example.com")
	}

	// Domain 2 (direct.example.com, EnforceHTTPS=false):
	// Must have ACME challenge route first, then direct customer routes (NO HttpsRedirect!)
	vh2, ok := vhostMap["direct.example.com"]
	if !ok {
		t.Fatalf("missing vhost for direct.example.com")
	}
	if len(vh2.Routes) < 2 {
		t.Fatalf("expected at least 2 routes for direct.example.com, got %d", len(vh2.Routes))
	}
	if vh2.Routes[0].Match.Prefix != "/.well-known/acme-challenge/" {
		t.Errorf("expected route 0 to be ACME challenge bypass, got %s", vh2.Routes[0].Match.Prefix)
	}
	for _, r := range vh2.Routes {
		if r.Redirect != nil && r.Redirect.HttpsRedirect {
			t.Errorf("direct.example.com with EnforceHTTPS=false must NOT have HttpsRedirect")
		}
	}
	// Verify customer route to cluster exists on HTTP port 80
	hasClusterRoute := false
	for _, r := range vh2.Routes {
		if r.Route != nil && strings.HasPrefix(r.Route.Cluster, "cluster_") {
			hasClusterRoute = true
			break
		}
	}
	if !hasClusterRoute {
		t.Errorf("direct.example.com on HTTP port 80 must have customer cluster route")
	}

	// Domain 3 (nocert.example.com):
	// Must have ACME challenge route first, then direct customer routes
	vh3, ok := vhostMap["nocert.example.com"]
	if !ok {
		t.Fatalf("missing vhost for nocert.example.com")
	}
	for _, r := range vh3.Routes {
		if r.Redirect != nil && r.Redirect.HttpsRedirect {
			t.Errorf("nocert.example.com without certificate must NOT have HttpsRedirect")
		}
	}
}

func TestCompiler_RoutePriorityOrdering(t *testing.T) {
	comp := compiler.NewCompiler(9901, 80, 443)
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	t.Setenv("NEXUSEDGE_ENV", "test")

	res, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj_prio",
		Hostname:       "priority.example.com",
		OriginAddress:  "root.example.com",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("onboard error: %v", err)
	}
	if _, err := svc.VerifyDomain(res.DomainID); err != nil {
		t.Fatalf("verify error: %v", err)
	}

	// Create two secondary pools
	poolAPI := &model.OriginPool{
		ID:        "pool_api",
		ProjectID: "proj_priority",
		Origins: []model.Origin{
			{ID: "orig_api", PoolID: "pool_api", Address: "api.example.com", Port: 443, Protocol: model.ProtocolHTTPS, Healthy: true},
		},
	}
	poolAuth := &model.OriginPool{
		ID:        "pool_auth",
		ProjectID: "proj_priority",
		Origins: []model.Origin{
			{ID: "orig_auth", PoolID: "pool_auth", Address: "auth.example.com", Port: 443, Protocol: model.ProtocolHTTPS, Healthy: true},
		},
	}
	st.SaveOriginPool(poolAPI)
	st.SaveOriginPool(poolAuth)

	// Save routes with different priorities and path lengths:
	// Route 1: "/" (Priority 0)
	// Route 2: "/api" (Priority 10)
	// Route 3: "/api/v1/auth" (Priority 10, longer prefix)
	// Route 4: "/static" (Priority 5)
	st.SaveRoute(&model.Route{ID: "r_root", DomainID: res.DomainID, PoolID: "pool_api", PathPrefix: "/", Priority: 0})
	st.SaveRoute(&model.Route{ID: "r_api", DomainID: res.DomainID, PoolID: "pool_api", PathPrefix: "/api", Priority: 10})
	st.SaveRoute(&model.Route{ID: "r_auth", DomainID: res.DomainID, PoolID: "pool_auth", PathPrefix: "/api/v1/auth", Priority: 10})
	st.SaveRoute(&model.Route{ID: "r_static", DomainID: res.DomainID, PoolID: "pool_api", PathPrefix: "/static", Priority: 5})

	topologies := st.GetActiveTopologies()
	cfg, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	httpHCM := cfg.StaticResources.Listeners[0].FilterChains[0].Filters[0].TypedConfig
	httpRouteCfg := httpHCM["route_config"].(map[string]interface{})
	httpVhosts := httpRouteCfg["virtual_hosts"].([]compiler.VirtualHost)
	vh := httpVhosts[0]

	// Find the customer routes (skipping index 0 which is ACME challenge)
	var prefixes []string
	for _, r := range vh.Routes {
		if r.Match.Prefix != "/.well-known/acme-challenge/" {
			prefixes = append(prefixes, r.Match.Prefix)
		}
	}

	// Expected order:
	// 1. /api/v1/auth (Priority 10, length 12)
	// 2. /api (Priority 10, length 4)
	// 3. /static (Priority 5, length 7)
	// 4. / (Priority 0, length 1)
	expectedOrder := []string{"/api/v1/auth", "/api", "/static", "/"}
	if len(prefixes) < 4 {
		t.Fatalf("expected at least 4 customer routes, got %v", prefixes)
	}
	for i := 0; i < 4; i++ {
		if prefixes[i] != expectedOrder[i] {
			t.Errorf("route index %d mismatch: expected prefix %s, got %s (full order: %v)", i, expectedOrder[i], prefixes[i], prefixes)
		}
	}
}

func TestCompiler_RuntimeDNSRebindingSSRF(t *testing.T) {
	st := store.NewStore()
	svc := onboarding.NewDomainService(st)
	comp := compiler.NewCompiler(9901, 80, 443)

	// Onboard customer domain with FQDN origin
	res, err := svc.OnboardDomain(onboarding.OnboardRequest{
		ProjectID:      "prj-dns-rebinding",
		Hostname:       "app.customer.com",
		OriginAddress:  "customer-origin.example.com",
		OriginPort:     443,
		OriginProtocol: "HTTPS",
	})
	if err != nil {
		t.Fatalf("onboard error: %v", err)
	}

	t.Setenv("NEXUSEDGE_DEV_MODE", "true")
	t.Setenv("NEXUSEDGE_ENV", "test")
	_, err = svc.VerifyDomain(res.DomainID)
	if err != nil {
		t.Fatalf("verify error: %v", err)
	}

	topologies := st.GetActiveTopologies()

	// 1. Initial Resolution: Safe public IP (93.184.216.34)
	comp.SetDNSResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "customer-origin.example.com" {
			return []net.IP{net.ParseIP("93.184.216.34")}, nil
		}
		return nil, net.UnknownNetworkError("nxdomain")
	})

	cfg1, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("compile error on safe dns: %v", err)
	}

	var originCluster1 *compiler.Cluster
	for i := range cfg1.StaticResources.Clusters {
		if strings.HasPrefix(cfg1.StaticResources.Clusters[i].Name, "cluster_") {
			originCluster1 = &cfg1.StaticResources.Clusters[i]
			break
		}
	}
	if originCluster1 == nil {
		t.Fatalf("expected origin cluster to be generated for safe public IP")
	}
	if originCluster1.Type != "STATIC" {
		t.Errorf("expected cluster type STATIC for IP-pinned resolution, got %s", originCluster1.Type)
	}
	if len(originCluster1.LoadAssignment.Endpoints[0].LbEndpoints) != 1 {
		t.Fatalf("expected 1 lb endpoint, got %d", len(originCluster1.LoadAssignment.Endpoints[0].LbEndpoints))
	}
	epAddr := originCluster1.LoadAssignment.Endpoints[0].LbEndpoints[0].Endpoint.Address.SocketAddress.Address
	if epAddr != "93.184.216.34" {
		t.Fatalf("expected pinned endpoint 93.184.216.34, got %s", epAddr)
	}

	// 2. DNS Rebinding / SSRF attack: DNS changes and resolves to 127.0.0.1 (loopback)
	comp.SetDNSResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "customer-origin.example.com" {
			return []net.IP{net.ParseIP("127.0.0.1")}, nil
		}
		return nil, net.UnknownNetworkError("nxdomain")
	})

	cfg2, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("compile error on rebinding dns: %v", err)
	}

	var originCluster2 *compiler.Cluster
	for i := range cfg2.StaticResources.Clusters {
		if strings.HasPrefix(cfg2.StaticResources.Clusters[i].Name, "cluster_") {
			originCluster2 = &cfg2.StaticResources.Clusters[i]
			break
		}
	}
	if originCluster2 != nil {
		for _, loc := range originCluster2.LoadAssignment.Endpoints {
			for _, lbEp := range loc.LbEndpoints {
				addr := lbEp.Endpoint.Address.SocketAddress.Address
				if addr == "127.0.0.1" || strings.HasPrefix(addr, "127.") {
					t.Fatalf("CRITICAL SECURITY VULNERABILITY: DNS rebinding allowed loopback 127.0.0.1 to be installed in Envoy cluster!")
				}
			}
		}
	}

	// 3. DNS Rebinding to Cloud Metadata (169.254.169.254)
	comp.SetDNSResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "customer-origin.example.com" {
			return []net.IP{net.ParseIP("169.254.169.254")}, nil
		}
		return nil, net.UnknownNetworkError("nxdomain")
	})

	cfg3, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("compile error on metadata dns: %v", err)
	}

	for _, cl := range cfg3.StaticResources.Clusters {
		for _, loc := range cl.LoadAssignment.Endpoints {
			for _, lbEp := range loc.LbEndpoints {
				addr := lbEp.Endpoint.Address.SocketAddress.Address
				if addr == "169.254.169.254" {
					t.Fatalf("CRITICAL SECURITY VULNERABILITY: DNS rebinding allowed metadata IP 169.254.169.254 in Envoy cluster!")
				}
			}
		}
	}

	// 4. Mixed resolution containing safe + RFC1918 private IP (10.0.0.1) -> Must reject completely
	comp.SetDNSResolver(func(ctx context.Context, host string) ([]net.IP, error) {
		if host == "customer-origin.example.com" {
			return []net.IP{net.ParseIP("93.184.216.34"), net.ParseIP("10.0.0.1")}, nil
		}
		return nil, net.UnknownNetworkError("nxdomain")
	})

	cfg4, err := comp.Compile(topologies)
	if err != nil {
		t.Fatalf("compile error on mixed dns: %v", err)
	}

	for _, cl := range cfg4.StaticResources.Clusters {
		for _, loc := range cl.LoadAssignment.Endpoints {
			for _, lbEp := range loc.LbEndpoints {
				addr := lbEp.Endpoint.Address.SocketAddress.Address
				if addr == "10.0.0.1" {
					t.Fatalf("CRITICAL SECURITY VULNERABILITY: Mixed DNS resolution allowed private IP 10.0.0.1 in Envoy cluster!")
				}
			}
		}
	}
}

func TestCompiler_DefaultResolverWiresInProduction(t *testing.T) {
	// P1 Finding 1 Verification: NewCompiler MUST have default resolver wired without manual SetDNSResolver
	comp := compiler.NewCompiler(9901, 80, 443)

	pool := &model.OriginPool{
		ID:          "pool_prod_dns",
		ProjectID:   "prj_test",
		Name:        "prod-dns-pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		Origins: []model.Origin{
			{
				ID:       "orig_fqdn_invalid",
				PoolID:   "pool_prod_dns",
				Address:  "unresolvable-domain-xyz-never-exists.invalid",
				Port:     443,
				Protocol: model.ProtocolHTTPS,
				Healthy:  true,
			},
		},
	}

	topo := &store.DomainTopology{
		Domain: &model.Domain{
			ID:        "dom_dns",
			Hostname:  "test-dns.example.com",
			ProjectID: "prj_test",
			Status:    model.DomainStatusActive,
		},
		Routes: []*model.Route{
			{
				ID:         "r_dns",
				DomainID:   "dom_dns",
				PoolID:     pool.ID,
				PathPrefix: "/",
				Priority:   1,
			},
		},
		Pools: map[string]*model.OriginPool{
			pool.ID: pool,
		},
	}

	cfg, err := comp.Compile([]*store.DomainTopology{topo})
	if err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	for _, cl := range cfg.StaticResources.Clusters {
		if cl.Name == "cluster_pool_prod_dns" {
			// Cluster must NOT fall back to STRICT_DNS when resolution fails or is unconfigured
			if cl.Type == "STRICT_DNS" {
				t.Fatalf("CRITICAL SECURITY VULNERABILITY: FQDN origin without resolution fell back to STRICT_DNS!")
			}
			// Cluster should fail-closed with 0 active endpoints
			if len(cl.LoadAssignment.Endpoints[0].LbEndpoints) != 0 {
				t.Fatalf("expected 0 endpoints for unresolvable FQDN origin, got %d", len(cl.LoadAssignment.Endpoints[0].LbEndpoints))
			}
		}
	}
}

func TestCompiler_MultiOriginHTTPSPerEndpointSNI(t *testing.T) {
	// P1/P2 Finding 3 Verification: Multi-origin HTTPS pool generates per-endpoint SNI matches
	comp := compiler.NewCompiler(9901, 80, 443)

	pool := &model.OriginPool{
		ID:          "pool_multi_sni",
		ProjectID:   "prj_test",
		Name:        "multi-sni-pool",
		LBAlgorithm: model.LBAlgorithmRoundRobin,
		Origins: []model.Origin{
			{
				ID:       "orig_1",
				PoolID:   "pool_multi_sni",
				Address:  "192.0.2.10",
				Port:     443,
				Protocol: model.ProtocolHTTPS,
				Healthy:  true,
			},
			{
				ID:       "orig_2",
				PoolID:   "pool_multi_sni",
				Address:  "192.0.2.20",
				Port:     443,
				Protocol: model.ProtocolHTTPS,
				Healthy:  true,
			},
		},
	}

	topo := &store.DomainTopology{
		Domain: &model.Domain{
			ID:        "dom_sni",
			Hostname:  "test-sni.example.com",
			ProjectID: "prj_test",
			Status:    model.DomainStatusActive,
		},
		Routes: []*model.Route{
			{
				ID:         "r_sni",
				DomainID:   "dom_sni",
				PoolID:     pool.ID,
				PathPrefix: "/",
				Priority:   1,
			},
		},
		Pools: map[string]*model.OriginPool{
			pool.ID: pool,
		},
	}

	cfg, err := comp.Compile([]*store.DomainTopology{topo})
	if err != nil {
		t.Fatalf("failed to compile: %v", err)
	}

	var targetCluster *compiler.Cluster
	for i := range cfg.StaticResources.Clusters {
		if cfg.StaticResources.Clusters[i].Name == "cluster_pool_multi_sni" {
			targetCluster = &cfg.StaticResources.Clusters[i]
			break
		}
	}

	if targetCluster == nil {
		t.Fatalf("expected cluster_pool_multi_sni to exist")
	}

	if len(targetCluster.TransportSocketMatches) != 2 {
		t.Fatalf("expected 2 transport socket matches for 2 distinct origins, got %d", len(targetCluster.TransportSocketMatches))
	}

	// Verify each lbEndpoint has metadata match corresponding to its origin address
	for _, ep := range targetCluster.LoadAssignment.Endpoints[0].LbEndpoints {
		meta, ok := ep.Metadata["filter_metadata"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected filter_metadata on lbEndpoint")
		}
		match, ok := meta["envoy.transport_socket_match"].(map[string]interface{})
		if !ok {
			t.Fatalf("expected envoy.transport_socket_match in filter_metadata")
		}
		sniHost, ok := match["sni_host"].(string)
		if !ok || sniHost == "" {
			t.Fatalf("expected non-empty sni_host in endpoint metadata")
		}
	}
}
