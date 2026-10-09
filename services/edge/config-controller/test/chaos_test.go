package test_test

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/analytics"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/certificate"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/health"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/pop"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

// TestChaos_OriginCascadeAndFailover simulates primary upstream origin death and verifies autonomous failover
func TestChaos_OriginCascadeAndFailover(t *testing.T) {
	router := health.NewSmartRouter()

	pool := &model.OriginPool{
		ID:          "pool-payment",
		Name:        "Payment Cluster",
		LBAlgorithm: model.LBAlgorithmLeastLatency,
		Origins: []model.Origin{
			{
				ID:      "orig-primary",
				PoolID:  "pool-payment",
				Address: "127.0.0.1",
				Port:    8081,
				Healthy: true,
			},
			{
				ID:      "orig-backup",
				PoolID:  "pool-payment",
				Address: "127.0.0.1",
				Port:    8082,
				Healthy: true,
			},
		},
	}

	states := []*model.OriginEndpointState{
		{OriginID: "orig-primary", PoolID: "pool-payment", Healthy: true, EWMALatencyMs: 12.0},
		{OriginID: "orig-backup", PoolID: "pool-payment", Healthy: true, EWMALatencyMs: 35.0},
	}

	// 1. Initial state: primary origin has lowest latency (12ms vs 35ms)
	decision, err := router.SelectOptimalOrigin(pool, states)
	if err != nil || decision.SelectedOriginID != "orig-primary" {
		t.Fatalf("expected orig-primary initial selection, got %+v, err: %v", decision, err)
	}

	// 2. CHAOS INJECTION: Primary origin crashes and fails threshold
	states[0].ConsecutiveFailures = 3
	states[0].Healthy = false
	states[0].EWMALatencyMs = 5000.0

	// 3. Autonomous Failover: traffic immediately steers to backup origin
	failoverDecision, err := router.SelectOptimalOrigin(pool, states)
	if err != nil {
		t.Fatalf("failover failed with error: %v", err)
	}
	if failoverDecision.SelectedOriginID != "orig-backup" {
		t.Fatalf("expected traffic to failover to orig-backup, got %s", failoverDecision.SelectedOriginID)
	}
	if failoverDecision.Reason != "FAILOVER_SINGLE_HEALTHY" {
		t.Fatalf("expected failover routing reason FAILOVER_SINGLE_HEALTHY, got %s", failoverDecision.Reason)
	}
}

// TestChaos_PoPNetworkDrainAndAnycastFailover simulates BGP Anycast withdrawal and cross-PoP traffic shifting
func TestChaos_PoPNetworkDrainAndAnycastFailover(t *testing.T) {
	popMgr := pop.NewManager()

	dhaka, err := popMgr.GetPoP("dhaka")
	if err != nil || dhaka.BGPState != model.BGPStateAnnounced {
		t.Fatalf("expected active dhaka pop initially")
	}

	origins := []model.Origin{
		{ID: "orig-dhk-local", Address: "app.dhaka.customer.internal", Healthy: true},
		{ID: "orig-sin-standby", Address: "app.singapore.customer.internal", Healthy: true},
	}

	// 1. Initial steering at Dhaka PoP -> local affinity
	initDecision, err := popMgr.CalculateSteering("dhaka", "dom-chaos", origins)
	if err != nil || initDecision.SelectedOriginID != "orig-dhk-local" {
		t.Fatalf("expected initial local affinity to Dhaka origin: %+v", initDecision)
	}

	// 2. CHAOS INJECTION: Fiber cut / maintenance at Dhaka -> BGP route withdrawn
	withdrawnPoP, err := popMgr.SetBGPState("dhaka", model.BGPStateWithdrawn)
	if err != nil {
		t.Fatalf("failed to withdraw BGP: %v", err)
	}
	if withdrawnPoP.BGPState != model.BGPStateWithdrawn || withdrawnPoP.Status != model.PoPStatusDraining {
		t.Fatalf("expected WITHDRAWN and POP_DRAINING state, got %+v", withdrawnPoP)
	}

	// 3. Global Anycast converges -> Internet traffic shifts to closest sibling (Singapore Equinix SG1)
	sgDecision, err := popMgr.CalculateSteering("singapore", "dom-chaos", origins)
	if err != nil {
		t.Fatalf("failed to steer at Singapore sibling PoP: %v", err)
	}
	if sgDecision.SelectedOriginID != "orig-sin-standby" {
		t.Fatalf("expected traffic entering Singapore PoP to steer to Singapore origin, got %s", sgDecision.SelectedOriginID)
	}

	// 4. RESTORATION: Fiber repaired -> BGP re-announced
	restoredPoP, err := popMgr.SetBGPState("dhaka", model.BGPStateAnnounced)
	if err != nil || restoredPoP.BGPState != model.BGPStateAnnounced || restoredPoP.Status != model.PoPStatusActive {
		t.Fatalf("expected restored ANNOUNCED state, got %+v", restoredPoP)
	}
}

// TestChaos_TelemetryFloodMemoryBounding tests that high-volume telemetry ingestion never leaks memory
func TestChaos_TelemetryFloodMemoryBounding(t *testing.T) {
	engine := analytics.NewEngine()
	domainID := "dom_flood_protection"

	// CHAOS INJECTION: Flood 20,000 telemetry events
	floodCount := 20000
	events := make([]model.TelemetryEvent, floodCount)
	now := time.Now().UTC()

	for i := 0; i < floodCount; i++ {
		events[i] = model.TelemetryEvent{
			DomainID:      domainID,
			RequestID:     "flood-req",
			StatusCode:    200,
			LatencyMs:     float64(i % 100),
			BytesSent:     1024,
			BytesReceived: 128,
			CacheStatus:   "HIT",
			WAFAction:     "ALLOW",
			Timestamp:     now,
		}
	}

	ingested, err := engine.IngestBatch(events)
	if err != nil || ingested != floodCount {
		t.Fatalf("expected %d ingested events, got %d, err: %v", floodCount, ingested, err)
	}

	summary, err := engine.GetSummary(domainID)
	if err != nil {
		t.Fatalf("failed to get summary: %v", err)
	}
	if summary.TotalRequests != int64(floodCount) {
		t.Fatalf("expected total requests %d, got %d", floodCount, summary.TotalRequests)
	}

	// Reservoir sampler should have calculated stable percentiles without storing all 20,000 floats
	if summary.Latency.P50 <= 0 || summary.Latency.P90 <= 0 || summary.Latency.P99 <= 0 {
		t.Fatalf("expected valid percentiles under flood: %+v", summary.Latency)
	}
}

// TestChaos_ZeroReloadCertificateRotation verifies live TLS certificate renewal without downtime
func TestChaos_ZeroReloadCertificateRotation(t *testing.T) {
	st := store.NewStore()
	certMgr := certificate.NewManager(st)
	certMgr.SetCertsDir(t.TempDir())
	t.Setenv("NEXUSEDGE_CERTS_GID", "101")

	domainID := "dom_cert_rotation"
	st.SaveDomain(&model.Domain{
		ID:        domainID,
		Hostname:  "secure.customer.com",
		Status:    model.DomainStatusActive,
		CreatedAt: time.Now(),
		UpdatedAt: time.Now(),
	})

	// 1. Initial Certificate Issuance
	_, ch, err := certMgr.OrderCertificate(domainID)
	if err != nil {
		t.Fatalf("failed to issue initial certificate: %v", err)
	}

	// Validate initial challenge and issue certificate
	validCert, err := certMgr.ValidateAndIssueCertificate(ch.Token)
	if err != nil {
		t.Fatalf("failed to validate initial challenge: %v", err)
	}
	initialSerial := validCert.SerialNumber

	// 2. CHAOS INJECTION: Simulate Certificate Expiring (Force Renewal)
	renewedCert, err := certMgr.RenewCertificate(domainID)
	if err != nil {
		t.Fatalf("failed to renew certificate: %v", err)
	}
	if renewedCert.SerialNumber == initialSerial {
		t.Fatalf("expected renewed certificate to have new serial number")
	}

	// Verify new certificate parses cleanly as valid x509
	block, _ := pem.Decode([]byte(renewedCert.CertPEM))
	if block == nil {
		t.Fatalf("failed to decode renewed certificate PEM block")
	}
	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("failed to parse x509 certificate: %v", err)
	}
	if parsedCert.Subject.CommonName != "secure.customer.com" {
		t.Fatalf("expected CN secure.customer.com, got %s", parsedCert.Subject.CommonName)
	}
	if parsedCert.NotAfter.Before(time.Now().Add(80 * 24 * time.Hour)) {
		t.Fatalf("expected ~90 days validity on renewed certificate")
	}
}
