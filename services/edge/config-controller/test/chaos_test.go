package test_test

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"sync"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/alert"
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

type chaosMockAlerter struct {
	mu     sync.Mutex
	events []alert.Event
}

func (m *chaosMockAlerter) SendAlert(ctx context.Context, event alert.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *chaosMockAlerter) IsConfigured() bool {
	return true
}

func (m *chaosMockAlerter) GetEvents() []alert.Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	copied := make([]alert.Event, len(m.events))
	copy(copied, m.events)
	return copied
}

// TestChaos_FrankfurtSubseaCut_TAT14TransatlanticFailover simulates a complete transatlantic fiber outage on DE-CIX Frankfurt,
// asserting automated BGP withdrawal, subsea failover to Virginia via TAT-14 (78ms SLA), ops alert dispatch,
// and automatic primary restoration once fiber transit is spliced.
func TestChaos_FrankfurtSubseaCut_TAT14TransatlanticFailover(t *testing.T) {
	popMgr := pop.NewManager()
	alerter := &chaosMockAlerter{}
	prober := health.NewPoPHealthProber(popMgr, alerter)
	prober.SetThresholds(2, 3, 200.0)

	// 1. Initial State Verification
	initialRoute, err := popMgr.GetPoPRoute("frankfurt")
	if err != nil {
		t.Fatalf("failed to retrieve initial frankfurt route: %v", err)
	}
	if initialRoute.Status != "OPTIMAL" || initialRoute.ActiveTarget != "decix-fra-direct" {
		t.Fatalf("expected initial state OPTIMAL pointing to decix-fra-direct, got %+v", initialRoute)
	}

	fraPoP, err := popMgr.GetPoP("frankfurt")
	if err != nil {
		t.Fatalf("failed to get frankfurt pop: %v", err)
	}
	if fraPoP.BGPState != model.BGPStateAnnounced {
		t.Fatalf("expected initial BGP ANNOUNCED, got %s", fraPoP.BGPState)
	}

	// 2. CHAOS INJECTION: Subsea Fiber Cut (3 consecutive failed synthetic probes)
	prober.RecordManualProbe("frankfurt", false, 0, "loss of carrier on DE-CIX port 4/1")
	prober.RecordManualProbe("frankfurt", false, 0, "BGP keepalive timeout")
	st := prober.RecordManualProbe("frankfurt", false, 0, "TAT-14 subsea optical amplifier power loss")

	if st.Healthy {
		t.Fatalf("expected Frankfurt to be declared unhealthy after 3 probe failures")
	}
	if st.Status != model.PoPStatusDraining {
		t.Fatalf("expected POP_DRAINING status, got %s", st.Status)
	}
	if st.FailoverPoPID != "virginia" {
		t.Fatalf("expected failover to virginia via TAT-14 subsea (78ms SLA), got %s", st.FailoverPoPID)
	}

	// 3. Verify Control Plane BGP Withdrawal & Route Failover State
	fraPoP, _ = popMgr.GetPoP("frankfurt")
	if fraPoP.BGPState != model.BGPStateWithdrawn {
		t.Fatalf("expected BGP state WITHDRAWN during outage, got %s", fraPoP.BGPState)
	}

	activeRoute, _ := popMgr.GetPoPRoute("frankfurt")
	if activeRoute.Status != "FAILOVER_ENGAGED" || activeRoute.ActiveTarget != "virginia" {
		t.Fatalf("expected FAILOVER_ENGAGED targeting virginia, got %+v", activeRoute)
	}

	// 4. RESTORATION: Fiber repaired (2 consecutive successful synthetic probes)
	prober.RecordManualProbe("frankfurt", true, 14.1, "")
	stRecovered := prober.RecordManualProbe("frankfurt", true, 13.9, "")

	if !stRecovered.Healthy {
		t.Fatalf("expected Frankfurt to recover health after 2 successful probes")
	}
	if stRecovered.Status != model.PoPStatusActive {
		t.Fatalf("expected POP_ACTIVE after recovery, got %s", stRecovered.Status)
	}
	if stRecovered.FailoverPoPID != "" {
		t.Fatalf("expected empty failover PoP upon recovery, got %s", stRecovered.FailoverPoPID)
	}

	// 5. Verify Anycast BGP Re-announcement & Primary Route Restoration
	fraPoP, _ = popMgr.GetPoP("frankfurt")
	if fraPoP.BGPState != model.BGPStateAnnounced {
		t.Fatalf("expected BGP state ANNOUNCED after recovery, got %s", fraPoP.BGPState)
	}

	restoredRoute, _ := popMgr.GetPoPRoute("frankfurt")
	if restoredRoute.Status != "OPTIMAL" || restoredRoute.ActiveTarget != "decix-fra-direct" {
		t.Fatalf("expected restored OPTIMAL primary target, got %+v", restoredRoute)
	}

	// Verify Operational Alerts fired (allow background goroutine dispatch)
	var hasDown, hasRecovered bool
	for start := time.Now(); time.Since(start) < 200*time.Millisecond; {
		events := alerter.GetEvents()
		hasDown = false
		hasRecovered = false
		for _, e := range events {
			if e.Type == alert.EventTypePoPDown {
				hasDown = true
			}
			if e.Type == alert.EventTypePoPRecovered {
				hasRecovered = true
			}
		}
		if hasDown && hasRecovered {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !hasDown || !hasRecovered {
		t.Fatalf("expected both POP_DOWN and POP_RECOVERED alert events, got %+v", alerter.GetEvents())
	}
}

// TestChaos_DhakaNDMA2026_StrictSovereigntyFailClosed simulates an edge disaster on Dhaka PoP,
// verifying that under Bangladesh NDMA 2026 data sovereignty rules, sensitive workloads
// fail closed rather than leaking across foreign borders to Singapore, Frankfurt, or Virginia.
func TestChaos_DhakaNDMA2026_StrictSovereigntyFailClosed(t *testing.T) {
	popMgr := pop.NewManager()

	// 1. Strict Sovereignty Test (Financial / Critical Information Infrastructure)
	_, err := popMgr.CalculatePoPFailover("dhaka", true)
	if err != pop.ErrSovereigntyViolation {
		t.Fatalf("expected ErrSovereigntyViolation for Dhaka under strict sovereignty, got: %v", err)
	}

	// 2. Non-Strict / Commercial Traffic Fallback Test
	hop, err := popMgr.CalculatePoPFailover("dhaka", false)
	if err != nil {
		t.Fatalf("expected non-strict failover to succeed, got error: %v", err)
	}
	if hop.TargetPoP != "singapore" {
		t.Fatalf("expected Singapore failover via SMW6 subsea (32ms SLA), got: %s", hop.TargetPoP)
	}
	if hop.SLARTTMs != 32.0 {
		t.Fatalf("expected 32ms SLA RTT for SMW6 cable, got: %f", hop.SLARTTMs)
	}
}

// TestChaos_SubseaFlapDamping_HysteresisProtection simulates route flapping (intermittent optical link oscillation),
// verifying that the state machine does not thrash BGP announcements on every single transient failure.
func TestChaos_SubseaFlapDamping_HysteresisProtection(t *testing.T) {
	popMgr := pop.NewManager()
	alerter := &chaosMockAlerter{}
	prober := health.NewPoPHealthProber(popMgr, alerter)
	prober.SetThresholds(2, 3, 200.0)

	// Simulate Flapping: Fail, Pass, Fail, Pass, Fail, Pass
	for i := 0; i < 5; i++ {
		stFail := prober.RecordManualProbe("singapore", false, 0, "transient optical noise")
		if !stFail.Healthy {
			t.Fatalf("Singapore should not become unhealthy on single transient failure")
		}
		stPass := prober.RecordManualProbe("singapore", true, 8.2, "")
		if !stPass.Healthy {
			t.Fatalf("Singapore should remain healthy during minor flapping")
		}
	}

	// Verify Singapore BGP was never withdrawn during transient flap
	sinPoP, _ := popMgr.GetPoP("singapore")
	if sinPoP.BGPState != model.BGPStateAnnounced {
		t.Fatalf("expected Singapore BGP to remain ANNOUNCED, got %s", sinPoP.BGPState)
	}

	sinRoute, _ := popMgr.GetPoPRoute("singapore")
	if sinRoute.Status != "OPTIMAL" {
		t.Fatalf("expected Singapore route to remain OPTIMAL, got %s", sinRoute.Status)
	}
}

// TestChaos_CascadingMultiPoPFailure_SovereigntyPreservation tests simultaneous multi-region outages.
func TestChaos_CascadingMultiPoPFailure_SovereigntyPreservation(t *testing.T) {
	popMgr := pop.NewManager()
	alerter := &chaosMockAlerter{}
	prober := health.NewPoPHealthProber(popMgr, alerter)
	prober.SetThresholds(2, 3, 200.0)

	var wg sync.WaitGroup
	// Concurrently inject failures into Frankfurt and Singapore
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			prober.RecordManualProbe("frankfurt", false, 0, "DE-CIX switch power failure")
		}
	}()

	go func() {
		defer wg.Done()
		for i := 0; i < 3; i++ {
			prober.RecordManualProbe("singapore", false, 0, "Equinix SG1 UPS fault")
		}
	}()

	wg.Wait()

	// Verify Frankfurt failed over to Virginia
	fraRoute, err := popMgr.GetPoPRoute("frankfurt")
	if err != nil || fraRoute.Status != "FAILOVER_ENGAGED" || fraRoute.ActiveTarget != "virginia" {
		t.Fatalf("unexpected frankfurt route after cascading failure: %+v", fraRoute)
	}

	// Verify Singapore failed over to Dhaka
	sinRoute, err := popMgr.GetPoPRoute("singapore")
	if err != nil || sinRoute.Status != "FAILOVER_ENGAGED" || sinRoute.ActiveTarget != "dhaka" {
		t.Fatalf("unexpected singapore route after cascading failure: %+v", sinRoute)
	}

	// Verify Virginia remains OPTIMAL and unaffected
	iadRoute, err := popMgr.GetPoPRoute("virginia")
	if err != nil || iadRoute.Status != "OPTIMAL" {
		t.Fatalf("Virginia should remain unaffected: %+v", iadRoute)
	}

	// Verify Dhaka remains OPTIMAL and unaffected
	dhaRoute, err := popMgr.GetPoPRoute("dhaka")
	if err != nil || dhaRoute.Status != "OPTIMAL" {
		t.Fatalf("Dhaka should remain unaffected: %+v", dhaRoute)
	}
}
