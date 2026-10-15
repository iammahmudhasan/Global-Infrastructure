package pop

import (
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

func TestPoPManager_DefaultPoPs(t *testing.T) {
	mgr := NewManager()

	pops := mgr.ListPoPs()
	if len(pops) != 4 {
		t.Fatalf("expected 4 default PoPs, got %d", len(pops))
	}

	dhaka, err := mgr.GetPoP("dhaka")
	if err != nil {
		t.Fatalf("expected dhaka PoP to exist: %v", err)
	}
	if dhaka.Country != "BD" || dhaka.ASN != 64512 || dhaka.AnycastIPv4 != "198.51.100.1" {
		t.Fatalf("unexpected dhaka PoP configuration: %+v", dhaka)
	}
	if dhaka.BGPState != model.BGPStateAnnounced || dhaka.Status != model.PoPStatusActive || !dhaka.IsSimulated {
		t.Fatalf("expected dhaka to be active, announced, and simulated, got %s / %s / %v", dhaka.Status, dhaka.BGPState, dhaka.IsSimulated)
	}
}

func TestPoPManager_NodeRegistrationAndHeartbeat(t *testing.T) {
	mgr := NewManager()

	// 1. Register Edge Node in Dhaka
	node, err := mgr.RegisterNode(model.EdgeNode{
		PoPID:               "dhaka",
		Hostname:            "edge-dhk-01.nexusedge.net",
		IPAddress:           "198.51.100.11",
		ActiveConfigVersion: "v1.0.0",
	})
	if err != nil {
		t.Fatalf("failed to register node: %v", err)
	}
	if node.ID == "" || node.PoPID != "dhaka" {
		t.Fatalf("unexpected registered node: %+v", node)
	}

	dhaka, _ := mgr.GetPoP("dhaka")
	if dhaka.NodeCount != 1 || dhaka.HealthyNodeCount != 1 {
		t.Fatalf("expected 1 healthy node, got total %d, healthy %d", dhaka.NodeCount, dhaka.HealthyNodeCount)
	}

	// 2. Heartbeat node
	err = mgr.HeartbeatNode("dhaka", node.ID, 18.5, 4096, 1250)
	if err != nil {
		t.Fatalf("failed to send heartbeat: %v", err)
	}

	nodes := mgr.ListNodes("dhaka")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node in dhaka, got %d", len(nodes))
	}
	if nodes[0].CPUUsagePercent != 18.5 || nodes[0].ActiveConnections != 1250 {
		t.Fatalf("telemetry not updated: %+v", nodes[0])
	}
}

func TestPoPManager_BGPRouteLifecycle(t *testing.T) {
	mgr := NewManager()

	// 1. Withdraw Anycast prefix for maintenance
	pop, err := mgr.SetBGPState("frankfurt", model.BGPStateWithdrawn)
	if err != nil {
		t.Fatalf("failed to withdraw BGP: %v", err)
	}
	if pop.BGPState != model.BGPStateWithdrawn || pop.Status != model.PoPStatusDraining {
		t.Fatalf("expected WITHDRAWN and POP_DRAINING, got %s / %s", pop.BGPState, pop.Status)
	}

	// 2. Re-announce Anycast prefix
	pop, err = mgr.SetBGPState("frankfurt", model.BGPStateAnnounced)
	if err != nil {
		t.Fatalf("failed to announce BGP: %v", err)
	}
	if pop.BGPState != model.BGPStateAnnounced || pop.Status != model.PoPStatusActive {
		t.Fatalf("expected ANNOUNCED and POP_ACTIVE, got %s / %s", pop.BGPState, pop.Status)
	}
}

func TestPoPManager_LatencyMatrixAndSteering(t *testing.T) {
	mgr := NewManager()

	routes := mgr.GetLatencyMatrix()
	if len(routes) == 0 {
		t.Fatalf("expected populated latency matrix")
	}

	origins := []model.Origin{
		{
			ID:      "orig-dhk-local",
			Address: "app.dhaka.customer.internal",
			Healthy: true,
		},
		{
			ID:      "orig-sin-backup",
			Address: "app.singapore.customer.internal",
			Healthy: true,
		},
		{
			ID:      "orig-fra-remote",
			Address: "app.frankfurt.customer.internal",
			Healthy: true,
		},
	}

	// 1. Client at Dhaka -> should choose local Dhaka origin (intra-metro fiber)
	decision, err := mgr.CalculateSteering("dhaka", "dom-test", origins)
	if err != nil {
		t.Fatalf("steering error: %v", err)
	}
	if decision.SelectedOriginID != "orig-dhk-local" {
		t.Fatalf("expected local Dhaka origin, got %s", decision.SelectedOriginID)
	}
	if decision.DirectLatencyMs > 10.0 {
		t.Fatalf("expected intra-metro latency <= 10ms, got %f", decision.DirectLatencyMs)
	}

	// 2. If Dhaka origin goes down -> failover to Singapore (lowest transit RTT ~32ms vs Frankfurt ~125ms)
	origins[0].Healthy = false
	failoverDecision, err := mgr.CalculateSteering("dhaka", "dom-test", origins)
	if err != nil {
		t.Fatalf("failover steering error: %v", err)
	}
	if failoverDecision.SelectedOriginID != "orig-sin-backup" {
		t.Fatalf("expected Singapore failover origin, got %s", failoverDecision.SelectedOriginID)
	}
	if failoverDecision.DirectLatencyMs != 32.0 {
		t.Fatalf("expected 32.0ms SMW6 fiber transit latency, got %f", failoverDecision.DirectLatencyMs)
	}

	// 3. All origins unhealthy
	origins[1].Healthy = false
	origins[2].Healthy = false
	_, err = mgr.CalculateSteering("dhaka", "dom-test", origins)
	if err != ErrNoOrigins {
		t.Fatalf("expected ErrNoOrigins, got %v", err)
	}
}

func TestPoPManager_MultiPoPRoutes(t *testing.T) {
	mgr := NewManager()

	routes := mgr.GetMultiPoPRoutes()
	if len(routes) != 4 {
		t.Fatalf("expected 4 PoP routes, got %d", len(routes))
	}

	expectedPoPs := map[string]string{
		"dhaka":     "asia-south1",
		"singapore": "asia-southeast1",
		"frankfurt": "europe-west3",
		"virginia":  "us-east1",
	}

	for _, r := range routes {
		region, exists := expectedPoPs[r.PoPID]
		if !exists {
			t.Fatalf("unexpected route PoP %s", r.PoPID)
		}
		if r.Region != region {
			t.Fatalf("expected region %s for %s, got %s", region, r.PoPID, r.Region)
		}
		if len(r.FailoverTargets) == 0 {
			t.Fatalf("expected failover targets for %s", r.PoPID)
		}
		if r.Status != "OPTIMAL" {
			t.Fatalf("expected status OPTIMAL, got %s", r.Status)
		}
	}

	// Test specific PoP lookup
	dhkRoute, err := mgr.GetPoPRoute("dhaka")
	if err != nil {
		t.Fatalf("failed to get dhaka route: %v", err)
	}
	if dhkRoute.PrimaryTarget != "bdix-dhaka-direct" || dhkRoute.PrimaryRTTMs != 4.0 {
		t.Fatalf("unexpected dhaka route: %+v", dhkRoute)
	}

	// Non-existent PoP
	_, err = mgr.GetPoPRoute("tokyo")
	if err != ErrRouteNotFound {
		t.Fatalf("expected ErrRouteNotFound, got %v", err)
	}
}

func TestPoPManager_CalculatePoPFailover(t *testing.T) {
	mgr := NewManager()

	// 1. Frankfurt failover -> TAT-14 transatlantic to Virginia (78ms)
	hop, err := mgr.CalculatePoPFailover("frankfurt", false)
	if err != nil {
		t.Fatalf("failed to calculate failover for frankfurt: %v", err)
	}
	if hop.TargetPoP != "virginia" || hop.SLARTTMs != 78.0 {
		t.Fatalf("expected failover to virginia with 78ms, got %+v", hop)
	}

	// 2. Dhaka failover with strict sovereignty enabled -> should be blocked by NDMA-2026
	_, err = mgr.CalculatePoPFailover("dhaka", true)
	if err != ErrSovereigntyViolation {
		t.Fatalf("expected ErrSovereigntyViolation for dhaka with strict sovereignty, got %v", err)
	}

	// 3. Dhaka failover without strict sovereignty -> should select Singapore via SMW6 (32ms)
	hop, err = mgr.CalculatePoPFailover("dhaka", false)
	if err != nil {
		t.Fatalf("expected failover to singapore, got error %v", err)
	}
	if hop.TargetPoP != "singapore" || hop.SLARTTMs != 32.0 {
		t.Fatalf("expected singapore failover with 32ms, got %+v", hop)
	}
}

func TestPoPManager_FailoverAndRestore(t *testing.T) {
	mgr := NewManager()

	// 1. Set failover for Singapore to Dhaka
	err := mgr.SetPoPRouteFailover("singapore", "dhaka")
	if err != nil {
		t.Fatalf("failed to set failover: %v", err)
	}

	route, err := mgr.GetPoPRoute("singapore")
	if err != nil {
		t.Fatalf("failed to get route: %v", err)
	}
	if route.ActiveTarget != "dhaka" || route.Status != "FAILOVER_ENGAGED" {
		t.Fatalf("expected FAILOVER_ENGAGED to dhaka, got %+v", route)
	}

	// 2. Restore primary route
	err = mgr.RestorePoPRoute("singapore")
	if err != nil {
		t.Fatalf("failed to restore route: %v", err)
	}

	route, err = mgr.GetPoPRoute("singapore")
	if err != nil {
		t.Fatalf("failed to get route: %v", err)
	}
	if route.ActiveTarget != route.PrimaryTarget || route.Status != "OPTIMAL" {
		t.Fatalf("expected restored primary target, got %+v", route)
	}
}
