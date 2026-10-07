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
	if dhaka.Country != "BD" || dhaka.ASN != 140685 || dhaka.AnycastIPv4 != "103.150.180.1" {
		t.Fatalf("unexpected dhaka PoP configuration: %+v", dhaka)
	}
	if dhaka.BGPState != model.BGPStateAnnounced || dhaka.Status != model.PoPStatusActive {
		t.Fatalf("expected dhaka to be active and announced, got %s / %s", dhaka.Status, dhaka.BGPState)
	}
}

func TestPoPManager_NodeRegistrationAndHeartbeat(t *testing.T) {
	mgr := NewManager()

	// 1. Register Edge Node in Dhaka
	node, err := mgr.RegisterNode(model.EdgeNode{
		PoPID:               "dhaka",
		Hostname:            "edge-dhk-01.nexusedge.net",
		IPAddress:           "103.150.180.11",
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
