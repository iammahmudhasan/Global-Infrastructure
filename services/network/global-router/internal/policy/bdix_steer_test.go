package policy

import (
	"testing"
)

func TestBDIXPeeringDomesticASN(t *testing.T) {
	engine := NewBDIXSteeringEngine()

	asns := []uint32{202456, 58715, 45786, 24432, 24389}
	for _, asn := range asns {
		decision, err := engine.ResolveSteering("103.10.1.5", "", asn)
		if err != nil {
			t.Fatalf("unexpected error for ASN %d: %v", asn, err)
		}
		if decision.RouteClass != RouteClassBDIXPeering {
			t.Errorf("expected RouteClassBDIXPeering, got %s", decision.RouteClass)
		}
		if decision.BGPCommunity != BGPCommunityBDIXLocal {
			t.Errorf("expected BGPCommunity %s, got %s", BGPCommunityBDIXLocal, decision.BGPCommunity)
		}
		if !decision.PinnedDomestic {
			t.Errorf("expected PinnedDomestic to be true for ASN %d", asn)
		}
		if decision.EstimatedLatency > 5.0 {
			t.Errorf("expected low latency under 5ms, got %.1f", decision.EstimatedLatency)
		}
	}
}

func TestBDIXPeeringDomesticIP(t *testing.T) {
	engine := NewBDIXSteeringEngine()

	bdIPs := []string{"103.14.24.1", "118.67.12.34", "119.30.50.60", "202.4.96.10"}
	for _, ip := range bdIPs {
		decision, err := engine.ResolveSteering("103.1.1.1", ip, 0)
		if err != nil {
			t.Fatalf("unexpected error for BD IP %s: %v", ip, err)
		}
		if decision.RouteClass != RouteClassBDIXPeering {
			t.Errorf("expected RouteClassBDIXPeering for IP %s, got %s", ip, decision.RouteClass)
		}
		if !decision.PinnedDomestic {
			t.Errorf("expected PinnedDomestic true for IP %s", ip)
		}
	}
}

func TestInternationalNominalSMW6(t *testing.T) {
	engine := NewBDIXSteeringEngine()

	decision, err := engine.ResolveSteering("103.1.1.1", "8.8.8.8", 15169)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.RouteClass != RouteClassSubseaTransit {
		t.Errorf("expected RouteClassSubseaTransit, got %s", decision.RouteClass)
	}
	if decision.BGPCommunity != BGPCommunitySMW6Subsea {
		t.Errorf("expected BGPCommunity %s, got %s", BGPCommunitySMW6Subsea, decision.BGPCommunity)
	}
	if decision.PinnedDomestic {
		t.Errorf("expected PinnedDomestic false for international IP")
	}
	if decision.EstimatedLatency != 32.0 {
		t.Errorf("expected nominal latency 32.0ms, got %.1f", decision.EstimatedLatency)
	}
}

func TestSubseaCableCutFailover(t *testing.T) {
	engine := NewBDIXSteeringEngine()
	engine.SetSMW6Status(true) // Simulate cable cut

	if !engine.IsSMW6Severed() {
		t.Fatalf("expected IsSMW6Severed to be true")
	}

	// 1. Domestic BDIX traffic MUST remain completely unaffected
	bdDecision, err := engine.ResolveSteering("103.1.1.1", "103.20.30.40", 202456)
	if err != nil {
		t.Fatalf("unexpected error for domestic: %v", err)
	}
	if bdDecision.RouteClass != RouteClassBDIXPeering {
		t.Errorf("expected domestic to remain BDIX_PEERING during cable cut, got %s", bdDecision.RouteClass)
	}
	if bdDecision.EstimatedLatency > 5.0 {
		t.Errorf("domestic latency must not be penalized, got %.1f", bdDecision.EstimatedLatency)
	}

	// 2. International traffic must failover to Terrestrial Backup with AS-Path prepending
	intlDecision, err := engine.ResolveSteering("103.1.1.1", "1.1.1.1", 13335)
	if err != nil {
		t.Fatalf("unexpected error for intl: %v", err)
	}
	if intlDecision.RouteClass != RouteClassTerrestrialBackup {
		t.Errorf("expected RouteClassTerrestrialBackup, got %s", intlDecision.RouteClass)
	}
	if intlDecision.BGPCommunity != BGPCommunityTerrestrialBackup {
		t.Errorf("expected BGP community %s, got %s", BGPCommunityTerrestrialBackup, intlDecision.BGPCommunity)
	}
	if intlDecision.ASPathPrepend != 3 {
		t.Errorf("expected 3 prepends, got %d", intlDecision.ASPathPrepend)
	}
	if intlDecision.EstimatedLatency < 100.0 {
		t.Errorf("expected penalized latency >= 100ms, got %.1f", intlDecision.EstimatedLatency)
	}
}

func TestInvalidIPInputs(t *testing.T) {
	engine := NewBDIXSteeringEngine()

	_, err := engine.ResolveSteering("invalid-src", "8.8.8.8", 0)
	if err != ErrInvalidSourceIP {
		t.Errorf("expected ErrInvalidSourceIP, got %v", err)
	}

	_, err = engine.ResolveSteering("103.1.1.1", "invalid-dst", 0)
	if err != ErrInvalidDestinationIP {
		t.Errorf("expected ErrInvalidDestinationIP, got %v", err)
	}
}
