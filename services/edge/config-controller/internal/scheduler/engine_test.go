package scheduler

import (
	"testing"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/policy"
)

func TestUniversalScheduler_BangladeshBankingSovereignty(t *testing.T) {
	sched := NewUniversalScheduler(nil)

	req := WorkloadRequirement{
		TenantID:             "tenant-cbr-bank",
		ProjectID:            "proj-fintech",
		WorkloadID:           "fintech-tx-01",
		WorkloadType:         "BANKING_API",
		ClientOrigin:         "dhaka",
		RequiredJurisdiction: "BD",
		StrictSovereignty:    true,
		DataClassification:   policy.ClassificationCII,
		MaxLatencyP95MS:      20,
		MaxCostPerHour:       5.0,
		GPUsRequested:        1,
	}

	decision, err := sched.FindOptimalPlacement(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Status != "SCHEDULED" {
		t.Fatalf("expected status SCHEDULED, got %s (reason: %s)", decision.Status, decision.Reason)
	}
	if decision.AssignedNode != "bd-dhaka-dgx01" {
		t.Fatalf("expected node bd-dhaka-dgx01, got %s", decision.AssignedNode)
	}
	if decision.Jurisdiction != "BD" {
		t.Fatalf("expected jurisdiction BD, got %s", decision.Jurisdiction)
	}
	if decision.MeasuredRTTMS != 4 {
		t.Fatalf("expected RTT 4ms, got %d", decision.MeasuredRTTMS)
	}

	// Verify idempotency cache
	decision2, err := sched.FindOptimalPlacement(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision2.RemainingNodeGPUs != decision.RemainingNodeGPUs {
		t.Fatalf("expected idempotency not to double decrement GPUs, got %d vs %d", decision2.RemainingNodeGPUs, decision.RemainingNodeGPUs)
	}
}

func TestUniversalScheduler_GreenEnergyPlacement(t *testing.T) {
	sched := NewUniversalScheduler(nil)

	req := WorkloadRequirement{
		TenantID:        "tenant-ai-research",
		ProjectID:       "proj-batch",
		WorkloadID:      "green-batch-01",
		WorkloadType:    "REASONING_AGENT",
		ClientOrigin:    "frankfurt",
		MaxLatencyP95MS: 100,
		MaxCostPerHour:  2.0,
		PrioritizeGreen: true,
		GPUsRequested:   2,
	}

	decision, err := sched.FindOptimalPlacement(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Status != "SCHEDULED" {
		t.Fatalf("expected status SCHEDULED, got %s", decision.Status)
	}
	if decision.AssignedNode != "is-green-gpu01" {
		t.Fatalf("expected node is-green-gpu01 for green energy, got %s", decision.AssignedNode)
	}
	if decision.CarbonClassification != "LOW_CARBON_RENEWABLE_POWER" {
		t.Fatalf("expected LOW_CARBON_RENEWABLE_POWER, got %s", decision.CarbonClassification)
	}
}

func TestUniversalScheduler_LatencyViolation(t *testing.T) {
	sched := NewUniversalScheduler(nil)

	// An impossible latency budget from Frankfurt (< 10ms for distant nodes)
	req := WorkloadRequirement{
		TenantID:             "tenant-ultra-low",
		ProjectID:            "proj-hft",
		WorkloadID:           "hft-01",
		ClientOrigin:         "frankfurt",
		RequiredJurisdiction: "BD",
		StrictSovereignty:    true,
		MaxLatencyP95MS:      20, // Frankfurt to Dhaka is 130ms, cannot meet 20ms
	}

	decision, err := sched.FindOptimalPlacement(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Status != "UNSCHEDULABLE" {
		t.Fatalf("expected UNSCHEDULABLE, got %s", decision.Status)
	}
}

func TestUniversalScheduler_LivePoPFailoverPenalty(t *testing.T) {
	sched := NewUniversalScheduler(nil)

	// Simulate PoP draining / subsea cable cut on Frankfurt
	sched.UpdatePoPTelemetry("frankfurt", false, "POP_DRAINING", 45.0, 15.0)

	// Require < 50ms from Frankfurt (Iceland is normally 35ms, but with 78ms penalty = 113ms)
	req := WorkloadRequirement{
		TenantID:        "tenant-fra",
		ProjectID:       "proj-fra",
		WorkloadID:      "fra-workload-01",
		ClientOrigin:    "frankfurt",
		MaxLatencyP95MS: 50,
	}

	decision, err := sched.FindOptimalPlacement(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if decision.Status != "UNSCHEDULABLE" {
		t.Fatalf("expected failover penalty to push latency past 50ms, got status %s", decision.Status)
	}
}
