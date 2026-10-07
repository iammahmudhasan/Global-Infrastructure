package scheduler_test

import (
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/circuitbreaker"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/registry"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/scheduler"
)

func TestBangladeshSovereignWorkloadPlacement(t *testing.T) {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	policy := scheduler.DispatchPolicy{
		WorkloadID:        "fintech-cbr-01",
		TenantID:          "tenant-cbr-banking",
		Name:              "Bangladesh Real-Time Clearing Workload",
		Residency:         registry.ResidencyBangladesh,
		StrictSovereignty: true, // Mandated by Bangladesh NDMA 2026
		MaxLatencyMs:      10,
		MaxCostRate:       5.0,
		Objective:         scheduler.ObjectiveLatency,
	}

	decision, err := eval.Evaluate(policy)
	if err != nil {
		t.Fatalf("expected successful placement, got: %v", err)
	}

	if decision.AssignedBackend.ID != "bd-dhaka-dgx01" {
		t.Errorf("expected placement on bd-dhaka-dgx01, got: %s", decision.AssignedBackend.ID)
	}

	if decision.AssignedBackend.Jurisdiction != registry.ResidencyBangladesh {
		t.Errorf("expected BD jurisdiction, got: %s", decision.AssignedBackend.Jurisdiction)
	}

	if decision.FallbackUsed {
		t.Errorf("fallback should not be used for sovereign node")
	}
}

func TestStrictSovereigntyRejection(t *testing.T) {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	// Mark Bangladesh node offline
	reg.UpdateHealth("bd-dhaka-dgx01", 999, false)

	policy := scheduler.DispatchPolicy{
		WorkloadID:        "cbr-audit-99",
		TenantID:          "tenant-cbr-banking",
		Name:              "Strict National Data Audit",
		Residency:         registry.ResidencyBangladesh,
		StrictSovereignty: true, // Must NOT route to AWS/GCP/US
		Objective:         scheduler.ObjectiveBalanced,
	}

	_, err := eval.Evaluate(policy)
	if err == nil {
		t.Fatalf("expected rejection due to strict sovereignty violation, got nil error")
	}
}

func TestZeroCarbonIcelandPlacement(t *testing.T) {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	policy := scheduler.DispatchPolicy{
		WorkloadID:        "batch-reasoning-42",
		TenantID:          "tenant-ai-labs",
		Name:              "DeepSeek Batch Distillation",
		Residency:         registry.ResidencyAny,
		StrictSovereignty: false,
		Objective:         scheduler.ObjectiveCarbon, // Prioritize geothermal / low carbon
	}

	decision, err := eval.Evaluate(policy)
	if err != nil {
		t.Fatalf("expected placement, got error: %v", err)
	}

	if decision.AssignedBackend.ID != "is-green-gpu01" {
		t.Errorf("expected placement on is-green-gpu01, got: %s", decision.AssignedBackend.ID)
	}

	if decision.AssignedBackend.CarbonIntensity > 20.0 {
		t.Errorf("expected low carbon intensity (<20), got: %.1f", decision.AssignedBackend.CarbonIntensity)
	}
}

func TestCircuitBreakerTripping(t *testing.T) {
	cb := circuitbreaker.New("test-upstream", 3, 50*time.Millisecond)

	// Initially closed
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected circuit closed, got: %v", err)
	}

	// 3 consecutive failures
	cb.RecordFailure()
	cb.RecordFailure()
	cb.RecordFailure()

	// Circuit should now be open
	if err := cb.Allow(); err != circuitbreaker.ErrCircuitOpen {
		t.Fatalf("expected circuit OPEN, got: %v", err)
	}

	// Wait for reset timeout
	time.Sleep(60 * time.Millisecond)

	// Should allow trial probe (half-open)
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected trial probe allowed, got: %v", err)
	}

	// Successful probe closes circuit
	cb.RecordSuccess()
	if cb.State() != circuitbreaker.StateClosed {
		t.Errorf("expected circuit state CLOSED, got: %s", cb.State())
	}
}

func TestIdempotency(t *testing.T) {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	policy := scheduler.DispatchPolicy{
		WorkloadID:     "workload-idem-1",
		TenantID:       "tenant-ai-labs",
		Name:           "Idempotent Dispatch",
		Residency:      registry.ResidencyUS,
		Objective:      scheduler.ObjectiveCost,
		IdempotencyKey: "idem-key-abc-123",
	}

	decision1, err := eval.Evaluate(policy)
	if err != nil {
		t.Fatalf("first evaluation failed: %v", err)
	}

	decision2, err := eval.Evaluate(policy)
	if err != nil {
		t.Fatalf("second evaluation failed: %v", err)
	}

	if decision1 != decision2 {
		t.Errorf("expected identical cached pointer for idempotent key")
	}
}
