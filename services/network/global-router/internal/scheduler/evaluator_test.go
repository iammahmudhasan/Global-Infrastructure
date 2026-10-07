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
		ProjectID:      "proj-alpha",
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

func TestProjectScopedIdempotencyIsolation(t *testing.T) {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	policyA := scheduler.DispatchPolicy{
		WorkloadID:     "workload-p1",
		TenantID:       "tenant-ai-labs",
		ProjectID:      "proj-finance",
		Name:           "Finance Dispatch",
		Residency:      registry.ResidencyUS,
		Objective:      scheduler.ObjectiveCost,
		IdempotencyKey: "shared-key-100",
	}

	policyB := scheduler.DispatchPolicy{
		WorkloadID:     "workload-p2",
		TenantID:       "tenant-ai-labs",
		ProjectID:      "proj-marketing",
		Name:           "Marketing Dispatch",
		Residency:      registry.ResidencyUS,
		Objective:      scheduler.ObjectiveCost,
		IdempotencyKey: "shared-key-100",
	}

	decA, err := eval.Evaluate(policyA)
	if err != nil {
		t.Fatalf("policyA evaluation failed: %v", err)
	}

	decB, err := eval.Evaluate(policyB)
	if err != nil {
		t.Fatalf("policyB evaluation failed: %v", err)
	}

	if decA.WorkloadID == decB.WorkloadID {
		t.Errorf("expected different workloads across projects despite identical idempotency key")
	}
	if decA.ProjectID != "proj-finance" || decB.ProjectID != "proj-marketing" {
		t.Errorf("expected project IDs to be preserved")
	}
}

func TestCapacityDepletionAndReservation(t *testing.T) {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	// bd-dhaka-dgx01 has 8 H100 GPUs default
	b, err := reg.Get("bd-dhaka-dgx01")
	if err != nil {
		t.Fatalf("failed to get bd-dhaka-dgx01: %v", err)
	}
	initialGPUs := b.AvailableGPUs

	// Request 6 GPUs with strict Bangladesh residency
	policy1 := scheduler.DispatchPolicy{
		WorkloadID:        "workload-cap-1",
		TenantID:          "tenant-fintech",
		Residency:         registry.ResidencyBangladesh,
		StrictSovereignty: true,
		GPUsRequested:     6,
		Objective:         scheduler.ObjectiveLatency,
	}

	dec1, err := eval.Evaluate(policy1)
	if err != nil {
		t.Fatalf("expected successful placement for 6 GPUs, got: %v", err)
	}
	if dec1.AssignedBackend.ID != "bd-dhaka-dgx01" {
		t.Fatalf("expected bd-dhaka-dgx01, got: %s", dec1.AssignedBackend.ID)
	}

	bAfter, _ := reg.Get("bd-dhaka-dgx01")
	if bAfter.AvailableGPUs != initialGPUs-6 {
		t.Errorf("expected %d available GPUs, got: %d", initialGPUs-6, bAfter.AvailableGPUs)
	}

	// Request 4 more GPUs with strict Bangladesh residency (only 2 left)
	policy2 := scheduler.DispatchPolicy{
		WorkloadID:        "workload-cap-2",
		TenantID:          "tenant-fintech",
		Residency:         registry.ResidencyBangladesh,
		StrictSovereignty: true,
		GPUsRequested:     4,
		Objective:         scheduler.ObjectiveLatency,
	}

	_, err2 := eval.Evaluate(policy2)
	if err2 == nil {
		t.Fatalf("expected failure due to capacity exhaustion, got nil error")
	}
}
