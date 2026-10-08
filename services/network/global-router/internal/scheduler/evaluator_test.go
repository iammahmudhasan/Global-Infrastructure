package scheduler_test

import (
	"fmt"
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

	if decision1 == decision2 {
		t.Errorf("expected distinct pointer copies for idempotent key to prevent mutation leakage")
	}
	if decision1.WorkloadID != decision2.WorkloadID || decision1.AssignedBackend.ID != decision2.AssignedBackend.ID {
		t.Errorf("expected identical decision contents for idempotent key, got %+v vs %+v", decision1, decision2)
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

func TestCandidateReservationFallback(t *testing.T) {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	// Register a second EU backend so there are multiple eligible candidates
	reg.Register(&registry.ComputeBackend{
		ID:              "hetzner-hel-h100",
		Name:            "Hetzner Helsinki H100",
		Provider:        "hetzner",
		Region:          "eu-north-1",
		Jurisdiction:    registry.ResidencyEU,
		Endpoint:        "https://hel.hetzner.internal/v1",
		GPUModel:        "H100",
		AvailableGPUs:   8,
		HourlyCost:      1.90,
		LatencyP95Ms:    135,
		CarbonIntensity: 150.0,
		Healthy:         true,
	})

	// Pre-reserve all 16 GPUs on the primary EU backend (gcp-fra-vertex-ai)
	err := reg.Reserve("concurrent-workload-x", "gcp-fra-vertex-ai", 16)
	if err != nil {
		t.Fatalf("failed to pre-reserve Frankfurt GPUs: %v", err)
	}

	policy := scheduler.DispatchPolicy{
		WorkloadID:        "workload-fallback-test",
		TenantID:          "tenant-ai",
		Residency:         registry.ResidencyEU,
		StrictSovereignty: true,
		GPUsRequested:     4,
		Objective:         scheduler.ObjectiveCost,
	}

	decision, err := eval.Evaluate(policy)
	if err != nil {
		t.Fatalf("expected placement on alternate candidate, got: %v", err)
	}

	if decision.AssignedBackend.ID != "hetzner-hel-h100" {
		t.Fatalf("expected placement on hetzner-hel-h100, got: %s", decision.AssignedBackend.ID)
	}

	if decision.GPUsAllocated != 4 {
		t.Errorf("expected 4 GPUs allocated, got %d", decision.GPUsAllocated)
	}
}

func TestDeterministicFallbackOrdering(t *testing.T) {
	// Verify that when no eligible candidate satisfies custom strict constraints (without sovereignty),
	// fallback selection is 100% deterministic and reproducible across multiple evaluations.
	var assignedIDs []string

	for i := 0; i < 5; i++ {
		reg := registry.NewRegistry()
		eval := scheduler.NewEvaluator(reg)

		policy := scheduler.DispatchPolicy{
			WorkloadID:        fmt.Sprintf("workload-fallback-%d", i),
			TenantID:          "tenant-test",
			GPUsRequested:     1,
			MaxCostRate:       0.01, // Intentionally impossible budget -> triggers fallback
			StrictSovereignty: false,
			Objective:         scheduler.ObjectiveCost,
		}

		decision, err := eval.Evaluate(policy)
		if err != nil {
			t.Fatalf("run %d: expected fallback placement, got error: %v", i, err)
		}
		if !decision.FallbackUsed {
			t.Fatalf("run %d: expected FallbackUsed to be true", i)
		}
		assignedIDs = append(assignedIDs, decision.AssignedBackend.ID)
	}

	for i := 1; i < len(assignedIDs); i++ {
		if assignedIDs[i] != assignedIDs[0] {
			t.Fatalf("non-deterministic fallback: run 0 selected %s, run %d selected %s",
				assignedIDs[0], i, assignedIDs[i])
		}
	}
}

func TestDeterministicScoreTieBreak(t *testing.T) {
	// Construct two eligible backends with identical metrics (identical composite score)
	// Evaluate repeatedly and assert the lexicographically lower backend ID is always chosen
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	// Register two backends with identical properties except ID
	reg.Register(&registry.ComputeBackend{
		ID:              "cluster-z-backend",
		Name:            "Cluster Z",
		Provider:        "custom",
		Region:          "us-east-1",
		Jurisdiction:    registry.ResidencyUS,
		Endpoint:        "https://z.internal/v1",
		GPUModel:        "A100",
		AvailableGPUs:   16,
		HourlyCost:      2.00,
		CostPer1kTokens: 0.002,
		LatencyP95Ms:    50,
		CarbonIntensity: 100.0,
		Healthy:         true,
	})
	reg.Register(&registry.ComputeBackend{
		ID:              "cluster-a-backend",
		Name:            "Cluster A",
		Provider:        "custom",
		Region:          "us-east-1",
		Jurisdiction:    registry.ResidencyUS,
		Endpoint:        "https://a.internal/v1",
		GPUModel:        "A100",
		AvailableGPUs:   16,
		HourlyCost:      2.00,
		CostPer1kTokens: 0.002,
		LatencyP95Ms:    50,
		CarbonIntensity: 100.0,
		Healthy:         true,
	})

	for i := 0; i < 5; i++ {
		policy := scheduler.DispatchPolicy{
			WorkloadID:    fmt.Sprintf("tie-break-workload-%d", i),
			TenantID:      "tenant-tie",
			RequiredGPU:   "A100",
			GPUsRequested: 1,
			Objective:     scheduler.ObjectiveBalanced,
		}

		decision, err := eval.Evaluate(policy)
		if err != nil {
			t.Fatalf("run %d: evaluate failed: %v", i, err)
		}

		// "cluster-a-backend" < "cluster-z-backend" lexicographically
		if decision.AssignedBackend.ID != "cluster-a-backend" {
			t.Fatalf("run %d: expected deterministic tie-break to select cluster-a-backend, got %s",
				i, decision.AssignedBackend.ID)
		}
	}
}

func TestSchedulerEnforcesCircuitBreakerAdmission(t *testing.T) {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	// Trip the breaker on "bd-dhaka-dgx01" by reporting consecutive failures
	for i := 0; i < 3; i++ {
		reg.UpdateHealth("bd-dhaka-dgx01", 999, false)
	}

	state := reg.CircuitState("bd-dhaka-dgx01")
	if state != circuitbreaker.StateOpen {
		t.Fatalf("expected breaker OPEN, got %s", state)
	}

	// Verify that scheduler rejects assigning to bd-dhaka-dgx01 while breaker is OPEN
	policy := scheduler.DispatchPolicy{
		WorkloadID:        "cb-guard-workload-1",
		TenantID:          "tenant-cbr-banking",
		Residency:         registry.ResidencyBangladesh,
		StrictSovereignty: true,
		Objective:         scheduler.ObjectiveLatency,
	}

	_, err := eval.Evaluate(policy)
	if err == nil {
		t.Fatalf("expected rejection when circuit breaker is OPEN, got nil error")
	}
}

func TestIdempotencyDecisionPointerIsolation(t *testing.T) {
	reg := registry.NewRegistry()
	eval := scheduler.NewEvaluator(reg)

	policy := scheduler.DispatchPolicy{
		WorkloadID:     "idempotent-wl-1",
		TenantID:       "tenant-test",
		ProjectID:      "proj-test",
		IdempotencyKey: "idem-key-isolate",
		Objective:      scheduler.ObjectiveLatency,
	}

	d1, err := eval.Evaluate(policy)
	if err != nil {
		t.Fatalf("first evaluate failed: %v", err)
	}

	origBackend := d1.AssignedBackend.ID
	origGPUs := d1.GPUsAllocated
	origReasonCodesLen := len(d1.ReasonCodes)

	// Mutate the returned decision object
	d1.AssignedBackend.ID = "mutated-backend-id"
	d1.GPUsAllocated = 99999
	d1.ReasonCodes = append(d1.ReasonCodes, "tampered-code")

	// Call Evaluate again with same idempotency key
	d2, err := eval.Evaluate(policy)
	if err != nil {
		t.Fatalf("second evaluate failed: %v", err)
	}

	if d2.AssignedBackend.ID != origBackend {
		t.Errorf("cached decision backend was mutated! Expected %s, got %s", origBackend, d2.AssignedBackend.ID)
	}
	if d2.GPUsAllocated != origGPUs {
		t.Errorf("cached decision GPUs was mutated! Expected %d, got %d", origGPUs, d2.GPUsAllocated)
	}
	if len(d2.ReasonCodes) != origReasonCodesLen {
		t.Errorf("cached decision reason codes slice was mutated! Expected len %d, got %d", origReasonCodesLen, len(d2.ReasonCodes))
	}
}

