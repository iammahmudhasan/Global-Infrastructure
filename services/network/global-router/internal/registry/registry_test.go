package registry_test

import (
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/circuitbreaker"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/registry"
)

func TestRegistry_DeepCloning(t *testing.T) {
	reg := registry.NewRegistry()

	backend, err := reg.Get("bd-dhaka-dgx01")
	if err != nil {
		t.Fatalf("failed to get backend: %v", err)
	}

	origGPUs := backend.AvailableGPUs
	origLatency := backend.LatencyP95Ms

	// Mutate the returned copy
	backend.AvailableGPUs = 999
	backend.LatencyP95Ms = 0

	// Retrieve again from registry
	fresh, err := reg.Get("bd-dhaka-dgx01")
	if err != nil {
		t.Fatalf("failed to get backend on second read: %v", err)
	}

	if fresh.AvailableGPUs != origGPUs {
		t.Errorf("internal available GPUs was mutated! Expected %d, got %d", origGPUs, fresh.AvailableGPUs)
	}
	if fresh.LatencyP95Ms != origLatency {
		t.Errorf("internal latency was mutated! Expected %d, got %d", origLatency, fresh.LatencyP95Ms)
	}

	// Verify List() also returns isolated deep clones
	backends := reg.List()
	for _, b := range backends {
		if b.ID == "bd-dhaka-dgx01" {
			b.AvailableGPUs = 42
		}
	}

	freshAfterList, _ := reg.Get("bd-dhaka-dgx01")
	if freshAfterList.AvailableGPUs != origGPUs {
		t.Errorf("internal available GPUs was mutated via List! Expected %d, got %d", origGPUs, freshAfterList.AvailableGPUs)
	}
}

func TestRegistry_ReservationLifecycle(t *testing.T) {
	reg := registry.NewRegistry()

	backendID := "bd-dhaka-dgx01"
	b, err := reg.Get(backendID)
	if err != nil {
		t.Fatalf("failed to get backend: %v", err)
	}
	initialGPUs := b.AvailableGPUs

	// 1. Successful reservation
	workloadID := "workload-ai-training-01"
	err = reg.Reserve(workloadID, backendID, 4)
	if err != nil {
		t.Fatalf("expected successful reservation, got: %v", err)
	}

	bAfter, _ := reg.Get(backendID)
	if bAfter.AvailableGPUs != initialGPUs-4 {
		t.Errorf("expected %d GPUs after reserve, got %d", initialGPUs-4, bAfter.AvailableGPUs)
	}

	// 2. Duplicate workload ID should fail
	err = reg.Reserve(workloadID, backendID, 2)
	if err == nil {
		t.Fatalf("expected duplicate workload reservation to fail")
	}

	// 3. Over-reservation should fail
	err = reg.Reserve("workload-greedy", backendID, initialGPUs+10)
	if err == nil {
		t.Fatalf("expected over-reservation to fail with ErrInsufficientCapacity")
	}

	// 4. Release workload capacity
	err = reg.Release(workloadID)
	if err != nil {
		t.Fatalf("expected successful release, got: %v", err)
	}

	bReleased, _ := reg.Get(backendID)
	if bReleased.AvailableGPUs != initialGPUs {
		t.Errorf("expected available GPUs restored to %d, got %d", initialGPUs, bReleased.AvailableGPUs)
	}

	// 5. Releasing already-released workload should fail (prevents phantom capacity explosion)
	err = reg.Release(workloadID)
	if err != registry.ErrReservationNotFound {
		t.Fatalf("expected ErrReservationNotFound on double release, got: %v", err)
	}
}

func TestRegistry_CircuitBreakerIsolationAndDeterministicList(t *testing.T) {
	reg := registry.NewRegistry()

	// 1. Verify Breaker is isolated (nil on clones) while CircuitState is populated
	b, err := reg.Get("bd-dhaka-dgx01")
	if err != nil {
		t.Fatalf("failed to get backend: %v", err)
	}
	if b.Breaker != nil {
		t.Errorf("expected Breaker pointer to be nil on cloned backend, got %v", b.Breaker)
	}
	if b.CircuitState == "" {
		t.Errorf("expected CircuitState to be populated, got empty string")
	}

	// 2. Verify List() is sorted by ID deterministically
	list := reg.List()
	if len(list) < 2 {
		t.Fatalf("expected at least 2 default backends, got %d", len(list))
	}
	for i := 1; i < len(list); i++ {
		if list[i-1].ID >= list[i].ID {
			t.Errorf("expected list to be sorted by ID ascending, but %s >= %s", list[i-1].ID, list[i].ID)
		}
	}
}

func TestRegistry_AdmitAndReserve(t *testing.T) {
	reg := registry.NewRegistry()

	// 1. Normal successful admission and reservation
	err := reg.AdmitAndReserve("workload-1", "tenant-test", "proj-test", "bd-dhaka-dgx01", 2)
	if err != nil {
		t.Fatalf("expected successful AdmitAndReserve, got: %v", err)
	}

	// Double reservation for same workload must fail
	if err := reg.AdmitAndReserve("workload-1", "tenant-test", "proj-test", "bd-dhaka-dgx01", 1); err != registry.ErrReservationExists {
		t.Errorf("expected ErrReservationExists, got: %v", err)
	}

	// 2. Insufficient capacity must fail and release trial
	// bd-dhaka-dgx01 has 8 GPUs total, 2 reserved -> 6 available
	if err := reg.AdmitAndReserve("workload-big", "tenant-test", "proj-test", "bd-dhaka-dgx01", 100); err != registry.ErrInsufficientCapacity {
		t.Errorf("expected ErrInsufficientCapacity, got: %v", err)
	}

	// Release workload-1
	_ = reg.Release("workload-1")

	// 3. Circuit breaker OPEN must reject AdmitAndReserve
	for i := 0; i < 3; i++ {
		reg.UpdateHealth("bd-dhaka-dgx01", 999, false)
	}
	if reg.CircuitState("bd-dhaka-dgx01") != circuitbreaker.StateOpen {
		t.Fatalf("expected StateOpen")
	}

	if err := reg.AdmitAndReserve("workload-cb", "tenant-test", "proj-test", "bd-dhaka-dgx01", 1); err != circuitbreaker.ErrCircuitOpen {
		t.Errorf("expected ErrCircuitOpen, got: %v", err)
	}
}

func TestRegistry_RegisterValidationAndCloning(t *testing.T) {
	reg := registry.NewRegistry()

	// 1. Validation tests
	if err := reg.Register(nil); err != registry.ErrInvalidBackend {
		t.Errorf("expected ErrInvalidBackend for nil backend, got %v", err)
	}

	invalidCases := []*registry.ComputeBackend{
		{ID: "", Endpoint: "https://test.internal", AvailableGPUs: 4, HourlyCost: 1.0, LatencyP95Ms: 10},
		{ID: "test-id", Endpoint: "", AvailableGPUs: 4, HourlyCost: 1.0, LatencyP95Ms: 10},
		{ID: "test-id", Endpoint: "https://test.internal", AvailableGPUs: -1, HourlyCost: 1.0, LatencyP95Ms: 10},
		{ID: "test-id", Endpoint: "https://test.internal", AvailableGPUs: 4, HourlyCost: -0.5, LatencyP95Ms: 10},
		{ID: "test-id", Endpoint: "https://test.internal", AvailableGPUs: 4, HourlyCost: 1.0, LatencyP95Ms: -5},
	}

	for i, tc := range invalidCases {
		if err := reg.Register(tc); err != registry.ErrInvalidBackend {
			t.Errorf("case %d: expected ErrInvalidBackend, got %v", i, err)
		}
	}

	// 2. Successful registration and defensive cloning
	callerBackend := &registry.ComputeBackend{
		ID:            "custom-node-01",
		Region:        "singapore",
		Endpoint:      "https://sgp.internal",
		GPUModel:      "A100",
		AvailableGPUs: 8,
		HourlyCost:    2.50,
		LatencyP95Ms:  25,
		Healthy:       true,
	}

	if err := reg.Register(callerBackend); err != nil {
		t.Fatalf("failed to register valid backend: %v", err)
	}

	// Mutate caller pointer
	callerBackend.AvailableGPUs = 999
	callerBackend.Healthy = false
	callerBackend.HourlyCost = 0.01

	stored, err := reg.Get("custom-node-01")
	if err != nil {
		t.Fatalf("failed to get registered backend: %v", err)
	}

	if stored.AvailableGPUs != 8 {
		t.Errorf("caller mutation leaked into registry! Expected 8, got %d", stored.AvailableGPUs)
	}
	if !stored.Healthy {
		t.Errorf("caller mutation of Healthy leaked into registry!")
	}
	if stored.HourlyCost != 2.50 {
		t.Errorf("caller mutation of HourlyCost leaked into registry! Expected 2.50, got %f", stored.HourlyCost)
	}

	// 3. Duplicate registration
	dup := &registry.ComputeBackend{
		ID:       "custom-node-01",
		Endpoint: "https://sgp2.internal",
	}
	if err := reg.Register(dup); err != registry.ErrDuplicateBackend {
		t.Errorf("expected ErrDuplicateBackend, got %v", err)
	}
}

func TestRegistry_CompleteWorkloadLifecycle(t *testing.T) {
	reg := registry.NewRegistry()

	backendID := "bd-dhaka-dgx01"
	b, err := reg.Get(backendID)
	if err != nil {
		t.Fatalf("failed to get backend: %v", err)
	}
	initialGPUs := b.AvailableGPUs

	workloadID := "wl-execution-01"
	if err := reg.AdmitAndReserve(workloadID, "tenant-test", "proj-test", backendID, 2); err != nil {
		t.Fatalf("failed to reserve workload: %v", err)
	}

	afterReserve, _ := reg.Get(backendID)
	if afterReserve.AvailableGPUs != initialGPUs-2 {
		t.Errorf("expected %d GPUs, got %d", initialGPUs-2, afterReserve.AvailableGPUs)
	}

	// 1. Complete with success
	if err := reg.CompleteWorkload(workloadID, true); err != nil {
		t.Fatalf("expected successful completion, got %v", err)
	}

	afterComplete, _ := reg.Get(backendID)
	if afterComplete.AvailableGPUs != initialGPUs {
		t.Errorf("expected GPUs restored to %d, got %d", initialGPUs, afterComplete.AvailableGPUs)
	}

	// 2. Double complete should return ErrReservationNotFound
	if err := reg.CompleteWorkload(workloadID, true); err != registry.ErrReservationNotFound {
		t.Errorf("expected ErrReservationNotFound, got %v", err)
	}

	// 3. Complete with failure feeds back into circuit breaker
	testBackend := &registry.ComputeBackend{
		ID:            "failing-node-01",
		Region:        "dhaka",
		Endpoint:      "https://fail.internal",
		GPUModel:      "H100",
		AvailableGPUs: 8,
		HourlyCost:    3.0,
		LatencyP95Ms:  50,
		Healthy:       true,
		Breaker:       circuitbreaker.New("failing-node-01", 2, 100*time.Millisecond),
	}
	if err := reg.Register(testBackend); err != nil {
		t.Fatalf("failed to register failing-node-01: %v", err)
	}

	// Trip breaker via workload failure feedback
	if err := reg.AdmitAndReserve("wl-fail-1", "tenant-test", "proj-test", "failing-node-01", 1); err != nil {
		t.Fatalf("admit 1 failed: %v", err)
	}
	_ = reg.CompleteWorkload("wl-fail-1", false)

	if reg.CircuitState("failing-node-01") != circuitbreaker.StateClosed {
		t.Errorf("expected StateClosed after 1 failure (max 2)")
	}

	if err := reg.AdmitAndReserve("wl-fail-2", "tenant-test", "proj-test", "failing-node-01", 1); err != nil {
		t.Fatalf("admit 2 failed: %v", err)
	}
	_ = reg.CompleteWorkload("wl-fail-2", false)

	// Now should be OPEN
	if reg.CircuitState("failing-node-01") != circuitbreaker.StateOpen {
		t.Errorf("expected StateOpen after 2 failures, got %s", reg.CircuitState("failing-node-01"))
	}

	// Subsequent admit must be rejected by circuit breaker
	if err := reg.AdmitAndReserve("wl-blocked", "tenant-test", "proj-test", "failing-node-01", 1); err != circuitbreaker.ErrCircuitOpen {
		t.Errorf("expected ErrCircuitOpen, got %v", err)
	}

	// 4. Safe release without explicit completion cleans up trial and capacity
	workloadSafe := "wl-safe-01"
	if err := reg.AdmitAndReserve(workloadSafe, "tenant-test", "proj-test", backendID, 3); err != nil {
		t.Fatalf("failed to reserve safe workload: %v", err)
	}
	if err := reg.Release(workloadSafe); err != nil {
		t.Fatalf("expected successful release: %v", err)
	}
	restored, _ := reg.Get(backendID)
	if restored.AvailableGPUs != initialGPUs {
		t.Errorf("expected GPUs restored to %d, got %d", initialGPUs, restored.AvailableGPUs)
	}
}

func TestRegistry_SweepExpiredReservations(t *testing.T) {
	reg := registry.NewRegistry()

	backendID := "bd-dhaka-dgx01"
	b, err := reg.Get(backendID)
	if err != nil {
		t.Fatalf("failed to get backend: %v", err)
	}
	initialGPUs := b.AvailableGPUs

	// Reserve capacity with a short 20ms lease for test sweep
	if err := reg.AdmitAndReserve("stale-workload", "tenant-test", "proj-test", backendID, 4, 20*time.Millisecond); err != nil {
		t.Fatalf("failed to reserve workload: %v", err)
	}

	bReserved, _ := reg.Get(backendID)
	if bReserved.AvailableGPUs != initialGPUs-4 {
		t.Fatalf("expected %d GPUs, got %d", initialGPUs-4, bReserved.AvailableGPUs)
	}

	// 1. Sweeping immediately before lease expiry reclaims 0
	swept := reg.SweepExpiredReservations()
	if swept != 0 {
		t.Errorf("expected 0 swept reservations before expiry, got %d", swept)
	}

	// 2. Wait for lease to expire, then sweep reclaims the capacity
	time.Sleep(30 * time.Millisecond)
	swept = reg.SweepExpiredReservations()
	if swept != 1 {
		t.Errorf("expected 1 swept reservation after lease expiry, got %d", swept)
	}

	bRestored, _ := reg.Get(backendID)
	if bRestored.AvailableGPUs != initialGPUs {
		t.Errorf("expected GPUs restored to %d after sweep, got %d", initialGPUs, bRestored.AvailableGPUs)
	}
}

func TestRegistry_OwnershipAndLeaseRenewal(t *testing.T) {
	reg := registry.NewRegistry()
	backendID := "bd-dhaka-dgx01"

	err := reg.AdmitAndReserve("wl-owner-01", "tenant-alpha", "proj-alpha", backendID, 2, 10*time.Minute)
	if err != nil {
		t.Fatalf("expected admission success, got: %v", err)
	}

	// 1. Cross-tenant release -> Forbidden
	err = reg.ReleaseOwned("wl-owner-01", "tenant-beta", "proj-beta", false)
	if err != registry.ErrReservationForbidden {
		t.Fatalf("expected ErrReservationForbidden for cross-tenant release, got: %v", err)
	}

	// 2. Cross-tenant complete -> Forbidden
	err = reg.CompleteWorkloadOwned("wl-owner-01", "tenant-beta", "proj-beta", true, false)
	if err != registry.ErrReservationForbidden {
		t.Fatalf("expected ErrReservationForbidden for cross-tenant complete, got: %v", err)
	}

	// 3. Cross-tenant lease renewal -> Forbidden
	_, err = reg.RenewReservation("wl-owner-01", "tenant-beta", "proj-beta", 30*time.Minute, false)
	if err != registry.ErrReservationForbidden {
		t.Fatalf("expected ErrReservationForbidden for cross-tenant renew, got: %v", err)
	}

	// 4. Authorized owner lease renewal -> Success
	newExpiry, err := reg.RenewReservation("wl-owner-01", "tenant-alpha", "proj-alpha", 45*time.Minute, false)
	if err != nil {
		t.Fatalf("expected successful renewal by owner, got: %v", err)
	}
	if time.Until(newExpiry) < 40*time.Minute {
		t.Errorf("expected extended expiry time, got: %v", newExpiry)
	}

	// 5. Authorized owner release -> Success
	err = reg.ReleaseOwned("wl-owner-01", "tenant-alpha", "proj-alpha", false)
	if err != nil {
		t.Fatalf("expected successful release by owner, got: %v", err)
	}
}

func TestRegistry_ReserveEnforcesCircuitBreaker(t *testing.T) {
	reg := registry.NewRegistry()
	backendID := "bd-dhaka-dgx01"

	// Trip circuit breaker with consecutive failures
	for i := 0; i < 3; i++ {
		reg.UpdateHealth(backendID, 500, false)
	}

	err := reg.Reserve("test-blocked-workload", backendID, 1)
	if err == nil {
		t.Fatalf("expected Reserve to fail when circuit breaker is OPEN")
	}
}

