package registry_test

import (
	"testing"

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
	err := reg.AdmitAndReserve("workload-1", "bd-dhaka-dgx01", 2)
	if err != nil {
		t.Fatalf("expected successful AdmitAndReserve, got: %v", err)
	}

	// Double reservation for same workload must fail
	if err := reg.AdmitAndReserve("workload-1", "bd-dhaka-dgx01", 1); err != registry.ErrReservationExists {
		t.Errorf("expected ErrReservationExists, got: %v", err)
	}

	// 2. Insufficient capacity must fail and release trial
	// bd-dhaka-dgx01 has 8 GPUs total, 2 reserved -> 6 available
	if err := reg.AdmitAndReserve("workload-big", "bd-dhaka-dgx01", 100); err != registry.ErrInsufficientCapacity {
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

	if err := reg.AdmitAndReserve("workload-cb", "bd-dhaka-dgx01", 1); err != circuitbreaker.ErrCircuitOpen {
		t.Errorf("expected ErrCircuitOpen, got: %v", err)
	}
}
