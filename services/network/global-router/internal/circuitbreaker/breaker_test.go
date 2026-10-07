package circuitbreaker_test

import (
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/circuitbreaker"
)

func TestCircuitBreakerFullLifecycle(t *testing.T) {
	cb := circuitbreaker.New("cw-gpu-node", 2, 20*time.Millisecond)

	// Step 1: Normal healthy state
	if cb.State() != circuitbreaker.StateClosed {
		t.Fatalf("expected initial state CLOSED, got: %s", cb.State())
	}
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected request allowed, got: %v", err)
	}

	// Step 2: Trigger failures
	cb.RecordFailure()
	if cb.State() != circuitbreaker.StateClosed {
		t.Fatalf("expected still CLOSED after 1 failure, got: %s", cb.State())
	}

	cb.RecordFailure() // Hits threshold 2
	if cb.State() != circuitbreaker.StateOpen {
		t.Fatalf("expected state OPEN after 2 failures, got: %s", cb.State())
	}

	// Step 3: Fast-fail on open
	if err := cb.Allow(); err != circuitbreaker.ErrCircuitOpen {
		t.Fatalf("expected ErrCircuitOpen, got: %v", err)
	}

	// Step 4: Wait for reset timeout
	time.Sleep(30 * time.Millisecond)

	// Step 5: Trial probe in Half-Open
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected trial probe allowed in half-open, got: %v", err)
	}

	// Concurrent request while trial probe is in flight must be rejected
	if err := cb.Allow(); err != circuitbreaker.ErrCircuitOpen {
		t.Fatalf("expected concurrent trial request to be rejected with ErrCircuitOpen, got: %v", err)
	}

	// Step 6: Success restores to closed
	cb.RecordSuccess()
	if cb.State() != circuitbreaker.StateClosed {
		t.Fatalf("expected state restored to CLOSED, got: %s", cb.State())
	}
	if cb.Failures() != 0 {
		t.Errorf("expected failure count reset to 0, got: %d", cb.Failures())
	}
}

func TestCircuitBreaker_ReleaseTrial(t *testing.T) {
	cb := circuitbreaker.New("cw-gpu-trial-node", 1, 15*time.Millisecond)

	// Fail and trip to OPEN
	cb.RecordFailure()
	if cb.State() != circuitbreaker.StateOpen {
		t.Fatalf("expected StateOpen, got: %s", cb.State())
	}

	// Sleep past reset timeout to allow transition to HALF_OPEN
	time.Sleep(20 * time.Millisecond)

	// First probe allowed in HALF_OPEN (trialInFlight becomes true)
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected trial allowed, got: %v", err)
	}

	// Immediate next probe rejected because trial is in flight
	if err := cb.Allow(); err != circuitbreaker.ErrCircuitOpen {
		t.Fatalf("expected ErrCircuitOpen while trial in flight, got: %v", err)
	}

	// Release trial without record success/failure (e.g. reservation race failed)
	cb.ReleaseTrial()

	// Another probe must now be allowed without having to wait for another timeout
	if err := cb.Allow(); err != nil {
		t.Fatalf("expected new trial allowed after ReleaseTrial, got: %v", err)
	}
}
