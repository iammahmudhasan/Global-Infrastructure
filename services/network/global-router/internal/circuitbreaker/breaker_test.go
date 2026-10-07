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
