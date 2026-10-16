package cable

import (
	"testing"
)

func TestCableManager_Lifecycle(t *testing.T) {
	mgr := NewManager()

	// 1. List cables
	cables := mgr.ListCables()
	if len(cables) < 4 {
		t.Fatalf("expected at least 4 default submarine cables, got %d", len(cables))
	}

	// 2. Get specific cable (SMW6)
	smw6, err := mgr.GetCable("smw6")
	if err != nil {
		t.Fatalf("expected to find smw6 cable, got %v", err)
	}
	if smw6.Status != StatusOnline {
		t.Errorf("expected smw6 to be online initially, got %s", smw6.Status)
	}
	if smw6.CurrentLatencyMs != 32.0 {
		t.Errorf("expected 32.0ms latency, got %f", smw6.CurrentLatencyMs)
	}

	// 3. Simulate Cable Cut on SMW6
	cutRes, err := mgr.SimulateCableCut("smw6")
	if err != nil {
		t.Fatalf("expected cut to succeed, got %v", err)
	}
	if cutRes.Status != StatusSevered {
		t.Errorf("expected severed status, got %s", cutRes.Status)
	}
	if !cutRes.BGPFailoverTriggered {
		t.Errorf("expected BGP failover to be triggered")
	}
	if cutRes.NewLatencyMs <= 32.0 {
		t.Errorf("expected latency penalty, got %f", cutRes.NewLatencyMs)
	}

	// 4. Duplicate Cut rejection
	_, err = mgr.SimulateCableCut("smw6")
	if err != ErrCableAlreadyCut {
		t.Errorf("expected ErrCableAlreadyCut, got %v", err)
	}

	// 5. Restore Cable
	restoreRes, err := mgr.RestoreCable("smw6")
	if err != nil {
		t.Fatalf("expected restore to succeed, got %v", err)
	}
	if restoreRes.Status != StatusOnline {
		t.Errorf("expected online status, got %s", restoreRes.Status)
	}
	if restoreRes.NewLatencyMs != 32.0 {
		t.Errorf("expected latency to return to 32.0ms, got %f", restoreRes.NewLatencyMs)
	}

	// 6. Duplicate Restore rejection
	_, err = mgr.RestoreCable("smw6")
	if err != ErrCableAlreadyAlive {
		t.Errorf("expected ErrCableAlreadyAlive, got %v", err)
	}
}
