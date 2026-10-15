package health

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/alert"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/pop"
)

type mockAlerter struct {
	mu     sync.Mutex
	events []alert.Event
}

func (m *mockAlerter) SendAlert(ctx context.Context, event alert.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.events = append(m.events, event)
	return nil
}

func (m *mockAlerter) IsConfigured() bool {
	return true
}

func TestPoPHealthProber_DefaultStates(t *testing.T) {
	popMgr := pop.NewManager()
	alerter := &mockAlerter{}
	prober := NewPoPHealthProber(popMgr, alerter)

	states := prober.GetHealthStates()
	if len(states) != 4 {
		t.Fatalf("expected 4 tracked PoPs, got %d", len(states))
	}

	expectedPoPs := map[string]string{
		"dhaka":     "asia-south1",
		"singapore": "asia-southeast1",
		"frankfurt": "europe-west3",
		"virginia":  "us-east1",
	}

	for _, s := range states {
		region, exists := expectedPoPs[s.PoPID]
		if !exists {
			t.Fatalf("unexpected tracked PoP: %s", s.PoPID)
		}
		if s.Region != region {
			t.Fatalf("expected region %s for %s, got %s", region, s.PoPID, s.Region)
		}
		if !s.Healthy || s.Status != model.PoPStatusActive {
			t.Fatalf("expected active and healthy initial state for %s", s.PoPID)
		}
	}
}

func TestPoPHealthProber_ExecuteProbeCycle(t *testing.T) {
	popMgr := pop.NewManager()
	alerter := &mockAlerter{}
	prober := NewPoPHealthProber(popMgr, alerter)

	results := prober.ExecuteProbeCycle(context.Background())
	if len(results) != 4 {
		t.Fatalf("expected 4 probe results, got %d", len(results))
	}

	for id, res := range results {
		if !res.Success {
			t.Fatalf("expected probe success for %s, got err: %s", id, res.Error)
		}
		if res.LatencyMs <= 0 {
			t.Fatalf("expected positive latency for %s, got %f", id, res.LatencyMs)
		}
		if res.StatusCode != 200 {
			t.Fatalf("expected HTTP 200 for %s, got %d", id, res.StatusCode)
		}
	}
}

func TestPoPHealthProber_FailoverAndRecoveryAutomation(t *testing.T) {
	popMgr := pop.NewManager()
	alerter := &mockAlerter{}
	prober := NewPoPHealthProber(popMgr, alerter)
	prober.SetThresholds(2, 3, 200.0)

	// 1. Simulate 3 probe failures on Frankfurt
	prober.RecordManualProbe("frankfurt", false, 0, "connection timeout to transit switch")
	prober.RecordManualProbe("frankfurt", false, 0, "BGP peer flap")
	st := prober.RecordManualProbe("frankfurt", false, 0, "loss of carrier on DE-CIX port")

	if st.Healthy {
		t.Fatalf("expected Frankfurt to be marked unhealthy after 3 failures")
	}
	if st.Status != model.PoPStatusDraining {
		t.Fatalf("expected status POP_DRAINING, got %s", st.Status)
	}
	if st.FailoverPoPID != "virginia" {
		t.Fatalf("expected failover to virginia on TAT-14 transatlantic cable, got %s", st.FailoverPoPID)
	}

	// Verify PoP Manager BGP withdrawal
	fraPoP, err := popMgr.GetPoP("frankfurt")
	if err != nil {
		t.Fatalf("failed to get frankfurt pop: %v", err)
	}
	if fraPoP.BGPState != model.BGPStateWithdrawn {
		t.Fatalf("expected BGP state WITHDRAWN, got %s", fraPoP.BGPState)
	}

	// Verify PoP route is in FAILOVER_ENGAGED state
	fraRoute, err := popMgr.GetPoPRoute("frankfurt")
	if err != nil {
		t.Fatalf("failed to get frankfurt route: %v", err)
	}
	if fraRoute.Status != "FAILOVER_ENGAGED" || fraRoute.ActiveTarget != "virginia" {
		t.Fatalf("expected FAILOVER_ENGAGED to virginia, got %+v", fraRoute)
	}

	// 2. Simulate 2 probe passes for recovery
	prober.RecordManualProbe("frankfurt", true, 14.1, "")
	stRecovered := prober.RecordManualProbe("frankfurt", true, 13.9, "")

	if !stRecovered.Healthy {
		t.Fatalf("expected Frankfurt to be marked healthy after 2 passes")
	}
	if stRecovered.Status != model.PoPStatusActive {
		t.Fatalf("expected status POP_ACTIVE, got %s", stRecovered.Status)
	}
	if stRecovered.FailoverPoPID != "" {
		t.Fatalf("expected empty failover target upon recovery, got %s", stRecovered.FailoverPoPID)
	}

	// Verify PoP Manager BGP re-announced
	fraPoP, _ = popMgr.GetPoP("frankfurt")
	if fraPoP.BGPState != model.BGPStateAnnounced {
		t.Fatalf("expected BGP state ANNOUNCED, got %s", fraPoP.BGPState)
	}

	// Verify PoP route restored to primary target
	fraRoute, _ = popMgr.GetPoPRoute("frankfurt")
	if fraRoute.Status != "OPTIMAL" || fraRoute.ActiveTarget != fraRoute.PrimaryTarget {
		t.Fatalf("expected restored primary route, got %+v", fraRoute)
	}
}

func TestPoPHealthProber_BackgroundLoop(t *testing.T) {
	popMgr := pop.NewManager()
	alerter := &mockAlerter{}
	prober := NewPoPHealthProber(popMgr, alerter)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	prober.Start(ctx, 10*time.Millisecond)
	time.Sleep(50 * time.Millisecond)
	prober.Stop()

	// Prober should have executed at least 1 probe
	states := prober.GetHealthStates()
	if len(states) == 0 {
		t.Fatalf("expected populated states")
	}

	// Query individual PoP state
	dhk, err := prober.GetHealthState("dhaka")
	if err != nil {
		t.Fatalf("failed to get dhaka state: %v", err)
	}
	if dhk.PoPID != "dhaka" {
		t.Fatalf("unexpected state: %+v", dhk)
	}

	// Query non-existent PoP
	_, err = prober.GetHealthState("sydney")
	if err != ErrPoPNotFoundInProber {
		t.Fatalf("expected ErrPoPNotFoundInProber, got %v", err)
	}
}

func TestPoPHealthProber_CustomProbeError(t *testing.T) {
	popMgr := pop.NewManager()
	alerter := &mockAlerter{}
	prober := NewPoPHealthProber(popMgr, alerter)

	prober.SetProbeFunc(func(ctx context.Context, popID, target string) (float64, error) {
		if popID == "virginia" {
			return 0, errors.New("upstream provider outage")
		}
		return 5.0, nil
	})

	results := prober.ExecuteProbeCycle(context.Background())
	if results["virginia"].Success {
		t.Fatalf("expected virginia probe to fail")
	}
	if results["dhaka"].Success != true {
		t.Fatalf("expected dhaka probe to succeed")
	}
}
