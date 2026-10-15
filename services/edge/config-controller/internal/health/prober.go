package health

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/alert"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/pop"
)

var (
	ErrPoPNotFoundInProber = errors.New("pop not tracked in health prober")
)

const (
	defaultPoPEWMAAlpha       = 0.25
	defaultHealthyThreshold   = 2
	defaultUnhealthyThreshold = 3
	defaultLatencyThresholdMs = 250.0
)

// PoPHealthProber automates synthetic health checking, failover routing, and BGP withdrawal across all PoPs.
type PoPHealthProber struct {
	mu                 sync.RWMutex
	popMgr             *pop.Manager
	alerter            alert.Alerter
	states             map[string]*model.PoPHealthState
	healthyThreshold   int
	unhealthyThreshold int
	latencyThresholdMs float64
	probeFunc          func(ctx context.Context, popID, target string) (float64, error)
	stopChan           chan struct{}
	running            bool
}

// NewPoPHealthProber constructs an automated prober seeded with the global 4-PoP mesh.
func NewPoPHealthProber(popMgr *pop.Manager, alerter alert.Alerter) *PoPHealthProber {
	p := &PoPHealthProber{
		popMgr:             popMgr,
		alerter:            alerter,
		states:             make(map[string]*model.PoPHealthState),
		healthyThreshold:   defaultHealthyThreshold,
		unhealthyThreshold: defaultUnhealthyThreshold,
		latencyThresholdMs: defaultLatencyThresholdMs,
		stopChan:           make(chan struct{}),
	}

	p.seedDefaultStates()

	// Default probe function simulates probe latency based on physical link SLAs
	p.probeFunc = func(ctx context.Context, popID, target string) (float64, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}

		switch strings.ToLower(popID) {
		case "dhaka":
			return 4.2, nil
		case "singapore":
			return 8.1, nil
		case "frankfurt":
			return 14.3, nil
		case "virginia":
			return 12.0, nil
		default:
			return 15.0, nil
		}
	}

	return p
}

func (p *PoPHealthProber) seedDefaultStates() {
	now := time.Now().UTC()
	defaults := []struct {
		id       string
		name     string
		region   string
		endpoint string
		baseRTT  float64
	}{
		{
			id:       "dhaka",
			name:     "Dhaka BDIX Edge 01 (Simulated)",
			region:   "asia-south1",
			endpoint: "198.51.100.1:443",
			baseRTT:  4.0,
		},
		{
			id:       "singapore",
			name:     "Singapore Equinix SG1 (Simulated)",
			region:   "asia-southeast1",
			endpoint: "80.225.241.129:443",
			baseRTT:  8.0,
		},
		{
			id:       "frankfurt",
			name:     "Frankfurt DE-CIX Edge 01 (Simulated)",
			region:   "europe-west3",
			endpoint: "198.51.100.21:443",
			baseRTT:  14.0,
		},
		{
			id:       "virginia",
			name:     "Virginia Equinix Ashburn DC2 (Simulated)",
			region:   "us-east1",
			endpoint: "198.51.100.31:443",
			baseRTT:  12.0,
		},
	}

	for _, d := range defaults {
		p.states[d.id] = &model.PoPHealthState{
			PoPID:               d.id,
			Name:                d.name,
			Region:              d.region,
			TargetEndpoint:      d.endpoint,
			Status:              model.PoPStatusActive,
			Healthy:             true,
			ConsecutivePasses:   5,
			ConsecutiveFailures: 0,
			LastRTTMs:           d.baseRTT,
			EWMALatencyMs:       d.baseRTT,
			PacketLossPercent:   0.0,
			LastProbedAt:        now,
		}
	}
}

// SetProbeFunc allows overriding the synthetic probe function (e.g. for testing or production probes)
func (p *PoPHealthProber) SetProbeFunc(fn func(ctx context.Context, popID, target string) (float64, error)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.probeFunc = fn
}

// SetThresholds configures healthy and unhealthy transition thresholds.
func (p *PoPHealthProber) SetThresholds(healthy, unhealthy int, latencyThresholdMs float64) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if healthy > 0 {
		p.healthyThreshold = healthy
	}
	if unhealthy > 0 {
		p.unhealthyThreshold = unhealthy
	}
	if latencyThresholdMs > 0 {
		p.latencyThresholdMs = latencyThresholdMs
	}
}

// ExecuteProbeCycle executes a concurrent synthetic probe run across all monitored PoPs
func (p *PoPHealthProber) ExecuteProbeCycle(ctx context.Context) map[string]*model.PoPProbeResult {
	p.mu.Lock()
	popIDs := make([]string, 0, len(p.states))
	targets := make(map[string]string)
	for id, st := range p.states {
		popIDs = append(popIDs, id)
		targets[id] = st.TargetEndpoint
	}
	p.mu.Unlock()

	type probeOutcome struct {
		popID     string
		latencyMs float64
		err       error
	}

	outcomes := make(chan probeOutcome, len(popIDs))
	var wg sync.WaitGroup

	for _, id := range popIDs {
		wg.Add(1)
		go func(popID, target string) {
			defer wg.Done()
			p.mu.RLock()
			fn := p.probeFunc
			p.mu.RUnlock()

			probeCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()

			lat, err := fn(probeCtx, popID, target)
			outcomes <- probeOutcome{popID: popID, latencyMs: lat, err: err}
		}(id, targets[id])
	}

	wg.Wait()
	close(outcomes)

	results := make(map[string]*model.PoPProbeResult)
	now := time.Now().UTC()

	for outcome := range outcomes {
		res := p.processProbeOutcome(outcome.popID, outcome.latencyMs, outcome.err, now)
		results[outcome.popID] = res
	}

	return results
}

func (p *PoPHealthProber) processProbeOutcome(popID string, latencyMs float64, err error, probedAt time.Time) *model.PoPProbeResult {
	p.mu.Lock()
	defer p.mu.Unlock()

	state, exists := p.states[popID]
	if !exists {
		return &model.PoPProbeResult{
			PoPID:      popID,
			Success:    false,
			Error:      "unregistered pop",
			Timestamp:  probedAt,
			StatusCode: 500,
		}
	}

	res := &model.PoPProbeResult{
		PoPID:     popID,
		Target:    state.TargetEndpoint,
		Timestamp: probedAt,
	}

	wasHealthy := state.Healthy
	state.LastProbedAt = probedAt

	if err != nil {
		// Probe Failed
		res.Success = false
		res.Error = err.Error()
		res.StatusCode = 503
		state.LastError = err.Error()
		state.ConsecutiveFailures++
		state.ConsecutivePasses = 0
		state.PacketLossPercent = 100.0

		if state.ConsecutiveFailures >= p.unhealthyThreshold && wasHealthy {
			// Trigger automated failover
			state.Healthy = false
			state.Status = model.PoPStatusDraining

			// 1. Withdraw Anycast BGP for the degraded PoP
			if p.popMgr != nil {
				_, _ = p.popMgr.SetBGPState(popID, model.BGPStateWithdrawn)

				// 2. Compute optimal healthy failover PoP
				failoverHop, fErr := p.popMgr.CalculatePoPFailover(popID, false)
				if fErr == nil && failoverHop != nil {
					state.FailoverPoPID = failoverHop.TargetPoP
					_ = p.popMgr.SetPoPRouteFailover(popID, failoverHop.TargetPoP)
				}
			}

			// 3. Dispatch Alert
			if p.alerter != nil && p.alerter.IsConfigured() {
				event := alert.Event{
					Type:      alert.EventTypePoPDown,
					Severity:  alert.SeverityCritical,
					Title:     fmt.Sprintf("PoP %s Unhealthy - Failover Engaged", strings.ToUpper(popID)),
					Message:   fmt.Sprintf("PoP %s failed %d consecutive probes. BGP withdrawn. Failover routed to %s.", popID, state.ConsecutiveFailures, state.FailoverPoPID),
					Origin:    state.TargetEndpoint,
					Timestamp: probedAt,
					Details: map[string]string{
						"pop_id":               popID,
						"failover_target":      state.FailoverPoPID,
						"consecutive_failures": strconv.Itoa(state.ConsecutiveFailures),
						"error":                err.Error(),
					},
				}
				go func() {
					_ = p.alerter.SendAlert(context.Background(), event)
				}()
			}
		}
		return res
	}

	// Probe Succeeded
	res.Success = true
	res.LatencyMs = latencyMs
	res.StatusCode = 200
	state.LastError = ""
	state.LastRTTMs = latencyMs
	state.ConsecutivePasses++
	state.ConsecutiveFailures = 0
	state.PacketLossPercent = 0.0

	// Update EWMA
	if state.EWMALatencyMs <= 0 {
		state.EWMALatencyMs = latencyMs
	} else {
		state.EWMALatencyMs = (defaultPoPEWMAAlpha * latencyMs) + ((1.0 - defaultPoPEWMAAlpha) * state.EWMALatencyMs)
	}

	if state.ConsecutivePasses >= p.healthyThreshold && !wasHealthy {
		// Trigger automated recovery
		state.Healthy = true
		state.Status = model.PoPStatusActive
		state.FailoverPoPID = ""

		// 1. Re-announce Anycast BGP for the recovered PoP
		if p.popMgr != nil {
			_, _ = p.popMgr.SetBGPState(popID, model.BGPStateAnnounced)
			_ = p.popMgr.RestorePoPRoute(popID)
		}

		// 2. Dispatch Recovery Alert
		if p.alerter != nil && p.alerter.IsConfigured() {
			event := alert.Event{
				Type:      alert.EventTypePoPRecovered,
				Severity:  alert.SeverityInfo,
				Title:     fmt.Sprintf("PoP %s Recovered - Primary Route Restored", strings.ToUpper(popID)),
				Message:   fmt.Sprintf("PoP %s passed consecutive probes (RTT: %.2f ms). BGP re-announced. Primary routing restored.", popID, latencyMs),
				Origin:    state.TargetEndpoint,
				LatencyMs: latencyMs,
				Timestamp: probedAt,
				Details: map[string]string{
					"pop_id":             popID,
					"ewma_latency_ms":    fmt.Sprintf("%.2f", state.EWMALatencyMs),
					"consecutive_passes": strconv.Itoa(state.ConsecutivePasses),
				},
			}
			go func() {
				_ = p.alerter.SendAlert(context.Background(), event)
			}()
		}
	}

	return res
}

// RecordManualProbe applies an external or simulated probe result to a PoP
func (p *PoPHealthProber) RecordManualProbe(popID string, success bool, latencyMs float64, errMsg string) *model.PoPHealthState {
	var err error
	if !success {
		if errMsg == "" {
			errMsg = "synthetic probe failed"
		}
		err = errors.New(errMsg)
	}
	p.processProbeOutcome(popID, latencyMs, err, time.Now().UTC())

	p.mu.RLock()
	defer p.mu.RUnlock()
	st := p.states[popID]
	if st == nil {
		return nil
	}
	copy := *st
	return &copy
}

// GetHealthStates returns real-time health metrics across all PoPs
func (p *PoPHealthProber) GetHealthStates() []model.PoPHealthState {
	p.mu.RLock()
	defer p.mu.RUnlock()

	res := make([]model.PoPHealthState, 0, len(p.states))
	for _, st := range p.states {
		res = append(res, *st)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].PoPID < res[j].PoPID
	})
	return res
}

// GetHealthState returns the health state of an individual PoP
func (p *PoPHealthProber) GetHealthState(popID string) (*model.PoPHealthState, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()

	st, exists := p.states[strings.ToLower(popID)]
	if !exists {
		return nil, ErrPoPNotFoundInProber
	}
	copy := *st
	return &copy, nil
}

// Start begins the background periodic health probe loop
func (p *PoPHealthProber) Start(ctx context.Context, interval time.Duration) {
	p.mu.Lock()
	if p.running {
		p.mu.Unlock()
		return
	}
	p.running = true
	stopChan := p.stopChan
	p.mu.Unlock()

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				_ = p.ExecuteProbeCycle(ctx)
			case <-stopChan:
				return
			case <-ctx.Done():
				return
			}
		}
	}()
}

// Stop gracefully terminates the background periodic health probe loop
func (p *PoPHealthProber) Stop() {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.running {
		p.running = false
		close(p.stopChan)
		p.stopChan = make(chan struct{})
	}
}
