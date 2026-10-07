package health

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

var (
	ErrNoHealthyOrigins = errors.New("no healthy origin endpoints available in pool")
)

const (
	defaultEWMAAlpha = 0.2 // Smoothing factor for network RTT
)

// Monitor coordinates active health checking and maintains real-time endpoint state
type Monitor struct {
	mu         sync.RWMutex
	httpClient *http.Client
}

func NewMonitor() *Monitor {
	return &Monitor{
		httpClient: &http.Client{
			Transport: &http.Transport{
				DisableKeepAlives: true,
				DialContext: (&net.Dialer{
					Timeout: 2 * time.Second,
				}).DialContext,
			},
		},
	}
}

// ProbeEndpoint executes an active health probe against a single origin endpoint
func (m *Monitor) ProbeEndpoint(ctx context.Context, origin *model.Origin, monitor *model.HealthMonitor, currentState *model.OriginEndpointState) *model.OriginEndpointState {
	if monitor == nil {
		monitor = &model.HealthMonitor{
			Protocol:            model.HealthCheckProtocolHTTP,
			Path:                "/healthz",
			Port:                origin.Port,
			TimeoutSeconds:      2,
			HealthyThreshold:    2,
			UnhealthyThreshold:  3,
			ExpectedStatusCodes: []int{200},
		}
	}

	state := &model.OriginEndpointState{
		OriginID:            origin.ID,
		PoolID:              origin.PoolID,
		Address:             origin.Address,
		Port:                origin.Port,
		Healthy:             origin.Healthy,
		ConsecutivePasses:   0,
		ConsecutiveFailures: 0,
		EWMALatencyMs:       0,
	}
	if currentState != nil {
		*state = *currentState
	}

	scheme := "http"
	if origin.Protocol == model.ProtocolHTTPS || monitor.Protocol == model.HealthCheckProtocolHTTPS {
		scheme = "https"
	}

	port := origin.Port
	if monitor.Port > 0 {
		port = monitor.Port
	}

	path := monitor.Path
	if path == "" {
		path = "/healthz"
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	probeURL := fmt.Sprintf("%s://%s:%d%s", scheme, origin.Address, port, path)
	timeout := time.Duration(monitor.TimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 2 * time.Second
	}

	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, probeURL, nil)
	if err != nil {
		m.recordFailure(state, monitor, 0, err.Error())
		return state
	}
	req.Header.Set("User-Agent", "NexusEdge-HealthMonitor/1.0")

	resp, err := m.httpClient.Do(req)
	latencyMs := float64(time.Since(start).Microseconds()) / 1000.0

	if err != nil {
		m.recordFailure(state, monitor, 0, err.Error())
		return state
	}
	defer resp.Body.Close()

	// Check if status code matches expected
	isExpected := false
	expectedCodes := monitor.ExpectedStatusCodes
	if len(expectedCodes) == 0 {
		expectedCodes = []int{200}
	}
	for _, code := range expectedCodes {
		if resp.StatusCode == code {
			isExpected = true
			break
		}
	}

	if !isExpected {
		m.recordFailure(state, monitor, resp.StatusCode, fmt.Sprintf("unexpected status code: %d", resp.StatusCode))
		return state
	}

	// Probe Succeeded
	m.recordSuccess(state, monitor, resp.StatusCode, latencyMs)
	return state
}

func (m *Monitor) recordSuccess(state *model.OriginEndpointState, monitor *model.HealthMonitor, statusCode int, latencyMs float64) {
	state.LastChecked = time.Now().UTC()
	state.LastStatusCode = statusCode
	state.LastError = ""
	state.ConsecutivePasses++
	state.ConsecutiveFailures = 0

	// Update EWMA Latency
	if state.EWMALatencyMs <= 0 {
		state.EWMALatencyMs = latencyMs
	} else {
		state.EWMALatencyMs = (defaultEWMAAlpha * latencyMs) + ((1.0 - defaultEWMAAlpha) * state.EWMALatencyMs)
	}

	threshold := monitor.HealthyThreshold
	if threshold <= 0 {
		threshold = 2
	}

	if state.ConsecutivePasses >= threshold {
		state.Healthy = true
	}
}

func (m *Monitor) recordFailure(state *model.OriginEndpointState, monitor *model.HealthMonitor, statusCode int, errMsg string) {
	state.LastChecked = time.Now().UTC()
	state.LastStatusCode = statusCode
	state.LastError = errMsg
	state.ConsecutiveFailures++
	state.ConsecutivePasses = 0

	threshold := monitor.UnhealthyThreshold
	if threshold <= 0 {
		threshold = 3
	}

	if state.ConsecutiveFailures >= threshold {
		state.Healthy = false
	}
}

// SmartRouter selects the optimal healthy origin based on health and EWMA latency
type SmartRouter struct{}

func NewSmartRouter() *SmartRouter {
	return &SmartRouter{}
}

// SelectOptimalOrigin selects the best healthy origin (Lowest EWMA Latency with automatic failover)
func (r *SmartRouter) SelectOptimalOrigin(pool *model.OriginPool, states []*model.OriginEndpointState) (*model.RoutingDecision, error) {
	if pool == nil || len(pool.Origins) == 0 {
		return nil, ErrNoHealthyOrigins
	}

	stateMap := make(map[string]*model.OriginEndpointState)
	for _, st := range states {
		stateMap[st.OriginID] = st
	}

	// 1. Filter healthy origins
	var healthyOrigins []model.Origin
	for _, o := range pool.Origins {
		st, exists := stateMap[o.ID]
		if exists && st.Healthy {
			healthyOrigins = append(healthyOrigins, o)
		} else if !exists && o.Healthy {
			healthyOrigins = append(healthyOrigins, o)
		}
	}

	if len(healthyOrigins) == 0 {
		return nil, ErrNoHealthyOrigins
	}

	// 2. If single healthy origin, choose it directly
	if len(healthyOrigins) == 1 {
		selected := healthyOrigins[0]
		st := stateMap[selected.ID]
		lat := 0.0
		if st != nil {
			lat = st.EWMALatencyMs
		}
		return &model.RoutingDecision{
			SelectedOriginID: selected.ID,
			OriginAddress:    selected.Address,
			OriginPort:       selected.Port,
			PoolID:           pool.ID,
			Reason:           "FAILOVER_SINGLE_HEALTHY",
			LatencyMs:        lat,
		}, nil
	}

	// 3. Multi-origin: Lowest EWMA Latency
	var bestOrigin *model.Origin
	lowestLatency := 999999.0
	hasEWMA := false

	for i := range healthyOrigins {
		o := &healthyOrigins[i]
		st, exists := stateMap[o.ID]
		if exists && st.EWMALatencyMs > 0 {
			hasEWMA = true
			if st.EWMALatencyMs < lowestLatency {
				lowestLatency = st.EWMALatencyMs
				bestOrigin = o
			}
		}
	}

	if hasEWMA && bestOrigin != nil {
		return &model.RoutingDecision{
			SelectedOriginID: bestOrigin.ID,
			OriginAddress:    bestOrigin.Address,
			OriginPort:       bestOrigin.Port,
			PoolID:           pool.ID,
			Reason:           "LOWEST_EWMA_LATENCY",
			LatencyMs:        lowestLatency,
		}, nil
	}

	// Fallback to highest weight or first healthy origin
	selected := healthyOrigins[0]
	return &model.RoutingDecision{
		SelectedOriginID: selected.ID,
		OriginAddress:    selected.Address,
		OriginPort:       selected.Port,
		PoolID:           pool.ID,
		Reason:           "ROUND_ROBIN",
		LatencyMs:        0,
	}, nil
}
