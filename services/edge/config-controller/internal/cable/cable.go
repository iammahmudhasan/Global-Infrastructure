package cable

import (
	"errors"
	"sync"
	"time"
)

// CableStatus denotes the physical operational state of subsea fiber.
type CableStatus string

const (
	StatusOnline   CableStatus = "ONLINE"
	StatusDegraded CableStatus = "DEGRADED"
	StatusSevered  CableStatus = "SEVERED"
)

var (
	ErrCableNotFound     = errors.New("subsea cable link not found")
	ErrCableAlreadyCut   = errors.New("cable is already severed")
	ErrCableAlreadyAlive = errors.New("cable is already online")
)

// SubseaCable models an international submarine fiber-optic route.
type SubseaCable struct {
	ID               string      `json:"id"`
	Name             string      `json:"name"`
	LandingPoints    []string    `json:"landing_points"`
	CapacityGbps     int64       `json:"capacity_gbps"`
	CurrentLatencyMs float64     `json:"current_latency_ms"`
	NormalLatencyMs  float64     `json:"normal_latency_ms"`
	Status           CableStatus `json:"status"`
	ActiveBGPPaths   int         `json:"active_bgp_paths"`
	AlternateRoute   string      `json:"alternate_route"`
	LastHealthCheck  time.Time   `json:"last_health_check"`
	CutAt            *time.Time  `json:"cut_at,omitempty"`
}

// CableEventResult contains the operational decision of a simulated fiber break or restore.
type CableEventResult struct {
	CableID              string      `json:"cable_id"`
	Status               CableStatus `json:"status"`
	BGPFailoverTriggered bool        `json:"bgp_failover_triggered"`
	ReroutedTo           string      `json:"rerouted_to"`
	NewLatencyMs         float64     `json:"new_latency_ms"`
	Message              string      `json:"message"`
	Timestamp            time.Time   `json:"timestamp"`
}

// Manager orchestrates physical subsea fiber telemetry and BGP route steering.
type Manager struct {
	mu     sync.RWMutex
	cables map[string]*SubseaCable
}

// NewManager creates a thread-safe subsea cable topology manager.
func NewManager() *Manager {
	m := &Manager{
		cables: make(map[string]*SubseaCable),
	}
	m.seedCables()
	return m
}

func (m *Manager) seedCables() {
	now := time.Now().UTC()
	defaults := []*SubseaCable{
		{
			ID:               "smw6",
			Name:             "SEA-ME-WE 6 (Cox's Bazar - Singapore - Marseille)",
			LandingPoints:    []string{"Cox's Bazar (BD)", "Tuas (SG)", "Mumbai (IN)", "Marseille (FR)"},
			CapacityGbps:     30000,
			NormalLatencyMs:  32.0,
			CurrentLatencyMs: 32.0,
			Status:           StatusOnline,
			ActiveBGPPaths:   4,
			AlternateRoute:   "SMW5 / Terrestrial India Cross-Connect",
			LastHealthCheck:  now,
		},
		{
			ID:               "bdix-ring",
			Name:             "BDIX Domestic Metro & Peering Fabric",
			LandingPoints:    []string{"Dhaka (BD)", "Chittagong (BD)", "Sylhet (BD)"},
			CapacityGbps:     2270,
			NormalLatencyMs:  4.0,
			CurrentLatencyMs: 4.0,
			Status:           StatusOnline,
			ActiveBGPPaths:   167,
			AlternateRoute:   "National Telecommunication Transmission Network (NTTN)",
			LastHealthCheck:  now,
		},
		{
			ID:               "tat14",
			Name:             "Transatlantic Fiber Direct (Frankfurt - Ashburn)",
			LandingPoints:    []string{"Norden (DE)", "Bude (UK)", "Tuckerton (US)"},
			CapacityGbps:     10000,
			NormalLatencyMs:  78.0,
			CurrentLatencyMs: 78.0,
			Status:           StatusOnline,
			ActiveBGPPaths:   6,
			AlternateRoute:   "Dunant Subsea Cable",
			LastHealthCheck:  now,
		},
		{
			ID:               "equinix-asean",
			Name:             "Equinix ASEAN Regional Ring (Singapore SG1)",
			LandingPoints:    []string{"Singapore (SG)", "Johor (MY)", "Batam (ID)"},
			CapacityGbps:     15000,
			NormalLatencyMs:  8.0,
			CurrentLatencyMs: 8.0,
			Status:           StatusOnline,
			ActiveBGPPaths:   12,
			AlternateRoute:   "Singtel Meg@POP Fabric",
			LastHealthCheck:  now,
		},
	}

	for _, c := range defaults {
		m.cables[c.ID] = c
	}
}

// ListCables returns all tracked international submarine and metro links.
func (m *Manager) ListCables() []*SubseaCable {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*SubseaCable
	for _, c := range m.cables {
		clone := *c
		result = append(result, &clone)
	}
	return result
}

// GetCable fetches details for a specific submarine cable link.
func (m *Manager) GetCable(id string) (*SubseaCable, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	c, exists := m.cables[id]
	if !exists {
		return nil, ErrCableNotFound
	}
	clone := *c
	return &clone, nil
}

// SimulateCableCut simulates a physical fiber break, triggering automated BGP Anycast failover.
func (m *Manager) SimulateCableCut(id string) (*CableEventResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, exists := m.cables[id]
	if !exists {
		return nil, ErrCableNotFound
	}
	if c.Status == StatusSevered {
		return nil, ErrCableAlreadyCut
	}

	now := time.Now().UTC()
	c.Status = StatusSevered
	c.CutAt = &now
	c.LastHealthCheck = now

	// Penalize latency by routing across terrestrial backup
	penaltyLatency := c.NormalLatencyMs * 3.8
	c.CurrentLatencyMs = penaltyLatency

	return &CableEventResult{
		CableID:              c.ID,
		Status:               StatusSevered,
		BGPFailoverTriggered: true,
		ReroutedTo:           c.AlternateRoute,
		NewLatencyMs:         penaltyLatency,
		Message:              "Subsea cable severed. BGP Anycast communities updated; traffic autonomously shifted to secondary terrestrial fiber path.",
		Timestamp:            now,
	}, nil
}

// RestoreCable restores physical submarine link to nominal operating parameters.
func (m *Manager) RestoreCable(id string) (*CableEventResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	c, exists := m.cables[id]
	if !exists {
		return nil, ErrCableNotFound
	}
	if c.Status == StatusOnline {
		return nil, ErrCableAlreadyAlive
	}

	now := time.Now().UTC()
	c.Status = StatusOnline
	c.CutAt = nil
	c.CurrentLatencyMs = c.NormalLatencyMs
	c.LastHealthCheck = now

	return &CableEventResult{
		CableID:              c.ID,
		Status:               StatusOnline,
		BGPFailoverTriggered: true,
		ReroutedTo:           "Primary Subsea Fiber Direct",
		NewLatencyMs:         c.NormalLatencyMs,
		Message:              "Subsea cable restored. Nominal BGP Anycast MED and AS-path reinstated.",
		Timestamp:            now,
	}, nil
}
