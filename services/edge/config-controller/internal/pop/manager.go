package pop

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

var (
	ErrPoPNotFound          = errors.New("pop not found")
	ErrNodeNotFound         = errors.New("edge node not found")
	ErrEmptyPoPID           = errors.New("pop_id is required")
	ErrNoOrigins            = errors.New("no healthy origins available for steering")
	ErrRouteNotFound        = errors.New("pop route configuration not found")
	ErrSovereigntyViolation = errors.New("failover blocked: cross-border transfer violates strict national data residency")
	ErrNoFailoverAvailable  = errors.New("no healthy failover PoP available")
)

// Manager orchestrates Edge Points of Presence, Anycast BGP announcements, and node health
type Manager struct {
	mu            sync.RWMutex
	pops          map[string]*model.EdgePoP
	nodes         map[string]map[string]*model.EdgeNode // popID -> nodeID -> Node
	latencyMatrix map[string]map[string]float64         // fromPoP -> toTarget -> latencyMs
	routes        map[string]*model.MultiPoPRouteRule   // popID -> MultiPoPRouteRule
}

func NewManager() *Manager {
	m := &Manager{
		pops:          make(map[string]*model.EdgePoP),
		nodes:         make(map[string]map[string]*model.EdgeNode),
		latencyMatrix: make(map[string]map[string]float64),
		routes:        make(map[string]*model.MultiPoPRouteRule),
	}
	m.seedDefaultPoPs()
	m.seedLatencyMatrix()
	m.seedMultiPoPRoutes()
	return m
}

func (m *Manager) seedDefaultPoPs() {
	now := time.Now().UTC()

	// Default simulated testbed topology.
	// Uses RFC 6996 Private ASN (64512), RFC 5737 TEST-NET-2 (198.51.100.1),
	// and RFC 3849 documentation IPv6 (2001:db8::1) to avoid real-world IP/ASN collision.
	defaults := []model.EdgePoP{
		{
			ID:               "dhaka",
			Name:             "Dhaka BDIX Edge 01 (Simulated)",
			Region:           "asia-south1",
			City:             "Dhaka",
			Country:          "BD",
			Latitude:         23.8103,
			Longitude:        90.4125,
			ASN:              64512,
			AnycastIPv4:      "198.51.100.1",
			AnycastIPv6:      "2001:db8::1",
			BGPState:         model.BGPStateAnnounced,
			Status:           model.PoPStatusActive,
			Mode:             "SIMULATION",
			Source:           "SIMULATED",
			IsSimulated:      true,
			NodeCount:        0,
			HealthyNodeCount: 0,
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			ID:               "singapore",
			Name:             "Singapore Equinix SG1 (Simulated)",
			Region:           "asia-southeast1",
			City:             "Singapore",
			Country:          "SG",
			Latitude:         1.3521,
			Longitude:        103.8198,
			ASN:              64512,
			AnycastIPv4:      "198.51.100.1",
			AnycastIPv6:      "2001:db8::1",
			BGPState:         model.BGPStateAnnounced,
			Status:           model.PoPStatusActive,
			Mode:             "SIMULATION",
			Source:           "SIMULATED",
			IsSimulated:      true,
			NodeCount:        0,
			HealthyNodeCount: 0,
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			ID:               "frankfurt",
			Name:             "Frankfurt DE-CIX Edge 01 (Simulated)",
			Region:           "europe-west3",
			City:             "Frankfurt",
			Country:          "DE",
			Latitude:         50.1109,
			Longitude:        8.6821,
			ASN:              64512,
			AnycastIPv4:      "198.51.100.1",
			AnycastIPv6:      "2001:db8::1",
			BGPState:         model.BGPStateAnnounced,
			Status:           model.PoPStatusActive,
			Mode:             "SIMULATION",
			Source:           "SIMULATED",
			IsSimulated:      true,
			NodeCount:        0,
			HealthyNodeCount: 0,
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			ID:               "virginia",
			Name:             "Virginia Equinix Ashburn DC2 (Simulated)",
			Region:           "us-east1",
			City:             "Ashburn",
			Country:          "US",
			Latitude:         39.0438,
			Longitude:        -77.4874,
			ASN:              64512,
			AnycastIPv4:      "198.51.100.1",
			AnycastIPv6:      "2001:db8::1",
			BGPState:         model.BGPStateAnnounced,
			Status:           model.PoPStatusActive,
			Mode:             "SIMULATION",
			Source:           "SIMULATED",
			IsSimulated:      true,
			NodeCount:        0,
			HealthyNodeCount: 0,
			CreatedAt:        now,
			UpdatedAt:        now,
		},
	}

	for _, pop := range defaults {
		p := pop
		m.pops[p.ID] = &p
		m.nodes[p.ID] = make(map[string]*model.EdgeNode)
	}
}

func (m *Manager) seedLatencyMatrix() {
	// Physical transit truths based on submarine cable paths (SMW6, AAE-1, TAT-14)
	m.setLatencyPair("dhaka", "singapore", 32.0)
	m.setLatencyPair("dhaka", "frankfurt", 125.0)
	m.setLatencyPair("dhaka", "virginia", 190.0)

	m.setLatencyPair("singapore", "frankfurt", 145.0)
	m.setLatencyPair("singapore", "virginia", 180.0)

	m.setLatencyPair("frankfurt", "virginia", 78.0)
}

func (m *Manager) setLatencyPair(a, b string, ms float64) {
	if m.latencyMatrix[a] == nil {
		m.latencyMatrix[a] = make(map[string]float64)
	}
	if m.latencyMatrix[b] == nil {
		m.latencyMatrix[b] = make(map[string]float64)
	}
	m.latencyMatrix[a][b] = ms
	m.latencyMatrix[b][a] = ms
}

func (m *Manager) seedMultiPoPRoutes() {
	now := time.Now().UTC()

	m.routes["dhaka"] = &model.MultiPoPRouteRule{
		PoPID:         "dhaka",
		Region:        "asia-south1",
		PrimaryTarget: "bdix-dhaka-direct",
		PrimaryRTTMs:  4.0,
		FailoverTargets: []model.FailoverHop{
			{
				TargetPoP:             "singapore",
				SubseaCable:           "SEA-ME-WE 6 (SMW6)",
				SLARTTMs:              32.0,
				SovereigntyRestricted: true,
				Status:                "STANDBY",
			},
			{
				TargetPoP:             "frankfurt",
				SubseaCable:           "AAE-1 / SMW5",
				SLARTTMs:              125.0,
				SovereigntyRestricted: true,
				Status:                "STANDBY",
			},
			{
				TargetPoP:             "virginia",
				SubseaCable:           "Atlantic-Indian Transit",
				SLARTTMs:              190.0,
				SovereigntyRestricted: true,
				Status:                "STANDBY",
			},
		},
		ActiveTarget: "bdix-dhaka-direct",
		Status:       "OPTIMAL",
		UpdatedAt:    now,
	}

	m.routes["singapore"] = &model.MultiPoPRouteRule{
		PoPID:         "singapore",
		Region:        "asia-southeast1",
		PrimaryTarget: "equinix-sg1-direct",
		PrimaryRTTMs:  8.0,
		FailoverTargets: []model.FailoverHop{
			{
				TargetPoP:             "dhaka",
				SubseaCable:           "SEA-ME-WE 6 (SMW6)",
				SLARTTMs:              32.0,
				SovereigntyRestricted: false,
				Status:                "STANDBY",
			},
			{
				TargetPoP:             "frankfurt",
				SubseaCable:           "Asia Africa Europe-1 (AAE-1)",
				SLARTTMs:              145.0,
				SovereigntyRestricted: false,
				Status:                "STANDBY",
			},
			{
				TargetPoP:             "virginia",
				SubseaCable:           "Japan-U.S. / Trans-Pacific",
				SLARTTMs:              180.0,
				SovereigntyRestricted: false,
				Status:                "STANDBY",
			},
		},
		ActiveTarget: "equinix-sg1-direct",
		Status:       "OPTIMAL",
		UpdatedAt:    now,
	}

	m.routes["frankfurt"] = &model.MultiPoPRouteRule{
		PoPID:         "frankfurt",
		Region:        "europe-west3",
		PrimaryTarget: "decix-fra-direct",
		PrimaryRTTMs:  14.0,
		FailoverTargets: []model.FailoverHop{
			{
				TargetPoP:             "virginia",
				SubseaCable:           "TAT-14 / Transatlantic Subsea",
				SLARTTMs:              78.0,
				SovereigntyRestricted: false,
				Status:                "STANDBY",
			},
			{
				TargetPoP:             "dhaka",
				SubseaCable:           "SMW6 Terrestrial Extension",
				SLARTTMs:              125.0,
				SovereigntyRestricted: false,
				Status:                "STANDBY",
			},
			{
				TargetPoP:             "singapore",
				SubseaCable:           "Asia Africa Europe-1 (AAE-1)",
				SLARTTMs:              145.0,
				SovereigntyRestricted: false,
				Status:                "STANDBY",
			},
		},
		ActiveTarget: "decix-fra-direct",
		Status:       "OPTIMAL",
		UpdatedAt:    now,
	}

	m.routes["virginia"] = &model.MultiPoPRouteRule{
		PoPID:         "virginia",
		Region:        "us-east1",
		PrimaryTarget: "equinix-dc2-direct",
		PrimaryRTTMs:  12.0,
		FailoverTargets: []model.FailoverHop{
			{
				TargetPoP:             "frankfurt",
				SubseaCable:           "TAT-14 / Transatlantic Subsea",
				SLARTTMs:              78.0,
				SovereigntyRestricted: false,
				Status:                "STANDBY",
			},
			{
				TargetPoP:             "singapore",
				SubseaCable:           "Japan-U.S. / Trans-Pacific",
				SLARTTMs:              180.0,
				SovereigntyRestricted: false,
				Status:                "STANDBY",
			},
			{
				TargetPoP:             "dhaka",
				SubseaCable:           "Atlantic-Indian Terrestrial Route",
				SLARTTMs:              190.0,
				SovereigntyRestricted: false,
				Status:                "STANDBY",
			},
		},
		ActiveTarget: "equinix-dc2-direct",
		Status:       "OPTIMAL",
		UpdatedAt:    now,
	}
}

// GetMultiPoPRoutes returns the global routing and failover policies for all active PoPs
func (m *Manager) GetMultiPoPRoutes() []model.MultiPoPRouteRule {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]model.MultiPoPRouteRule, 0, len(m.routes))
	for _, r := range m.routes {
		res = append(res, *r)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].PoPID < res[j].PoPID
	})
	return res
}

// GetPoPRoute returns the routing and failover rule for a specific PoP
func (m *Manager) GetPoPRoute(popID string) (*model.MultiPoPRouteRule, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	route, exists := m.routes[strings.ToLower(popID)]
	if !exists {
		return nil, ErrRouteNotFound
	}
	copy := *route
	return &copy, nil
}

// CalculatePoPFailover selects the optimal healthy failover PoP respecting latency and data sovereignty
func (m *Manager) CalculatePoPFailover(popID string, strictSovereignty bool) (*model.FailoverHop, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	popID = strings.ToLower(popID)
	route, exists := m.routes[popID]
	if !exists {
		return nil, ErrRouteNotFound
	}

	for _, hop := range route.FailoverTargets {
		if strictSovereignty && hop.SovereigntyRestricted {
			continue // In-country residency prevents foreign failover
		}

		targetPoP, ok := m.pops[hop.TargetPoP]
		if ok && targetPoP.Status == model.PoPStatusActive && targetPoP.BGPState == model.BGPStateAnnounced {
			return &hop, nil
		}
	}

	if strictSovereignty {
		return nil, ErrSovereigntyViolation
	}
	return nil, ErrNoFailoverAvailable
}

// SetPoPRouteFailover updates the active route target of a PoP to an engaged failover destination
func (m *Manager) SetPoPRouteFailover(popID, failoverTarget string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	popID = strings.ToLower(popID)
	route, exists := m.routes[popID]
	if !exists {
		return ErrRouteNotFound
	}

	route.ActiveTarget = failoverTarget
	route.Status = "FAILOVER_ENGAGED"
	for i := range route.FailoverTargets {
		if strings.EqualFold(route.FailoverTargets[i].TargetPoP, failoverTarget) {
			route.FailoverTargets[i].Status = "ACTIVE_FAILOVER"
		} else {
			route.FailoverTargets[i].Status = "STANDBY"
		}
	}
	route.UpdatedAt = time.Now().UTC()
	return nil
}

// RestorePoPRoute returns a PoP to its optimal primary route target
func (m *Manager) RestorePoPRoute(popID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	popID = strings.ToLower(popID)
	route, exists := m.routes[popID]
	if !exists {
		return ErrRouteNotFound
	}

	route.ActiveTarget = route.PrimaryTarget
	route.Status = "OPTIMAL"
	for i := range route.FailoverTargets {
		route.FailoverTargets[i].Status = "STANDBY"
	}
	route.UpdatedAt = time.Now().UTC()
	return nil
}

func (m *Manager) ListPoPs() []model.EdgePoP {
	m.mu.RLock()
	defer m.mu.RUnlock()

	res := make([]model.EdgePoP, 0, len(m.pops))
	for _, p := range m.pops {
		res = append(res, *p)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].ID < res[j].ID
	})
	return res
}

func (m *Manager) GetPoP(popID string) (*model.EdgePoP, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	pop, exists := m.pops[strings.ToLower(popID)]
	if !exists {
		return nil, ErrPoPNotFound
	}
	copy := *pop
	return &copy, nil
}

func (m *Manager) RegisterNode(node model.EdgeNode) (*model.EdgeNode, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	popID := strings.ToLower(node.PoPID)
	pop, exists := m.pops[popID]
	if !exists {
		return nil, ErrPoPNotFound
	}

	if node.ID == "" {
		node.ID = fmt.Sprintf("node-%s-%s", popID[:min(len(popID), 3)], generateHex(3))
	}
	if node.Status == "" {
		node.Status = "HEALTHY"
	}
	node.PoPID = popID
	node.LastHeartbeat = time.Now().UTC()

	m.nodes[popID][node.ID] = &node
	m.recalculatePoPNodes(pop)

	res := node
	return &res, nil
}

func (m *Manager) HeartbeatNode(popID, nodeID string, cpu float64, mem int64, conns int) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	popID = strings.ToLower(popID)
	pop, exists := m.pops[popID]
	if !exists {
		return ErrPoPNotFound
	}

	node, exists := m.nodes[popID][nodeID]
	if !exists {
		return ErrNodeNotFound
	}

	node.CPUUsagePercent = cpu
	node.MemoryUsageMB = mem
	node.ActiveConnections = conns
	node.LastHeartbeat = time.Now().UTC()
	node.Status = "HEALTHY"

	m.recalculatePoPNodes(pop)
	return nil
}

func (m *Manager) ListNodes(popID string) []model.EdgeNode {
	m.mu.RLock()
	defer m.mu.RUnlock()

	popID = strings.ToLower(popID)
	nodesMap, exists := m.nodes[popID]
	if !exists {
		return []model.EdgeNode{}
	}

	res := make([]model.EdgeNode, 0, len(nodesMap))
	for _, n := range nodesMap {
		res = append(res, *n)
	}

	sort.Slice(res, func(i, j int) bool {
		return res[i].ID < res[j].ID
	})
	return res
}

// SetBGPState updates the simulated BGP route announcement state in the local control plane.
// NOTE: In simulation mode, this toggles in-memory state representation. Production V3 will integrate
// with external BGP speaker daemons (e.g. ExaBGP/FRRouting) via gRPC/UNIX domain socket.
func (m *Manager) SetBGPState(popID string, state model.BGPState) (*model.EdgePoP, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	popID = strings.ToLower(popID)
	pop, exists := m.pops[popID]
	if !exists {
		return nil, ErrPoPNotFound
	}

	pop.BGPState = state
	if state == model.BGPStateWithdrawn {
		pop.Status = model.PoPStatusDraining
	} else if state == model.BGPStateAnnounced {
		pop.Status = model.PoPStatusActive
	}
	pop.UpdatedAt = time.Now().UTC()

	copy := *pop
	return &copy, nil
}

func (m *Manager) GetLatencyMatrix() []model.LatencyRoute {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var routes []model.LatencyRoute
	for from, targets := range m.latencyMatrix {
		for to, latency := range targets {
			routes = append(routes, model.LatencyRoute{
				FromPoP:     from,
				ToTarget:    to,
				LatencyMs:   latency,
				Status:      "SIMULATED",
				IsSimulated: true,
				Source:      "ESTIMATED_FIBER_TRANSIT",
			})
		}
	}

	sort.Slice(routes, func(i, j int) bool {
		if routes[i].FromPoP == routes[j].FromPoP {
			return routes[i].ToTarget < routes[j].ToTarget
		}
		return routes[i].FromPoP < routes[j].FromPoP
	})
	return routes
}

// CalculateSteering selects the optimal upstream origin based on client PoP proximity and health
func (m *Manager) CalculateSteering(clientPoP, domainID string, availableOrigins []model.Origin) (*model.GeoSteeringDecision, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	clientPoP = strings.ToLower(clientPoP)
	if _, exists := m.pops[clientPoP]; !exists {
		return nil, ErrPoPNotFound
	}

	var healthyOrigins []model.Origin
	for _, o := range availableOrigins {
		if o.Healthy {
			healthyOrigins = append(healthyOrigins, o)
		}
	}

	if len(healthyOrigins) == 0 {
		return nil, ErrNoOrigins
	}

	// 1. Check if any healthy origin is in the same local region/city (direct local hop <= 10ms)
	for _, o := range healthyOrigins {
		if strings.Contains(strings.ToLower(o.Address), clientPoP) {
			return &model.GeoSteeringDecision{
				ClientPoP:        clientPoP,
				DomainID:         domainID,
				SelectedOriginID: o.ID,
				OriginAddress:    o.Address,
				OriginRegion:     clientPoP,
				DirectLatencyMs:  4.5, // Intra-metro local fiber
				Reason:           "LOCAL_METRO_AFFINITY",
			}, nil
		}
	}

	// 2. Find closest origin based on Inter-PoP Latency Matrix
	bestOrigin := healthyOrigins[0]
	lowestLatency := 9999.0
	bestRegion := "global"

	for _, o := range healthyOrigins {
		originLower := strings.ToLower(o.Address)
		matchedLatency := 100.0 // default fallback RTT
		matchedRegion := "default"

		for candidatePoP, latency := range m.latencyMatrix[clientPoP] {
			if strings.Contains(originLower, candidatePoP) {
				matchedLatency = latency
				matchedRegion = candidatePoP
				break
			}
		}

		if matchedLatency < lowestLatency {
			lowestLatency = matchedLatency
			bestOrigin = o
			bestRegion = matchedRegion
		}
	}

	return &model.GeoSteeringDecision{
		ClientPoP:        clientPoP,
		DomainID:         domainID,
		SelectedOriginID: bestOrigin.ID,
		OriginAddress:    bestOrigin.Address,
		OriginRegion:     bestRegion,
		DirectLatencyMs:  lowestLatency,
		Reason:           "LOWEST_RTT_TRANSIT",
	}, nil
}

func (m *Manager) recalculatePoPNodes(pop *model.EdgePoP) {
	nodesMap := m.nodes[pop.ID]
	pop.NodeCount = len(nodesMap)

	healthy := 0
	for _, n := range nodesMap {
		if n.Status == "HEALTHY" {
			healthy++
		}
	}
	pop.HealthyNodeCount = healthy
	pop.UpdatedAt = time.Now().UTC()
}

func generateHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
