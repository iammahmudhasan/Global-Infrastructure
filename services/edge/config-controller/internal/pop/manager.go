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
	ErrPoPNotFound  = errors.New("pop not found")
	ErrNodeNotFound = errors.New("edge node not found")
	ErrEmptyPoPID   = errors.New("pop_id is required")
	ErrNoOrigins    = errors.New("no healthy origins available for steering")
)

// Manager orchestrates Edge Points of Presence, Anycast BGP announcements, and node health
type Manager struct {
	mu            sync.RWMutex
	pops          map[string]*model.EdgePoP
	nodes         map[string]map[string]*model.EdgeNode // popID -> nodeID -> Node
	latencyMatrix map[string]map[string]float64         // fromPoP -> toTarget -> latencyMs
}

func NewManager() *Manager {
	m := &Manager{
		pops:          make(map[string]*model.EdgePoP),
		nodes:         make(map[string]map[string]*model.EdgeNode),
		latencyMatrix: make(map[string]map[string]float64),
	}
	m.seedDefaultPoPs()
	m.seedLatencyMatrix()
	return m
}

func (m *Manager) seedDefaultPoPs() {
	now := time.Now().UTC()

	defaults := []model.EdgePoP{
		{
			ID:               "dhaka",
			Name:             "Dhaka BDIX Edge 01",
			Region:           "asia-south1",
			City:             "Dhaka",
			Country:          "BD",
			Latitude:         23.8103,
			Longitude:        90.4125,
			ASN:              140685,
			AnycastIPv4:      "103.150.180.1",
			AnycastIPv6:      "2a0e:b107::1",
			BGPState:         model.BGPStateAnnounced,
			Status:           model.PoPStatusActive,
			NodeCount:        0,
			HealthyNodeCount: 0,
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			ID:               "singapore",
			Name:             "Singapore Equinix SG1",
			Region:           "asia-southeast1",
			City:             "Singapore",
			Country:          "SG",
			Latitude:         1.3521,
			Longitude:        103.8198,
			ASN:              140685,
			AnycastIPv4:      "103.150.180.1",
			AnycastIPv6:      "2a0e:b107::1",
			BGPState:         model.BGPStateAnnounced,
			Status:           model.PoPStatusActive,
			NodeCount:        0,
			HealthyNodeCount: 0,
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			ID:               "frankfurt",
			Name:             "Frankfurt DE-CIX Edge 01",
			Region:           "europe-west3",
			City:             "Frankfurt",
			Country:          "DE",
			Latitude:         50.1109,
			Longitude:        8.6821,
			ASN:              140685,
			AnycastIPv4:      "103.150.180.1",
			AnycastIPv6:      "2a0e:b107::1",
			BGPState:         model.BGPStateAnnounced,
			Status:           model.PoPStatusActive,
			NodeCount:        0,
			HealthyNodeCount: 0,
			CreatedAt:        now,
			UpdatedAt:        now,
		},
		{
			ID:               "virginia",
			Name:             "Virginia Equinix Ashburn DC2",
			Region:           "us-east1",
			City:             "Ashburn",
			Country:          "US",
			Latitude:         39.0438,
			Longitude:        -77.4874,
			ASN:              140685,
			AnycastIPv4:      "103.150.180.1",
			AnycastIPv6:      "2a0e:b107::1",
			BGPState:         model.BGPStateAnnounced,
			Status:           model.PoPStatusActive,
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
				FromPoP:   from,
				ToTarget:  to,
				LatencyMs: latency,
				Status:    "ACTIVE",
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
