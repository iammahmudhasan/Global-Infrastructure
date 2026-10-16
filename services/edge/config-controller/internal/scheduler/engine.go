package scheduler

import (
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/policy"
)

// ComputeNode represents an execution substrate node with physical and economic telemetry.
type ComputeNode struct {
	NodeID           string  `json:"node_id"`
	Provider         string  `json:"provider"`
	Region           string  `json:"region"`
	Jurisdiction     string  `json:"jurisdiction"`
	GPUType          string  `json:"gpu_type"`
	TotalGPUs        int     `json:"total_gpus"`
	AvailableGPUs    int     `json:"available_gpus"`
	CostPerGPUHour   float64 `json:"cost_per_gpu_hour"`
	CarbonIntensity  float64 `json:"carbon_intensity"` // gCO2/kWh
	RTTFromDhaka     int     `json:"rtt_from_dhaka"`
	RTTFromFrankfurt int     `json:"rtt_from_frankfurt"`
	RTTFromVirginia  int     `json:"rtt_from_virginia"`
	RTTFromSingapore int     `json:"rtt_from_singapore"`
	KVCacheWarmth    float64 `json:"kv_cache_warmth"` // 0.0 to 1.0
}

// WorkloadRequirement specifies client constraints and placement preferences.
type WorkloadRequirement struct {
	TenantID             string                    `json:"tenant_id"`
	ProjectID            string                    `json:"project_id"`
	WorkloadID           string                    `json:"workload_id"`
	WorkloadType         string                    `json:"workload_type"` // "GPU_INFERENCE", "BANKING_API", "REASONING_AGENT"
	ClientOrigin         string                    `json:"client_origin"` // "dhaka", "singapore", "frankfurt", "virginia"
	RequiredJurisdiction string                    `json:"required_jurisdiction,omitempty"`
	StrictSovereignty    bool                      `json:"strict_sovereignty"`
	DataClassification   policy.DataClassification `json:"data_classification,omitempty"`
	MaxLatencyP95MS      int                       `json:"max_latency_p95_ms"`
	MaxCostPerHour       float64                   `json:"max_cost_per_hour"`
	GPUsRequested        int                       `json:"gpus_requested"`
	PrioritizeGreen      bool                      `json:"prioritize_green_energy"`
}

// SchedulingDecision returns the deterministic optimization decision.
type SchedulingDecision struct {
	WorkloadID           string    `json:"workload_id"`
	Status               string    `json:"status"` // "SCHEDULED", "UNSCHEDULABLE"
	AssignedNode         string    `json:"assigned_node,omitempty"`
	Provider             string    `json:"provider,omitempty"`
	Region               string    `json:"region,omitempty"`
	Jurisdiction         string    `json:"jurisdiction,omitempty"`
	MeasuredRTTMS        int       `json:"measured_rtt_ms,omitempty"`
	HourlyCost           float64   `json:"hourly_cost,omitempty"`
	CarbonGCO2KWh        float64   `json:"carbon_gco2_kwh,omitempty"`
	CarbonClassification string    `json:"carbon_classification,omitempty"`
	RemainingNodeGPUs    int       `json:"remaining_node_gpus,omitempty"`
	OptimizationScore    float64   `json:"optimization_score,omitempty"`
	Reason               string    `json:"reason"`
	EvaluatedAt          time.Time `json:"evaluated_at"`
	Error                string    `json:"error,omitempty"`
}

var (
	ErrNoSatisfyingNode = errors.New("no available compute node satisfies constraints or capacity exhausted")
	ErrInvalidOrigin    = errors.New("client origin must be specified")
)

// PoPTelemetrySnapshot contains live RTT and status for an edge location.
type PoPTelemetrySnapshot struct {
	PoPID             string
	Healthy           bool
	Status            string
	EWMALatencyMS     float64
	PacketLossPercent float64
}

// UniversalScheduler manages global workload placement and capacity allocation.
type UniversalScheduler struct {
	mu               sync.RWMutex
	nodes            map[string]*ComputeNode
	idempotencyCache map[string]*SchedulingDecision
	popTelemetry     map[string]PoPTelemetrySnapshot
	policyEvaluator  *policy.Evaluator
}

// DefaultTopology returns the standard production edge nodes.
func DefaultTopology() []*ComputeNode {
	return []*ComputeNode{
		{
			NodeID:           "bd-dhaka-dgx01",
			Provider:         "baremetal-bd",
			Region:           "ap-south-2",
			Jurisdiction:     "BD",
			GPUType:          "H100",
			TotalGPUs:        8,
			AvailableGPUs:    8,
			CostPerGPUHour:   2.10,
			CarbonIntensity:  480.0,
			RTTFromDhaka:     4,
			RTTFromFrankfurt: 130,
			RTTFromVirginia:  210,
			RTTFromSingapore: 32,
			KVCacheWarmth:    0.9,
		},
		{
			NodeID:           "sg-aws-gpu01",
			Provider:         "aws",
			Region:           "ap-southeast-1",
			Jurisdiction:     "SG",
			GPUType:          "H100",
			TotalGPUs:        16,
			AvailableGPUs:    16,
			CostPerGPUHour:   3.20,
			CarbonIntensity:  390.0,
			RTTFromDhaka:     32,
			RTTFromFrankfurt: 115,
			RTTFromVirginia:  180,
			RTTFromSingapore: 8,
			KVCacheWarmth:    0.5,
		},
		{
			NodeID:           "is-green-gpu01",
			Provider:         "iceland-green-dc",
			Region:           "is-north-1",
			Jurisdiction:     "IS",
			GPUType:          "H100",
			TotalGPUs:        32,
			AvailableGPUs:    32,
			CostPerGPUHour:   1.45,
			CarbonIntensity:  12.0,
			RTTFromDhaka:     160,
			RTTFromFrankfurt: 35,
			RTTFromVirginia:  75,
			RTTFromSingapore: 145,
			KVCacheWarmth:    0.2,
		},
		{
			NodeID:           "us-cw-h100-iad",
			Provider:         "coreweave",
			Region:           "us-east-1",
			Jurisdiction:     "US",
			GPUType:          "H100",
			TotalGPUs:        64,
			AvailableGPUs:    64,
			CostPerGPUHour:   2.40,
			CarbonIntensity:  340.0,
			RTTFromDhaka:     215,
			RTTFromFrankfurt: 80,
			RTTFromVirginia:  8,
			RTTFromSingapore: 195,
			KVCacheWarmth:    0.7,
		},
	}
}

// NewUniversalScheduler initializes the Universal Scheduler with default nodes.
func NewUniversalScheduler(customNodes []*ComputeNode) *UniversalScheduler {
	nodes := customNodes
	if len(nodes) == 0 {
		nodes = DefaultTopology()
	}

	nodeMap := make(map[string]*ComputeNode, len(nodes))
	for _, n := range nodes {
		cp := *n
		nodeMap[n.NodeID] = &cp
	}

	return &UniversalScheduler{
		nodes:            nodeMap,
		idempotencyCache: make(map[string]*SchedulingDecision),
		popTelemetry:     make(map[string]PoPTelemetrySnapshot),
		policyEvaluator:  policy.NewEvaluator(),
	}
}

// UpdatePoPTelemetry ingests live health prober telemetry into the scheduler.
func (s *UniversalScheduler) UpdatePoPTelemetry(popID string, healthy bool, status string, ewmaMS float64, lossPercent float64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.popTelemetry[strings.ToLower(popID)] = PoPTelemetrySnapshot{
		PoPID:             popID,
		Healthy:           healthy,
		Status:            status,
		EWMALatencyMS:     ewmaMS,
		PacketLossPercent: lossPercent,
	}
}

// FindOptimalPlacement calculates the global optimal placement for a given workload.
func (s *UniversalScheduler) FindOptimalPlacement(req WorkloadRequirement) (*SchedulingDecision, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if strings.TrimSpace(req.TenantID) == "" {
		req.TenantID = "tenant-default"
	}
	if strings.TrimSpace(req.ProjectID) == "" {
		req.ProjectID = "proj-default"
	}
	if strings.TrimSpace(req.WorkloadID) == "" {
		req.WorkloadID = fmt.Sprintf("wl-%d", time.Now().UnixNano())
	}
	if req.GPUsRequested <= 0 {
		req.GPUsRequested = 1
	}

	idempotencyKey := fmt.Sprintf("%s:%s:%s", req.TenantID, req.ProjectID, req.WorkloadID)
	if existing, found := s.idempotencyCache[idempotencyKey]; found {
		return existing, nil
	}

	origin := strings.ToLower(strings.TrimSpace(req.ClientOrigin))
	if origin == "" {
		origin = "dhaka"
	}

	popSnapshot := s.popTelemetry[origin]

	type candidate struct {
		node *ComputeNode
		rtt  int
	}
	var candidates []candidate

	for _, node := range s.nodes {
		// 1. Capacity check
		if node.AvailableGPUs < req.GPUsRequested {
			continue
		}

		// 2. Sovereign Policy Validation
		evalReq := &policy.SovereignEvaluationRequest{
			TenantID:           req.TenantID,
			ProjectID:          req.ProjectID,
			WorkloadID:         req.WorkloadID,
			DataClassification: req.DataClassification,
			SourceJurisdiction: policy.Jurisdiction(strings.ToUpper(req.RequiredJurisdiction)),
			TargetJurisdiction: policy.Jurisdiction(node.Jurisdiction),
			TargetRegion:       node.Region,
			TargetNodeID:       node.NodeID,
			StrictSovereignty:  req.StrictSovereignty,
		}
		if evalReq.SourceJurisdiction == "" && origin == "dhaka" && req.StrictSovereignty {
			evalReq.SourceJurisdiction = policy.JurisdictionBD
		}
		polRes, err := s.policyEvaluator.Evaluate(evalReq)
		if err == nil && !polRes.Allowed {
			continue
		}

		// 3. Latency Upper Bound with live telemetry
		baseRTT := s.calculateBaseRTT(node, origin)
		rtt := baseRTT
		if popSnapshot.PoPID != "" {
			if !popSnapshot.Healthy || popSnapshot.Status == "POP_DRAINING" || popSnapshot.Status == "POP_DOWN" {
				rtt = baseRTT + 78 // Subsea cut / failover reroute penalty
			} else {
				jitterPenalty := int(popSnapshot.PacketLossPercent * 25.0)
				rtt = baseRTT + jitterPenalty
				if rtt < 1 {
					rtt = 1
				}
			}
		}

		if req.MaxLatencyP95MS > 0 && rtt > req.MaxLatencyP95MS {
			continue
		}

		// 4. Budget Constraint Check
		if req.MaxCostPerHour > 0 && node.CostPerGPUHour > req.MaxCostPerHour {
			continue
		}

		candidates = append(candidates, candidate{node: node, rtt: rtt})
	}

	now := time.Now().UTC()

	if len(candidates) == 0 {
		failedDecision := &SchedulingDecision{
			WorkloadID:  req.WorkloadID,
			Status:      "UNSCHEDULABLE",
			Reason:      "No available compute node satisfies constraints, capacity exhausted, or sovereign boundary violated",
			EvaluatedAt: now,
			Error:       ErrNoSatisfyingNode.Error(),
		}
		s.idempotencyCache[idempotencyKey] = failedDecision
		return failedDecision, nil
	}

	// Multi-Objective Optimization Scoring Function (Lower Score is Better)
	wLat := 1.0
	wCost := 10.0
	wCarbon := 0.05
	if req.PrioritizeGreen {
		wCarbon = 0.5
	}
	wKV := 30.0

	var bestNode *ComputeNode
	bestScore := math.MaxFloat64
	bestRTT := 0

	for _, c := range candidates {
		score := (wLat * float64(c.rtt)) +
			(wCost * c.node.CostPerGPUHour) +
			(wCarbon * c.node.CarbonIntensity) -
			(wKV * c.node.KVCacheWarmth)

		if req.RequiredJurisdiction != "" && strings.EqualFold(c.node.Jurisdiction, req.RequiredJurisdiction) {
			score -= 50.0 // Sovereign locality bonus
		}

		if score < bestScore {
			bestScore = score
			bestNode = c.node
			bestRTT = c.rtt
		}
	}

	// Capacity Allocation
	bestNode.AvailableGPUs -= req.GPUsRequested

	carbonLabel := "STANDARD_GRID"
	if bestNode.CarbonIntensity < 50.0 {
		carbonLabel = "LOW_CARBON_RENEWABLE_POWER"
	}

	decision := &SchedulingDecision{
		WorkloadID:           req.WorkloadID,
		Status:               "SCHEDULED",
		AssignedNode:         bestNode.NodeID,
		Provider:             bestNode.Provider,
		Region:               bestNode.Region,
		Jurisdiction:         bestNode.Jurisdiction,
		MeasuredRTTMS:        bestRTT,
		HourlyCost:           bestNode.CostPerGPUHour,
		CarbonGCO2KWh:        bestNode.CarbonIntensity,
		CarbonClassification: carbonLabel,
		RemainingNodeGPUs:    bestNode.AvailableGPUs,
		OptimizationScore:    math.Round(bestScore*100) / 100,
		Reason: fmt.Sprintf("Optimized via Universal Scheduler (RTT: %dms, Cost: $%.2f/h, Sovereignty: %s, Power: %s)",
			bestRTT, bestNode.CostPerGPUHour, bestNode.Jurisdiction, carbonLabel),
		EvaluatedAt: now,
	}

	s.idempotencyCache[idempotencyKey] = decision
	return decision, nil
}

// GetNodes returns snapshot copies of all managed compute nodes.
func (s *UniversalScheduler) GetNodes() []*ComputeNode {
	s.mu.RLock()
	defer s.mu.RUnlock()

	res := make([]*ComputeNode, 0, len(s.nodes))
	for _, n := range s.nodes {
		cp := *n
		res = append(res, &cp)
	}
	return res
}

func (s *UniversalScheduler) calculateBaseRTT(node *ComputeNode, origin string) int {
	switch origin {
	case "dhaka":
		return node.RTTFromDhaka
	case "frankfurt":
		return node.RTTFromFrankfurt
	case "virginia":
		return node.RTTFromVirginia
	case "singapore":
		return node.RTTFromSingapore
	default:
		return 100
	}
}
