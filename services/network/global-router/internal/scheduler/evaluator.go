package scheduler

import (
	"fmt"
	"math"
	"sync"
	"time"
)

// WorkloadController evaluates real-time telemetry and policies to route compute jobs
type WorkloadController struct {
	mu       sync.RWMutex
	backends map[string]*ComputeBackend
}

func NewWorkloadController() *WorkloadController {
	c := &WorkloadController{
		backends: make(map[string]*ComputeBackend),
	}
	c.bootstrapDefaultBackends()
	return c
}

func (c *WorkloadController) bootstrapDefaultBackends() {
	// Sample heterogeneous backends
	c.backends["coreweave-us-h100"] = &ComputeBackend{
		ID:            "coreweave-us-h100",
		Provider:      "coreweave",
		Region:        "us-east-1",
		Jurisdiction:  ResidencyUS,
		Endpoint:      "https://cw-iad.inference.internal",
		CurrentCost1k: 0.0012, // High-throughput cheap batch compute
		LatencyP95Ms:  110,
		Healthy:       true,
		ErrorRate:     0.01,
	}

	c.backends["aws-ap-southeast-bedrock"] = &ComputeBackend{
		ID:            "aws-ap-southeast-bedrock",
		Provider:      "aws",
		Region:        "ap-southeast-1",
		Jurisdiction:  ResidencySingapore,
		Endpoint:      "https://bedrock.ap-southeast-1.amazonaws.com",
		CurrentCost1k: 0.0025,
		LatencyP95Ms:  28,
		Healthy:       true,
		ErrorRate:     0.005,
	}

	c.backends["onprem-dgx-dhaka"] = &ComputeBackend{
		ID:            "onprem-dgx-dhaka",
		Provider:      "on-prem-dhaka",
		Region:        "ap-south-2",
		Jurisdiction:  ResidencyBangladesh,
		Endpoint:      "https://dgx01.colocation.dhaka.internal",
		CurrentCost1k: 0.0018, // Amortized hardware cost
		LatencyP95Ms:  6,      // Ultra-low local round-trip
		Healthy:       true,
		ErrorRate:     0.001,
	}

	c.backends["gcp-fra-vertex"] = &ComputeBackend{
		ID:            "gcp-fra-vertex",
		Provider:      "gcp",
		Region:        "eu-central-1",
		Jurisdiction:  ResidencyEU,
		Endpoint:      "https://europe-west3-aiplatform.googleapis.com",
		CurrentCost1k: 0.0028,
		LatencyP95Ms:  135,
		Healthy:       true,
		ErrorRate:     0.002,
	}
}

// EvaluateWorkload answers the core thesis question:
// "Where should this application or AI inference workload run right now?"
func (c *WorkloadController) EvaluateWorkload(policy Policy) (*DispatchDecision, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	var eligible []*ComputeBackend

	for _, b := range c.backends {
		if !b.Healthy || b.ErrorRate > 0.05 {
			continue // Skip unhealthy or failing nodes
		}

		// 1. Enforce Sovereignty Constraints
		if policy.StrictSovereign && policy.Residency != ResidencyAny {
			if b.Jurisdiction != policy.Residency {
				continue // Hard legal rejection
			}
		}

		// 2. Enforce Cost Upper Bound
		if policy.MaxCostPer1k > 0 && b.CurrentCost1k > policy.MaxCostPer1k {
			continue // Budget constraint breached
		}

		eligible = append(eligible, b)
	}

	if len(eligible) == 0 {
		return nil, fmt.Errorf("no eligible compute backend satisfies policy: %s (Residency: %s, MaxCost: $%.4f)",
			policy.Name, policy.Residency, policy.MaxCostPer1k)
	}

	// 3. Multi-Objective Cost Optimization Function
	// Score = w_lat * NormalizedLatency + w_cost * NormalizedCost + w_err * ErrorRate - PreferenceBonus
	var bestBackend *ComputeBackend
	bestScore := math.MaxFloat64
	var alternatives []string

	for _, b := range eligible {
		alternatives = append(alternatives, b.ID)

		// Calculate composite score (lower is better)
		score := (float64(b.LatencyP95Ms) * 1.5) + (b.CurrentCost1k * 50000.0) + (b.ErrorRate * 2000.0)

		if policy.PreferredCloud != "" && b.Provider == policy.PreferredCloud {
			score -= 50.0 // Preferred cloud bonus
		}

		if policy.Residency != ResidencyAny && b.Jurisdiction == policy.Residency {
			score -= 80.0 // Sovereign locality affinity bonus
		}

		if score < bestScore {
			bestScore = score
			bestBackend = b
		}
	}

	reason := fmt.Sprintf("Optimized for latency (%dms P95), cost ($%.4f/1k), and sovereignty (%s)",
		bestBackend.LatencyP95Ms, bestBackend.CurrentCost1k, bestBackend.Jurisdiction)

	return &DispatchDecision{
		SelectedBackend: bestBackend,
		Score:           bestScore,
		Reason:          reason,
		CalculatedAt:    time.Now().UTC(),
		Alternatives:    alternatives,
	}, nil
}

func (c *WorkloadController) ListBackends() []*ComputeBackend {
	c.mu.RLock()
	defer c.mu.RUnlock()

	list := make([]*ComputeBackend, 0, len(c.backends))
	for _, b := range c.backends {
		list = append(list, b)
	}
	return list
}

func (c *WorkloadController) RegisterBackend(backend *ComputeBackend) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.backends[backend.ID] = backend
}
