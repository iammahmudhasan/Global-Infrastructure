package scheduler

import (
	"errors"
	"fmt"
	"math"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/circuitbreaker"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/registry"
)

var (
	ErrNoEligibleBackends = errors.New("no eligible compute backend satisfies workload constraints")
	ErrInvalidPolicy      = errors.New("invalid workload dispatch policy: missing required parameters")
)

type Evaluator struct {
	mu          sync.RWMutex
	reg         *registry.Registry
	idempotency map[string]*DispatchDecision
}

func NewEvaluator(reg *registry.Registry) *Evaluator {
	return &Evaluator{
		reg:         reg,
		idempotency: make(map[string]*DispatchDecision),
	}
}

// Evaluate answers: "Where should this application, AI inference request, and compute workload run right now?"
func (e *Evaluator) Evaluate(policy DispatchPolicy) (*DispatchDecision, error) {
	if policy.WorkloadID == "" || policy.TenantID == "" {
		return nil, ErrInvalidPolicy
	}

	// 1. Tenant-Scoped Idempotency Check (Rule 16, Finding 16)
	idempotencyKey := ""
	if policy.IdempotencyKey != "" {
		idempotencyKey = policy.TenantID + ":" + policy.IdempotencyKey
		e.mu.RLock()
		if existing, found := e.idempotency[idempotencyKey]; found {
			e.mu.RUnlock()
			return existing, nil
		}
		e.mu.RUnlock()
	}

	candidates := e.reg.List()
	var eligible []*registry.ComputeBackend
	var filterReasons []string

	// 2. Strict Constraint Filtering (Rules 23, 111)
	for _, b := range candidates {
		// Circuit Breaker & Health Check (Rule 14)
		if b.Breaker != nil && b.Breaker.State() == circuitbreaker.StateOpen {
			filterReasons = append(filterReasons, fmt.Sprintf("%s: circuit breaker OPEN", b.ID))
			continue
		}
		if !b.Healthy {
			filterReasons = append(filterReasons, fmt.Sprintf("%s: health check failed", b.ID))
			continue
		}

		// Strict Data Residency / Sovereignty Enforcement (Rules 106, 111)
		// Bangladesh NDMA 2026 mandates synchronized national copy for CII
		if policy.StrictSovereignty && policy.Residency != registry.ResidencyAny {
			if b.Jurisdiction != policy.Residency {
				filterReasons = append(filterReasons, fmt.Sprintf("%s: jurisdiction mismatch (%s != %s)", b.ID, b.Jurisdiction, policy.Residency))
				continue
			}
		}

		// GPU Architecture Constraint
		if policy.RequiredGPU != "" && b.GPUModel != policy.RequiredGPU {
			filterReasons = append(filterReasons, fmt.Sprintf("%s: requires GPU %s (has %s)", b.ID, policy.RequiredGPU, b.GPUModel))
			continue
		}

		// Cost Upper Bound Constraint
		if policy.MaxCostRate > 0 && b.HourlyCost > policy.MaxCostRate {
			filterReasons = append(filterReasons, fmt.Sprintf("%s: cost $%.2f exceeds max $%.2f", b.ID, b.HourlyCost, policy.MaxCostRate))
			continue
		}

		// Latency Upper Bound Constraint
		if policy.MaxLatencyMs > 0 && b.LatencyP95Ms > policy.MaxLatencyMs {
			filterReasons = append(filterReasons, fmt.Sprintf("%s: latency %dms exceeds max %dms", b.ID, b.LatencyP95Ms, policy.MaxLatencyMs))
			continue
		}

		eligible = append(eligible, b)
	}

	// 3. Deterministic Fallback if Candidates Empty (Rule 30)
	if len(eligible) == 0 {
		// If strict sovereignty was requested, never violate the law (Rule 28)
		if policy.StrictSovereignty {
			return nil, fmt.Errorf("%w: strict sovereignty constraints violated. Filter details: %v",
				ErrNoEligibleBackends, filterReasons)
		}

		// Otherwise, attempt fallback to best available healthy node
		for _, b := range candidates {
			if b.Healthy && (b.Breaker == nil || b.Breaker.State() != circuitbreaker.StateOpen) {
				decision := &DispatchDecision{
					WorkloadID:      policy.WorkloadID,
					TenantID:        policy.TenantID,
					Status:          "SCHEDULED",
					AssignedBackend: b,
					CompositeScore:  999.0,
					Reason:          "Deterministic fallback: placed on nearest healthy node",
					ReasonCodes:     []string{"DETERMINISTIC_FALLBACK_ACTIVE", "HEALTHY_TARGET"},
					FallbackUsed:    true,
					CalculatedAt:    time.Now().UTC(),
				}
				e.recordIdempotency(policy.IdempotencyKey, decision)
				return decision, nil
			}
		}

		return nil, fmt.Errorf("%w: all nodes unhealthy or filtered. Details: %v", ErrNoEligibleBackends, filterReasons)
	}

	// 4. Multi-Objective Placement Optimization Function
	// Score weights calibrated by optimization objective
	var wLat, wCost, wCarb float64
	switch policy.Objective {
	case ObjectiveLatency:
		wLat, wCost, wCarb = 3.0, 10.0, 0.1
	case ObjectiveCost:
		wLat, wCost, wCarb = 0.5, 50.0, 0.1
	case ObjectiveCarbon:
		wLat, wCost, wCarb = 0.5, 10.0, 2.0
	default: // Balanced
		wLat, wCost, wCarb = 1.5, 25.0, 0.5
	}

	var bestBackend *registry.ComputeBackend
	bestScore := math.MaxFloat64
	var alternatives []string
	var reasonCodes []string

	for _, b := range eligible {
		alternatives = append(alternatives, b.ID)

		// Calculate composite penalty score (lower is better)
		score := (float64(b.LatencyP95Ms) * wLat) + (b.HourlyCost * wCost) + (b.CarbonIntensity * wCarb)

		// Affinity & Preference Bonuses
		if policy.PreferredProvider != "" && b.Provider == policy.PreferredProvider {
			score -= 30.0 // Preferred cloud partner bonus
		}
		if policy.Residency != registry.ResidencyAny && b.Jurisdiction == policy.Residency {
			score -= 50.0 // Sovereign local data anchor bonus
		}

		if score < bestScore {
			bestScore = score
			bestBackend = b
		}
	}

	// 5. Synthesize Explainable Decision Codes (Rule 112)
	reasonCodes = append(reasonCodes, fmt.Sprintf("OPTIMAL_SCORE_%.2f", bestScore))
	if bestBackend.Jurisdiction == registry.ResidencyBangladesh {
		reasonCodes = append(reasonCodes, "SOVEREIGN_JURISDICTION_BD_MATCH")
	}
	if bestBackend.LatencyP95Ms <= 10 {
		reasonCodes = append(reasonCodes, "ULTRA_LOW_LATENCY_SUB_10MS")
	}
	if bestBackend.CarbonIntensity < 50.0 {
		reasonCodes = append(reasonCodes, "LOW_CARBON_RENEWABLE_POWER")
	}

	reason := fmt.Sprintf("Placed on %s (%s, %s): RTT %dms, Cost $%.2f/hr, Carbon %.1fgCO2/kWh [Objective: %s]",
		bestBackend.Name, bestBackend.Provider, bestBackend.Region,
		bestBackend.LatencyP95Ms, bestBackend.HourlyCost, bestBackend.CarbonIntensity, policy.Objective)

	decision := &DispatchDecision{
		WorkloadID:      policy.WorkloadID,
		TenantID:        policy.TenantID,
		Status:          "SCHEDULED",
		AssignedBackend: bestBackend,
		CompositeScore:  bestScore,
		Reason:          reason,
		ReasonCodes:     reasonCodes,
		Alternatives:    alternatives,
		FallbackUsed:    false,
		CalculatedAt:    time.Now().UTC(),
	}

	e.recordIdempotency(idempotencyKey, decision)
	return decision, nil
}

func (e *Evaluator) recordIdempotency(key string, decision *DispatchDecision) {
	if key == "" {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.idempotency[key] = decision
}
