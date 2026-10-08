package scheduler

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/circuitbreaker"
	"github.com/iammahmudhasan/nexusedge-control-plane/internal/registry"
)

var (
	ErrNoEligibleBackends = errors.New("no eligible compute backend satisfies workload constraints")
	ErrInvalidPolicy      = errors.New("invalid workload dispatch policy: missing required parameters")
)

type cachedDecision struct {
	decision     *DispatchDecision
	expiresAt    time.Time
	lastAccessed time.Time
}

type Evaluator struct {
	mu          sync.Mutex
	reg         *registry.Registry
	idempotency map[string]*cachedDecision
}

func NewEvaluator(reg *registry.Registry) *Evaluator {
	return &Evaluator{
		reg:         reg,
		idempotency: make(map[string]*cachedDecision),
	}
}

// Evaluate answers: "Where should this application, AI inference request, and compute workload run right now?"
// Critical section is serialized to ensure atomic idempotency checks and capacity reservations (Findings 6, 7).
func (e *Evaluator) Evaluate(policy DispatchPolicy) (*DispatchDecision, error) {
	if policy.WorkloadID == "" || policy.TenantID == "" {
		return nil, ErrInvalidPolicy
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	// 0. Periodic Cleanup of Expired Idempotency Entries
	now := time.Now()
	for k, v := range e.idempotency {
		if now.After(v.expiresAt) {
			delete(e.idempotency, k)
		}
	}

	// 1. Tenant & Project-Scoped Idempotency Check (Rules 16, 54, 55, Finding 21)
	idempotencyKey := ""
	if policy.IdempotencyKey != "" {
		projectScope := policy.ProjectID
		if projectScope == "" {
			projectScope = "default"
		}
		idempotencyKey = fmt.Sprintf("%s:%s:%s", policy.TenantID, projectScope, policy.IdempotencyKey)
		if cached, found := e.idempotency[idempotencyKey]; found {
			if now.Before(cached.expiresAt) {
				cached.lastAccessed = now
				return cloneDecision(cached.decision), nil
			}
		}
	}

	gpusReq := policy.GPUsRequested
	if gpusReq <= 0 {
		gpusReq = 1
	}

	candidates := e.reg.List()
	var eligible []*registry.ComputeBackend
	var filterReasons []string

	// 2. Strict Constraint Filtering (Rules 23, 111, Finding 20)
	for _, b := range candidates {
		// Circuit Breaker & Health Check (Rule 14)
		if b.CircuitState == circuitbreaker.StateOpen {
			filterReasons = append(filterReasons, fmt.Sprintf("%s: circuit breaker OPEN", b.ID))
			continue
		}
		if !b.Healthy {
			filterReasons = append(filterReasons, fmt.Sprintf("%s: health check failed", b.ID))
			continue
		}

		// GPU Capacity Constraint (Finding 20)
		if b.AvailableGPUs < gpusReq {
			filterReasons = append(filterReasons, fmt.Sprintf("%s: insufficient GPUs (available %d, requested %d)", b.ID, b.AvailableGPUs, gpusReq))
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

	// 3. Multi-Objective Optimization Weights
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

	// 4. Deterministic Fallback if Candidates Empty (Rule 30)
	if len(eligible) == 0 {
		// If strict sovereignty was requested, never violate the law (Rule 28)
		if policy.StrictSovereignty {
			return nil, fmt.Errorf("%w: strict sovereignty constraints violated. Filter details: %v",
				ErrNoEligibleBackends, filterReasons)
		}

		// Collect healthy candidate fallback nodes with capacity and score them deterministically
		type fallbackCandidate struct {
			backend *registry.ComputeBackend
			score   float64
		}
		var fallbackList []fallbackCandidate
		for _, b := range candidates {
			if b.Healthy && b.CircuitState != circuitbreaker.StateOpen && b.AvailableGPUs >= gpusReq {
				score := (float64(b.LatencyP95Ms) * wLat) + (b.HourlyCost * wCost) + (b.CarbonIntensity * wCarb)
				fallbackList = append(fallbackList, fallbackCandidate{backend: b, score: score})
			}
		}
		sort.Slice(fallbackList, func(i, j int) bool {
			if fallbackList[i].score != fallbackList[j].score {
				return fallbackList[i].score < fallbackList[j].score
			}
			return fallbackList[i].backend.ID < fallbackList[j].backend.ID
		})

		for _, item := range fallbackList {
			b := item.backend
			// Atomically check circuit breaker admission and reserve capacity
			if err := e.reg.AdmitAndReserve(policy.WorkloadID, b.ID, gpusReq); err == nil {
				decision := &DispatchDecision{
					WorkloadID:      policy.WorkloadID,
					TenantID:        policy.TenantID,
					ProjectID:       policy.ProjectID,
					Status:          "SCHEDULED",
					AssignedBackend: b,
					GPUsAllocated:   gpusReq,
					CompositeScore:  item.score,
					Reason:          "Deterministic fallback: placed on lowest-score healthy node with capacity",
					ReasonCodes:     []string{"DETERMINISTIC_FALLBACK_ACTIVE", "HEALTHY_TARGET", "CAPACITY_RESERVED"},
					FallbackUsed:    true,
					CalculatedAt:    time.Now().UTC(),
				}
				e.recordIdempotencyLocked(idempotencyKey, decision)
				return decision, nil
			}
		}

		return nil, fmt.Errorf("%w: all nodes unhealthy or filtered. Details: %v", ErrNoEligibleBackends, filterReasons)
	}

	// 5. Multi-Objective Placement Optimization Function

	type scoredBackend struct {
		backend *registry.ComputeBackend
		score   float64
	}

	scored := make([]scoredBackend, 0, len(eligible))
	var alternatives []string

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

		scored = append(scored, scoredBackend{
			backend: b,
			score:   score,
		})
	}

	// Sort eligible candidates by score: lowest penalty score first, tie-break by backend ID (Finding 1)
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].score != scored[j].score {
			return scored[i].score < scored[j].score
		}
		return scored[i].backend.ID < scored[j].backend.ID
	})

	// 5. Reserve Capacity with Fallback to Next Best Candidate (Finding 6, 7)
	// Note on V1 Lifecycle: Allow() guards admission and admits a single trial probe when in HALF_OPEN state.
	// Downstream execution feedback (invoking RecordSuccess / RecordFailure via Registry.UpdateHealth or execution
	// response hooks) belongs to the workload execution layer.
	var bestBackend *registry.ComputeBackend
	var bestScore float64

	for _, item := range scored {
		// Atomically check circuit breaker admission and reserve capacity
		if err := e.reg.AdmitAndReserve(policy.WorkloadID, item.backend.ID, gpusReq); err == nil {
			bestBackend = item.backend
			bestScore = item.score
			break
		}
	}

	if bestBackend == nil {
		return nil, fmt.Errorf("%w: candidate capacity exhausted during reservation race", ErrNoEligibleBackends)
	}

	// 6. Synthesize Explainable Decision Codes (Rule 112)
	var reasonCodes []string
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
		ProjectID:       policy.ProjectID,
		Status:          "SCHEDULED",
		AssignedBackend: bestBackend,
		GPUsAllocated:   gpusReq,
		CompositeScore:  bestScore,
		Reason:          reason,
		ReasonCodes:     reasonCodes,
		Alternatives:    alternatives,
		FallbackUsed:    false,
		CalculatedAt:    time.Now().UTC(),
	}

	e.recordIdempotencyLocked(idempotencyKey, decision)
	return cloneDecision(decision), nil
}

func cloneDecision(d *DispatchDecision) *DispatchDecision {
	if d == nil {
		return nil
	}
	cp := *d
	if d.AssignedBackend != nil {
		backend := *d.AssignedBackend
		cp.AssignedBackend = &backend
	}
	if d.ReasonCodes != nil {
		cp.ReasonCodes = append([]string(nil), d.ReasonCodes...)
	}
	if d.Alternatives != nil {
		cp.Alternatives = append([]string(nil), d.Alternatives...)
	}
	return &cp
}

const MaxIdempotencyEntries = 10000

func (e *Evaluator) IdempotencyCount() int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.idempotency)
}

func (e *Evaluator) HasIdempotencyKey(key string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	_, found := e.idempotency[key]
	return found
}

func (e *Evaluator) RecordIdempotencyForTesting(key string, decision *DispatchDecision) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.recordIdempotencyLocked(key, decision)
}

func (e *Evaluator) SetLastAccessedForTesting(key string, t time.Time) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if entry, ok := e.idempotency[key]; ok {
		entry.lastAccessed = t
	}
}

func (e *Evaluator) recordIdempotencyLocked(key string, decision *DispatchDecision) {
	if key == "" {
		return
	}

	now := time.Now()
	// Update existing entry if present
	if cached, exists := e.idempotency[key]; exists {
		cached.decision = cloneDecision(decision)
		cached.expiresAt = now.Add(24 * time.Hour)
		cached.lastAccessed = now
		return
	}

	// Enforce bounded memory pool to prevent unbounded cache growth (True LRU eviction)
	if len(e.idempotency) >= MaxIdempotencyEntries {
		// 1. Purge expired entries
		for k, v := range e.idempotency {
			if now.After(v.expiresAt) {
				delete(e.idempotency, k)
			}
		}

		// 2. If still at or above capacity, evict least recently accessed entry (true LRU)
		if len(e.idempotency) >= MaxIdempotencyEntries {
			var oldestKey string
			var oldestAccessed time.Time
			first := true
			for k, v := range e.idempotency {
				if first || v.lastAccessed.Before(oldestAccessed) {
					oldestKey = k
					oldestAccessed = v.lastAccessed
					first = false
				}
			}
			if oldestKey != "" {
				delete(e.idempotency, oldestKey)
			}
		}
	}

	e.idempotency[key] = &cachedDecision{
		decision:     cloneDecision(decision),
		expiresAt:    now.Add(24 * time.Hour),
		lastAccessed: now,
	}
}
