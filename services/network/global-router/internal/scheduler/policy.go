package scheduler

import (
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/registry"
)

type OptimizationObjective string

const (
	ObjectiveBalanced OptimizationObjective = "BALANCED"
	ObjectiveLatency  OptimizationObjective = "LOW_LATENCY"
	ObjectiveCost     OptimizationObjective = "MIN_COST"
	ObjectiveCarbon   OptimizationObjective = "ZERO_CARBON"
)

const (
	MaxWorkloadID        = 128
	MaxIdempotencyKey    = 256
	MaxWorkloadName      = 512
	MaxPreferredProvider = 128
	MaxRequiredGPU       = 64
)

// DispatchPolicy encapsulates client workload constraints and optimization targets (Rule 23)
type DispatchPolicy struct {
	WorkloadID        string                 `json:"workload_id"`
	TenantID          string                 `json:"tenant_id"`
	ProjectID         string                 `json:"project_id"`
	Name              string                 `json:"name"`
	Residency         registry.DataResidency `json:"residency"`
	StrictSovereignty bool                   `json:"strict_sovereignty"` // Bangladesh NDMA 2026 / EU GDPR
	RequiredGPU       string                 `json:"required_gpu"`       // "H100", "B200", "L40S", "A100"
	GPUsRequested     int                    `json:"gpus_requested"`     // Number of GPUs required
	MaxLatencyMs      int                    `json:"max_latency_ms"`     // Upper SLA bound
	MaxCostRate       float64                `json:"max_cost_rate"`      // Maximum hourly budget ($/hr)
	PreferredProvider string                 `json:"preferred_provider"` // "on-prem-dhaka", "aws", "coreweave"
	Objective         OptimizationObjective  `json:"objective"`
	IdempotencyKey    string                 `json:"idempotency_key"`
}

// DispatchDecision records the explainable result of an infrastructure placement (Rules 28, 111, 112)
type DispatchDecision struct {
	WorkloadID      string                   `json:"workload_id"`
	TenantID        string                   `json:"tenant_id"`
	ProjectID       string                   `json:"project_id"`
	Status          string                   `json:"status"` // "SCHEDULED", "FAILED_NO_CAPACITY"
	AssignedBackend *registry.ComputeBackend `json:"assigned_backend"`
	GPUsAllocated   int                      `json:"gpus_allocated"`
	CompositeScore  float64                  `json:"composite_score"`
	Reason          string                   `json:"reason"`
	ReasonCodes     []string                 `json:"reason_codes"`
	Alternatives    []string                 `json:"alternatives"`
	FallbackUsed    bool                     `json:"fallback_used"`
	CalculatedAt    time.Time                `json:"calculated_at"`
}
