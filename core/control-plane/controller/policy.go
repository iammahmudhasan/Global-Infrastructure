package controller

import "time"

// DataResidency specifies sovereign legal jurisdiction constraints
type DataResidency string

const (
	ResidencyAny        DataResidency = "ANY"
	ResidencyBangladesh DataResidency = "BD" // Complies with National Data Management Act 2026
	ResidencyEU         DataResidency = "EU" // Complies with GDPR & EU AI Act
	ResidencyUS         DataResidency = "US"
	ResidencySingapore  DataResidency = "SG"
)

// Policy defines customer constraints for intelligent workload dispatching
type Policy struct {
	Name            string        `json:"name"`
	Residency       DataResidency `json:"residency"`
	MaxLatencyMs    int           `json:"max_latency_ms"`
	MaxCostPer1k    float64       `json:"max_cost_per_1k"` // Max price per 1000 tokens / compute units ($)
	StrictSovereign bool          `json:"strict_sovereign"` // If true, never route outside legal jurisdiction
	PreferredCloud  string        `json:"preferred_cloud"`  // Optional preference (e.g. "coreweave", "aws", "on-prem")
	Timeout         time.Duration `json:"timeout"`
}

// ComputeBackend represents a registered heterogeneous execution target
type ComputeBackend struct {
	ID            string        `json:"id"`
	Provider      string        `json:"provider"` // "aws", "gcp", "coreweave", "on-prem-dhaka", "azure"
	Region        string        `json:"region"`   // "ap-south-2", "us-east-1", "eu-central-1"
	Jurisdiction  DataResidency `json:"jurisdiction"`
	Endpoint      string        `json:"endpoint"`
	CurrentCost1k float64       `json:"current_cost_1k"` // Real-time cost per 1k compute units ($)
	LatencyP95Ms  int           `json:"latency_p95_ms"`
	Healthy       bool          `json:"healthy"`
	ErrorRate     float64       `json:"error_rate"`      // 0.0 to 1.0
	ActiveLoads   int           `json:"active_loads"`
}

// DispatchDecision records why a specific backend was selected
type DispatchDecision struct {
	SelectedBackend *ComputeBackend `json:"selected_backend"`
	Score           float64         `json:"score"`
	Reason          string          `json:"reason"`
	CalculatedAt    time.Time       `json:"calculated_at"`
	Alternatives    []string        `json:"alternatives"`
}
