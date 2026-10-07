package registry

import (
	"errors"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/circuitbreaker"
)

type DataResidency string

const (
	ResidencyAny        DataResidency = "ANY"
	ResidencyBangladesh DataResidency = "BD" // National Data Management Act 2026 Compliant
	ResidencyEU         DataResidency = "EU" // GDPR & EU AI Act Compliant
	ResidencyUS         DataResidency = "US"
	ResidencySingapore  DataResidency = "SG"
	ResidencyIceland    DataResidency = "IS" // 100% Geothermal / Zero-Carbon
)

var (
	ErrBackendNotFound = errors.New("compute backend not found")
	ErrDuplicateBackend = errors.New("backend with ID already exists")
)

// ComputeBackend represents a registered heterogeneous execution target (Bare-metal, Cloud, Edge)
type ComputeBackend struct {
	ID              string                         `json:"id"`
	Name            string                         `json:"name"`
	Provider        string                         `json:"provider"` // "on-prem-dhaka", "aws", "coreweave", "gcp"
	Region          string                         `json:"region"`
	Jurisdiction    DataResidency                  `json:"jurisdiction"`
	Endpoint        string                         `json:"endpoint"`
	GPUModel        string                         `json:"gpu_model"` // "H100", "B200", "L40S", "A100"
	AvailableGPUs   int                            `json:"available_gpus"`
	HourlyCost      float64                        `json:"hourly_cost"`        // $/hr per GPU
	CostPer1kTokens float64                        `json:"cost_per_1k_tokens"` // Cost per 1000 inference tokens
	LatencyP95Ms    int                            `json:"latency_p95_ms"`     // Real-time measured RTT
	CarbonIntensity float64                        `json:"carbon_intensity"`   // gCO2/kWh
	Healthy         bool                           `json:"healthy"`
	ActiveWorkloads int                            `json:"active_workloads"`
	LastHealthCheck time.Time                      `json:"last_health_check"`
	Breaker         *circuitbreaker.CircuitBreaker `json:"-"`
}

type Registry struct {
	mu       sync.RWMutex
	backends map[string]*ComputeBackend
}

func NewRegistry() *Registry {
	r := &Registry{
		backends: make(map[string]*ComputeBackend),
	}
	r.bootstrapDefaults()
	return r
}

func (r *Registry) bootstrapDefaults() {
	defaults := []*ComputeBackend{
		{
			ID:              "bd-dhaka-dgx01",
			Name:            "Dhaka Sovereign DGX Superpod",
			Provider:        "on-prem-dhaka",
			Region:          "ap-south-2",
			Jurisdiction:    ResidencyBangladesh,
			Endpoint:        "https://dgx01.colocation.dhaka.internal/v1",
			GPUModel:        "H100",
			AvailableGPUs:   8,
			HourlyCost:      2.10,
			CostPer1kTokens: 0.0018,
			LatencyP95Ms:    4, // Sub-5ms national fiber RTT via BDIX
			CarbonIntensity: 480.0,
			Healthy:         true,
			Breaker:         circuitbreaker.New("bd-dhaka-dgx01", 3, 10*time.Second),
		},
		{
			ID:              "cw-iad-h100-cluster",
			Name:            "CoreWeave Virginia H100 Cluster",
			Provider:        "coreweave",
			Region:          "us-east-1",
			Jurisdiction:    ResidencyUS,
			Endpoint:        "https://cw-iad.inference.internal/v1",
			GPUModel:        "H100",
			AvailableGPUs:   64,
			HourlyCost:      2.25,
			CostPer1kTokens: 0.0012, // High volume discount
			LatencyP95Ms:    110,
			CarbonIntensity: 340.0,
			Healthy:         true,
			Breaker:         circuitbreaker.New("cw-iad-h100-cluster", 3, 10*time.Second),
		},
		{
			ID:              "aws-sin-bedrock-01",
			Name:            "AWS Singapore Bedrock Enterprise",
			Provider:        "aws",
			Region:          "ap-southeast-1",
			Jurisdiction:    ResidencySingapore,
			Endpoint:        "https://bedrock.ap-southeast-1.amazonaws.com",
			GPUModel:        "L40S",
			AvailableGPUs:   32,
			HourlyCost:      1.80,
			CostPer1kTokens: 0.0022,
			LatencyP95Ms:    28, // Fast via SMW6 cable to Cox's Bazar / Singapore
			CarbonIntensity: 390.0,
			Healthy:         true,
			Breaker:         circuitbreaker.New("aws-sin-bedrock-01", 3, 10*time.Second),
		},
		{
			ID:              "gcp-fra-vertex-ai",
			Name:            "GCP Frankfurt Vertex Sovereign AI",
			Provider:        "gcp",
			Region:          "eu-central-1",
			Jurisdiction:    ResidencyEU,
			Endpoint:        "https://europe-west3-aiplatform.googleapis.com",
			GPUModel:        "A100",
			AvailableGPUs:   16,
			HourlyCost:      2.60,
			CostPer1kTokens: 0.0025,
			LatencyP95Ms:    130,
			CarbonIntensity: 210.0,
			Healthy:         true,
			Breaker:         circuitbreaker.New("gcp-fra-vertex-ai", 3, 10*time.Second),
		},
		{
			ID:              "is-green-gpu01",
			Name:            "Iceland Geothermal Zero-Carbon DC",
			Provider:        "iceland-green-dc",
			Region:          "is-north-1",
			Jurisdiction:    ResidencyIceland,
			Endpoint:        "https://green-compute.reykjavik.internal/v1",
			GPUModel:        "H100",
			AvailableGPUs:   128,
			HourlyCost:      1.45,
			CostPer1kTokens: 0.0011,
			LatencyP95Ms:    145,
			CarbonIntensity: 12.0, // Clean geothermal power
			Healthy:         true,
			Breaker:         circuitbreaker.New("is-green-gpu01", 3, 10*time.Second),
		},
	}

	for _, b := range defaults {
		r.backends[b.ID] = b
	}
}

func (r *Registry) Register(b *ComputeBackend) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.backends[b.ID]; exists {
		return ErrDuplicateBackend
	}

	if b.Breaker == nil {
		b.Breaker = circuitbreaker.New(b.ID, 3, 10*time.Second)
	}
	b.LastHealthCheck = time.Now()
	r.backends[b.ID] = b
	return nil
}

func (r *Registry) Get(id string) (*ComputeBackend, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	b, exists := r.backends[id]
	if !exists {
		return nil, ErrBackendNotFound
	}
	return b, nil
}

func (r *Registry) List() []*ComputeBackend {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]*ComputeBackend, 0, len(r.backends))
	for _, b := range r.backends {
		list = append(list, b)
	}
	return list
}

func (r *Registry) UpdateHealth(id string, latencyMs int, healthy bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if b, exists := r.backends[id]; exists {
		b.LatencyP95Ms = latencyMs
		b.Healthy = healthy
		b.LastHealthCheck = time.Now()
		if healthy {
			b.Breaker.RecordSuccess()
		} else {
			b.Breaker.RecordFailure()
		}
	}
}
