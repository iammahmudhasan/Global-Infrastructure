package registry

import (
	"errors"
	"sort"
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
	ErrBackendNotFound      = errors.New("compute backend not found")
	ErrDuplicateBackend     = errors.New("backend with ID already exists")
	ErrInsufficientCapacity = errors.New("insufficient GPU capacity on backend")
	ErrReservationExists    = errors.New("workload reservation already exists")
	ErrReservationNotFound  = errors.New("workload reservation not found")
	ErrInvalidBackend       = errors.New("invalid backend: missing required fields or negative capacity/cost/latency")
)

// Reservation tracks capacity ownership by a specific workload
type Reservation struct {
	WorkloadID string    `json:"workload_id"`
	BackendID  string    `json:"backend_id"`
	GPUs       int       `json:"gpus"`
	ReservedAt time.Time `json:"reserved_at"`
}

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
	Mode            string                         `json:"mode"`   // "SIMULATION" or "PRODUCTION"
	Source          string                         `json:"source"` // "SIMULATED" or "PROVIDER_API"
	Breaker         *circuitbreaker.CircuitBreaker `json:"-"`
	CircuitState    circuitbreaker.State           `json:"circuit_state"`
}

type Registry struct {
	mu           sync.RWMutex
	backends     map[string]*ComputeBackend
	reservations map[string]*Reservation
}

func NewRegistry() *Registry {
	r := &Registry{
		backends:     make(map[string]*ComputeBackend),
		reservations: make(map[string]*Reservation),
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
		b.Mode = "SIMULATION"
		b.Source = "SIMULATED"
		r.backends[b.ID] = b
	}
}

func (r *Registry) Register(b *ComputeBackend) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if b == nil || b.ID == "" || b.Endpoint == "" || b.AvailableGPUs < 0 || b.HourlyCost < 0 || b.LatencyP95Ms < 0 {
		return ErrInvalidBackend
	}

	if _, exists := r.backends[b.ID]; exists {
		return ErrDuplicateBackend
	}

	cloned := *b
	if cloned.Breaker == nil {
		cloned.Breaker = circuitbreaker.New(cloned.ID, 3, 10*time.Second)
	}
	cloned.LastHealthCheck = time.Now().UTC()
	r.backends[cloned.ID] = &cloned
	return nil
}

func cloneBackend(b *ComputeBackend) *ComputeBackend {
	if b == nil {
		return nil
	}
	cp := *b
	cp.Breaker = nil
	if b.Breaker != nil {
		cp.CircuitState = b.Breaker.State()
	} else {
		cp.CircuitState = circuitbreaker.StateClosed
	}
	return &cp
}

func (r *Registry) CircuitState(id string) circuitbreaker.State {
	r.mu.RLock()
	defer r.mu.RUnlock()
	b, ok := r.backends[id]
	if !ok || b.Breaker == nil {
		return circuitbreaker.StateClosed
	}
	return b.Breaker.State()
}

// AllowBackend checks whether an outgoing request should proceed through the backend's circuit breaker
func (r *Registry) AllowBackend(id string) error {
	r.mu.RLock()
	b, ok := r.backends[id]
	r.mu.RUnlock()

	if !ok {
		return ErrBackendNotFound
	}
	if b.Breaker == nil {
		return nil
	}

	return b.Breaker.Allow()
}

func (r *Registry) Get(id string) (*ComputeBackend, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	b, exists := r.backends[id]
	if !exists {
		return nil, ErrBackendNotFound
	}
	return cloneBackend(b), nil
}

func (r *Registry) List() []*ComputeBackend {
	r.mu.RLock()
	defer r.mu.RUnlock()

	list := make([]*ComputeBackend, 0, len(r.backends))
	for _, b := range r.backends {
		list = append(list, cloneBackend(b))
	}
	sort.Slice(list, func(i, j int) bool {
		return list[i].ID < list[j].ID
	})
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
		b.CircuitState = b.Breaker.State()
	}
}

// AdmitAndReserve atomically checks circuit breaker admission and reserves compute capacity.
// If the breaker is in HALF_OPEN state and admits a trial, but capacity reservation fails,
// the trial in flight is immediately released to prevent deadlock (P2/P1 Finding).
func (r *Registry) AdmitAndReserve(workloadID, backendID string, count int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.reservations[workloadID]; exists {
		return ErrReservationExists
	}

	b, ok := r.backends[backendID]
	if !ok {
		return ErrBackendNotFound
	}

	if b.Breaker != nil {
		if err := b.Breaker.Allow(); err != nil {
			return err
		}
	}

	if count <= 0 {
		count = 1
	}

	if b.AvailableGPUs < count {
		if b.Breaker != nil {
			b.Breaker.ReleaseTrial()
		}
		return ErrInsufficientCapacity
	}

	b.AvailableGPUs -= count
	b.ActiveWorkloads++
	r.reservations[workloadID] = &Reservation{
		WorkloadID: workloadID,
		BackendID:  backendID,
		GPUs:       count,
		ReservedAt: time.Now().UTC(),
	}
	return nil
}

// Reserve tracks capacity ownership by a specific workload, preventing double reservations
func (r *Registry) Reserve(workloadID, backendID string, count int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if _, exists := r.reservations[workloadID]; exists {
		return ErrReservationExists
	}

	b, ok := r.backends[backendID]
	if !ok {
		return ErrBackendNotFound
	}
	if count <= 0 {
		count = 1
	}
	if b.AvailableGPUs < count {
		return ErrInsufficientCapacity
	}

	b.AvailableGPUs -= count
	b.ActiveWorkloads++
	r.reservations[workloadID] = &Reservation{
		WorkloadID: workloadID,
		BackendID:  backendID,
		GPUs:       count,
		ReservedAt: time.Now().UTC(),
	}
	return nil
}

// CompleteWorkload records the execution outcome (success or failure) of a reserved workload,
// feeding back directly into the circuit breaker lifecycle and releasing reserved GPU capacity.
func (r *Registry) CompleteWorkload(workloadID string, success bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, exists := r.reservations[workloadID]
	if !exists {
		return ErrReservationNotFound
	}

	if b, ok := r.backends[res.BackendID]; ok {
		b.AvailableGPUs += res.GPUs
		if b.ActiveWorkloads > 0 {
			b.ActiveWorkloads--
		}
		if b.Breaker != nil {
			if success {
				b.Breaker.RecordSuccess()
			} else {
				b.Breaker.RecordFailure()
			}
			b.CircuitState = b.Breaker.State()
		}
	}
	delete(r.reservations, workloadID)
	return nil
}

// Release restores reserved GPU capacity using workload reservation ownership validation.
// If the backend has an in-flight trial probe without an explicit completion outcome, it releases the trial.
func (r *Registry) Release(workloadID string) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	res, exists := r.reservations[workloadID]
	if !exists {
		return ErrReservationNotFound
	}

	if b, ok := r.backends[res.BackendID]; ok {
		b.AvailableGPUs += res.GPUs
		if b.ActiveWorkloads > 0 {
			b.ActiveWorkloads--
		}
		if b.Breaker != nil {
			b.Breaker.ReleaseTrial()
			b.CircuitState = b.Breaker.State()
		}
	}
	delete(r.reservations, workloadID)
	return nil
}

// SweepExpiredReservations reclaims GPU capacity from abandoned or leaked reservations exceeding ttl.
// It also resets in-flight trial probes on the backend's circuit breaker to prevent deadlock.
func (r *Registry) SweepExpiredReservations(ttl time.Duration) int {
	r.mu.Lock()
	defer r.mu.Unlock()

	swept := 0
	for wid, res := range r.reservations {
		if time.Since(res.ReservedAt) >= ttl {
			if b, ok := r.backends[res.BackendID]; ok {
				b.AvailableGPUs += res.GPUs
				if b.ActiveWorkloads > 0 {
					b.ActiveWorkloads--
				}
				if b.Breaker != nil {
					b.Breaker.ReleaseTrial()
					b.CircuitState = b.Breaker.State()
				}
			}
			delete(r.reservations, wid)
			swept++
		}
	}
	return swept
}
