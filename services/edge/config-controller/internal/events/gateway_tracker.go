package events

import (
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// GatewaySyncStatus defines the convergence health of an individual Edge Gateway.
type GatewaySyncStatus string

const (
	SyncStatusInSync   GatewaySyncStatus = "IN_SYNC"
	SyncStatusLagging  GatewaySyncStatus = "LAGGING"
	SyncStatusApplying GatewaySyncStatus = "APPLYING"
	SyncStatusError    GatewaySyncStatus = "ERROR"
	SyncStatusStale    GatewaySyncStatus = "STALE"
)

// GatewaySyncRecord represents the convergence state reported by an Edge Gateway.
type GatewaySyncRecord struct {
	GatewayID        string            `json:"gateway_id"`
	PoPID            string            `json:"pop_id"`
	AppliedVersion   int64             `json:"applied_version"`
	AppliedChecksum  string            `json:"applied_checksum"`
	TargetVersion    int64             `json:"target_version"`
	TargetChecksum   string            `json:"target_checksum"`
	VersionLag       int64             `json:"version_lag"`
	Status           GatewaySyncStatus `json:"status"`
	LastError        string            `json:"last_error,omitempty"`
	LastAckAt        time.Time         `json:"last_ack_at"`
	ConvergenceLagMs int64             `json:"convergence_lag_ms"`
}

// GatewaySyncAcknowledgement is received from Edge Gateways upon applying configuration.
type GatewaySyncAcknowledgement struct {
	GatewayID       string `json:"gateway_id"`
	PoPID           string `json:"pop_id"`
	AppliedVersion  int64  `json:"applied_version"`
	AppliedChecksum string `json:"applied_checksum"`
	Status          string `json:"status"`
	Error           string `json:"error,omitempty"`
}

// GatewaySyncTracker coordinates configuration generation tracking, per-gateway ACKs,
// lag monitoring, and detects stale edge nodes (P1 Edge Convergence Engine).
type GatewaySyncTracker struct {
	mu              sync.RWMutex
	targetVersion   atomic.Int64
	targetChecksum  string
	targetUpdatedAt time.Time
	gateways        map[string]*GatewaySyncRecord
	staleThreshold  time.Duration
}

// NewGatewaySyncTracker creates an initialized GatewaySyncTracker.
func NewGatewaySyncTracker(staleThreshold time.Duration) *GatewaySyncTracker {
	if staleThreshold <= 0 {
		staleThreshold = 15 * time.Second
	}
	t := &GatewaySyncTracker{
		gateways:        make(map[string]*GatewaySyncRecord),
		staleThreshold:  staleThreshold,
		targetUpdatedAt: time.Now().UTC(),
	}
	t.targetVersion.Store(1)
	return t
}

// AdvanceTargetVersion increments the global configuration generation.
func (t *GatewaySyncTracker) AdvanceTargetVersion(delta int64, checksum string) int64 {
	if delta <= 0 {
		delta = 1
	}
	newVer := t.targetVersion.Add(delta)

	t.mu.Lock()
	t.targetChecksum = checksum
	t.targetUpdatedAt = time.Now().UTC()
	t.mu.Unlock()

	return newVer
}

// TargetVersion returns the active target configuration version.
func (t *GatewaySyncTracker) TargetVersion() int64 {
	return t.targetVersion.Load()
}

// TargetChecksum returns the checksum of the active target configuration version.
func (t *GatewaySyncTracker) TargetChecksum() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.targetChecksum
}

// RecordAck records an applied version acknowledgement from an edge gateway.
func (t *GatewaySyncTracker) RecordAck(ack GatewaySyncAcknowledgement) (*GatewaySyncRecord, error) {
	if strings.TrimSpace(ack.GatewayID) == "" {
		return nil, errors.New("gateway_id is required")
	}
	if strings.TrimSpace(ack.PoPID) == "" {
		return nil, errors.New("pop_id is required")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	targetVer := t.targetVersion.Load()
	targetChk := t.targetChecksum
	now := time.Now().UTC()

	lag := targetVer - ack.AppliedVersion
	if lag < 0 {
		lag = 0
	}

	var status GatewaySyncStatus
	if strings.ToUpper(ack.Status) == string(SyncStatusError) || ack.Error != "" {
		status = SyncStatusError
	} else if ack.AppliedVersion >= targetVer {
		status = SyncStatusInSync
	} else if strings.ToUpper(ack.Status) == string(SyncStatusApplying) {
		status = SyncStatusApplying
	} else {
		status = SyncStatusLagging
	}

	var convLagMs int64
	if !t.targetUpdatedAt.IsZero() {
		convLagMs = now.Sub(t.targetUpdatedAt).Milliseconds()
		if convLagMs < 0 {
			convLagMs = 0
		}
	}

	rec := &GatewaySyncRecord{
		GatewayID:        ack.GatewayID,
		PoPID:            ack.PoPID,
		AppliedVersion:   ack.AppliedVersion,
		AppliedChecksum:  ack.AppliedChecksum,
		TargetVersion:    targetVer,
		TargetChecksum:   targetChk,
		VersionLag:       lag,
		Status:           status,
		LastError:        ack.Error,
		LastAckAt:        now,
		ConvergenceLagMs: convLagMs,
	}

	t.gateways[ack.GatewayID] = rec
	recCopy := *rec
	return &recCopy, nil
}

// GetGateway returns convergence state for a specific gateway.
func (t *GatewaySyncTracker) GetGateway(gatewayID string) (*GatewaySyncRecord, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	rec, exists := t.gateways[gatewayID]
	if !exists {
		return nil, false
	}
	copy := *rec
	return &copy, true
}

// ListGateways returns a snapshot of all registered edge gateways with stale detection.
func (t *GatewaySyncTracker) ListGateways() []*GatewaySyncRecord {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UTC()
	list := make([]*GatewaySyncRecord, 0, len(t.gateways))

	for _, rec := range t.gateways {
		copy := *rec
		if now.Sub(rec.LastAckAt) > t.staleThreshold && copy.Status != SyncStatusError {
			copy.Status = SyncStatusStale
			rec.Status = SyncStatusStale
		}
		list = append(list, &copy)
	}

	return list
}

// GetConvergenceSummary returns aggregated edge synchronization metrics.
func (t *GatewaySyncTracker) GetConvergenceSummary() map[string]interface{} {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now().UTC()
	targetVer := t.targetVersion.Load()

	total := len(t.gateways)
	inSync := 0
	lagging := 0
	stale := 0
	errCount := 0
	var maxLag int64

	for _, rec := range t.gateways {
		if now.Sub(rec.LastAckAt) > t.staleThreshold && rec.Status != SyncStatusError {
			rec.Status = SyncStatusStale
		}
		switch rec.Status {
		case SyncStatusInSync:
			inSync++
		case SyncStatusLagging:
			lagging++
		case SyncStatusStale:
			stale++
		case SyncStatusError:
			errCount++
		}
		if rec.VersionLag > maxLag {
			maxLag = rec.VersionLag
		}
	}

	fullyConverged := total > 0 && inSync == total

	return map[string]interface{}{
		"target_version":   targetVer,
		"target_checksum":  t.targetChecksum,
		"total_gateways":   total,
		"in_sync_gateways": inSync,
		"lagging_gateways": lagging,
		"stale_gateways":   stale,
		"error_gateways":   errCount,
		"max_version_lag":  maxLag,
		"fully_converged":  fullyConverged,
		"updated_at":       t.targetUpdatedAt.Format(time.RFC3339),
	}
}
