package events

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

// GatewaySyncStatus defines the convergence health of an individual Edge Gateway.
type GatewaySyncStatus = model.GatewaySyncStatus

const (
	SyncStatusInSync           = model.SyncStatusInSync
	SyncStatusLagging          = model.SyncStatusLagging
	SyncStatusApplying         = model.SyncStatusApplying
	SyncStatusError            = model.SyncStatusError
	SyncStatusStale            = model.SyncStatusStale
	SyncStatusChecksumMismatch = model.SyncStatusChecksumMismatch
)

// GatewaySyncRecord represents the convergence state reported by an Edge Gateway.
type GatewaySyncRecord = model.GatewaySyncRecord

// GatewaySyncAcknowledgement is received from Edge Gateways upon applying configuration.
type GatewaySyncAcknowledgement = model.GatewaySyncAcknowledgement

// GatewayConvergenceStore defines the durable persistence interface required by the convergence tracker.
type GatewayConvergenceStore interface {
	SaveEdgeConvergenceHead(ctx context.Context, targetVersion int64, targetChecksum string) error
	GetEdgeConvergenceHead(ctx context.Context) (targetVersion int64, targetChecksum string, updatedAt time.Time, err error)
	SaveGatewaySyncRecord(ctx context.Context, rec *model.GatewaySyncRecord) error
	GetGatewaySyncRecord(ctx context.Context, gatewayID string) (*model.GatewaySyncRecord, error)
	ListGatewaySyncRecords(ctx context.Context) ([]*model.GatewaySyncRecord, error)
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
	store           GatewayConvergenceStore
}

// NewGatewaySyncTracker creates an in-memory GatewaySyncTracker.
func NewGatewaySyncTracker(staleThreshold time.Duration) *GatewaySyncTracker {
	return NewGatewaySyncTrackerWithStore(staleThreshold, nil)
}

// NewGatewaySyncTrackerWithStore creates a GatewaySyncTracker backed by durable storage.
// On startup, it loads the persisted convergence head and previously acknowledged gateway states,
// preventing loss of convergence history upon control plane restart.
func NewGatewaySyncTrackerWithStore(staleThreshold time.Duration, s GatewayConvergenceStore) *GatewaySyncTracker {
	if staleThreshold <= 0 {
		staleThreshold = 15 * time.Second
	}
	t := &GatewaySyncTracker{
		gateways:        make(map[string]*GatewaySyncRecord),
		staleThreshold:  staleThreshold,
		targetUpdatedAt: time.Now().UTC(),
		store:           s,
	}
	t.targetVersion.Store(1)

	if s != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ver, chk, updated, err := s.GetEdgeConvergenceHead(ctx)
		if err == nil && ver > 0 {
			t.targetVersion.Store(ver)
			t.targetChecksum = chk
			if !updated.IsZero() {
				t.targetUpdatedAt = updated
			}
		}

		if records, err := s.ListGatewaySyncRecords(ctx); err == nil {
			for _, rec := range records {
				if rec != nil && rec.GatewayID != "" {
					cp := *rec
					t.gateways[rec.GatewayID] = &cp
				}
			}
		}
	}

	return t
}

// AdvanceTargetVersion increments the global configuration generation idempotently.
// If checksum is non-empty and identical to current target checksum, this represents
// duplicate event delivery for the same desired state; the version is NOT incremented.
func (t *GatewaySyncTracker) AdvanceTargetVersion(delta int64, checksum string) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()

	// Idempotency: avoid incrementing version if desired configuration checksum has not changed
	if checksum != "" && t.targetChecksum == checksum {
		return t.targetVersion.Load()
	}

	if delta <= 0 {
		delta = 1
	}
	newVer := t.targetVersion.Add(delta)
	t.targetChecksum = checksum
	t.targetUpdatedAt = time.Now().UTC()

	if t.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = t.store.SaveEdgeConvergenceHead(ctx, newVer, checksum)
	}

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
// Rejects applied checksum mismatch with ErrChecksumMismatch and sets status to CHECKSUM_MISMATCH.
// A gateway CANNOT be marked IN_SYNC unless both version and checksum match authoritative desired state.
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

	var convLagMs int64
	if !t.targetUpdatedAt.IsZero() {
		convLagMs = now.Sub(t.targetUpdatedAt).Milliseconds()
		if convLagMs < 0 {
			convLagMs = 0
		}
	}

	// Strict checksum validation: Gateway cannot be IN_SYNC on checksum mismatch for target version
	if ack.AppliedVersion >= targetVer && targetChk != "" && ack.AppliedChecksum != "" && ack.AppliedChecksum != targetChk {
		errMsg := fmt.Sprintf("applied checksum mismatch: expected %s, got %s", targetChk, ack.AppliedChecksum)
		rec := &GatewaySyncRecord{
			GatewayID:        ack.GatewayID,
			PoPID:            ack.PoPID,
			AppliedVersion:   ack.AppliedVersion,
			AppliedChecksum:  ack.AppliedChecksum,
			TargetVersion:    targetVer,
			TargetChecksum:   targetChk,
			VersionLag:       lag,
			Status:           model.SyncStatusChecksumMismatch,
			LastError:        errMsg,
			LastAckAt:        now,
			ConvergenceLagMs: convLagMs,
		}
		t.gateways[ack.GatewayID] = rec
		if t.store != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = t.store.SaveGatewaySyncRecord(ctx, rec)
		}
		recCopy := *rec
		return &recCopy, model.ErrChecksumMismatch
	}

	var status GatewaySyncStatus
	if strings.ToUpper(ack.Status) == string(model.SyncStatusError) || ack.Error != "" {
		status = model.SyncStatusError
	} else if ack.AppliedVersion >= targetVer && (targetChk == "" || ack.AppliedChecksum == targetChk) {
		status = model.SyncStatusInSync
	} else if strings.ToUpper(ack.Status) == string(model.SyncStatusApplying) {
		status = model.SyncStatusApplying
	} else {
		status = model.SyncStatusLagging
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
	if t.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = t.store.SaveGatewaySyncRecord(ctx, rec)
	}
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
		if now.Sub(rec.LastAckAt) > t.staleThreshold && copy.Status != SyncStatusError && copy.Status != SyncStatusChecksumMismatch {
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
		if now.Sub(rec.LastAckAt) > t.staleThreshold && rec.Status != SyncStatusError && rec.Status != SyncStatusChecksumMismatch {
			rec.Status = SyncStatusStale
		}
		switch rec.Status {
		case SyncStatusInSync:
			inSync++
		case SyncStatusLagging:
			lagging++
		case SyncStatusStale:
			stale++
		case SyncStatusError, SyncStatusChecksumMismatch:
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
