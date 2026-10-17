package events

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
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
	AllocateEdgeConvergenceHead(ctx context.Context, checksum string) (targetVersion int64, targetChecksum string, err error)
	SaveGatewaySyncRecord(ctx context.Context, rec *model.GatewaySyncRecord) error
	GetGatewaySyncRecord(ctx context.Context, gatewayID string) (*model.GatewaySyncRecord, error)
	ListGatewaySyncRecords(ctx context.Context) ([]*model.GatewaySyncRecord, error)
}

// GatewaySyncTracker coordinates configuration generation tracking, per-gateway ACKs,
// lag monitoring, and detects stale edge nodes (P1 Edge Convergence Engine).
type GatewaySyncTracker struct {
	mu                 sync.RWMutex
	targetVersion      atomic.Int64
	targetChecksum     string
	targetUpdatedAt    time.Time
	popTargetChecksums map[string]string
	gateways           map[string]*GatewaySyncRecord
	staleThreshold     time.Duration
	store              GatewayConvergenceStore
	startupErr         error
}

// NewGatewaySyncTracker creates an in-memory GatewaySyncTracker.
func NewGatewaySyncTracker(staleThreshold time.Duration) *GatewaySyncTracker {
	tracker, _ := NewGatewaySyncTrackerWithStore(staleThreshold, nil)
	return tracker
}

// NewGatewaySyncTrackerWithStore creates a GatewaySyncTracker backed by durable storage.
// On startup, it loads the persisted convergence head and previously acknowledged gateway states,
// preventing loss of convergence history upon control plane restart.
// In production mode, failure to load durable state results in an error (fail-closed startup).
func NewGatewaySyncTrackerWithStore(staleThreshold time.Duration, s GatewayConvergenceStore) (*GatewaySyncTracker, error) {
	if staleThreshold <= 0 {
		staleThreshold = 15 * time.Second
	}
	t := &GatewaySyncTracker{
		popTargetChecksums: make(map[string]string),
		gateways:           make(map[string]*GatewaySyncRecord),
		staleThreshold:     staleThreshold,
		targetUpdatedAt:    time.Now().UTC(),
		store:              s,
	}
	t.targetVersion.Store(1)

	if s != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		ver, chk, updated, err := s.GetEdgeConvergenceHead(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.startupErr = fmt.Errorf("load edge convergence head: %w", err)
			isProd := os.Getenv("NEXUSEDGE_DEV_MODE") == "false" || os.Getenv("NEXUSEDGE_ENV") == "production"
			if isProd {
				return nil, fmt.Errorf("fail-closed: %w", t.startupErr)
			}
		} else if ver > 0 {
			t.targetVersion.Store(ver)
			t.targetChecksum = chk
			if !updated.IsZero() {
				t.targetUpdatedAt = updated
			}
		}

		records, err := s.ListGatewaySyncRecords(ctx)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			if t.startupErr == nil {
				t.startupErr = fmt.Errorf("load gateway sync records: %w", err)
			}
			isProd := os.Getenv("NEXUSEDGE_DEV_MODE") == "false" || os.Getenv("NEXUSEDGE_ENV") == "production"
			if isProd {
				return nil, fmt.Errorf("fail-closed: %w", t.startupErr)
			}
		} else {
			for _, rec := range records {
				if rec != nil && rec.GatewayID != "" {
					cp := *rec
					t.gateways[rec.GatewayID] = &cp
				}
			}
		}
	}

	return t, nil
}

// StartupError returns any initialization error encountered while recovering durable state.
func (t *GatewaySyncTracker) StartupError() error {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.startupErr
}

// IsReady reports whether the tracker successfully loaded its durable state.
func (t *GatewaySyncTracker) IsReady() bool {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.startupErr == nil
}

// AdvanceTargetVersion increments the global configuration generation idempotently and fail-closed.
// If store is configured, it executes an authoritative transaction-safe allocation in PostgreSQL.
// If persistence fails, an error is returned and the in-memory state is NOT advanced.
func (t *GatewaySyncTracker) AdvanceTargetVersion(ctx context.Context, checksum string) (int64, string, error) {
	if t.store != nil {
		if ctx == nil {
			var cancel context.CancelFunc
			ctx, cancel = context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
		}
		newVer, newChk, err := t.store.AllocateEdgeConvergenceHead(ctx, checksum)
		if err != nil {
			return 0, "", fmt.Errorf("durable generation allocation failed: %w", err)
		}

		t.mu.Lock()
		t.targetVersion.Store(newVer)
		t.targetChecksum = newChk
		t.targetUpdatedAt = time.Now().UTC()
		t.mu.Unlock()

		return newVer, newChk, nil
	}

	// In-memory fallback (standalone unit tests without persistent store)
	t.mu.Lock()
	defer t.mu.Unlock()

	// Idempotency: avoid incrementing version if desired configuration checksum has not changed
	if checksum != "" && t.targetChecksum == checksum {
		return t.targetVersion.Load(), t.targetChecksum, nil
	}

	newVer := t.targetVersion.Add(1)
	t.targetChecksum = checksum
	t.targetUpdatedAt = time.Now().UTC()

	return newVer, checksum, nil
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

// TargetUpdatedAt returns the timestamp when target configuration was last updated.
func (t *GatewaySyncTracker) TargetUpdatedAt() time.Time {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.targetUpdatedAt
}

// SetPoPTargetChecksum records the authoritative compiled snapshot checksum for a specific PoP.
func (t *GatewaySyncTracker) SetPoPTargetChecksum(popID string, checksum string) {
	if strings.TrimSpace(popID) == "" || strings.TrimSpace(checksum) == "" {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.popTargetChecksums == nil {
		t.popTargetChecksums = make(map[string]string)
	}
	t.popTargetChecksums[popID] = checksum
}

// GetPoPTargetChecksum returns the authoritative compiled snapshot checksum for a PoP,
// falling back to the global target checksum if not specifically set for that PoP.
func (t *GatewaySyncTracker) GetPoPTargetChecksum(popID string) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.popTargetChecksums != nil {
		if chk, exists := t.popTargetChecksums[popID]; exists && chk != "" {
			return chk
		}
	}
	return t.targetChecksum
}

// RecordAck records an applied version acknowledgement from an edge gateway.
// Rejects applied checksum mismatch with ErrChecksumMismatch and sets status to CHECKSUM_MISMATCH.
// A gateway CANNOT be marked IN_SYNC unless both version and checksum match authoritative desired state.
// Invariant: Fail-closed persistence. If persistent store write fails, in-memory state is NOT updated
// and an error is returned to caller.
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
	expectedChk := t.targetChecksum
	if t.popTargetChecksums != nil {
		if popChk, ok := t.popTargetChecksums[ack.PoPID]; ok && popChk != "" {
			expectedChk = popChk
		}
	}
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
	if ack.AppliedVersion >= targetVer && expectedChk != "" && ack.AppliedChecksum != "" && ack.AppliedChecksum != expectedChk {
		errMsg := fmt.Sprintf("applied checksum mismatch for pop %s: expected %s, got %s", ack.PoPID, expectedChk, ack.AppliedChecksum)
		rec := &GatewaySyncRecord{
			GatewayID:        ack.GatewayID,
			PoPID:            ack.PoPID,
			AppliedVersion:   ack.AppliedVersion,
			AppliedChecksum:  ack.AppliedChecksum,
			TargetVersion:    targetVer,
			TargetChecksum:   expectedChk,
			VersionLag:       lag,
			Status:           model.SyncStatusChecksumMismatch,
			LastError:        errMsg,
			LastAckAt:        now,
			ConvergenceLagMs: convLagMs,
		}
		if t.store != nil {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			if err := t.store.SaveGatewaySyncRecord(ctx, rec); err != nil {
				return nil, fmt.Errorf("failed to persist gateway sync record: %w", err)
			}
		}
		t.gateways[ack.GatewayID] = rec
		recCopy := *rec
		return &recCopy, model.ErrChecksumMismatch
	}

	var status GatewaySyncStatus
	if strings.ToUpper(ack.Status) == string(model.SyncStatusError) || ack.Error != "" {
		status = model.SyncStatusError
	} else if ack.AppliedVersion >= targetVer && (expectedChk == "" || ack.AppliedChecksum == expectedChk) {
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
		TargetChecksum:   expectedChk,
		VersionLag:       lag,
		Status:           status,
		LastError:        ack.Error,
		LastAckAt:        now,
		ConvergenceLagMs: convLagMs,
	}

	if t.store != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := t.store.SaveGatewaySyncRecord(ctx, rec); err != nil {
			return nil, fmt.Errorf("failed to persist gateway sync record: %w", err)
		}
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
