package events

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

// failingConvergenceStore simulates database failure for fail-closed verification.
type failingConvergenceStore struct {
	*store.Store
	savePoPErr error
	getPoPErr  error
}

func (f *failingConvergenceStore) SavePoPSnapshotHead(ctx context.Context, popID string, targetVersion int64, targetChecksum string) error {
	if f.savePoPErr != nil {
		return f.savePoPErr
	}
	return f.Store.SavePoPSnapshotHead(ctx, popID, targetVersion, targetChecksum)
}

func (f *failingConvergenceStore) GetPoPSnapshotHead(ctx context.Context, popID string) (int64, string, time.Time, error) {
	if f.getPoPErr != nil {
		return 0, "", time.Time{}, f.getPoPErr
	}
	return f.Store.GetPoPSnapshotHead(ctx, popID)
}

func TestGatewaySyncTracker_MultiReplicaConvergence(t *testing.T) {
	sharedStore := store.NewStore()

	// Replica A generates snapshot for pop-dhaka-01 and persists PoP target checksum
	trackerA, err := NewGatewaySyncTrackerWithStore(10*time.Second, sharedStore)
	if err != nil {
		t.Fatalf("unexpected NewGatewaySyncTrackerWithStore error on replica A: %v", err)
	}
	if err := trackerA.SetPoPTargetChecksum("pop-dhaka-01", 42, "hash-dhaka-v42"); err != nil {
		t.Fatalf("SetPoPTargetChecksum failed: %v", err)
	}

	// Replica B starts with empty in-memory pop map, sharing the same backing store
	trackerB, err := NewGatewaySyncTrackerWithStore(10*time.Second, sharedStore)
	if err != nil {
		t.Fatalf("unexpected NewGatewaySyncTrackerWithStore error on replica B: %v", err)
	}

	// Gateway in pop-dhaka-01 acknowledges version 42 to Replica B
	ack := GatewaySyncAcknowledgement{
		GatewayID:       "gw-dhaka-01",
		PoPID:           "pop-dhaka-01",
		AppliedVersion:  42,
		AppliedChecksum: "hash-dhaka-v42",
		Status:          "APPLIED",
	}

	rec, err := trackerB.RecordAck(ack)
	if err != nil {
		t.Fatalf("RecordAck failed on replica B: %v", err)
	}

	if rec.Status != model.SyncStatusInSync {
		t.Fatalf("expected status IN_SYNC, got %s (error: %s)", rec.Status, rec.LastError)
	}
	if rec.TargetVersion != 42 {
		t.Fatalf("expected TargetVersion 42, got %d", rec.TargetVersion)
	}
	if rec.TargetChecksum != "hash-dhaka-v42" {
		t.Fatalf("expected TargetChecksum hash-dhaka-v42, got %s", rec.TargetChecksum)
	}

	// Checksum mismatch on Replica B
	mismatchAck := GatewaySyncAcknowledgement{
		GatewayID:       "gw-dhaka-02",
		PoPID:           "pop-dhaka-01",
		AppliedVersion:  42,
		AppliedChecksum: "corrupted-hash",
		Status:          "APPLIED",
	}

	recMismatch, errMismatch := trackerB.RecordAck(mismatchAck)
	if errMismatch != model.ErrChecksumMismatch {
		t.Fatalf("expected ErrChecksumMismatch, got %v", errMismatch)
	}
	if recMismatch.Status != model.SyncStatusChecksumMismatch {
		t.Fatalf("expected status CHECKSUM_MISMATCH, got %s", recMismatch.Status)
	}
}

func TestGatewaySyncTracker_MultiReplica_StaleCacheBypassedByAuthoritativeDB(t *testing.T) {
	sharedStore := store.NewStore()

	trackerA, _ := NewGatewaySyncTrackerWithStore(10*time.Second, sharedStore)
	trackerB, _ := NewGatewaySyncTrackerWithStore(10*time.Second, sharedStore)

	// Step 1: Both replicas initially see version 1
	_ = trackerA.SetPoPTargetChecksum("pop-sin-01", 1, "hash-v1")
	_, _, _ = trackerB.GetPoPTargetChecksum("pop-sin-01") // populates trackerB local memory with v1

	// Step 2: Replica A publishes new authoritative snapshot version 2 to DB
	if err := trackerA.SetPoPTargetChecksum("pop-sin-01", 2, "hash-v2"); err != nil {
		t.Fatalf("trackerA SetPoPTargetChecksum failed: %v", err)
	}

	// Step 3: Gateway sends ACK for version 2 to Replica B.
	// Invariant: Replica B MUST NOT use its stale in-memory v1; it MUST query the authoritative store.
	ack := GatewaySyncAcknowledgement{
		GatewayID:       "gw-sin-01",
		PoPID:           "pop-sin-01",
		AppliedVersion:  2,
		AppliedChecksum: "hash-v2",
		Status:          "APPLIED",
	}

	rec, err := trackerB.RecordAck(ack)
	if err != nil {
		t.Fatalf("trackerB RecordAck failed: %v", err)
	}
	if rec.Status != model.SyncStatusInSync {
		t.Fatalf("expected IN_SYNC using DB authority, but got %s (err: %s)", rec.Status, rec.LastError)
	}
	if rec.TargetVersion != 2 || rec.TargetChecksum != "hash-v2" {
		t.Fatalf("expected target v2 hash-v2, got %d %s", rec.TargetVersion, rec.TargetChecksum)
	}
}

func TestGatewaySyncTracker_FailClosedOnStorePersistenceFailure(t *testing.T) {
	sharedStore := store.NewStore()
	mockFail := &failingConvergenceStore{
		Store:      sharedStore,
		savePoPErr: errors.New("database connection refused"),
	}

	tracker, _ := NewGatewaySyncTrackerWithStore(10*time.Second, mockFail)

	// Invariant: If store persistence fails, SetPoPTargetChecksum MUST return an error
	// and MUST NOT update the local cache with uncommitted state.
	err := tracker.SetPoPTargetChecksum("pop-failed-01", 100, "hash-uncommitted")
	if err == nil {
		t.Fatalf("expected SetPoPTargetChecksum to fail when store returns error")
	}

	// Verify local cache did not adopt uncommitted state
	ver, chk, _ := tracker.GetPoPTargetChecksum("pop-failed-01")
	if chk == "hash-uncommitted" {
		t.Fatalf("CRITICAL BUG: local cache adopted uncommitted snapshot hash!")
	}
	if ver == 100 {
		t.Fatalf("CRITICAL BUG: local cache adopted uncommitted snapshot version!")
	}
}

func TestGatewaySyncTracker_FailClosedOnStoreQueryFailureDuringAck(t *testing.T) {
	sharedStore := store.NewStore()
	mockFail := &failingConvergenceStore{
		Store:     sharedStore,
		getPoPErr: errors.New("database outage"),
	}

	tracker, _ := NewGatewaySyncTrackerWithStore(10*time.Second, mockFail)

	ack := GatewaySyncAcknowledgement{
		GatewayID:       "gw-outage-01",
		PoPID:           "pop-outage-01",
		AppliedVersion:  1,
		AppliedChecksum: "hash-1",
		Status:          "APPLIED",
	}

	// Invariant: Fail closed when authoritative store is unreachable.
	// Must not falsely mark IN_SYNC or report spurious mismatch.
	_, err := tracker.RecordAck(ack)
	if err == nil {
		t.Fatalf("expected RecordAck to fail closed when store query returns database outage")
	}
}

func TestGatewaySyncTracker_FutureVersionRejection(t *testing.T) {
	sharedStore := store.NewStore()
	tracker, err := NewGatewaySyncTrackerWithStore(10*time.Second, sharedStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if err := tracker.SetPoPTargetChecksum("pop-sin-01", 10, "hash-v10"); err != nil {
		t.Fatalf("SetPoPTargetChecksum failed: %v", err)
	}

	// 1. Gateway sends future version 11 (AppliedVersion > targetVer 10)
	futureAck := GatewaySyncAcknowledgement{
		GatewayID:       "gw-sin-01",
		PoPID:           "pop-sin-01",
		AppliedVersion:  11,
		AppliedChecksum: "hash-v11",
		Status:          "APPLIED",
	}

	recFuture, err := tracker.RecordAck(futureAck)
	if err != nil {
		t.Fatalf("unexpected RecordAck error: %v", err)
	}
	if recFuture.Status != model.SyncStatusError {
		t.Fatalf("expected future version to be marked ERROR, got %s", recFuture.Status)
	}

	// 2. Gateway sends exact version 10 with matching checksum -> IN_SYNC
	exactAck := GatewaySyncAcknowledgement{
		GatewayID:       "gw-sin-01",
		PoPID:           "pop-sin-01",
		AppliedVersion:  10,
		AppliedChecksum: "hash-v10",
		Status:          "APPLIED",
	}

	recExact, err := tracker.RecordAck(exactAck)
	if err != nil {
		t.Fatalf("unexpected RecordAck error: %v", err)
	}
	if recExact.Status != model.SyncStatusInSync {
		t.Fatalf("expected exact version to be marked IN_SYNC, got %s", recExact.Status)
	}

	// 3. Gateway sends lagging version 9 -> LAGGING
	laggingAck := GatewaySyncAcknowledgement{
		GatewayID:       "gw-sin-02",
		PoPID:           "pop-sin-01",
		AppliedVersion:  9,
		AppliedChecksum: "hash-v9",
		Status:          "APPLIED",
	}

	recLagging, err := tracker.RecordAck(laggingAck)
	if err != nil {
		t.Fatalf("unexpected RecordAck error: %v", err)
	}
	if recLagging.Status != model.SyncStatusLagging {
		t.Fatalf("expected lagging version to be marked LAGGING, got %s", recLagging.Status)
	}
}

func TestGatewaySyncTracker_DurableStoreRestart(t *testing.T) {
	sharedStore := store.NewStore()

	// Initial tracker sets convergence head
	ctx := context.Background()
	if err := sharedStore.SaveEdgeConvergenceHead(ctx, 15, "hash-global-v15"); err != nil {
		t.Fatalf("SaveEdgeConvergenceHead failed: %v", err)
	}
	if err := sharedStore.SavePoPSnapshotHead(ctx, "pop-fra-01", 15, "hash-fra-v15"); err != nil {
		t.Fatalf("SavePoPSnapshotHead failed: %v", err)
	}

	// Tracker started after restart
	restartedTracker, err := NewGatewaySyncTrackerWithStore(10*time.Second, sharedStore)
	if err != nil {
		t.Fatalf("NewGatewaySyncTrackerWithStore failed after restart: %v", err)
	}

	ver, chk, err := restartedTracker.GetPoPTargetChecksum("pop-fra-01")
	if err != nil {
		t.Fatalf("GetPoPTargetChecksum failed after restart: %v", err)
	}
	if ver != 15 || chk != "hash-fra-v15" {
		t.Fatalf("expected ver 15, chk hash-fra-v15 after restart, got %d, %s", ver, chk)
	}
}
