package events

import (
	"context"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestGatewaySyncTracker_MultiReplicaConvergence(t *testing.T) {
	sharedStore := store.NewStore()

	// Replica A generates snapshot for pop-dhaka-01 and persists PoP target checksum
	trackerA, err := NewGatewaySyncTrackerWithStore(10*time.Second, sharedStore)
	if err != nil {
		t.Fatalf("unexpected NewGatewaySyncTrackerWithStore error on replica A: %v", err)
	}
	trackerA.SetPoPTargetChecksum("pop-dhaka-01", 42, "hash-dhaka-v42")

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

func TestGatewaySyncTracker_FutureVersionRejection(t *testing.T) {
	sharedStore := store.NewStore()
	tracker, err := NewGatewaySyncTrackerWithStore(10*time.Second, sharedStore)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	tracker.SetPoPTargetChecksum("pop-sin-01", 10, "hash-v10")

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

	ver, chk := restartedTracker.GetPoPTargetChecksum("pop-fra-01")
	if ver != 15 || chk != "hash-fra-v15" {
		t.Fatalf("expected ver 15, chk hash-fra-v15 after restart, got %d, %s", ver, chk)
	}
}
