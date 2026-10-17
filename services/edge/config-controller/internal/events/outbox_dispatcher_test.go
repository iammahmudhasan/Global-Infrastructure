package events

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

func TestOutboxDispatcher_SingleBatchDispatch(t *testing.T) {
	s := store.NewStore()
	b := NewBroadcaster()
	defer b.Close()

	bridge := NewBroadcasterBridge(b)
	cfg := OutboxDispatcherConfig{
		WorkerID:      "test-worker-01",
		BatchSize:     10,
		PollInterval:  100 * time.Millisecond,
		LeaseDuration: 5 * time.Second,
	}

	dispatcher, err := NewOutboxDispatcher(s, bridge, cfg)
	if err != nil {
		t.Fatalf("unexpected NewOutboxDispatcher error: %v", err)
	}

	dom := &model.Domain{
		ID:          "dom-test-outbox-01",
		ProjectID:   "proj-test",
		Hostname:    "test.example.com",
		Status:      model.DomainStatusActive,
		AllowedPoPs: []string{"singapore", "dhaka"},
		Version:     1,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
	}
	if err := s.SaveDomain(dom); err != nil {
		t.Fatalf("SaveDomain failed: %v", err)
	}

	// Verify pending outbox event exists
	pending, err := s.GetPendingOutboxEvents(context.Background(), 10)
	if err != nil {
		t.Fatalf("GetPendingOutboxEvents error: %v", err)
	}
	if len(pending) != 1 {
		t.Fatalf("expected 1 pending outbox event, got %d", len(pending))
	}
	if pending[0].EventType != "domain.config.changed" {
		t.Fatalf("expected domain.config.changed event, got %s", pending[0].EventType)
	}

	// Execute single batch dispatch
	count, err := dispatcher.DispatchBatch(context.Background())
	if err != nil {
		t.Fatalf("DispatchBatch error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event dispatched, got %d", count)
	}

	// Verify no pending events remain
	pendingAfter, _ := s.GetPendingOutboxEvents(context.Background(), 10)
	if len(pendingAfter) != 0 {
		t.Fatalf("expected 0 pending events after dispatch, got %d", len(pendingAfter))
	}

	stats := dispatcher.Stats()
	if stats.EventsClaimed != 1 {
		t.Errorf("expected 1 claimed event, got %d", stats.EventsClaimed)
	}
	if stats.EventsProcessed != 1 {
		t.Errorf("expected 1 processed event, got %d", stats.EventsProcessed)
	}
	if stats.EventsFailed != 0 {
		t.Errorf("expected 0 failed events, got %d", stats.EventsFailed)
	}
}

func TestOutboxDispatcher_BroadcasterBridgeDelivery(t *testing.T) {
	s := store.NewStore()
	b := NewBroadcaster()
	defer b.Close()

	chSg, cancelSg := b.Subscribe("singapore")
	defer cancelSg()

	chAll, cancelAll := b.Subscribe("*")
	defer cancelAll()

	bridge := NewBroadcasterBridge(b)
	cfg := OutboxDispatcherConfig{
		WorkerID:      "test-worker-bridge",
		BatchSize:     10,
		PollInterval:  50 * time.Millisecond,
		LeaseDuration: 5 * time.Second,
	}
	dispatcher, _ := NewOutboxDispatcher(s, bridge, cfg)

	payload, _ := json.Marshal(map[string]interface{}{
		"domain_id":    "dom-bridge-01",
		"allowed_pops": []string{"singapore"},
	})
	s.SaveOutboxEvent(&store.OutboxEvent{
		EventID:       "evt-bridge-01",
		AggregateType: "domain",
		AggregateID:   "dom-bridge-01",
		EventType:     "domain.config.changed",
		Payload:       payload,
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	count, err := dispatcher.DispatchBatch(context.Background())
	if err != nil {
		t.Fatalf("DispatchBatch error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event dispatched, got %d", count)
	}

	// Singapore subscriber must receive notification
	select {
	case evt := <-chSg:
		if evt.Type != "domain.config.changed" && evt.Type != EventConfigUpdate {
			t.Errorf("unexpected event type: %s", evt.Type)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for Singapore event notification")
	}

	// Global wildcard subscriber must also receive notification
	select {
	case <-chAll:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timed out waiting for wildcard event notification")
	}
}

func TestOutboxDispatcher_HandlerFailureAndRetryExhaustion(t *testing.T) {
	s := store.NewStore()

	attempts := 0
	failingHandler := OutboxEventHandlerFunc(func(ctx context.Context, ev *store.OutboxEvent) error {
		attempts++
		return errors.New("simulated transient network failure")
	})

	cfg := OutboxDispatcherConfig{
		WorkerID:      "test-failing-worker",
		BatchSize:     10,
		PollInterval:  50 * time.Millisecond,
		LeaseDuration: 5 * time.Second,
	}
	dispatcher, _ := NewOutboxDispatcher(s, failingHandler, cfg)

	s.SaveOutboxEvent(&store.OutboxEvent{
		EventID:       "evt-fail-01",
		AggregateType: "domain",
		AggregateID:   "dom-fail-01",
		EventType:     "domain.config.changed",
		Payload:       []byte(`{"domain_id":"dom-fail-01"}`),
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	// Dispatch 1st attempt: fails and resets to PENDING
	count, err := dispatcher.DispatchBatch(context.Background())
	if err != nil {
		t.Fatalf("DispatchBatch error: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event dispatched, got %d", count)
	}

	stats := dispatcher.Stats()
	if stats.EventsFailed != 1 {
		t.Errorf("expected 1 failed event, got %d", stats.EventsFailed)
	}

	// Repeatedly fail until retry_count reaches 5 -> DEAD_LETTER
	for i := 1; i < 5; i++ {
		_, _ = dispatcher.DispatchBatch(context.Background())
	}

	// After 5 attempts, event must be DEAD_LETTER and no longer returned as PENDING
	pending, _ := s.GetPendingOutboxEvents(context.Background(), 10)
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending events after 5 failed retries, got %d", len(pending))
	}
}

func TestOutboxDispatcher_BackgroundDaemonAndTrigger(t *testing.T) {
	s := store.NewStore()
	var processedEvents []string
	var mu sync.Mutex

	handler := OutboxEventHandlerFunc(func(ctx context.Context, ev *store.OutboxEvent) error {
		mu.Lock()
		defer mu.Unlock()
		processedEvents = append(processedEvents, ev.EventID)
		return nil
	})

	cfg := OutboxDispatcherConfig{
		WorkerID:      "test-daemon-worker",
		BatchSize:     10,
		PollInterval:  5 * time.Second, // Long interval to prove Trigger() works immediately
		LeaseDuration: 5 * time.Second,
	}
	dispatcher, _ := NewOutboxDispatcher(s, handler, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	dispatcher.Start(ctx)
	defer dispatcher.Stop()

	// Enqueue event
	s.SaveOutboxEvent(&store.OutboxEvent{
		EventID:       "evt-trigger-test",
		AggregateType: "domain",
		AggregateID:   "dom-trigger",
		EventType:     "domain.config.changed",
		Payload:       []byte(`{}`),
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	// Trigger immediate execution
	dispatcher.Trigger()

	// Assert processed within 500ms
	deadline := time.Now().Add(1 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		mu.Lock()
		if len(processedEvents) > 0 && processedEvents[0] == "evt-trigger-test" {
			found = true
			mu.Unlock()
			break
		}
		mu.Unlock()
		time.Sleep(20 * time.Millisecond)
	}

	if !found {
		t.Fatal("background daemon failed to process triggered outbox event promptly")
	}
}

func TestOutboxDispatcher_ConcurrentWorkersLeaseFencing(t *testing.T) {
	s := store.NewStore()

	processedMap := make(map[string]int)
	var mu sync.Mutex

	handler := OutboxEventHandlerFunc(func(ctx context.Context, ev *store.OutboxEvent) error {
		mu.Lock()
		defer mu.Unlock()
		processedMap[ev.EventID]++
		return nil
	})

	cfg1 := OutboxDispatcherConfig{
		WorkerID:      "worker-node-1",
		BatchSize:     5,
		PollInterval:  20 * time.Millisecond,
		LeaseDuration: 5 * time.Second,
	}
	cfg2 := OutboxDispatcherConfig{
		WorkerID:      "worker-node-2",
		BatchSize:     5,
		PollInterval:  20 * time.Millisecond,
		LeaseDuration: 5 * time.Second,
	}

	d1, _ := NewOutboxDispatcher(s, handler, cfg1)
	d2, _ := NewOutboxDispatcher(s, handler, cfg2)

	// Enqueue 20 events
	for i := 0; i < 20; i++ {
		evID := "evt-conc-" + string(rune('a'+i))
		s.SaveOutboxEvent(&store.OutboxEvent{
			EventID:       evID,
			AggregateType: "domain",
			AggregateID:   "dom-conc",
			EventType:     "domain.config.changed",
			Payload:       []byte(`{}`),
			Status:        "PENDING",
			CreatedAt:     time.Now().UTC(),
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	d1.Start(ctx)
	d2.Start(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		count := len(processedMap)
		mu.Unlock()
		if count == 20 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	d1.Stop()
	d2.Stop()

	mu.Lock()
	defer mu.Unlock()

	if len(processedMap) != 20 {
		t.Fatalf("expected 20 unique events processed, got %d", len(processedMap))
	}
	for id, count := range processedMap {
		if count != 1 {
			t.Errorf("event %s was processed %d times (expected exactly 1 under lease fencing)", id, count)
		}
	}
}

func TestOutboxDispatcher_MalformedPayloadQuarantine(t *testing.T) {
	s := store.NewStore()
	b := NewBroadcaster()
	defer b.Close()

	tracker := NewGatewaySyncTracker(10 * time.Second)
	bridge := NewBroadcasterBridgeWithTracker(b, tracker)

	cfg := OutboxDispatcherConfig{
		WorkerID:      "worker-quarantine-test",
		BatchSize:     10,
		PollInterval:  50 * time.Millisecond,
		LeaseDuration: 5 * time.Second,
	}

	dispatcher, err := NewOutboxDispatcher(s, bridge, cfg)
	if err != nil {
		t.Fatalf("NewOutboxDispatcher failed: %v", err)
	}

	// 1. Insert an outbox event with corrupt/malformed JSON
	corruptEventID := "evt-corrupt-01"
	s.SaveOutboxEvent(&store.OutboxEvent{
		EventID:       corruptEventID,
		AggregateType: "domain",
		AggregateID:   "dom-corrupt",
		EventType:     "domain.config.changed",
		Payload:       []byte("{corrupt-non-json-payload-marker"),
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	// Dispatch batch: must quarantine immediately
	count, err := dispatcher.DispatchBatch(context.Background())
	if err != nil {
		t.Fatalf("DispatchBatch failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event processed in batch, got %d", count)
	}

	stats := dispatcher.Stats()
	if stats.EventsFailed != 1 {
		t.Fatalf("expected 1 failed event, got %d", stats.EventsFailed)
	}

	// Verify the event in store is now DEAD_LETTER (quarantined) and NOT pending
	pending, _ := s.GetPendingOutboxEvents(context.Background(), 10)
	if len(pending) != 0 {
		t.Fatalf("expected 0 pending events after quarantine, got %d", len(pending))
	}
}

func TestOutboxDispatcher_SchemaValidationFailureQuarantine(t *testing.T) {
	s := store.NewStore()
	b := NewBroadcaster()
	defer b.Close()

	bridge := NewBroadcasterBridge(b)
	cfg := OutboxDispatcherConfig{
		WorkerID:      "worker-schema-test",
		BatchSize:     10,
		PollInterval:  50 * time.Millisecond,
		LeaseDuration: 5 * time.Second,
	}

	dispatcher, _ := NewOutboxDispatcher(s, bridge, cfg)

	// Valid JSON, but missing required domain_id field
	s.SaveOutboxEvent(&store.OutboxEvent{
		EventID:       "evt-bad-schema-01",
		AggregateType: "domain",
		AggregateID:   "dom-bad",
		EventType:     "domain.config.changed",
		Payload:       []byte(`{"status": "ACTIVE"}`), // missing domain_id
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	count, err := dispatcher.DispatchBatch(context.Background())
	if err != nil {
		t.Fatalf("DispatchBatch failed: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 event processed, got %d", count)
	}

	// Must be quarantined to DEAD_LETTER
	pending, _ := s.GetPendingOutboxEvents(context.Background(), 10)
	if len(pending) != 0 {
		t.Fatalf("expected event to be quarantined to DEAD_LETTER, but found %d pending events", len(pending))
	}
}

func TestOutboxDispatcher_DeadlineAwareShutdown(t *testing.T) {
	s := store.NewStore()

	// Handler that blocks until unblocked or context canceled
	blockCh := make(chan struct{})
	defer close(blockCh)

	slowHandler := OutboxEventHandlerFunc(func(ctx context.Context, ev *store.OutboxEvent) error {
		select {
		case <-blockCh:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	})

	cfg := OutboxDispatcherConfig{
		WorkerID:        "worker-timeout-test",
		BatchSize:       1,
		PollInterval:    10 * time.Millisecond,
		LeaseDuration:   2 * time.Second,
		ShutdownTimeout: 50 * time.Millisecond,
	}

	d, _ := NewOutboxDispatcher(s, slowHandler, cfg)
	s.SaveOutboxEvent(&store.OutboxEvent{
		EventID:       "evt-slow-01",
		AggregateType: "domain",
		AggregateID:   "dom-slow",
		EventType:     "domain.config.changed",
		Payload:       []byte(`{"domain_id": "dom-slow"}`),
		Status:        "PENDING",
		CreatedAt:     time.Now().UTC(),
	})

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	d.Start(ctx)

	// Wait briefly for worker to pick up event
	time.Sleep(30 * time.Millisecond)

	startStop := time.Now()
	err := d.Stop()
	elapsed := time.Since(startStop)

	// Stop must return within reasonable deadline and not hang
	if elapsed > 1*time.Second {
		t.Fatalf("d.Stop() took %v, exceeded shutdown deadline", elapsed)
	}
	if err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, context.Canceled) {
		t.Fatalf("unexpected stop error: %v", err)
	}
}

func TestBroadcaster_DropTrackingWhenBufferSaturated(t *testing.T) {
	b := NewBroadcasterWithBufferSize(2)
	defer b.Close()

	ch, cleanup := b.Subscribe("dhaka")
	defer cleanup()

	// Send 5 events without reading from ch (bufferSize=2)
	for i := 0; i < 5; i++ {
		b.Broadcast("dhaka", Event{Type: "test_event"})
	}

	if b.DeliveredCount() != 2 {
		t.Fatalf("expected 2 delivered events, got %d", b.DeliveredCount())
	}
	if b.DroppedCount() != 3 {
		t.Fatalf("expected 3 dropped events due to full buffer, got %d", b.DroppedCount())
	}

	// Read 2 events from channel
	for i := 0; i < 2; i++ {
		<-ch
	}
}

func TestGatewaySyncTracker_ConvergenceLifecycle(t *testing.T) {
	tracker := NewGatewaySyncTracker(100 * time.Millisecond)

	// Advance target version
	v1 := tracker.AdvanceTargetVersion(1, "chk-1")
	if v1 != 2 {
		t.Fatalf("expected target version 2, got %d", v1)
	}

	// 1. Gateway 1 ACKs version 2 -> IN_SYNC
	rec1, err := tracker.RecordAck(GatewaySyncAcknowledgement{
		GatewayID:       "gw-sg-01",
		PoPID:           "singapore",
		AppliedVersion:  2,
		AppliedChecksum: "chk-1",
		Status:          "IN_SYNC",
	})
	if err != nil {
		t.Fatalf("RecordAck failed: %v", err)
	}
	if rec1.Status != SyncStatusInSync || rec1.VersionLag != 0 {
		t.Fatalf("expected IN_SYNC and lag 0, got status=%s lag=%d", rec1.Status, rec1.VersionLag)
	}

	// 2. Gateway 2 ACKs version 1 -> LAGGING
	rec2, err := tracker.RecordAck(GatewaySyncAcknowledgement{
		GatewayID:       "gw-dhk-01",
		PoPID:           "dhaka",
		AppliedVersion:  1,
		AppliedChecksum: "chk-0",
		Status:          "APPLYING",
	})
	if err != nil {
		t.Fatalf("RecordAck failed: %v", err)
	}
	if rec2.Status != SyncStatusApplying || rec2.VersionLag != 1 {
		t.Fatalf("expected APPLYING and lag 1, got status=%s lag=%d", rec2.Status, rec2.VersionLag)
	}

	// 3. Summary check
	summary := tracker.GetConvergenceSummary()
	if summary["total_gateways"] != 2 {
		t.Fatalf("expected 2 total gateways, got %v", summary["total_gateways"])
	}
	if summary["in_sync_gateways"] != 1 {
		t.Fatalf("expected 1 in_sync gateway, got %v", summary["in_sync_gateways"])
	}
	if summary["fully_converged"] != false {
		t.Fatalf("expected fully_converged to be false, got %v", summary["fully_converged"])
	}

	// 4. Stale detection: wait past staleThreshold (100ms)
	time.Sleep(120 * time.Millisecond)
	list := tracker.ListGateways()
	for _, gw := range list {
		if gw.Status != SyncStatusStale {
			t.Errorf("expected gateway %s to become STALE, got status %s", gw.GatewayID, gw.Status)
		}
	}
}

func TestGatewaySyncTracker_WrongChecksumRejection(t *testing.T) {
	st := store.NewStore()
	tracker := NewGatewaySyncTrackerWithStore(1*time.Minute, st)

	tracker.AdvanceTargetVersion(4, "chk-authoritative-5")
	if tracker.TargetVersion() != 5 {
		t.Fatalf("expected target version 5, got %d", tracker.TargetVersion())
	}

	// Gateway reports applied version 5, but wrong checksum "bad-chk"
	rec, err := tracker.RecordAck(GatewaySyncAcknowledgement{
		GatewayID:       "gw-fra-01",
		PoPID:           "frankfurt",
		AppliedVersion:  5,
		AppliedChecksum: "bad-chk",
		Status:          "IN_SYNC",
	})
	if !errors.Is(err, model.ErrChecksumMismatch) {
		t.Fatalf("expected ErrChecksumMismatch, got: %v", err)
	}
	if rec.Status != model.SyncStatusChecksumMismatch {
		t.Fatalf("expected status CHECKSUM_MISMATCH, got: %s", rec.Status)
	}
	if rec.LastError == "" {
		t.Fatalf("expected non-empty LastError detailing checksum mismatch")
	}

	// Verify gateway is not listed as IN_SYNC in summary
	summary := tracker.GetConvergenceSummary()
	if summary["in_sync_gateways"] != 0 {
		t.Fatalf("expected 0 in_sync_gateways, got %v", summary["in_sync_gateways"])
	}
	if summary["fully_converged"] != false {
		t.Fatalf("expected fully_converged false")
	}
}

func TestGatewaySyncTracker_DuplicateEventIdempotency(t *testing.T) {
	st := store.NewStore()
	tracker := NewGatewaySyncTrackerWithStore(1*time.Minute, st)

	// First event advances target to version 2
	v1 := tracker.AdvanceTargetVersion(1, "chk-config-v2")
	if v1 != 2 {
		t.Fatalf("expected version 2, got %d", v1)
	}

	// Duplicate event arrives with identical checksum -> version must NOT advance
	v2 := tracker.AdvanceTargetVersion(1, "chk-config-v2")
	if v2 != 2 {
		t.Fatalf("expected version to remain 2 on duplicate checksum, got %d", v2)
	}

	// Third event with distinct checksum advances target to version 3
	v3 := tracker.AdvanceTargetVersion(1, "chk-config-v3")
	if v3 != 3 {
		t.Fatalf("expected version to advance to 3 on new checksum, got %d", v3)
	}
}

func TestGatewaySyncTracker_RestartRecovery(t *testing.T) {
	st := store.NewStore()
	tracker1 := NewGatewaySyncTrackerWithStore(1*time.Minute, st)

	tracker1.AdvanceTargetVersion(9, "chk-state-10")
	rec, err := tracker1.RecordAck(GatewaySyncAcknowledgement{
		GatewayID:       "gw-dhk-01",
		PoPID:           "dhaka",
		AppliedVersion:  10,
		AppliedChecksum: "chk-state-10",
		Status:          "IN_SYNC",
	})
	if err != nil {
		t.Fatalf("initial RecordAck failed: %v", err)
	}
	if rec.Status != SyncStatusInSync {
		t.Fatalf("expected IN_SYNC, got %s", rec.Status)
	}

	// Simulate control plane restart by creating a new tracker against the same store
	tracker2 := NewGatewaySyncTrackerWithStore(1*time.Minute, st)
	if tracker2.TargetVersion() != 10 {
		t.Fatalf("expected recovered target version 10, got %d", tracker2.TargetVersion())
	}
	if tracker2.TargetChecksum() != "chk-state-10" {
		t.Fatalf("expected recovered target checksum 'chk-state-10', got %s", tracker2.TargetChecksum())
	}

	gw, ok := tracker2.GetGateway("gw-dhk-01")
	if !ok {
		t.Fatalf("expected gateway 'gw-dhk-01' to be recovered from persistent store")
	}
	if gw.Status != SyncStatusInSync || gw.AppliedVersion != 10 {
		t.Fatalf("expected recovered gateway status IN_SYNC and version 10, got status=%s ver=%d", gw.Status, gw.AppliedVersion)
	}
}

func TestOutboxSchema_AllowlistRejection(t *testing.T) {
	// 1. Known event types should pass schema validation
	validPayload := map[string]interface{}{"domain_id": "dom-test-01"}
	if err := validateOutboxPayloadSchema("domain.config.changed", validPayload); err != nil {
		t.Fatalf("expected domain.config.changed to pass, got: %v", err)
	}

	// 2. Unknown event type should be strictly rejected by allowlist
	unknownErr := validateOutboxPayloadSchema("malicious.unregistered.event", validPayload)
	if unknownErr == nil {
		t.Fatalf("expected unknown event type to be rejected by strict allowlist")
	}

	// 3. NewOutboxDispatcher rejects nil handler
	st := store.NewStore()
	cfg := DefaultOutboxDispatcherConfig()
	_, err := NewOutboxDispatcher(st, nil, cfg)
	if err == nil {
		t.Fatalf("expected NewOutboxDispatcher to reject nil handler")
	}
}
