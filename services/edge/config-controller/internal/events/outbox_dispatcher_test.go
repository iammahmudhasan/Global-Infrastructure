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
