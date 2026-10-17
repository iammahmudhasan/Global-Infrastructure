package events

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

// OutboxDispatcherConfig tunes the transactional outbox worker daemon.
type OutboxDispatcherConfig struct {
	WorkerID        string
	BatchSize       int
	PollInterval    time.Duration
	LeaseDuration   time.Duration
	ShutdownTimeout time.Duration
}

// DefaultOutboxDispatcherConfig returns safe production defaults.
func DefaultOutboxDispatcherConfig() OutboxDispatcherConfig {
	hostname, _ := os.Hostname()
	if hostname == "" {
		hostname = "unknown-host"
	}
	return OutboxDispatcherConfig{
		WorkerID:        fmt.Sprintf("dispatcher-%s-%d", hostname, time.Now().UnixNano()),
		BatchSize:       50,
		PollInterval:    500 * time.Millisecond,
		LeaseDuration:   30 * time.Second,
		ShutdownTimeout: 5 * time.Second,
	}
}

// OutboxEventHandler defines the destination contract for claimed outbox events.
type OutboxEventHandler interface {
	HandleOutboxEvent(ctx context.Context, ev *store.OutboxEvent) error
}

// OutboxEventHandlerFunc is an adapter allowing normal functions to act as OutboxEventHandlers.
type OutboxEventHandlerFunc func(ctx context.Context, ev *store.OutboxEvent) error

// HandleOutboxEvent calls f(ctx, ev).
func (f OutboxEventHandlerFunc) HandleOutboxEvent(ctx context.Context, ev *store.OutboxEvent) error {
	return f(ctx, ev)
}

// BroadcasterBridge adapts store.OutboxEvent into edge notifications for Broadcaster.
type BroadcasterBridge struct {
	broadcaster *Broadcaster
}

// NewBroadcasterBridge creates a bridge connecting outbox dispatching to real-time Edge Gateways.
func NewBroadcasterBridge(b *Broadcaster) *BroadcasterBridge {
	return &BroadcasterBridge{broadcaster: b}
}

// HandleOutboxEvent translates an outbox event into Broadcaster notifications.
func (b *BroadcasterBridge) HandleOutboxEvent(ctx context.Context, ev *store.OutboxEvent) error {
	if b.broadcaster == nil || ev == nil {
		return nil
	}

	var payload map[string]interface{}
	if len(ev.Payload) > 0 {
		_ = json.Unmarshal(ev.Payload, &payload)
	}

	var allowedPoPs []string
	if payload != nil {
		if rawPoPs, ok := payload["allowed_pops"].([]interface{}); ok {
			for _, p := range rawPoPs {
				if s, ok := p.(string); ok && s != "" {
					allowedPoPs = append(allowedPoPs, s)
				}
			}
		}
	}

	outEvent := Event{
		Type:      ev.EventType,
		Timestamp: ev.CreatedAt,
		Payload:   payload,
	}

	if len(allowedPoPs) > 0 {
		for _, pop := range allowedPoPs {
			b.broadcaster.Broadcast(pop, outEvent)
			b.broadcaster.BroadcastConfigUpdate(pop, "")
		}
	} else {
		b.broadcaster.Broadcast("*", outEvent)
		b.broadcaster.BroadcastConfigUpdate("*", "")
	}

	return nil
}

// DispatcherStats captures live operational telemetry for the outbox worker daemon.
type DispatcherStats struct {
	EventsClaimed    int64         `json:"events_claimed"`
	EventsProcessed  int64         `json:"events_processed"`
	EventsFailed     int64         `json:"events_failed"`
	BatchesExecuted  int64         `json:"batches_executed"`
	LastDispatchedAt time.Time     `json:"last_dispatched_at"`
	LastLag          time.Duration `json:"last_lag"`
}

// OutboxDispatcher coordinates transactional outbox polling, lease-fenced claiming,
// dispatching to event sinks, and atomic state acknowledgement.
type OutboxDispatcher struct {
	store     store.OutboxStore
	handler   OutboxEventHandler
	cfg       OutboxDispatcherConfig
	triggerCh chan struct{}

	mu      sync.RWMutex
	running bool
	cancel  context.CancelFunc
	wg      sync.WaitGroup

	eventsClaimed   atomic.Int64
	eventsProcessed atomic.Int64
	eventsFailed    atomic.Int64
	batchesExecuted atomic.Int64

	statsMu          sync.RWMutex
	lastDispatchedAt time.Time
	lastLag          time.Duration
}

// NewOutboxDispatcher constructs an initialized OutboxDispatcher.
func NewOutboxDispatcher(outboxStore store.OutboxStore, handler OutboxEventHandler, cfg OutboxDispatcherConfig) (*OutboxDispatcher, error) {
	if outboxStore == nil {
		return nil, errors.New("outboxStore cannot be nil")
	}
	if handler == nil {
		handler = OutboxEventHandlerFunc(func(ctx context.Context, ev *store.OutboxEvent) error {
			return nil
		})
	}
	defaults := DefaultOutboxDispatcherConfig()
	if cfg.WorkerID == "" {
		cfg.WorkerID = defaults.WorkerID
	}
	if cfg.BatchSize <= 0 {
		cfg.BatchSize = defaults.BatchSize
	}
	if cfg.PollInterval <= 0 {
		cfg.PollInterval = defaults.PollInterval
	}
	if cfg.LeaseDuration <= 0 {
		cfg.LeaseDuration = defaults.LeaseDuration
	}
	if cfg.ShutdownTimeout <= 0 {
		cfg.ShutdownTimeout = defaults.ShutdownTimeout
	}

	return &OutboxDispatcher{
		store:     outboxStore,
		handler:   handler,
		cfg:       cfg,
		triggerCh: make(chan struct{}, 1),
	}, nil
}

// Start launches the background outbox dispatcher daemon loop.
func (d *OutboxDispatcher) Start(ctx context.Context) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.running {
		return
	}
	d.running = true

	runCtx, cancel := context.WithCancel(ctx)
	d.cancel = cancel

	d.wg.Add(1)
	go d.run(runCtx)
}

// Stop initiates a graceful shutdown of the outbox worker and waits for active processing to drain.
func (d *OutboxDispatcher) Stop() {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return
	}
	d.running = false
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()

	d.wg.Wait()
}

// Trigger notifies the dispatcher to immediately evaluate pending events without waiting for the next ticker tick.
func (d *OutboxDispatcher) Trigger() {
	select {
	case d.triggerCh <- struct{}{}:
	default:
	}
}

// DispatchBatch executes a single claim-process-ack iteration.
func (d *OutboxDispatcher) DispatchBatch(ctx context.Context) (int, error) {
	events, err := d.store.ClaimOutboxEvents(ctx, d.cfg.WorkerID, d.cfg.BatchSize, d.cfg.LeaseDuration)
	if err != nil {
		return 0, fmt.Errorf("claim outbox events: %w", err)
	}

	d.batchesExecuted.Add(1)
	if len(events) == 0 {
		return 0, nil
	}

	now := time.Now().UTC()
	for _, ev := range events {
		d.eventsClaimed.Add(1)

		handleErr := d.handler.HandleOutboxEvent(ctx, ev)
		if handleErr == nil {
			if ackErr := d.store.MarkOutboxEventProcessed(ctx, ev.EventID, d.cfg.WorkerID, ev.LeaseToken); ackErr != nil {
				if errors.Is(ackErr, store.ErrOutboxLeaseLost) {
					log.Printf("[WARN] Outbox event %s lease lost during ack (worker=%s): %v", ev.EventID, d.cfg.WorkerID, ackErr)
				} else {
					log.Printf("[ERROR] Failed to mark outbox event %s processed: %v", ev.EventID, ackErr)
				}
				d.eventsFailed.Add(1)
			} else {
				d.eventsProcessed.Add(1)
			}
		} else {
			d.eventsFailed.Add(1)
			if failErr := d.store.MarkOutboxEventFailed(ctx, ev.EventID, d.cfg.WorkerID, ev.LeaseToken, handleErr.Error()); failErr != nil {
				log.Printf("[ERROR] Failed to mark outbox event %s failed: %v", ev.EventID, failErr)
			}
		}

		lag := now.Sub(ev.CreatedAt)
		if lag < 0 {
			lag = 0
		}
		d.statsMu.Lock()
		d.lastDispatchedAt = now
		d.lastLag = lag
		d.statsMu.Unlock()
	}

	return len(events), nil
}

// Stats returns a thread-safe snapshot of dispatcher telemetry.
func (d *OutboxDispatcher) Stats() DispatcherStats {
	d.statsMu.RLock()
	defer d.statsMu.RUnlock()

	return DispatcherStats{
		EventsClaimed:    d.eventsClaimed.Load(),
		EventsProcessed:  d.eventsProcessed.Load(),
		EventsFailed:     d.eventsFailed.Load(),
		BatchesExecuted:  d.batchesExecuted.Load(),
		LastDispatchedAt: d.lastDispatchedAt,
		LastLag:          d.lastLag,
	}
}

// WorkerID returns the assigned worker identifier.
func (d *OutboxDispatcher) WorkerID() string {
	return d.cfg.WorkerID
}

func (d *OutboxDispatcher) run(ctx context.Context) {
	defer d.wg.Done()

	ticker := time.NewTicker(d.cfg.PollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-d.triggerCh:
		}

		for {
			select {
			case <-ctx.Done():
				return
			default:
			}

			count, err := d.DispatchBatch(ctx)
			if err != nil {
				if !errors.Is(err, context.Canceled) {
					log.Printf("[WARN] Outbox dispatcher batch execution error (worker=%s): %v", d.cfg.WorkerID, err)
				}
				break
			}

			// If the batch was completely full, immediately loop to drain the backlog before sleeping
			if count < d.cfg.BatchSize {
				break
			}
		}
	}
}
