package events

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/store"
)

// PermanentError marks an unrecoverable poison-pill error that must be quarantined immediately.
type PermanentError interface {
	error
	IsPermanent() bool
}

type permanentError struct {
	err error
}

func (p *permanentError) Error() string     { return p.err.Error() }
func (p *permanentError) IsPermanent() bool { return true }
func (p *permanentError) Unwrap() error     { return p.err }

// NewPermanentError wraps an error as permanent to trigger immediate quarantine.
func NewPermanentError(err error) error {
	if err == nil {
		return nil
	}
	return &permanentError{err: err}
}

// IsPermanent returns true if err or its cause implements PermanentError.
func IsPermanent(err error) bool {
	var pe PermanentError
	return errors.As(err, &pe) && pe.IsPermanent()
}

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

func validateOutboxPayloadSchema(eventType string, payload map[string]interface{}) error {
	if payload == nil {
		return errors.New("payload cannot be empty")
	}

	checkNonEmptyStr := func(key string) error {
		val, ok := payload[key]
		if !ok || val == nil {
			return fmt.Errorf("missing required field '%s'", key)
		}
		s, ok := val.(string)
		if !ok || strings.TrimSpace(s) == "" {
			return fmt.Errorf("field '%s' must be a non-empty string", key)
		}
		return nil
	}

	switch eventType {
	case "domain.config.changed", "domain.status.changed", "domain.deleted":
		return checkNonEmptyStr("domain_id")
	case "pool.config.changed":
		return checkNonEmptyStr("pool_id")
	case "route.config.changed":
		if err := checkNonEmptyStr("route_id"); err != nil {
			return err
		}
		return checkNonEmptyStr("domain_id")
	case "security.policy.changed":
		return checkNonEmptyStr("domain_id")
	case "certificate.changed":
		certID, hasCertID := payload["cert_id"].(string)
		if !hasCertID || strings.TrimSpace(certID) == "" {
			certID, hasCertID = payload["certificate_id"].(string)
		}
		if !hasCertID || strings.TrimSpace(certID) == "" {
			return errors.New("outbox payload schema error: cert_id or certificate_id is required")
		}
		return checkNonEmptyStr("domain_id")
	case "ai_provider.changed":
		return checkNonEmptyStr("provider_id")
	default:
		return fmt.Errorf("unknown or unsupported outbox event type: %q (strict allowlist rejection)", eventType)
	}
}

// BroadcasterBridge adapts store.OutboxEvent into edge notifications for Broadcaster
// and advances the global Edge Configuration Convergence Tracker (P1).
type BroadcasterBridge struct {
	broadcaster *Broadcaster
	tracker     *GatewaySyncTracker
}

// NewBroadcasterBridge creates a bridge connecting outbox dispatching to real-time Edge Gateways.
func NewBroadcasterBridge(b *Broadcaster) *BroadcasterBridge {
	return &BroadcasterBridge{broadcaster: b}
}

// NewBroadcasterBridgeWithTracker creates a bridge with integrated edge convergence tracking.
func NewBroadcasterBridgeWithTracker(b *Broadcaster, tracker *GatewaySyncTracker) *BroadcasterBridge {
	return &BroadcasterBridge{
		broadcaster: b,
		tracker:     tracker,
	}
}

// HandleOutboxEvent translates an outbox event into Broadcaster notifications,
// strictly validating payloads and advancing the target configuration version.
func (b *BroadcasterBridge) HandleOutboxEvent(ctx context.Context, ev *store.OutboxEvent) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}

	if ev == nil {
		return nil
	}

	if len(ev.Payload) == 0 {
		return NewPermanentError(fmt.Errorf("empty payload in outbox event %s", ev.EventID))
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(ev.Payload, &payload); err != nil {
		return NewPermanentError(fmt.Errorf("malformed JSON in outbox payload for event %s: %w", ev.EventID, err))
	}

	if err := validateOutboxPayloadSchema(ev.EventType, payload); err != nil {
		return NewPermanentError(fmt.Errorf("payload schema validation error for event %s (%s): %w", ev.EventID, ev.EventType, err))
	}

	canonicalPayload := fmt.Sprintf("%s:%s:%s:%s", ev.EventType, ev.AggregateType, ev.AggregateID, string(ev.Payload))
	sum := sha256.Sum256([]byte(canonicalPayload))
	checksum := hex.EncodeToString(sum[:])

	var targetVer int64
	if b.tracker != nil {
		var advErr error
		targetVer, checksum, advErr = b.tracker.AdvanceTargetVersion(ctx, checksum)
		if advErr != nil {
			return fmt.Errorf("advance target version: %w", advErr)
		}
	} else if os.Getenv("NEXUSEDGE_DEV_MODE") == "false" || os.Getenv("NEXUSEDGE_ENV") == "production" {
		return errors.New("fail-closed: tracker is nil in production outbox dispatcher")
	}

	var allowedPoPs []string
	if rawPoPs, ok := payload["allowed_pops"].([]interface{}); ok {
		for _, p := range rawPoPs {
			if s, ok := p.(string); ok && s != "" {
				allowedPoPs = append(allowedPoPs, s)
			}
		}
	}

	payload["target_version"] = targetVer
	payload["checksum"] = checksum

	outEvent := Event{
		Type:      ev.EventType,
		Timestamp: ev.CreatedAt,
		Checksum:  checksum,
		Payload:   payload,
	}

	if b.broadcaster != nil {
		if len(allowedPoPs) > 0 {
			for _, pop := range allowedPoPs {
				b.broadcaster.Broadcast(pop, outEvent)
				b.broadcaster.BroadcastConfigUpdate(pop, checksum)
			}
		} else {
			b.broadcaster.Broadcast("*", outEvent)
			b.broadcaster.BroadcastConfigUpdate("*", checksum)
		}
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
		return nil, errors.New("outbox event handler cannot be nil")
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
// Stop initiates a graceful shutdown bounded by cfg.ShutdownTimeout (default 5s).
func (d *OutboxDispatcher) Stop() error {
	timeout := d.cfg.ShutdownTimeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return d.StopWithContext(ctx)
}

// StopWithContext initiates a graceful shutdown bounded by the provided context deadline.
func (d *OutboxDispatcher) StopWithContext(ctx context.Context) error {
	d.mu.Lock()
	if !d.running {
		d.mu.Unlock()
		return nil
	}
	d.running = false
	if d.cancel != nil {
		d.cancel()
	}
	d.mu.Unlock()

	done := make(chan struct{})
	go func() {
		d.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
		return nil
	case <-ctx.Done():
		log.Printf("[WARN] OutboxDispatcher shutdown deadline exceeded (%v): active tasks drained or left for lease expiry", ctx.Err())
		return ctx.Err()
	}
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
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
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
			failReason := handleErr.Error()
			if IsPermanent(handleErr) {
				failReason = "QUARANTINE: " + failReason
			}
			if failErr := d.store.MarkOutboxEventFailed(ctx, ev.EventID, d.cfg.WorkerID, ev.LeaseToken, failReason); failErr != nil {
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

// IsRunning reports whether the background dispatcher loop is running.
func (d *OutboxDispatcher) IsRunning() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.running
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
