package store

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrOutboxLeaseLost is returned when attempting to ack or fail an outbox event
	// whose lease expired or was reclaimed by another worker under lease fencing.
	ErrOutboxLeaseLost = errors.New("outbox event lease lost or claimed by another worker")

	// ErrOutboxNotFound is returned when an outbox event ID does not exist.
	ErrOutboxNotFound = errors.New("outbox event not found")
)

// OutboxEvent represents an atomic desired-state event generated within the same
// transaction as domain/config mutations for reliable asynchronous reconciliation.
type OutboxEvent struct {
	EventID       string     `json:"event_id"`
	AggregateType string     `json:"aggregate_type"`
	AggregateID   string     `json:"aggregate_id"`
	EventType     string     `json:"event_type"`
	Payload       []byte     `json:"payload"`
	Status        string     `json:"status"`
	RetryCount    int        `json:"retry_count"`
	LeaseToken    string     `json:"lease_token,omitempty"`
	CreatedAt     time.Time  `json:"created_at"`
	ProcessedAt   *time.Time `json:"processed_at,omitempty"`
}

// OutboxStore defines the transactional outbox operations required for event claiming, leasing, and dispatch.
type OutboxStore interface {
	ClaimOutboxEvents(ctx context.Context, workerID string, limit int, leaseDuration time.Duration) ([]*OutboxEvent, error)
	MarkOutboxEventProcessed(ctx context.Context, eventID string, workerID string, leaseToken string) error
	MarkOutboxEventFailed(ctx context.Context, eventID string, workerID string, leaseToken string, reason string) error
	GetPendingOutboxEvents(ctx context.Context, limit int) ([]*OutboxEvent, error)
}
