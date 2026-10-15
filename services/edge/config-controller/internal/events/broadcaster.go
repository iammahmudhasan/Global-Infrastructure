package events

import (
	"sync"
	"time"
)

const (
	// EventConfigUpdate indicates that routing, origins, or AI providers have changed for a PoP.
	EventConfigUpdate = "config_update"

	// EventSTEKUpdate indicates that TLS Session Ticket Encryption Keys have rotated.
	EventSTEKUpdate = "stek_update"

	// EventHeartbeat indicates a periodic keepalive ping.
	EventHeartbeat = "heartbeat"

	// DefaultBufferSize is the channel buffer size for each subscriber to absorb bursts without blocking.
	DefaultBufferSize = 32
)

// Event represents a real-time notification emitted by the Control Plane to subscribed Edge Nodes.
type Event struct {
	Type      string                 `json:"type"`
	PoPID     string                 `json:"pop_id,omitempty"`
	Checksum  string                 `json:"checksum,omitempty"`
	Timestamp time.Time              `json:"timestamp"`
	Payload   map[string]interface{} `json:"payload,omitempty"`
}

// Broadcaster manages real-time event distribution to connected Edge Gateways with per-PoP isolation.
type Broadcaster struct {
	mu          sync.RWMutex
	subscribers map[string]map[chan Event]struct{}
	bufferSize  int
	closed      bool
}

// NewBroadcaster creates an initialized Broadcaster.
func NewBroadcaster() *Broadcaster {
	return NewBroadcasterWithBufferSize(DefaultBufferSize)
}

// NewBroadcasterWithBufferSize creates a Broadcaster with a custom per-subscriber buffer size.
func NewBroadcasterWithBufferSize(bufSize int) *Broadcaster {
	if bufSize <= 0 {
		bufSize = DefaultBufferSize
	}
	return &Broadcaster{
		subscribers: make(map[string]map[chan Event]struct{}),
		bufferSize:  bufSize,
	}
}

// Subscribe registers a new subscriber channel for the given PoPID (or "*" for global broadcast).
// It returns the receive-only channel and an idempotent cancellation function.
func (b *Broadcaster) Subscribe(popID string) (<-chan Event, func()) {
	b.mu.Lock()
	defer b.mu.Unlock()

	ch := make(chan Event, b.bufferSize)
	if b.closed {
		close(ch)
		return ch, func() {}
	}

	if _, exists := b.subscribers[popID]; !exists {
		b.subscribers[popID] = make(map[chan Event]struct{})
	}
	b.subscribers[popID][ch] = struct{}{}

	var once sync.Once
	cleanup := func() {
		once.Do(func() {
			b.mu.Lock()
			defer b.mu.Unlock()
			if subs, ok := b.subscribers[popID]; ok {
				delete(subs, ch)
				if len(subs) == 0 {
					delete(b.subscribers, popID)
				}
			}
			close(ch)
		})
	}

	return ch, cleanup
}

// Broadcast sends an event to all subscribers registered for popID and wildcard ("*") subscribers.
// Sends are strictly non-blocking to prevent slow or stalled consumers from impacting line-rate dispatch.
func (b *Broadcaster) Broadcast(popID string, evt Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()

	if b.closed {
		return
	}

	if evt.Timestamp.IsZero() {
		evt.Timestamp = time.Now().UTC()
	}

	deliver := func(subs map[chan Event]struct{}) {
		for ch := range subs {
			select {
			case ch <- evt:
			default:
				// Buffer saturated: drop to protect overall system throughput and avoid goroutine leaks
			}
		}
	}

	if subs, ok := b.subscribers[popID]; ok {
		deliver(subs)
	}

	// Always deliver to wildcard subscribers unless the event was already targeting wildcard
	if popID != "*" {
		if subs, ok := b.subscribers["*"]; ok {
			deliver(subs)
		}
	}
}

// BroadcastConfigUpdate is a helper to broadcast a configuration invalidation event for a specific PoP.
func (b *Broadcaster) BroadcastConfigUpdate(popID, checksum string) {
	b.Broadcast(popID, Event{
		Type:      EventConfigUpdate,
		PoPID:     popID,
		Checksum:  checksum,
		Timestamp: time.Now().UTC(),
	})
}

// SubscriberCount returns the total active subscriber channels for a given popID.
func (b *Broadcaster) SubscriberCount(popID string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if subs, ok := b.subscribers[popID]; ok {
		return len(subs)
	}
	return 0
}

// TotalSubscribers returns the aggregate active subscribers across all PoPs.
func (b *Broadcaster) TotalSubscribers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	total := 0
	for _, subs := range b.subscribers {
		total += len(subs)
	}
	return total
}

// Close shuts down the broadcaster and closes all remaining subscriber channels.
func (b *Broadcaster) Close() {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.closed {
		return
	}
	b.closed = true

	for popID, subs := range b.subscribers {
		for ch := range subs {
			close(ch)
		}
		delete(b.subscribers, popID)
	}
}
