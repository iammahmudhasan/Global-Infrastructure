package api

import (
	"errors"
	"sync"
	"time"
)

const (
	// MaxTrackedClients bounds active client buckets in memory to prevent exhaustion (P2 Finding 5)
	MaxTrackedClients = 10000

	// DefaultMaxClientConcurrent limits expensive operations per client for tenant fairness (P2 Finding 4)
	DefaultMaxClientConcurrent = 10
)

var (
	ErrRateLimitExceeded              = errors.New("control plane rate limit exceeded for expensive operation")
	ErrConcurrencyLimitExceeded       = errors.New("control plane global concurrency limit exceeded for expensive operation")
	ErrClientConcurrencyLimitExceeded = errors.New("control plane per-client concurrency limit exceeded for expensive operation")
)

type clientBucket struct {
	tokens   float64
	lastSeen time.Time
	inFlight int
}

// ControlPlaneLimiter bounds concurrent and per-client request rates for expensive operations (P2 Control Plane Rate Limiting)
type ControlPlaneLimiter struct {
	mu                  sync.Mutex
	ratePerSec          float64
	burst               float64
	maxConcurrent       int
	maxClientConcurrent int
	currentInFlight     int
	clients             map[string]*clientBucket
	cleanupTimer        time.Time
}

func NewControlPlaneLimiter(ratePerSec float64, burst int, maxConcurrent int) *ControlPlaneLimiter {
	return NewControlPlaneLimiterWithClientConcurrency(ratePerSec, burst, maxConcurrent, DefaultMaxClientConcurrent)
}

func NewControlPlaneLimiterWithClientConcurrency(ratePerSec float64, burst int, maxConcurrent int, maxClientConcurrent int) *ControlPlaneLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 100.0 // Default 100 req/sec
	}
	if burst <= 0 {
		burst = 100
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 200
	}
	if maxClientConcurrent <= 0 {
		maxClientConcurrent = DefaultMaxClientConcurrent
	}
	return &ControlPlaneLimiter{
		ratePerSec:          ratePerSec,
		burst:               float64(burst),
		maxConcurrent:       maxConcurrent,
		maxClientConcurrent: maxClientConcurrent,
		clients:             make(map[string]*clientBucket),
		cleanupTimer:        time.Now(),
	}
}

// Acquire attempts to reserve capacity for an expensive operation.
// Returns a release callback function if successful, or an error if rate or concurrency limit is exceeded.
func (l *ControlPlaneLimiter) Acquire(clientKey string) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Periodic cleanup of stale client buckets (older than 10 minutes with 0 in-flight)
	if now.Sub(l.cleanupTimer) > 5*time.Minute {
		l.cleanupTimer = now
		for k, b := range l.clients {
			if b.inFlight == 0 && now.Sub(b.lastSeen) > 10*time.Minute {
				delete(l.clients, k)
			}
		}
	}

	// 1. Global Concurrency Check
	if l.currentInFlight >= l.maxConcurrent {
		return nil, ErrConcurrencyLimitExceeded
	}

	// 2. Client Bucket Lookup and Eviction Bound (Finding 5)
	bucket, exists := l.clients[clientKey]
	if !exists {
		if len(l.clients) >= MaxTrackedClients {
			// Find stalest client bucket with 0 in-flight requests to evict
			var oldestKey string
			var oldestTime time.Time
			for k, b := range l.clients {
				if b.inFlight == 0 && (oldestKey == "" || b.lastSeen.Before(oldestTime)) {
					oldestKey = k
					oldestTime = b.lastSeen
				}
			}
			if oldestKey != "" {
				delete(l.clients, oldestKey)
			} else {
				return nil, ErrConcurrencyLimitExceeded
			}
		}

		bucket = &clientBucket{
			tokens:   l.burst,
			lastSeen: now,
			inFlight: 0,
		}
		l.clients[clientKey] = bucket
	} else {
		elapsed := now.Sub(bucket.lastSeen).Seconds()
		bucket.lastSeen = now
		bucket.tokens += elapsed * l.ratePerSec
		if bucket.tokens > l.burst {
			bucket.tokens = l.burst
		}
	}

	// 3. Per-Client Concurrency Isolation Check (Finding 4)
	if bucket.inFlight >= l.maxClientConcurrent {
		return nil, ErrClientConcurrencyLimitExceeded
	}

	// 4. Token Bucket Rate Check
	if bucket.tokens < 1.0 {
		return nil, ErrRateLimitExceeded
	}

	bucket.tokens -= 1.0
	bucket.inFlight++
	l.currentInFlight++

	var once sync.Once
	release := func() {
		once.Do(func() {
			l.mu.Lock()
			if l.currentInFlight > 0 {
				l.currentInFlight--
			}
			if bucket.inFlight > 0 {
				bucket.inFlight--
			}
			l.mu.Unlock()
		})
	}

	return release, nil
}
