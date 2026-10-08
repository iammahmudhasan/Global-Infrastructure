package api

import (
	"errors"
	"sync"
	"time"
)

var (
	ErrRateLimitExceeded        = errors.New("control plane rate limit exceeded for expensive operation")
	ErrConcurrencyLimitExceeded = errors.New("control plane concurrency limit exceeded for expensive operation")
)

type clientBucket struct {
	tokens   float64
	lastSeen time.Time
}

// ControlPlaneLimiter bounds concurrent and per-client request rates for expensive operations (P2 Control Plane Rate Limiting)
type ControlPlaneLimiter struct {
	mu              sync.Mutex
	ratePerSec      float64
	burst           float64
	maxConcurrent   int
	currentInFlight int
	clients         map[string]*clientBucket
	cleanupTimer    time.Time
}

func NewControlPlaneLimiter(ratePerSec float64, burst int, maxConcurrent int) *ControlPlaneLimiter {
	if ratePerSec <= 0 {
		ratePerSec = 100.0 // Default 100 req/sec
	}
	if burst <= 0 {
		burst = 100
	}
	if maxConcurrent <= 0 {
		maxConcurrent = 50
	}
	return &ControlPlaneLimiter{
		ratePerSec:    ratePerSec,
		burst:         float64(burst),
		maxConcurrent: maxConcurrent,
		clients:       make(map[string]*clientBucket),
		cleanupTimer:  time.Now(),
	}
}

// Acquire attempts to reserve capacity for an expensive operation.
// Returns a release callback function if successful, or an error if rate or concurrency limit is exceeded.
func (l *ControlPlaneLimiter) Acquire(clientKey string) (func(), error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()

	// Periodic cleanup of stale client buckets (older than 10 minutes)
	if now.Sub(l.cleanupTimer) > 5*time.Minute {
		l.cleanupTimer = now
		for k, b := range l.clients {
			if now.Sub(b.lastSeen) > 10*time.Minute {
				delete(l.clients, k)
			}
		}
	}

	// 1. Concurrency Check
	if l.currentInFlight >= l.maxConcurrent {
		return nil, ErrConcurrencyLimitExceeded
	}

	// 2. Token Bucket Rate Check
	bucket, exists := l.clients[clientKey]
	if !exists {
		bucket = &clientBucket{
			tokens:   l.burst,
			lastSeen: now,
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

	if bucket.tokens < 1.0 {
		return nil, ErrRateLimitExceeded
	}

	bucket.tokens -= 1.0
	l.currentInFlight++

	var once sync.Once
	release := func() {
		once.Do(func() {
			l.mu.Lock()
			if l.currentInFlight > 0 {
				l.currentInFlight--
			}
			l.mu.Unlock()
		})
	}

	return release, nil
}
