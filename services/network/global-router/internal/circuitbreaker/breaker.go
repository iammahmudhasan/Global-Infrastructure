package circuitbreaker

import (
	"errors"
	"sync"
	"time"
)

type State string

const (
	StateClosed   State = "CLOSED"    // Normal healthy operation
	StateHalfOpen State = "HALF_OPEN" // Trial state: testing recovering upstream
	StateOpen     State = "OPEN"      // Tripped: fail fast without calling upstream
)

var (
	ErrCircuitOpen = errors.New("circuit breaker is open: upstream unhealthy")
)

// CircuitBreaker protects downstream callers from cascading failures (Rules 14, 15, 37)
type CircuitBreaker struct {
	mu            sync.RWMutex
	name          string
	state         State
	failureCount  int
	maxFailures   int
	resetTimeout  time.Duration
	lastStateTime time.Time
	trialInFlight bool
}

func New(name string, maxFailures int, resetTimeout time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		name:          name,
		state:         StateClosed,
		maxFailures:   maxFailures,
		resetTimeout:  resetTimeout,
		lastStateTime: time.Now(),
		trialInFlight: false,
	}
}

// Allow checks whether an outgoing request should proceed
func (cb *CircuitBreaker) Allow() error {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	now := time.Now()

	switch cb.state {
	case StateClosed:
		return nil
	case StateOpen:
		if now.Sub(cb.lastStateTime) > cb.resetTimeout {
			cb.state = StateHalfOpen
			cb.lastStateTime = now
			cb.trialInFlight = true
			return nil // Allow single trial probe upon entering half-open state
		}
		return ErrCircuitOpen
	case StateHalfOpen:
		if cb.trialInFlight {
			return ErrCircuitOpen // Reject concurrent requests during in-flight trial probe
		}
		cb.trialInFlight = true
		return nil
	default:
		return nil
	}
}

// RecordSuccess records a healthy upstream response
func (cb *CircuitBreaker) RecordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount = 0
	cb.trialInFlight = false
	if cb.state == StateHalfOpen {
		cb.state = StateClosed
		cb.lastStateTime = time.Now()
	}
}

// RecordFailure records a timeout or 5xx error
func (cb *CircuitBreaker) RecordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()

	cb.failureCount++
	cb.trialInFlight = false
	cb.lastStateTime = time.Now()

	if cb.state == StateHalfOpen || cb.failureCount >= cb.maxFailures {
		cb.state = StateOpen
	}
}

func (cb *CircuitBreaker) State() State {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.state
}

func (cb *CircuitBreaker) Failures() int {
	cb.mu.RLock()
	defer cb.mu.RUnlock()
	return cb.failureCount
}
