package analytics

import (
	"errors"
	"math"
	"math/rand"
	"sort"
	"sync"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

var (
	ErrDomainNotFound  = errors.New("domain not found in analytics store")
	ErrEmptyTelemetry  = errors.New("telemetry event cannot be empty")
	ErrInvalidDomainID = errors.New("domain_id is required")
)

const (
	defaultReservoirCapacity = 2048
	bytesPerGigabyte         = 1000000000.0 // 10^9 decimal GB for transit/billing standard
	pricePerEgressGBUSD      = 0.05         // $0.05 per GB
	pricePerMillionReqUSD    = 0.75         // $0.75 per 1,000,000 requests
	baseDomainMonthlyFeeUSD  = 20.00        // $20 base tier fee
	timeSeriesRetention      = 30 * 24 * time.Hour
	pruneInterval            = 5 * time.Minute
)

// ReservoirSampler maintains a bounded, statistically representative sample of latency measurements
type ReservoirSampler struct {
	mu       sync.Mutex
	capacity int
	count    int64
	samples  []float64
	rng      *rand.Rand
}

func NewReservoirSampler(capacity int) *ReservoirSampler {
	if capacity <= 0 {
		capacity = defaultReservoirCapacity
	}
	return &ReservoirSampler{
		capacity: capacity,
		samples:  make([]float64, 0, capacity),
		rng:      rand.New(rand.NewSource(time.Now().UnixNano())),
	}
}

func (s *ReservoirSampler) Add(val float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.count++
	if len(s.samples) < s.capacity {
		s.samples = append(s.samples, val)
		return
	}

	// Algorithm R: pick a random index between 0 and count-1
	j := s.rng.Int63n(s.count)
	if j < int64(s.capacity) {
		s.samples[j] = val
	}
}

func (s *ReservoirSampler) Percentiles() model.LatencyPercentiles {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.samples) == 0 {
		return model.LatencyPercentiles{}
	}

	sorted := make([]float64, len(s.samples))
	copy(sorted, s.samples)
	sort.Float64s(sorted)

	n := len(sorted)
	var sum float64
	for _, v := range sorted {
		sum += v
	}

	p50Idx := int(math.Round(float64(n-1) * 0.50))
	p90Idx := int(math.Round(float64(n-1) * 0.90))
	p95Idx := int(math.Round(float64(n-1) * 0.95))
	p99Idx := int(math.Round(float64(n-1) * 0.99))

	return model.LatencyPercentiles{
		P50: roundDecimals(sorted[p50Idx], 2),
		P90: roundDecimals(sorted[p90Idx], 2),
		P95: roundDecimals(sorted[p95Idx], 2),
		P99: roundDecimals(sorted[p99Idx], 2),
		Min: roundDecimals(sorted[0], 2),
		Max: roundDecimals(sorted[n-1], 2),
		Avg: roundDecimals(sum/float64(n), 2),
	}
}

type MonthlyUsageCounter struct {
	TotalRequests int64
	BytesSent     int64
	BytesReceived int64
}

type DomainAggregator struct {
	mu              sync.RWMutex
	domainID        string
	totalRequests   int64
	status2xx       int64
	status3xx       int64
	status4xx       int64
	status5xx       int64
	cacheHits       int64
	cacheMisses     int64
	bytesSent       int64
	bytesReceived   int64
	securityBlocked int64
	sampler         *ReservoirSampler
	timeSeriesMap   map[int64]*model.TimeSeriesPoint // Unix minute timestamp -> aggregate
	monthlyUsage    map[string]*MonthlyUsageCounter  // YYYY-MM -> monthly usage counter
	lastPrunedAt    time.Time
	lastUpdated     time.Time
}

func NewDomainAggregator(domainID string) *DomainAggregator {
	return &DomainAggregator{
		domainID:      domainID,
		sampler:       NewReservoirSampler(defaultReservoirCapacity),
		timeSeriesMap: make(map[int64]*model.TimeSeriesPoint),
		monthlyUsage:  make(map[string]*MonthlyUsageCounter),
		lastUpdated:   time.Now().UTC(),
	}
}

func (da *DomainAggregator) Record(event model.TelemetryEvent) {
	da.mu.Lock()
	defer da.mu.Unlock()

	da.totalRequests++
	da.bytesSent += event.BytesSent
	da.bytesReceived += event.BytesReceived
	da.lastUpdated = time.Now().UTC()

	eventTime := event.Timestamp
	if eventTime.IsZero() {
		eventTime = time.Now().UTC()
	}
	monthKey := eventTime.Format("2006-01")
	monthCounter, exists := da.monthlyUsage[monthKey]
	if !exists {
		monthCounter = &MonthlyUsageCounter{}
		da.monthlyUsage[monthKey] = monthCounter
	}
	monthCounter.TotalRequests++
	monthCounter.BytesSent += event.BytesSent
	monthCounter.BytesReceived += event.BytesReceived

	// Status code distribution
	switch {
	case event.StatusCode >= 200 && event.StatusCode < 300:
		da.status2xx++
	case event.StatusCode >= 300 && event.StatusCode < 400:
		da.status3xx++
	case event.StatusCode >= 400 && event.StatusCode < 500:
		da.status4xx++
	case event.StatusCode >= 500:
		da.status5xx++
	}

	// Cache status
	switch event.CacheStatus {
	case "HIT":
		da.cacheHits++
	case "MISS":
		da.cacheMisses++
	}

	// Security action
	if event.WAFAction == "BLOCK" {
		da.securityBlocked++
	}

	// Latency sample
	if event.LatencyMs >= 0 {
		da.sampler.Add(event.LatencyMs)
	}

	// Time-series rollups: bucket into 1-minute window
	minuteKey := eventTime.Truncate(time.Minute).Unix()

	point, exists := da.timeSeriesMap[minuteKey]
	if !exists {
		point = &model.TimeSeriesPoint{
			Timestamp: time.Unix(minuteKey, 0).UTC(),
		}
		da.timeSeriesMap[minuteKey] = point
	}

	point.Requests++
	point.BytesSent += event.BytesSent
	point.BytesReceived += event.BytesReceived
	if event.StatusCode >= 400 {
		point.ErrorCount++
	}
	// Incremental average latency for this window
	point.AvgLatencyMs = ((point.AvgLatencyMs * float64(point.Requests-1)) + event.LatencyMs) / float64(point.Requests)
	point.AvgLatencyMs = roundDecimals(point.AvgLatencyMs, 2)

	// Periodic time-series retention pruning: limit memory growth to 30 days (Finding 5)
	if da.lastPrunedAt.IsZero() || eventTime.Sub(da.lastPrunedAt) >= pruneInterval {
		cutoff := eventTime.Add(-timeSeriesRetention).Truncate(time.Minute).Unix()
		for ts := range da.timeSeriesMap {
			if ts < cutoff {
				delete(da.timeSeriesMap, ts)
			}
		}
		da.lastPrunedAt = eventTime
	}
}

func (da *DomainAggregator) Summary() model.AnalyticsSummary {
	da.mu.RLock()
	defer da.mu.RUnlock()

	var errorRate float64
	var cacheHitRate float64

	if da.totalRequests > 0 {
		errorCount := da.status4xx + da.status5xx
		errorRate = roundDecimals(float64(errorCount)/float64(da.totalRequests), 4)

		totalCacheable := da.cacheHits + da.cacheMisses
		if totalCacheable > 0 {
			cacheHitRate = roundDecimals(float64(da.cacheHits)/float64(totalCacheable), 4)
		}
	}

	return model.AnalyticsSummary{
		DomainID:        da.domainID,
		TotalRequests:   da.totalRequests,
		Status2xx:       da.status2xx,
		Status3xx:       da.status3xx,
		Status4xx:       da.status4xx,
		Status5xx:       da.status5xx,
		ErrorRate:       errorRate,
		CacheHitRate:    cacheHitRate,
		CacheHits:       da.cacheHits,
		CacheMisses:     da.cacheMisses,
		BytesSent:       da.bytesSent,
		BytesReceived:   da.bytesReceived,
		SecurityBlocked: da.securityBlocked,
		Latency:         da.sampler.Percentiles(),
		LastUpdated:     da.lastUpdated,
	}
}

func (da *DomainAggregator) TimeSeries(limit int) []model.TimeSeriesPoint {
	da.mu.RLock()
	defer da.mu.RUnlock()

	points := make([]model.TimeSeriesPoint, 0, len(da.timeSeriesMap))
	for _, p := range da.timeSeriesMap {
		points = append(points, *p)
	}

	sort.Slice(points, func(i, j int) bool {
		return points[i].Timestamp.Before(points[j].Timestamp)
	})

	if limit > 0 && len(points) > limit {
		points = points[len(points)-limit:]
	}

	return points
}

func (da *DomainAggregator) BillingUsage(period string) model.BillingUsage {
	da.mu.RLock()
	defer da.mu.RUnlock()

	if period == "" {
		period = time.Now().UTC().Format("2006-01")
	}

	var reqCount int64
	var bytesSent int64
	var bytesReceived int64

	if counter, exists := da.monthlyUsage[period]; exists {
		reqCount = counter.TotalRequests
		bytesSent = counter.BytesSent
		bytesReceived = counter.BytesReceived
	}

	egressGB := roundDecimals(float64(bytesSent)/bytesPerGigabyte, 4)
	ingressGB := roundDecimals(float64(bytesReceived)/bytesPerGigabyte, 4)

	bandwidthCost := roundDecimals(egressGB*pricePerEgressGBUSD, 2)
	requestCost := roundDecimals((float64(reqCount)/1000000.0)*pricePerMillionReqUSD, 4)
	totalCost := roundDecimals(baseDomainMonthlyFeeUSD+bandwidthCost+requestCost, 2)

	return model.BillingUsage{
		DomainID:         da.domainID,
		BillingPeriod:    period,
		TotalRequests:    reqCount,
		EgressGB:         egressGB,
		IngressGB:        ingressGB,
		BaseFeeUSD:       baseDomainMonthlyFeeUSD,
		BandwidthCostUSD: bandwidthCost,
		RequestCostUSD:   requestCost,
		TotalCostUSD:     totalCost,
		GeneratedAt:      time.Now().UTC(),
	}
}

// Engine coordinates real-time traffic observability, percentiles, and usage billing across all domains
type Engine struct {
	mu      sync.RWMutex
	domains map[string]*DomainAggregator
}

func NewEngine() *Engine {
	return &Engine{
		domains: make(map[string]*DomainAggregator),
	}
}

func (e *Engine) Ingest(event model.TelemetryEvent) error {
	if event.DomainID == "" {
		return ErrInvalidDomainID
	}

	agg := e.getOrCreateAggregator(event.DomainID)
	agg.Record(event)
	return nil
}

func (e *Engine) IngestBatch(events []model.TelemetryEvent) (int, error) {
	if len(events) == 0 {
		return 0, ErrEmptyTelemetry
	}

	count := 0
	for _, event := range events {
		if err := e.Ingest(event); err == nil {
			count++
		}
	}
	return count, nil
}

func (e *Engine) GetSummary(domainID string) (*model.AnalyticsSummary, error) {
	if domainID == "" {
		return nil, ErrInvalidDomainID
	}

	e.mu.RLock()
	agg, exists := e.domains[domainID]
	e.mu.RUnlock()

	if !exists {
		empty := model.AnalyticsSummary{
			DomainID:    domainID,
			LastUpdated: time.Now().UTC(),
		}
		return &empty, nil
	}

	summary := agg.Summary()
	return &summary, nil
}

func (e *Engine) GetTimeSeries(domainID string, limit int) ([]model.TimeSeriesPoint, error) {
	if domainID == "" {
		return nil, ErrInvalidDomainID
	}

	e.mu.RLock()
	agg, exists := e.domains[domainID]
	e.mu.RUnlock()

	if !exists {
		return []model.TimeSeriesPoint{}, nil
	}

	return agg.TimeSeries(limit), nil
}

func (e *Engine) GetBillingUsage(domainID string, period string) (*model.BillingUsage, error) {
	if domainID == "" {
		return nil, ErrInvalidDomainID
	}

	e.mu.RLock()
	agg, exists := e.domains[domainID]
	e.mu.RUnlock()

	if !exists {
		if period == "" {
			period = time.Now().UTC().Format("2006-01")
		}
		empty := model.BillingUsage{
			DomainID:         domainID,
			BillingPeriod:    period,
			BaseFeeUSD:       baseDomainMonthlyFeeUSD,
			BandwidthCostUSD: 0,
			RequestCostUSD:   0,
			TotalCostUSD:     baseDomainMonthlyFeeUSD,
			GeneratedAt:      time.Now().UTC(),
		}
		return &empty, nil
	}

	usage := agg.BillingUsage(period)
	return &usage, nil
}

func (e *Engine) Reset(domainID string) {
	e.mu.Lock()
	delete(e.domains, domainID)
	e.mu.Unlock()
}

func (e *Engine) getOrCreateAggregator(domainID string) *DomainAggregator {
	e.mu.Lock()
	defer e.mu.Unlock()

	agg, exists := e.domains[domainID]
	if !exists {
		agg = NewDomainAggregator(domainID)
		e.domains[domainID] = agg
	}
	return agg
}

func roundDecimals(val float64, places int) float64 {
	shift := math.Pow(10, float64(places))
	return math.Round(val*shift) / shift
}
