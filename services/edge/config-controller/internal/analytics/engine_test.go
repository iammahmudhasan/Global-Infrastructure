package analytics

import (
	"fmt"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-config-controller/internal/model"
)

func TestReservoirSampler_Percentiles(t *testing.T) {
	sampler := NewReservoirSampler(100)

	// Add sequential values 1..100
	for i := 1; i <= 100; i++ {
		sampler.Add(float64(i))
	}

	p := sampler.Percentiles()
	if p.Min != 1.0 {
		t.Fatalf("expected min 1.0, got %f", p.Min)
	}
	if p.Max != 100.0 {
		t.Fatalf("expected max 100.0, got %f", p.Max)
	}
	if p.P50 < 49.0 || p.P50 > 52.0 {
		t.Fatalf("expected p50 around 50.0, got %f", p.P50)
	}
	if p.P90 < 89.0 || p.P90 > 92.0 {
		t.Fatalf("expected p90 around 90.0, got %f", p.P90)
	}
	if p.P95 < 94.0 || p.P95 > 96.0 {
		t.Fatalf("expected p95 around 95.0, got %f", p.P95)
	}
	if p.P99 < 98.0 || p.P99 > 100.0 {
		t.Fatalf("expected p99 around 99.0, got %f", p.P99)
	}
	if p.Avg < 50.0 || p.Avg > 51.0 {
		t.Fatalf("expected avg around 50.5, got %f", p.Avg)
	}
}

func TestReservoirSampler_CapacityLimit(t *testing.T) {
	capacity := 50
	sampler := NewReservoirSampler(capacity)

	// Add 10,000 values
	for i := 1; i <= 10000; i++ {
		sampler.Add(float64(i))
	}

	sampler.mu.Lock()
	count := len(sampler.samples)
	sampler.mu.Unlock()

	if count != capacity {
		t.Fatalf("expected samples count bounded to %d, got %d", capacity, count)
	}

	p := sampler.Percentiles()
	if p.Max <= 0 {
		t.Fatalf("expected max to be positive, got %f", p.Max)
	}
}

func TestDomainAggregator_Metrics(t *testing.T) {
	domainID := "dom_metrics_test"
	agg := NewDomainAggregator(domainID)

	now := time.Now().UTC()

	// 1. 200 OK Cache Hit
	agg.Record(model.TelemetryEvent{
		DomainID:      domainID,
		RequestID:     "req_1",
		StatusCode:    200,
		LatencyMs:     12.5,
		BytesSent:     4000,
		BytesReceived: 500,
		CacheStatus:   "HIT",
		WAFAction:     "ALLOW",
		Timestamp:     now,
	})

	// 2. 200 OK Cache Miss
	agg.Record(model.TelemetryEvent{
		DomainID:      domainID,
		RequestID:     "req_2",
		StatusCode:    200,
		LatencyMs:     85.0,
		BytesSent:     8000,
		BytesReceived: 1000,
		CacheStatus:   "MISS",
		WAFAction:     "ALLOW",
		Timestamp:     now,
	})

	// 3. 403 Forbidden WAF Block
	agg.Record(model.TelemetryEvent{
		DomainID:      domainID,
		RequestID:     "req_3",
		StatusCode:    403,
		LatencyMs:     1.2,
		BytesSent:     300,
		BytesReceived: 200,
		CacheStatus:   "BYPASS",
		WAFAction:     "BLOCK",
		Timestamp:     now,
	})

	// 4. 502 Bad Gateway
	agg.Record(model.TelemetryEvent{
		DomainID:      domainID,
		RequestID:     "req_4",
		StatusCode:    502,
		LatencyMs:     250.0,
		BytesSent:     600,
		BytesReceived: 400,
		CacheStatus:   "BYPASS",
		WAFAction:     "ALLOW",
		Timestamp:     now,
	})

	summary := agg.Summary()

	if summary.TotalRequests != 4 {
		t.Fatalf("expected 4 total requests, got %d", summary.TotalRequests)
	}
	if summary.Status2xx != 2 {
		t.Fatalf("expected 2 2xx requests, got %d", summary.Status2xx)
	}
	if summary.Status4xx != 1 {
		t.Fatalf("expected 1 4xx requests, got %d", summary.Status4xx)
	}
	if summary.Status5xx != 1 {
		t.Fatalf("expected 1 5xx requests, got %d", summary.Status5xx)
	}
	if summary.ErrorRate != 0.50 { // 2 errors out of 4 requests = 50%
		t.Fatalf("expected error rate 0.50, got %f", summary.ErrorRate)
	}
	if summary.CacheHits != 1 || summary.CacheMisses != 1 {
		t.Fatalf("expected 1 hit and 1 miss, got %d hits %d misses", summary.CacheHits, summary.CacheMisses)
	}
	if summary.CacheHitRate != 0.50 { // 1 hit / (1 hit + 1 miss) = 50%
		t.Fatalf("expected cache hit rate 0.50, got %f", summary.CacheHitRate)
	}
	if summary.SecurityBlocked != 1 {
		t.Fatalf("expected 1 security block, got %d", summary.SecurityBlocked)
	}
	if summary.BytesSent != 12900 {
		t.Fatalf("expected 12900 bytes sent, got %d", summary.BytesSent)
	}
	if summary.BytesReceived != 2100 {
		t.Fatalf("expected 2100 bytes received, got %d", summary.BytesReceived)
	}
	if summary.Latency.Min != 1.2 || summary.Latency.Max != 250.0 {
		t.Fatalf("unexpected latency range: min %f, max %f", summary.Latency.Min, summary.Latency.Max)
	}
}

func TestEngine_TimeSeriesAndBilling(t *testing.T) {
	engine := NewEngine()
	domainID := "dom_billing_test"

	baseTime := time.Date(2026, 10, 7, 12, 0, 0, 0, time.UTC)

	// Ingest 100 events across 2 consecutive minutes
	var events []model.TelemetryEvent
	for i := 0; i < 60; i++ {
		events = append(events, model.TelemetryEvent{
			DomainID:      domainID,
			RequestID:     fmt.Sprintf("req_min1_%d", i),
			StatusCode:    200,
			LatencyMs:     20.0,
			BytesSent:     50000000, // 50 MB
			BytesReceived: 1000000,  // 1 MB
			CacheStatus:   "HIT",
			WAFAction:     "ALLOW",
			Timestamp:     baseTime.Add(time.Duration(i) * time.Second),
		})
	}

	for i := 0; i < 40; i++ {
		status := 200
		if i%10 == 0 {
			status = 500
		}
		events = append(events, model.TelemetryEvent{
			DomainID:      domainID,
			RequestID:     fmt.Sprintf("req_min2_%d", i),
			StatusCode:    status,
			LatencyMs:     40.0,
			BytesSent:     50000000, // 50 MB
			BytesReceived: 1000000,  // 1 MB
			CacheStatus:   "MISS",
			WAFAction:     "ALLOW",
			Timestamp:     baseTime.Add(time.Minute + time.Duration(i)*time.Second),
		})
	}

	count, err := engine.IngestBatch(events)
	if err != nil {
		t.Fatalf("failed to ingest batch: %v", err)
	}
	if count != 100 {
		t.Fatalf("expected 100 ingested, got %d", count)
	}

	// 1. Verify TimeSeries rollups
	timeSeries, err := engine.GetTimeSeries(domainID, 10)
	if err != nil {
		t.Fatalf("failed to get time series: %v", err)
	}
	if len(timeSeries) != 2 {
		t.Fatalf("expected 2 minute buckets, got %d", len(timeSeries))
	}
	if timeSeries[0].Requests != 60 {
		t.Fatalf("expected 60 requests in minute 0, got %d", timeSeries[0].Requests)
	}
	if timeSeries[1].Requests != 40 {
		t.Fatalf("expected 40 requests in minute 1, got %d", timeSeries[1].Requests)
	}
	if timeSeries[1].ErrorCount != 4 {
		t.Fatalf("expected 4 errors in minute 1, got %d", timeSeries[1].ErrorCount)
	}

	// 2. Verify Billing Usage
	usage, err := engine.GetBillingUsage(domainID, "2026-10")
	if err != nil {
		t.Fatalf("failed to get billing usage: %v", err)
	}
	if usage.TotalRequests != 100 {
		t.Fatalf("expected 100 requests, got %d", usage.TotalRequests)
	}
	// Total bytes sent = 100 * 50MB = 5,000,000,000 bytes = 5.0 GB
	if usage.EgressGB != 5.0 {
		t.Fatalf("expected 5.0 GB egress, got %f", usage.EgressGB)
	}
	// Bandwidth cost = 5.0 GB * $0.05 = $0.25
	if usage.BandwidthCostUSD != 0.25 {
		t.Fatalf("expected $0.25 bandwidth cost, got %f", usage.BandwidthCostUSD)
	}
	if usage.BaseFeeUSD != 20.00 {
		t.Fatalf("expected $20.00 base fee, got %f", usage.BaseFeeUSD)
	}
	// Total cost = $20.00 + $0.25 + requestCost (~0.0001) = $20.25
	if usage.TotalCostUSD != 20.25 {
		t.Fatalf("expected $20.25 total cost, got %f", usage.TotalCostUSD)
	}
}

func TestEngine_Validation(t *testing.T) {
	engine := NewEngine()

	// Missing domain ID in Ingest
	err := engine.Ingest(model.TelemetryEvent{})
	if err != ErrInvalidDomainID {
		t.Fatalf("expected ErrInvalidDomainID, got %v", err)
	}

	// Empty batch
	_, err = engine.IngestBatch(nil)
	if err != ErrEmptyTelemetry {
		t.Fatalf("expected ErrEmptyTelemetry, got %v", err)
	}

	// Unknown domain summary returns clean empty summary
	summary, err := engine.GetSummary("non_existent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if summary.TotalRequests != 0 {
		t.Fatalf("expected 0 requests, got %d", summary.TotalRequests)
	}

	// Reset
	engine.Reset("non_existent")
}

func TestEngine_MonthlyBillingIsolation(t *testing.T) {
	engine := NewEngine()
	domainID := "dom_monthly_isolation"

	septTime := time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)
	octTime := time.Date(2026, 10, 5, 14, 0, 0, 0, time.UTC)

	// Ingest September event: 50 requests, 2 GB egress
	for i := 0; i < 50; i++ {
		err := engine.Ingest(model.TelemetryEvent{
			DomainID:      domainID,
			RequestID:     fmt.Sprintf("req_sep_%d", i),
			StatusCode:    200,
			BytesSent:     40000000, // 40 MB * 50 = 2,000,000,000 bytes (2 GB)
			BytesReceived: 1000000,
			Timestamp:     septTime,
		})
		if err != nil {
			t.Fatalf("failed to ingest sept event: %v", err)
		}
	}

	// Ingest October event: 100 requests, 5 GB egress
	for i := 0; i < 100; i++ {
		err := engine.Ingest(model.TelemetryEvent{
			DomainID:      domainID,
			RequestID:     fmt.Sprintf("req_oct_%d", i),
			StatusCode:    200,
			BytesSent:     50000000, // 50 MB * 100 = 5,000,000,000 bytes (5 GB)
			BytesReceived: 1000000,
			Timestamp:     octTime,
		})
		if err != nil {
			t.Fatalf("failed to ingest oct event: %v", err)
		}
	}

	// 1. Verify September Billing (only September traffic)
	sepUsage, err := engine.GetBillingUsage(domainID, "2026-09")
	if err != nil {
		t.Fatalf("failed to get september usage: %v", err)
	}
	if sepUsage.TotalRequests != 50 {
		t.Errorf("expected 50 requests in Sep, got %d", sepUsage.TotalRequests)
	}
	if sepUsage.EgressGB != 2.0 {
		t.Errorf("expected 2.0 GB in Sep, got %f", sepUsage.EgressGB)
	}
	if sepUsage.BandwidthCostUSD != 0.10 {
		t.Errorf("expected $0.10 bandwidth in Sep, got %f", sepUsage.BandwidthCostUSD)
	}
	if sepUsage.TotalCostUSD != 20.10 {
		t.Errorf("expected $20.10 total cost in Sep, got %f", sepUsage.TotalCostUSD)
	}

	// 2. Verify October Billing (only October traffic)
	octUsage, err := engine.GetBillingUsage(domainID, "2026-10")
	if err != nil {
		t.Fatalf("failed to get october usage: %v", err)
	}
	if octUsage.TotalRequests != 100 {
		t.Errorf("expected 100 requests in Oct, got %d", octUsage.TotalRequests)
	}
	if octUsage.EgressGB != 5.0 {
		t.Errorf("expected 5.0 GB in Oct, got %f", octUsage.EgressGB)
	}
	if octUsage.BandwidthCostUSD != 0.25 {
		t.Errorf("expected $0.25 bandwidth in Oct, got %f", octUsage.BandwidthCostUSD)
	}
	if octUsage.TotalCostUSD != 20.25 {
		t.Errorf("expected $20.25 total cost in Oct, got %f", octUsage.TotalCostUSD)
	}

	// 3. Verify November Billing (zero traffic, base fee only)
	novUsage, err := engine.GetBillingUsage(domainID, "2026-11")
	if err != nil {
		t.Fatalf("failed to get november usage: %v", err)
	}
	if novUsage.TotalRequests != 0 {
		t.Errorf("expected 0 requests in Nov, got %d", novUsage.TotalRequests)
	}
	if novUsage.EgressGB != 0.0 {
		t.Errorf("expected 0.0 GB in Nov, got %f", novUsage.EgressGB)
	}
	if novUsage.TotalCostUSD != 20.00 {
		t.Errorf("expected $20.00 base fee only in Nov, got %f", novUsage.TotalCostUSD)
	}
}
