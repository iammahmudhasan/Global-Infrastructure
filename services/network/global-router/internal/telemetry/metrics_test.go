package telemetry_test

import (
	"strings"
	"testing"
	"time"

	"github.com/iammahmudhasan/nexusedge-control-plane/internal/telemetry"
)

func TestMetricsCollectorPrometheusExport(t *testing.T) {
	collector := telemetry.GlobalMetrics

	collector.RecordDispatch("BD", "on-prem-dhaka", 5*time.Millisecond, true)
	collector.RecordDispatch("US", "coreweave", 110*time.Millisecond, true)
	collector.RecordDispatch("EU", "gcp", 140*time.Millisecond, false)

	prom := collector.ExportPrometheus()

	if !strings.Contains(prom, "nexusedge_router_requests_total") {
		t.Errorf("expected prometheus to export total requests")
	}

	if !strings.Contains(prom, "nexusedge_router_dispatches_success_total") {
		t.Errorf("expected prometheus to export successful dispatches")
	}

	if !strings.Contains(prom, "nexusedge_router_dispatches_failed_total") {
		t.Errorf("expected prometheus to export failed dispatches")
	}

	if !strings.Contains(prom, `jurisdiction="BD"`) {
		t.Errorf("expected prometheus to export BD jurisdiction metric")
	}
}
