package telemetry

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestNewMetricsCountersAndHistogram(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("metrics must not be nil")
	}

	m.ScanRunsTotal.Add(1)
	m.FindingsGenerated.Add(2)
	m.ScanDurationMS.Observe(250)

	if got := testutil.ToFloat64(m.ScanRunsTotal); got != 1 {
		t.Fatalf("expected scan runs 1, got %v", got)
	}
	if got := testutil.ToFloat64(m.FindingsGenerated); got != 2 {
		t.Fatalf("expected findings generated 2, got %v", got)
	}
}
