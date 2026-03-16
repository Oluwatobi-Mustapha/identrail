package telemetry

import (
	"errors"
	"testing"
)

func TestNewLoggerFallsBackOnInvalidLevel(t *testing.T) {
	logger, err := NewLogger("not-a-real-level")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if logger == nil {
		t.Fatal("logger must not be nil")
	}
	_ = logger.Sync()
}

func TestZapFieldHelpers(t *testing.T) {
	if f := String("k", "v"); f.Key != "k" {
		t.Fatalf("unexpected string key: %q", f.Key)
	}
	if f := ZapError(errors.New("boom")); f.Key != "error" {
		t.Fatalf("unexpected error key: %q", f.Key)
	}
}
