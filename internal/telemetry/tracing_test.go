package telemetry

import (
	"context"
	"testing"
)

func TestSetupTracing(t *testing.T) {
	shutdown, err := SetupTracing(context.Background(), "identrail")
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if shutdown == nil {
		t.Fatal("shutdown func must not be nil")
	}
	if err := shutdown(context.Background()); err != nil {
		t.Fatalf("unexpected shutdown err: %v", err)
	}
}
