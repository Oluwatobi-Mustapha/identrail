package worker

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func TestRunWithCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := config.Config{
		LogLevel:       "info",
		ServiceName:    "identrail-test",
		Provider:       "aws",
		ScanInterval:   10 * time.Millisecond,
		WorkerRunNow:   false,
		AWSFixturePath: []string{"testdata/aws/role_with_policies.json"},
	}

	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err != nil {
		t.Fatalf("expected nil error, got %v", err)
	}
}
