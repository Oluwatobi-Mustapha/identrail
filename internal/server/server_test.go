package server

import (
	"context"
	"os"
	"testing"

	"github.com/Oluwatobi-Mustapha/identrail/internal/config"
)

func TestNewBootstrap(t *testing.T) {
	cfg := config.Config{HTTPAddr: ":0", LogLevel: "info", Provider: "aws", ServiceName: "identrail-test"}
	bootstrap, err := NewBootstrap(context.Background(), cfg)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if bootstrap.Logger == nil || bootstrap.Metrics == nil || bootstrap.Router == nil || bootstrap.TraceShutdown == nil {
		t.Fatal("bootstrap dependencies must all be initialized")
	}
}

func TestNewHTTPServer(t *testing.T) {
	cfg := config.Config{HTTPAddr: ":9999"}
	srv := NewHTTPServer(cfg, nil)
	if srv.Addr != ":9999" {
		t.Fatalf("unexpected addr: %q", srv.Addr)
	}
	if srv.ReadTimeout <= 0 || srv.WriteTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Fatal("timeouts must be set")
	}
}

func TestRunCancelledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	cfg := config.Config{HTTPAddr: ":0", LogLevel: "info", Provider: "aws", ServiceName: "identrail-test"}
	sigCh := make(chan os.Signal, 1)
	if err := Run(ctx, cfg, sigCh); err != nil {
		t.Fatalf("expected clean shutdown, got err: %v", err)
	}
}
