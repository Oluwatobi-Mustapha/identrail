package config

import (
	"os"
	"testing"
)

func TestLoadDefaults(t *testing.T) {
	t.Setenv("AURELIUS_HTTP_ADDR", "")
	t.Setenv("AURELIUS_LOG_LEVEL", "")
	t.Setenv("AURELIUS_PROVIDER", "")
	t.Setenv("AURELIUS_SERVICE_NAME", "")

	cfg := Load()
	if cfg.HTTPAddr != defaultHTTPAddr {
		t.Fatalf("expected default addr %q, got %q", defaultHTTPAddr, cfg.HTTPAddr)
	}
	if cfg.LogLevel != defaultLogLevel {
		t.Fatalf("expected default log level %q, got %q", defaultLogLevel, cfg.LogLevel)
	}
	if cfg.Provider != defaultProvider {
		t.Fatalf("expected default provider %q, got %q", defaultProvider, cfg.Provider)
	}
	if cfg.ServiceName != defaultServiceName {
		t.Fatalf("expected default service name %q, got %q", defaultServiceName, cfg.ServiceName)
	}
}

func TestLoadFromEnv(t *testing.T) {
	t.Setenv("AURELIUS_HTTP_ADDR", "127.0.0.1:9090")
	t.Setenv("AURELIUS_LOG_LEVEL", "DEBUG")
	t.Setenv("AURELIUS_PROVIDER", "AWS")
	t.Setenv("AURELIUS_SERVICE_NAME", "aurelius-dev")

	cfg := Load()
	if cfg.HTTPAddr != "127.0.0.1:9090" {
		t.Fatalf("unexpected addr: %q", cfg.HTTPAddr)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("unexpected log level: %q", cfg.LogLevel)
	}
	if cfg.Provider != "aws" {
		t.Fatalf("unexpected provider: %q", cfg.Provider)
	}
	if cfg.ServiceName != "aurelius-dev" {
		t.Fatalf("unexpected service name: %q", cfg.ServiceName)
	}
}

func TestGetEnvTrimmedFallback(t *testing.T) {
	key := "AURELIUS_TEST_ENV"
	_ = os.Unsetenv(key)

	if got := getEnv(key, "fallback"); got != "fallback" {
		t.Fatalf("expected fallback, got %q", got)
	}
	t.Setenv(key, "  actual  ")
	if got := getEnv(key, "fallback"); got != "actual" {
		t.Fatalf("expected trimmed value, got %q", got)
	}
}
