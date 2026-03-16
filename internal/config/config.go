package config

import (
	"os"
	"strings"
)

const (
	defaultHTTPAddr    = ":8080"
	defaultLogLevel    = "info"
	defaultProvider    = "aws"
	defaultServiceName = "identrail"
)

// Config centralizes process-level configuration. It keeps module wiring simple
// and deterministic for API, worker, and CLI binaries.
type Config struct {
	HTTPAddr    string
	LogLevel    string
	Provider    string
	ServiceName string
}

// Load reads environment variables and applies safe defaults for local and CI use.
func Load() Config {
	return Config{
		HTTPAddr:    getEnv("IDENTRAIL_HTTP_ADDR", defaultHTTPAddr),
		LogLevel:    strings.ToLower(getEnv("IDENTRAIL_LOG_LEVEL", defaultLogLevel)),
		Provider:    strings.ToLower(getEnv("IDENTRAIL_PROVIDER", defaultProvider)),
		ServiceName: getEnv("IDENTRAIL_SERVICE_NAME", defaultServiceName),
	}
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}
