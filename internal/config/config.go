package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultHTTPAddr     = ":8080"
	defaultLogLevel     = "info"
	defaultProvider     = "aws"
	defaultServiceName  = "identrail"
	defaultAWSFixtures  = "testdata/aws/role_with_policies.json,testdata/aws/role_with_urlencoded_trust.json"
	defaultScanInterval = 15 * time.Minute
)

// Config centralizes process-level configuration. It keeps module wiring simple
// and deterministic for API, worker, and CLI binaries.
type Config struct {
	HTTPAddr       string
	LogLevel       string
	Provider       string
	ServiceName    string
	DatabaseURL    string
	AWSFixturePath []string
	ScanInterval   time.Duration
	WorkerRunNow   bool
}

// Load reads environment variables and applies safe defaults for local and CI use.
func Load() Config {
	return Config{
		HTTPAddr:       getEnv("IDENTRAIL_HTTP_ADDR", defaultHTTPAddr),
		LogLevel:       strings.ToLower(getEnv("IDENTRAIL_LOG_LEVEL", defaultLogLevel)),
		Provider:       strings.ToLower(getEnv("IDENTRAIL_PROVIDER", defaultProvider)),
		ServiceName:    getEnv("IDENTRAIL_SERVICE_NAME", defaultServiceName),
		DatabaseURL:    getEnv("IDENTRAIL_DATABASE_URL", ""),
		AWSFixturePath: parseCommaSeparated(getEnv("IDENTRAIL_AWS_FIXTURES", defaultAWSFixtures)),
		ScanInterval:   parseDuration(getEnv("IDENTRAIL_SCAN_INTERVAL", defaultScanInterval.String()), defaultScanInterval),
		WorkerRunNow:   parseBool(getEnv("IDENTRAIL_WORKER_RUN_NOW", "true"), true),
	}
}

func getEnv(key, fallback string) string {
	value := strings.TrimSpace(os.Getenv(key))
	if value == "" {
		return fallback
	}
	return value
}

func parseCommaSeparated(value string) []string {
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, part := range parts {
		trimmed := strings.TrimSpace(part)
		if trimmed == "" {
			continue
		}
		result = append(result, trimmed)
	}
	return result
}

func parseDuration(value string, fallback time.Duration) time.Duration {
	parsed, err := time.ParseDuration(strings.TrimSpace(value))
	if err != nil || parsed <= 0 {
		return fallback
	}
	return parsed
}

func parseBool(value string, fallback bool) bool {
	parsed, err := strconv.ParseBool(strings.TrimSpace(value))
	if err != nil {
		return fallback
	}
	return parsed
}
