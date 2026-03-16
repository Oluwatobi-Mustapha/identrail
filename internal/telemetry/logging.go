package telemetry

import "go.uber.org/zap"

// NewLogger returns a production-safe structured logger.
func NewLogger(level string) (*zap.Logger, error) {
	cfg := zap.NewProductionConfig()
	if err := cfg.Level.UnmarshalText([]byte(level)); err != nil {
		cfg.Level.SetLevel(zap.InfoLevel)
	}
	return cfg.Build()
}

// ZapError centralizes error field formatting.
func ZapError(err error) zap.Field {
	return zap.Error(err)
}

// String aliases zap.String for cleaner call sites outside telemetry package.
func String(key, val string) zap.Field {
	return zap.String(key, val)
}
