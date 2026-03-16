package telemetry

import (
	"context"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/trace"
)

// SetupTracing wires a no-op tracer provider for now.
// This keeps instrumentation API-stable while allowing exporter rollout later.
func SetupTracing(_ context.Context, _ string) (func(context.Context) error, error) {
	otel.SetTracerProvider(trace.NewNoopTracerProvider())
	return func(context.Context) error { return nil }, nil
}
