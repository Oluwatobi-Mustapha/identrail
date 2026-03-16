# Aurelius

Aurelius is a production-grade machine identity security platform for discovering, mapping, analyzing, and securing workload identities across AWS, Kubernetes, and Azure.

Inspired by Marcus Aurelius' stoic governance, Aurelius emphasizes disciplined visibility, principled least privilege, and calm control under pressure.

## Vision

Build the "iPhone of machine identity security": simple, intuitive, and elegant without sacrificing rigor.

## Current Status

This repository now includes the Phase 1 foundation:

- Modular monolith skeleton in Go
- Typed domain model for identities, workloads, relationships, findings, and scans
- Provider abstraction interfaces for AWS/Kubernetes/Azure extensibility
- REST server entrypoint (`cmd/server`) with health and metrics
- CLI entrypoint (`cmd/cli`) with initial `scan` and `findings` commands
- Observability hooks: Zap logging, Prometheus metrics, tracing setup
- Unit tests for core foundation packages

## Project Layout

```text
/cmd
  /server
  /cli
/internal
  /app
  /config
  /domain
  /providers
  /api
  /telemetry
/migrations
/web
/deploy
/docs
/testdata
```

## Quick Start

```bash
go mod tidy
go test ./... -cover

go run ./cmd/server
# in a second terminal:
# curl localhost:8080/healthz

# CLI
# go run ./cmd/cli scan
# go run ./cmd/cli findings
```

## Documentation

- `docs/architecture.md`
- `docs/phase-1.md`
- `docs/testing.md`
