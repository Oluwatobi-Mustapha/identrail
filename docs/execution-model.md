# Execution Model

This document defines how scans are triggered, executed, and serialized.

## Cloud Identity Scans

1. Client calls `POST /v1/scans`.
2. API enqueues a scan record.
3. Worker queue runner claims queued jobs.
4. Worker executes scan pipeline and persists artifacts/findings.
5. Scan lifecycle/events are updated through completion.

API behavior:
- `202` when accepted into queue.
- `429` when queue limit is reached.

## Repository Scans

1. Client calls `POST /v1/repo-scans`.
2. API validates request and enqueues repo-scan record.
3. Worker claims and executes repo scan.
4. Repo findings and scan lifecycle records are persisted.

API behavior:
- `202` accepted
- `400` invalid request
- `403` target outside allowlist
- `409` target already in progress
- `429` queue full
- `503` repo scan disabled

## Locks and Concurrency

- Cloud lock key: `scan:<provider>`
- Repo lock key: `repo-scan:<target>`
- Lock backend: `inmemory` or `postgres` (`auto` picks postgres in DB mode)

## Queue and Worker Controls

- `IDENTRAIL_SCAN_QUEUE_MAX_PENDING`
- `IDENTRAIL_REPO_SCAN_QUEUE_MAX_PENDING`
- `IDENTRAIL_WORKER_API_JOB_QUEUE_ENABLED`
- `IDENTRAIL_WORKER_API_JOB_QUEUE_INTERVAL`
- `IDENTRAIL_WORKER_API_JOB_QUEUE_BATCH_SIZE`

## Operational Implications

- API trigger latency and scan completion latency are decoupled.
- If worker is down, queue depth rises until limit.
- Queue tuning and worker health are required for stable execution throughput.
