# Enterprise 5-Minute Quickstart

This quickstart gets Identrail running with enterprise-safe defaults for auth scope, tenant/workspace context, and decision audit logging.

## Prerequisites

- Docker + Docker Compose
- `curl` + `jq`

## 1. Configure Environment

```bash
cp deploy/docker/.env.example deploy/docker/.env
```

Edit `deploy/docker/.env` and set at minimum:

- `IDENTRAIL_API_KEYS` with strong unique keys
- `IDENTRAIL_WRITE_API_KEYS` with only write-authorized keys
- `IDENTRAIL_API_KEY_SCOPES` (recommended), for example:
  - `IDENTRAIL_API_KEY_SCOPES=reader-key:read;writer-key:read,write;admin-key:read,write,admin`
- `IDENTRAIL_AUDIT_LOG_FILE=/tmp/identrail-audit.jsonl`

Optional hardening:
- `IDENTRAIL_AUDIT_FORWARD_URL=https://audit.example.com/events`
- `IDENTRAIL_AUDIT_FORWARD_HMAC_SECRET=<strong-secret>`

## 2. Start the Stack

```bash
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env up -d --build
```

## 3. Health and Auth Smoke Checks

```bash
curl -sS http://localhost:8080/healthz
```

```bash
curl -sS "http://localhost:8080/v1/scans?limit=5" \
  -H "X-API-Key: reader-key" \
  -H "X-Identrail-Tenant-ID: tenant-a" \
  -H "X-Identrail-Workspace-ID: workspace-a" | jq .
```

## 4. Trigger and Verify a Scan

```bash
SCAN_ID=$(
  curl -sS -X POST "http://localhost:8080/v1/scans" \
    -H "X-API-Key: writer-key" \
    -H "X-Identrail-Tenant-ID: tenant-a" \
    -H "X-Identrail-Workspace-ID: workspace-a" \
  | jq -r '.scan.id'
)
echo "scan_id=${SCAN_ID}"
```

```bash
curl -sS "http://localhost:8080/v1/scans/${SCAN_ID}/events?limit=10" \
  -H "X-API-Key: reader-key" \
  -H "X-Identrail-Tenant-ID: tenant-a" \
  -H "X-Identrail-Workspace-ID: workspace-a" | jq .
```

## 5. Verify AuthZ Decision Explainability

```bash
curl -sS -X POST "http://localhost:8080/v1/authz/policies/simulate" \
  -H "Content-Type: application/json" \
  -H "X-API-Key: admin-key" \
  -H "X-Identrail-Tenant-ID: tenant-a" \
  -H "X-Identrail-Workspace-ID: workspace-a" \
  -d '{
    "subject": {"type":"subject","id":"user-1","roles":["admin"]},
    "action": "findings.read",
    "resource": {"type":"finding","id":"finding-1"},
    "context": {"request_path":"/v1/findings","request_method":"GET"}
  }' | jq '{decision, trace}'
```

Expected:
- `decision` contains `allowed`, `stage`, `reason`
- `trace` includes ordered stages from tenant isolation through default deny

## 6. Verify Decision Audit Log

```bash
docker exec identrail-api sh -lc 'tail -n 50 /tmp/identrail-audit.jsonl' \
  | jq -c 'select(.authz != null) | {method,path,status,authz}'
```

Confirm:
- authz decision block exists for protected routes
- no raw API key values in audit payload
- subject/resource IDs appear only as hashed identifiers (`*_id_hash`)

## 7. Clean Shutdown

```bash
docker compose -f deploy/docker/docker-compose.yml --env-file deploy/docker/.env down
```
