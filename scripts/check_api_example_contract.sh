#!/usr/bin/env bash
set -euo pipefail

# Validate tracked docs/frontend snippets against the v1 API contract.
readonly bad_patterns=(
  '/v1/scans/execute'
  '/v1/repo-scan/jobs'
  '/v1/repo-scans/jobs'
  '/v1/findings?severity=high,critical&status=open'
)

fail=0
for pattern in "${bad_patterns[@]}"; do
  if git grep -n -- "${pattern}" -- docs web >/tmp/api-contract-check.out 2>/dev/null; then
    echo "Found stale API example pattern: ${pattern}"
    cat /tmp/api-contract-check.out
    fail=1
  fi
done

rm -f /tmp/api-contract-check.out

if [[ "${fail}" -ne 0 ]]; then
  cat <<'EOF'
Expected canonical examples:
- POST /v1/scans
- GET /v1/findings?severity=high&lifecycle_status=open
- POST /v1/repo-scans
EOF
  exit 1
fi

echo "API example contract check passed."
