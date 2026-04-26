#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || true)"
if [[ -z "${ROOT_DIR}" ]]; then
  echo "ERROR: must run from inside the identrail git repository"
  exit 1
fi

cd "${ROOT_DIR}"

if ! command -v gh >/dev/null 2>&1; then
  echo "ERROR: GitHub CLI (gh) is required"
  exit 1
fi

# Production deploys must always come from the dev branch on GitHub, not from the
# operator's local working tree (which may be stale).
gh workflow run .github/workflows/vercel-production-deploy.yml --ref dev

echo "Triggered Vercel production deploy for ref=dev."
echo "Follow progress: gh run list --workflow .github/workflows/vercel-production-deploy.yml -L 5"
