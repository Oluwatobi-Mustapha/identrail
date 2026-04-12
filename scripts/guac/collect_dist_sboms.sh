#!/usr/bin/env bash
set -euo pipefail

ARTIFACT_DIR="${1:-dist}"

if ! command -v guacone >/dev/null 2>&1; then
  echo "ERROR: guacone is required on PATH" >&2
  exit 1
fi

if [[ ! -d "${ARTIFACT_DIR}" ]]; then
  echo "ERROR: artifact directory not found: ${ARTIFACT_DIR}" >&2
  exit 1
fi

if ! find "${ARTIFACT_DIR}" -maxdepth 1 -type f -name '*.sbom.cdx.json' | grep -q .; then
  echo "ERROR: no CycloneDX SBOM artifacts (*.sbom.cdx.json) found in ${ARTIFACT_DIR}" >&2
  exit 1
fi

echo "Ingesting SBOM artifacts from ${ARTIFACT_DIR} into GUAC"
guacone collect --add-vuln-on-ingest --add-license-on-ingest files "${ARTIFACT_DIR}"
