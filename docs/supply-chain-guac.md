# GUAC Integration Scaffold

Identrail already generates signed supply-chain artifacts (SBOM + provenance) in CI. This guide adds a practical path to ingest those artifacts into GUAC for graph-based analysis.

## Prerequisites

- `guacgql` running (in-memory or postgres-backed deployment)
- `guacone` installed and available on `PATH`
- `dist/` artifact directory from the `supply-chain-trust` workflow

## Ingest SBOM Artifacts

Use the helper script:

```bash
scripts/guac/collect_dist_sboms.sh dist
```

This runs `guacone collect ... files <dir>` to ingest CycloneDX SBOM files into GUAC.

## Enrich Vulnerability Data (Optional)

After ingestion, run:

```bash
guacone certifier osv
```

This augments ingested packages with OSV vulnerability relationships.

## Suggested Next Step

Attach this ingestion step to your artifact promotion pipeline so release candidates continuously populate the security graph.
