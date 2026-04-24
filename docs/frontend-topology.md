# Frontend Topology

Identrail currently has two frontend surfaces with different purposes.

## `web/` (product dashboard)

- Stack: Vite + React
- Purpose: operator-facing app experience tied to API workflows
- Typical runtime: containerized deployment (`deploy/docker/Dockerfile.web`, optional Helm `web.enabled`)
- API URL input: `VITE_IDENTRAIL_API_URL`

## `site/` (marketing site)

- Stack: Next.js
- Purpose: public marketing/documentation landing pages
- Typical runtime: Vercel-hosted static/dynamic site
- Not part of the core API/worker runtime path

## Operational Guidance

- Treat `web/` as product UI release surface coupled to API compatibility.
- Treat `site/` as marketing/content release surface with independent cadence.
- Validate both in CI where relevant, but keep deployment ownership boundaries explicit.
