# Frontend Topology

Identrail uses `web/` as the active tracked frontend on `dev`.

## `web/` (product dashboard)

- Stack: Vite + React
- Purpose: operator-facing app experience tied to API workflows
- Typical runtime: containerized deployment (`deploy/docker/Dockerfile.web`, optional Helm `web.enabled`)
- API URL input: `VITE_IDENTRAIL_API_URL`
- Vercel (marketing/demo deploy): set `VITE_IDENTRAIL_API_URL` in Vercel project environment variables (or set GitHub Actions variable `VITE_IDENTRAIL_API_URL` so the deploy workflow upserts it).
- Production deploys should be triggered from `dev` (example: `make vercel-prod-deploy` / `task vercel-prod-deploy`) to avoid accidentally deploying from a stale local branch.

## `site/` (legacy Next.js marketing surface)

- Stack: Next.js
- Purpose: public marketing/documentation landing pages
- Typical runtime: Vercel-hosted static/dynamic site
- Not part of the core API/worker runtime path
- Not tracked in this branch snapshot; local leftovers can drift from API contract and should not be treated as source of truth.

## Operational Guidance

- Treat `web/` as product UI release surface coupled to API compatibility.
- Treat `site/` as legacy/branch-specific surface unless explicitly restored and reviewed.
- Validate both in CI where relevant, but keep deployment ownership boundaries explicit.
