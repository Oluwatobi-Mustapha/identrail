# Versioning and Support Policy

This document defines how Identrail versions releases, how long releases are supported,
and how deprecations are announced and removed.

## Scope

This policy applies to:
- Identrail server/API binaries
- Worker binaries
- CLI binaries
- Official container images published by the project
- Public API contracts documented under `docs/`

## Versioning Model

Identrail uses [Semantic Versioning](https://semver.org/) (`MAJOR.MINOR.PATCH`).

- `MAJOR`: breaking changes to behavior, public APIs, or operational contracts.
- `MINOR`: backward-compatible features and non-breaking enhancements.
- `PATCH`: backward-compatible bug fixes and security fixes.

### Breaking Change Rules

A change is considered breaking if it requires operator or client changes to keep existing
workloads functioning. Breaking changes include:
- Removing or renaming API fields/endpoints without compatibility fallback.
- Changing default security behavior in a way that requires configuration migration.
- Removing documented flags, config keys, or environment variables.

Breaking changes must ship only in a major release, except for emergency security actions
where immediate mitigation is required.

## Support Windows

Identrail follows a two-track support window.

- `Active Support`:
  - Latest minor of the current major version.
  - Receives feature updates, bug fixes, and security fixes.
- `Maintenance Support`:
  - Latest minor of the previous major version.
  - Receives security fixes and critical bug fixes only.
- `End of Support`:
  - No further fixes or backports.

When a new major version is released, the previous major remains in Maintenance Support for
6 months after the new major GA date.

## Deprecation Policy

Deprecations must be announced before removal.

- Minimum notice period: **the longer of 90 days or 2 minor releases**.
- Deprecations are announced in:
  - `CHANGELOG.md`
  - GitHub release notes
  - Relevant docs under `docs/`
- Deprecated behavior should continue to work during the notice period unless a critical
  security issue requires accelerated removal.

Removals should happen in the next major release after the notice period. If a removal must
happen sooner for security reasons, the release notes must include clear migration guidance.

## Backport Policy

- Security fixes are backported to Active and Maintenance support lines when feasible.
- Critical stability fixes may be backported to Maintenance at maintainer discretion.
- Feature work is not backported to Maintenance lines.

## Supported Versions Table

This table is updated as majors are released.

| Version line | Status | Support level |
| --- | --- | --- |
| `v1` | Active | Features, bug fixes, security fixes |

## Policy Updates

Policy updates are proposed by pull request and announced in release notes when materially
impacting users or contributors.
