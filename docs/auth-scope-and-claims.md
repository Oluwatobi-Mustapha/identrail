# Auth Scope and Claims Mapping

This guide defines how tenant/workspace scope is derived and how OIDC claims map into authorization context.

## Scope Resolution Order

For each request, scope context is resolved in this order:

1. Verified token claims (`tenant`, `workspace` mapped claims)
2. Scope headers (`X-Identrail-Tenant-ID`, `X-Identrail-Workspace-ID`)
3. Runtime defaults (`IDENTRAIL_DEFAULT_TENANT_ID`, `IDENTRAIL_DEFAULT_WORKSPACE_ID`)

## OIDC Claim Mapping

Claim names are configurable:

- `IDENTRAIL_OIDC_TENANT_CLAIM` (default `tenant_id`)
- `IDENTRAIL_OIDC_WORKSPACE_CLAIM` (default `workspace_id`)
- `IDENTRAIL_OIDC_GROUPS_CLAIM` (default `groups`)
- `IDENTRAIL_OIDC_ROLES_CLAIM` (default `roles`)

Issuer/audience controls:

- `IDENTRAIL_OIDC_ISSUER_URL`
- `IDENTRAIL_OIDC_AUDIENCE`

## Write Authorization

Write access is enforced by scope policy for both API keys and OIDC bearer tokens.

- API keys: scoped keys (`write`/`admin`) or legacy write-key config
- OIDC: write scopes configured via `IDENTRAIL_OIDC_WRITE_SCOPES`

## Operator Checks

- verify claim names match your IdP token shape
- verify headers are only trusted from approved proxy paths
- verify defaults are explicit and valid for your tenant/workspace topology
