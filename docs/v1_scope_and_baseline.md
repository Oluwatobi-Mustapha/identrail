# V1 Scope And Baseline (First 5 Priorities)

This document locks the first five non-negotiable V1 priorities.

## 1) Scope Freeze

- Core path: AWS + Kubernetes discovery, normalization, graph, risk findings, API, dashboard.
- Optional module: GitHub repository exposure scanner (`repo-scan`) remains separate from core identity scan flow.
- Provider guardrail: startup validation accepts only `aws` or `kubernetes` for V1 runtime.

## 2) Standards Baseline

- Auth baseline: API key auth plus OIDC/OAuth2-compatible bearer auth (Keycloak-compatible issuer/audience model).
- Finding baseline: typed internal finding model enriched with control references.
- Export baseline:
  - OCSF-aligned payload export
  - AWS Security Finding Format (ASFF) export
- Compliance baseline: each finding type maps to CIS/NIST-style control references in evidence.

## 3) Reliability Hardening

- Idempotent persistence for scans, artifacts, findings, and repo findings.
- Single-flight locking for scan execution (`scan:<provider>`, `repo-scan:<target>`).
- AWS collector retries transient IAM failures with bounded exponential backoff and jitter.
- Partial-failure visibility through scan event stream and explicit failed/completed scan status transitions.

## 4) Data Contract Hardening

- Graph relationship contract is explicit and validated:
  - `can_assume`
  - `attached_policy`
  - `attached_to`
  - `bound_to`
  - `can_access`
  - `can_impersonate`
- Fixture-based contract tests verify normalized identities and relationship types for AWS and Kubernetes pipelines.

## 5) Risk Engine Productionization

- High-value rules in place:
  - admin-equivalent/overprivileged access
  - wildcard/broad trust
  - stale identities
  - ownerless identities
  - escalation paths
- Findings are typed, deterministic, and include evidence + remediation text.
- Evidence ordering is deterministic across reruns to keep diffing stable.
