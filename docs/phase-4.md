# Phase 4: Kubernetes Integration (Foundation)

## Goal

Add first Kubernetes support for identity/workload mapping and core risk detections.

## Implemented in this milestone

- Kubernetes fixture collector:
  - reads `ServiceAccount`, `RoleBinding`/`ClusterRoleBinding`, and `Pod` objects
  - supports file and directory fixture paths
  - deduplicates by stable source IDs
- Kubernetes normalizer:
  - maps service accounts to normalized identities
  - maps pods to workloads and links workloads to service account identities
  - maps role bindings into normalized policies with semantic statements
- Kubernetes permission resolver:
  - expands normalized statements into permission tuples
- Kubernetes graph resolver:
  - builds `bound_to`, `attached_policy`, and `can_access` relationships
- Kubernetes risk rules:
  - detects overprivileged service accounts
  - detects escalation paths from workload -> service account -> privileged access
  - detects ownerless service accounts
- Runtime and CLI wiring:
  - provider switch now supports `aws` and `kubernetes`
  - new config support: `IDENTRAIL_K8S_FIXTURES`

## User stories covered

- As a platform security engineer, I can scan Kubernetes fixture data and see risky service account privilege paths.
- As an IAM owner, I can identify ownerless service accounts that block accountability.
- As a responder, I can trace workload blast radius through bound identities and permissions.

## Next Kubernetes slices

1. Real Kubernetes API collector (read-only service account, role, role binding, pod fetchers).
2. Namespace-aware policy semantics (Role vs ClusterRole resolution by actual rules).
3. Additional rules (secret-read concentration, broad binding fanout, default SA abuse).
