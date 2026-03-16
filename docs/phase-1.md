# Phase 1: AWS Core Scanner

## Goal

Deliver a usable AWS scanner that collects IAM identity data, normalizes relationships, and produces typed findings for overprivilege, escalation paths, risky trust relationships, staleness, and missing ownership.

## User Stories

- As a cloud security engineer, I can run a scan and get a list of risky identities.
- As an IAM admin, I can understand why a finding exists and how to remediate it.
- As a DevSecOps engineer, I can re-run scans safely without corrupting historical data.

## Scope

- AWS collector for IAM roles, policies, and trust relationships
- Normalized domain mapping
- Graph edge construction (`can_assume`, `attached_policy`, `bound_to`)
- Deterministic risk rules for core identity risks
- CLI commands for `scan` and `findings`

## Out of Scope (Phase 1)

- Automated remediation
- SIEM integrations
- Multi-tenant RBAC
- AI-generated recommendations

## Incremental Milestones

1. Foundation (this step): skeleton, interfaces, telemetry, CLI/API entrypoints
2. AWS Collector: IAM role + policy retrieval with pagination and retries
3. Normalizer + Graph: semantic permission expansion and edge materialization
4. Risk Engine: first rule set with evidence-rich findings
5. CLI UX pass: friendly summaries and actionable remediation output

## Phase Diagram

```text
[AWS IAM APIs] --> [Collector] --> [Normalizer] --> [Graph] --> [Risk Rules] --> [Findings Output]
```
