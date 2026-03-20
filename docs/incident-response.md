# Incident Response Workflow

Use this flow for high-severity identity findings.

## 1) Triage

1. Confirm finding severity and evidence.
2. Confirm affected identity/workload scope.
3. Check if the finding is new or persisted using scan diff.

## 2) Containment

1. For wildcard/admin paths, reduce permissions or trust policy immediately.
2. For ownerless identities, assign temporary owner and freeze new changes.
3. For stale identities, disable or quarantine when safe.

## 3) Verification

1. Trigger a new scan.
2. Confirm finding resolved in `/v1/scans/{scan_id}/diff`.
3. Confirm no new critical regressions appeared.

## 4) Post-Incident

1. Record root cause and remediation in ticket.
2. Add missing preventive guardrails (policy, rule, alert, or runbook update).
3. Update threat model/ADR if architecture or trust assumptions changed.
