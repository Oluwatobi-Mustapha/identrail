# identrail-reviewer Operations Runbook

## SLO targets

- PR review latency p95: <= 90 seconds for typical PR size.
- High-severity precision (P0/P1): >= 95% on replay benchmark.
- False-positive rate overall: <= 8%.

## Incident response

1. Detection: identify spike in workflow failures, bad comments, or merge blocks.
2. Containment: set rollout phase to `advisory` in `.github/identrail-reviewer/rollout.v1.json`.
3. Verification: replay benchmark cases and compare recent audit artifacts.
4. Recovery: patch rules/policy and restore previous phase only after validation.

## Change management

- Policy and rollout changes must be reviewed via pull request.
- Every rollout phase change should include a rationale in PR description.
- Weekly report artifacts should be inspected for trend breaks.
