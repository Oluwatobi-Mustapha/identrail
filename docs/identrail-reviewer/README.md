# identrail-reviewer

`identrail-reviewer` is the repository-native PR and issue reviewer for Identrail.

It is optimized for high-precision review in this codebase using:
- deterministic policy checks first
- evidence-based findings with confidence scoring
- abstain behavior when confidence is too low
- a continuously evaluated benchmark and replay dataset

## Delivery Tracks

- Week 1: foundation, contracts, context capture, benchmark scaffolding.
- Week 2: judgment engine with deterministic review logic and structured findings.
- Week 3: enterprise hardening (security, reliability, auditability, policy governance).
- Week 4: controlled rollout, enforcement gates, quality operations, runbooks.

## Core Design Principles

- Precision over volume: avoid noisy comments.
- Explainability: every finding must include evidence and rationale.
- Safety: low-confidence paths should abstain.
- Measurability: quality and latency are continuously tracked.
