# Week 1 Foundation Plan

This phase establishes the operational foundation for `identrail-reviewer`.

## Scope

- Reviewer contract and schema (`.github/identrail-reviewer/finding.schema.json`).
- Reviewer policy baseline (`.github/identrail-reviewer/reviewer-config.yml`).
- Shadow mode context collection workflow (`.github/workflows/identrail-reviewer-shadow.yml`).
- Ground-truth benchmark data scaffolding (`data/identrail-reviewer/benchmark`).

## Why this phase exists

Without a strict contract and historical benchmark, reviewer quality cannot be measured
reliably. Shadow mode lets us inspect behavior before any blocking policy is enabled.

## Acceptance Criteria

- Shadow workflow captures pull request and issue context as artifacts.
- Output schema is defined and versioned.
- Confidence thresholds and abstain policy are defined.
- Benchmark folder exists with a documented record format.
