# Ground Truth Dataset Guide

The benchmark dataset under `data/identrail-reviewer/benchmark` is used for replay-based
precision/recall and false-positive measurement.

## Record types

- `pr_review_case`: a pull request snapshot with expected findings.
- `issue_triage_case`: an issue snapshot with expected classification and severity.

## Required fields

Each case should include:
- `id`: stable identifier
- `source_url`: PR or issue URL
- `captured_at`: ISO 8601 timestamp
- `expected`: array of expected outcomes
- `notes`: maintainer annotation explaining decisions

## Quality rules

- Keep expected outcomes tied to exact file and line where possible.
- Mark uncertain historical decisions explicitly.
- Do not include generated secrets or private data.
