# identrail-reviewer benchmark

Place replay cases in this directory using one JSON file per case.

## Suggested naming

- `pr-<number>.json`
- `issue-<number>.json`

## Minimal PR case shape

```json
{
  "type": "pr_review_case",
  "id": "pr-123",
  "source_url": "https://github.com/Oluwatobi-Mustapha/identrail/pull/123",
  "captured_at": "2026-04-04T00:00:00Z",
  "expected": [
    {
      "severity": "P1",
      "file": ".github/workflows/release.yml",
      "line": 210,
      "summary": "Hardcoded production placeholder URL in release image build",
      "disposition": "true_positive"
    }
  ],
  "notes": "Validated by maintainer after merge"
}
```
