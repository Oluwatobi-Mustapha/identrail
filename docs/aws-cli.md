# AWS CLI UX (Phase 1)

## Commands

- `identrail scan`
- `identrail findings`

## What `scan` does

`scan` executes the full AWS phase-1 pipeline:

1. collect raw IAM role assets (fixture-backed collector)
2. normalize identities and policies
3. resolve permissions and graph relationships
4. evaluate typed risk findings
5. print findings summary and save local state

## Default Fixture Mode

By default, `scan` uses local fixtures in `testdata/aws/` for deterministic development and testing.

You can override fixture paths:

```bash
identrail scan --fixture testdata/aws/role_with_policies.json --fixture testdata/aws/role_with_urlencoded_trust.json
```

You can also pass a directory of JSON fixtures:

```bash
identrail scan --fixture testdata/aws
```

## Output

- `--output table` (default): human-friendly summary
- `--output json`: machine-friendly result payload

## Local State

After scan, findings are saved locally (default):

- `.identrail/last-findings.json`

`findings` reads this file:

```bash
identrail findings
identrail findings --output json
```

Override state location with `--state-file`.

## Notes

- Phase 1 supports AWS only.
- Phase 1 CLI uses fixture-backed ingestion by design; live AWS API adapter wiring is a follow-on hardening step.
