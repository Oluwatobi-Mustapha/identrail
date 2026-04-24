# CLI UX

## Commands

- `identrail scan`
- `identrail findings`
- `identrail repo-scan`
- `identrail authz rollback`

## What `scan` does

`scan` executes the provider pipeline:

1. collect raw assets
2. normalize identities and policies
3. resolve permissions and relationships
4. evaluate typed risk findings
5. print summary and optionally persist local state

Provider behavior is selected by `IDENTRAIL_PROVIDER`:
- `aws`
- `kubernetes`

Default fixture paths are provider-aware and can be overridden with `--fixture`.

## Output

- `--output table` (default)
- `--output json`

## Local State

By default, `scan` writes findings state to `.identrail/last-findings.json`.

`findings` reads this file:

```bash
identrail findings
identrail findings --output json
```

Use `--state-file` to override location.

## Repository Exposure Scan

```bash
identrail repo-scan --repo owner/repo
identrail repo-scan --repo https://github.com/owner/repo.git
identrail repo-scan --repo /path/to/local/repo
```

Useful flags:
- `--history-limit`
- `--max-findings`
- `--output table|json`

## AuthZ Rollback

```bash
identrail authz rollback \
  --api-url http://127.0.0.1:8080 \
  --api-key "$IDENTRAIL_API_KEY" \
  --tenant-id default \
  --workspace-id default \
  --policy-set-id central_authorization \
  --target-version 1
```

`--api-url` defaults from `IDENTRAIL_API_URL` (or `http://127.0.0.1:8080`).
