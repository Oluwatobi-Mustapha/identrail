# Documentation Quality Checks

Use this checklist before merging documentation changes.

## Required Checks

1. Local links resolve correctly.
2. New docs are indexed in `docs/README.md`.
3. API behavior statements match current handlers/contracts.
4. Env var references match `internal/config/config.go` and `internal/config/security.go`.

## Link Integrity Check (local)

Run from repo root:

```bash
python3 - <<'PY'
import re
from pathlib import Path
root=Path('.').resolve()
paths=[root/'docs', root/'deploy', root/'site', root/'README.md']
files=[]
for p in paths:
    if p.is_file():
        files.append(p)
    elif p.is_dir():
        files.extend(x for x in p.rglob('*.md') if 'node_modules' not in x.parts and '.next' not in x.parts)
errors=[]
for f in files:
    txt=f.read_text(errors='ignore')
    for m in re.finditer(r'\[[^\]]+\]\(([^)]+)\)', txt):
        t=m.group(1).strip().split(None, 1)[0].strip('<>').split('#',1)[0]
        if not t or t.startswith(('http://','https://','mailto:','#')):
            continue
        if not (f.parent/t).resolve().exists():
            errors.append((f,t))
if errors:
    for f,t in errors:
        print(f"{f}: {t}")
    raise SystemExit(1)
print('OK: no broken local markdown links')
PY
```
