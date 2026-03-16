# sqlcdb

This directory is reserved for sqlc-generated query code.

Generation command:

```bash
cd sqlc
sqlc generate
```

Current Postgres store read paths now call typed wrappers in this package, aligned with `sqlc/queries`.
The next iteration will replace wrappers with generated methods directly.
