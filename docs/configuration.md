# Configuration reference

AuthDiff loads YAML, JSON, or TOML. Secrets use `${ENV_VAR}` interpolation.

## `scope`

| Key | Type | Default | Meaning |
|-----|------|---------|---------|
| `allow_hosts` | list[str] | `[]` | Host globs (e.g. `*.target.com`) |
| `allow_cidrs` | list[str] | `[]` | IP/CIDR allowlist (DNS pinned once resolved) |
| `rate_per_sec` | float | `5` | Token-bucket refill rate |
| `burst` | int | `5` | Bucket capacity |
| `max_concurrency` | int | `8` | Global in-flight cap |
| `allow_writes` | bool | `false` | Permit POST/PUT/PATCH/DELETE |
| `kill_switch_file` | str | `null` | Abort if this file exists |

## `identities` (≥ 2 required)

```yaml
identities:
  - id: alice
    tenant: t1
    role: user
    headers: { Authorization: "Bearer ${ALICE_TOKEN}" }
    cookies: {}
```

## `observed`

Inline requests (`owner`, `method`, `url`, optional `headers`, `body`). You can
also ingest captures with `--input alice=alice.har` (HAR/OpenAPI/Postman).

## `seed` (optional)

Templated write that plants a canary into each identity's own field. `{canary}`
and `{owner}` placeholders are substituted per identity.

## `race` (optional)

`n`, `seeded_capacity`, and a `request` block for single-packet confirmation.

## Exit codes

`0` none · `1` findings · `2` config error · `3` scope/safety violation.
