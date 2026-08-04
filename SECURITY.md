# Security Policy

## Intended use

AuthDiff is for **authorized** security testing and education only: systems you
own, or targets covered by an explicit bug-bounty scope or written engagement.
Misuse against systems you are not permitted to test may be illegal.

Built-in safeguards:

- `--authorized` is required for every network command.
- Non-destructive by default; writes require `--allow-writes`.
- Scope Governor v2 (host + CIDR allowlist, DNS pinning) blocks out-of-scope egress.
- Kill-switch via file (`kill_switch_file`) or `AUTHDIFF_KILL=1`.
- Secrets are read from environment variables and redacted from logs.

## Reporting a vulnerability

Please report security issues in AuthDiff itself privately via GitHub Security
Advisories on the repository rather than opening a public issue. We aim to
acknowledge within 72 hours.

## Handling of secrets

Never commit tokens or HAR files containing credentials. Config supports
`${ENV_VAR}` interpolation so secrets stay in the environment. The default
`.gitignore` excludes `.authdiff_state.json`, `*.har`, and `config.*`.
