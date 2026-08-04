# Architecture

AuthDiff is a small set of composable layers:

- **core/** — dependency-free deterministic primitives: `CanaryMint`/`KeyRing`,
  the `Finding`/`Identity`/`ObservedRequest` models, and the oracles.
- **safety/** — `ScopeGovernor` gates every egress (host+CIDR allowlist, DNS
  pinning, rate limiting, non-destructive default, kill-switch).
- **network/** — async pooled `AsyncHttpClient` (HTTP/2, 429 back-off) and the
  `SinglePacketRacer`.
- **inputs/** — HAR, OpenAPI, Postman parsers with auto-detection.
- **engine/** — the differential replay matrix, the async runner, and the
  oracle plugin system.
- **outputs/** — JSON-lines, SARIF, JUnit, HTML, webhooks.
- **cli/** — Typer entry point with CI-friendly exit codes.

## The differential model

Authorization correctness is expressed as invariants that must always hold:

```
I1  Horizontal (BOLA/IDOR):     Reach(i) ∩ Priv(j) = ∅        for all i ≠ j
I2  Vertical  (BFLA):           privileged capability c ∉ Cap(i)   for unauthorized i
I3  Property  (BOPLA):          WritableFields(i,E) ⊆ IntendedFields(E)
```

A finding is emitted **iff** a canary or numeric witness breaks an invariant.
Soundness comes from HMAC unforgeability; completeness (over the observed
surface) comes from exhaustively replaying every object reference across the
identity matrix.
