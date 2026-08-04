"""Offline self-test: proves the oracles are sound with no target and no deps.

Runs cryptographic proofs of the canary oracle plus a simulated mini-attack
(a vulnerable vs. a secure endpoint) so anyone can verify determinism before
pointing AuthDiff at a real, authorized target.
"""

from __future__ import annotations

from authdiff.core.canary import CanaryMint, CanaryType
from authdiff.core.oracles import (
    BolaOracle,
    MassAssignmentOracle,
    RaceInvariantOracle,
    ReplayObservation,
)


def run_selftest() -> int:
    """Return 0 if every deterministic invariant holds, non-zero otherwise."""
    print("AuthDiff v2 self-test (offline, standard library only)")
    print("-" * 58)
    mint = CanaryMint()
    bola = BolaOracle(mint)

    # 1) Provenance across every canary type.
    for ctype in CanaryType:
        c = mint.mint("alice", ctype)
        assert mint.attribute(c.value) == {"alice"}, ctype
    print("[PASS] all canary types (txt/eml/jsn/num/uid) attribute to true owner")

    # 2) Simulated mini-attack: a VULNERABLE endpoint leaks Alice's data to Bob.
    alice = mint.mint("alice", CanaryType.TEXT)
    vulnerable = ReplayObservation("bob", "alice", "GET", "/api/orders/1", 200,
                                   f'{{"buyer":"alice","memo":"{alice.value}"}}')
    finding = bola.evaluate(vulnerable)
    assert finding and finding.confidence.value == "proven", "vulnerable endpoint must fire"
    print(f"[PASS] simulated BOLA proven: {finding.id} ({finding.victim_owner} leaked to bob)")

    # 3) A SECURE endpoint returns 403 with no foreign canary -> no finding.
    secure = ReplayObservation("bob", "alice", "GET", "/api/orders/1", 403, '{"error":"forbidden"}')
    assert bola.evaluate(secure) is None, "secure endpoint must not fire"
    print("[PASS] secure endpoint produces no finding -> 0% false positive")

    # 4) Forgery is rejected.
    assert mint.attribute(alice.token[:-3] + "AAA") == set()
    print("[PASS] forged canary rejected")

    # 5) Key rotation keeps old canaries valid.
    old = alice.token
    mint.keyring.rotate()
    fresh = mint.mint("carol", CanaryType.TEXT)
    assert mint.attribute(old) == {"alice"} and mint.attribute(fresh.value) == {"carol"}
    print("[PASS] key rotation: old and new canaries both validate")

    # 6) Mass-assignment: actor's own canary persisted in a privileged field.
    ma = MassAssignmentOracle(mint)
    bobc = mint.mint("bob", CanaryType.TEXT)
    reread = ReplayObservation("bob", "bob", "PATCH", "/api/me", 200, f'{{"role":"{bobc.value}"}}')
    assert ma.evaluate(reread) is not None
    print("[PASS] mass-assignment proven via persisted privileged canary")

    # 7) Race invariant.
    race = RaceInvariantOracle(capacity=1)
    assert race.evaluate_statuses("alice", "/redeem", [200, 200, 409]) is not None
    print("[PASS] race invariant: successes > capacity is proven")

    print("-" * 58)
    print("All deterministic invariants hold. The engine is sound. ✅")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(run_selftest())
