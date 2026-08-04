from __future__ import annotations

from authdiff.core.canary import CanaryMint, CanaryType
from authdiff.core.models import Confidence
from authdiff.core.oracles import (
    BflaOracle,
    BolaOracle,
    MassAssignmentOracle,
    RaceInvariantOracle,
    ReplayObservation,
)


def test_bola_proven(mint: CanaryMint) -> None:
    c = mint.mint("alice", CanaryType.TEXT)
    obs = ReplayObservation("bob", "alice", "GET", "/n", 200, f'{{"x":"{c.value}"}}')
    f = BolaOracle(mint).evaluate(obs)
    assert f and f.confidence is Confidence.PROVEN and f.victim_owner == "alice"


def test_bola_no_finding_when_forbidden(mint: CanaryMint) -> None:
    obs = ReplayObservation("bob", "alice", "GET", "/n", 403, '{"error":"no"}')
    assert BolaOracle(mint).evaluate(obs) is None


def test_bola_content_invariant_heuristic(mint: CanaryMint) -> None:
    body = '{"same":"payload"}'
    obs = ReplayObservation("bob", "alice", "GET", "/n", 200, body, baseline_body_text=body)
    f = BolaOracle(mint).evaluate(obs)
    assert f and f.confidence is Confidence.HEURISTIC


def test_bfla_heuristic() -> None:
    obs = ReplayObservation("bob", "alice", "DELETE", "/admin", 200, "")
    f = BflaOracle().evaluate(obs)
    assert f and f.kind == "BFLA"


def test_mass_assignment_proven(mint: CanaryMint) -> None:
    c = mint.mint("bob", CanaryType.TEXT)
    obs = ReplayObservation("bob", "bob", "PATCH", "/me", 200, f'{{"role":"{c.value}"}}')
    f = MassAssignmentOracle(mint).evaluate(obs)
    assert f and f.confidence is Confidence.PROVEN


def test_race_invariant() -> None:
    f = RaceInvariantOracle(1).evaluate_statuses("a", "/r", [200, 200, 409])
    assert f and "successes" in f.proof[0]
    assert RaceInvariantOracle(2).evaluate_statuses("a", "/r", [200, 200]) is None
