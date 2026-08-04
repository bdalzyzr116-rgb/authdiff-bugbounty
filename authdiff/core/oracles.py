"""Deterministic oracles.

Each oracle turns a replay observation into an optional :class:`Finding`. The
canary-backed oracles are *proven* (0% false positive); the BFLA oracle is a
*heuristic* signal because an unexpected 2xx alone is not cryptographic proof.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Protocol

from authdiff.core.canary import CanaryMint
from authdiff.core.models import Confidence, Finding, Severity


@dataclass(frozen=True)
class ReplayObservation:
    """The result of replaying one request under one actor."""

    actor_id: str
    owner_id: str
    method: str
    url: str
    status_code: int
    body_text: str
    baseline_status: int | None = None
    baseline_body_text: str | None = None


class Oracle(Protocol):
    """A pluggable decision procedure over a :class:`ReplayObservation`."""

    name: str

    def evaluate(self, obs: ReplayObservation) -> Finding | None:  # pragma: no cover
        ...


class BolaOracle:
    """Proven BOLA/IDOR: a foreign canary appears in the actor's response.

    An optional content-hash / size invariant can additionally flag responses
    that are byte-identical to the owner's baseline even when the canary is not
    echoed verbatim (e.g. binary blobs) — reported as HEURISTIC.
    """

    name = "BOLA"

    def __init__(self, mint: CanaryMint, use_content_invariants: bool = True):
        self._mint = mint
        self._content = use_content_invariants

    def evaluate(self, obs: ReplayObservation) -> Finding | None:
        leaked = [(o, ev) for o, ev in self._mint.attribute_detailed(obs.body_text)
                  if o != obs.actor_id]
        if leaked:
            return Finding(
                kind="BOLA", severity=Severity.HIGH, confidence=Confidence.PROVEN,
                actor=obs.actor_id, victim_owner=sorted({o for o, _ in leaked})[0],
                method=obs.method, url=obs.url, status_code=obs.status_code,
                proof=[ev for _, ev in leaked], cvss=8.1,
            )
        if (self._content and obs.baseline_body_text is not None
                and 200 <= obs.status_code < 300 and obs.body_text
                and obs.body_text == obs.baseline_body_text):
            digest = hashlib.sha256(obs.body_text.encode()).hexdigest()[:16]
            return Finding(
                kind="BOLA", severity=Severity.MEDIUM, confidence=Confidence.HEURISTIC,
                actor=obs.actor_id, victim_owner=obs.owner_id, method=obs.method,
                url=obs.url, status_code=obs.status_code,
                proof=[f"actor response identical to owner baseline (sha256:{digest})"],
                cvss=6.5,
            )
        return None


class BflaOracle:
    """Heuristic BFLA: a lower-privilege actor gets a success on a privileged op."""

    name = "BFLA"

    def __init__(self, success_range: range = range(200, 400)):
        self._ok = success_range

    def evaluate(self, obs: ReplayObservation) -> Finding | None:
        if obs.status_code in self._ok:
            return Finding(
                kind="BFLA", severity=Severity.HIGH, confidence=Confidence.HEURISTIC,
                actor=obs.actor_id, victim_owner=obs.owner_id, method=obs.method,
                url=obs.url, status_code=obs.status_code,
                proof=[f"unexpected {obs.status_code} for unauthorized role on privileged endpoint"],
                cvss=8.2,
            )
        return None


class MassAssignmentOracle:
    """Proven mass-assignment: an actor-planted privileged canary persisted.

    Run this over a *re-read* of the object after a write attempt: if the
    privileged field now contains the actor's own canary, the write was accepted.
    """

    name = "MASS_ASSIGNMENT"

    def __init__(self, mint: CanaryMint):
        self._mint = mint

    def evaluate(self, obs: ReplayObservation) -> Finding | None:
        mine = [ev for o, ev in self._mint.attribute_detailed(obs.body_text)
                if o == obs.actor_id]
        if mine:
            return Finding(
                kind="MASS_ASSIGNMENT", severity=Severity.HIGH, confidence=Confidence.PROVEN,
                actor=obs.actor_id, victim_owner=obs.actor_id, method=obs.method,
                url=obs.url, status_code=obs.status_code,
                proof=[f"privileged field accepted actor-controlled canary: {mine[0]}"],
                cvss=8.0,
            )
        return None


class RaceInvariantOracle:
    """Proven limit-bypass: successful consumptions exceed the seeded capacity."""

    name = "RACE_LIMIT_BYPASS"

    def __init__(self, capacity: int):
        self._capacity = capacity

    def evaluate_statuses(self, actor_id: str, url: str, statuses: list[int]) -> Finding | None:
        successes = sum(1 for s in statuses if 200 <= s < 300)
        if successes > self._capacity:
            return Finding(
                kind="RACE_LIMIT_BYPASS", severity=Severity.HIGH, confidence=Confidence.PROVEN,
                actor=actor_id, victim_owner=actor_id, method="POST", url=url,
                status_code=200,
                proof=[f"{successes} successes > capacity {self._capacity} (invariant broken)"],
                evidence={"statuses": statuses}, cvss=7.5,
            )
        return None

    def evaluate(self, obs: ReplayObservation) -> Finding | None:  # Protocol shim
        return None
