"""Differential replay-matrix construction.

The matrix is the Cartesian product of every object-referencing request with
every *other* identity (plus the anonymous actor). This is what makes AuthDiff
complete over the observed surface.
"""

from __future__ import annotations

from dataclasses import dataclass

from authdiff.core.models import Identity, ObservedRequest, RequestTag


@dataclass(frozen=True)
class ReplayTask:
    """A single (request, actor) cell of the differential matrix."""

    request: ObservedRequest
    actor: Identity | None  # None == anonymous


def build_matrix(observed: list[ObservedRequest], identities: list[Identity], *,
                 include_anonymous: bool = True,
                 object_refs_only: bool = True) -> list[ReplayTask]:
    """Build the cross-identity replay matrix from observed traffic."""
    tasks: list[ReplayTask] = []
    seen: set[tuple[str, str]] = set()
    for req in observed:
        if object_refs_only and RequestTag.OBJECT_REF not in req.tags:
            continue
        dedup_key = req.fingerprint()
        for actor in identities:
            if actor.id == req.owner.id:
                continue
            key = (dedup_key, actor.id)
            if key in seen:
                continue
            seen.add(key)
            tasks.append(ReplayTask(req, actor))
        if include_anonymous:
            key = (dedup_key, "<anonymous>")
            if key not in seen:
                seen.add(key)
                tasks.append(ReplayTask(req, None))
    return tasks
