from __future__ import annotations

from authdiff.core.models import Identity, ObservedRequest, RequestTag
from authdiff.engine.matrix import build_matrix

A = Identity("alice")
B = Identity("bob")


def _req(owner, url):
    return ObservedRequest(owner, "GET", url, tags=frozenset({RequestTag.READ, RequestTag.OBJECT_REF}))


def test_matrix_cross_identity_plus_anon() -> None:
    obs = [_req(A, "https://x/api/orders/1")]
    tasks = build_matrix(obs, [A, B])
    actors = {t.actor.id if t.actor else "<anon>" for t in tasks}
    assert actors == {"bob", "<anon>"}  # never replays as owner


def test_matrix_skips_non_object_refs() -> None:
    plain = ObservedRequest(A, "GET", "https://x/api/health", tags=frozenset({RequestTag.READ}))
    assert build_matrix([plain], [A, B]) == []
