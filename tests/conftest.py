from __future__ import annotations

import pytest

from authdiff.core.canary import CanaryMint
from authdiff.core.models import Identity


@pytest.fixture()
def mint() -> CanaryMint:
    return CanaryMint()


@pytest.fixture()
def identities() -> list[Identity]:
    return [
        Identity("alice", tenant="a", headers={"Authorization": "Bearer A"}),
        Identity("bob", tenant="b", headers={"Authorization": "Bearer B"}),
    ]
