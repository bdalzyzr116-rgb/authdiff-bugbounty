from __future__ import annotations

import pytest

from authdiff.core.canary import CanaryMint, CanaryType, KeyRing


@pytest.mark.parametrize("ctype", list(CanaryType))
def test_attribute_roundtrip(mint: CanaryMint, ctype: CanaryType) -> None:
    c = mint.mint("alice", ctype)
    assert mint.attribute(c.value) == {"alice"}


def test_forged_token_rejected(mint: CanaryMint) -> None:
    c = mint.mint("alice")
    assert mint.attribute(c.token[:-3] + "AAA") == set()


def test_owner_reading_own_canary_is_not_foreign(mint: CanaryMint) -> None:
    c = mint.mint("alice")
    leaked = {o for o in mint.attribute(c.value) if o != "alice"}
    assert leaked == set()


def test_key_rotation_keeps_old_valid(mint: CanaryMint) -> None:
    old = mint.mint("alice").token
    mint.keyring.rotate()
    new = mint.mint("bob")
    assert mint.attribute(old) == {"alice"}
    assert mint.attribute(new.value) == {"bob"}


def test_keyring_export_import() -> None:
    ring = KeyRing()
    data, active = ring.export(), ring.active_kid
    restored = KeyRing.from_export(data, active)
    assert restored.active_kid == active
    assert restored.key(active) == ring.key(active)
