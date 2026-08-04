"""Self-authenticating canary tokens — the deterministic oracle backbone.

A canary is a value written into ONE identity's private data. It is bound to its
owner with an HMAC so that discovering it anywhere is an *unforgeable* proof of
provenance. Detection therefore reduces to a cryptographic equality check, which
is what gives AuthDiff its 0%-false-positive guarantee.

Token format (self-describing types)::

    AUTHDIFF.v2.<kid>.<ctype>.<owner>.<nonce_b32>.<tag_b32>
    tag = HMAC_SHA256(key[kid], "<kid>.<ctype>.<owner>.<nonce>")[:10 bytes]

The ``kid`` (key id) enables **key rotation**: a :class:`KeyRing` may hold several
secrets; new canaries are minted with the current key while previously seeded
canaries still validate against retired keys.

Numeric and UUID canaries cannot embed a text token, so they are tracked in a
per-run registry and attributed by exact-value match — still fully deterministic.
"""

from __future__ import annotations

import base64
import enum
import hmac
import os
import re
import secrets
import uuid
from dataclasses import dataclass


def _b32(raw: bytes) -> str:
    return base64.b32encode(raw).decode().rstrip("=")


_TOKEN_RE = re.compile(
    r"AUTHDIFF\.v2\.([A-Za-z0-9]+)\.([a-z]+)\.([A-Za-z0-9_-]+)\.([A-Z2-7]+)\.([A-Z2-7]+)"
)


class CanaryType(str, enum.Enum):
    """Rendering type so a canary can be written into differently-typed fields."""

    TEXT = "txt"
    EMAIL = "eml"
    JSON = "jsn"
    NUMBER = "num"
    UUID = "uid"


@dataclass(frozen=True)
class Canary:
    """A minted canary and the concrete value to write into a field."""

    token: str
    owner_id: str
    ctype: CanaryType
    value: str  # what actually gets written into the target field

    def as_json_object(self) -> dict[str, str]:
        return {"authdiff_marker": self.token}


class KeyRing:
    """Holds one active HMAC key plus any number of retired keys for rotation."""

    def __init__(self, keys: dict[str, bytes] | None = None, active: str | None = None):
        self._keys: dict[str, bytes] = dict(keys or {})
        if not self._keys:
            kid = _b32(os.urandom(4)).lower()
            self._keys[kid] = secrets.token_bytes(32)
            active = kid
        self._active = active or next(iter(self._keys))

    @property
    def active_kid(self) -> str:
        return self._active

    def key(self, kid: str) -> bytes | None:
        return self._keys.get(kid)

    def rotate(self) -> str:
        """Introduce a fresh active key while keeping the old ones for validation."""
        kid = _b32(os.urandom(4)).lower()
        self._keys[kid] = secrets.token_bytes(32)
        self._active = kid
        return kid

    def export(self) -> dict[str, str]:
        return {kid: key.hex() for kid, key in self._keys.items()}

    @classmethod
    def from_export(cls, data: dict[str, str], active: str) -> "KeyRing":
        return cls({kid: bytes.fromhex(h) for kid, h in data.items()}, active)


class CanaryMint:
    """Mints and attributes canaries against a :class:`KeyRing`."""

    def __init__(self, keyring: KeyRing | None = None):
        self._ring = keyring or KeyRing()
        # registry for non-self-describing types (number/uuid) -> owner_id
        self._registry: dict[str, str] = {}

    @property
    def keyring(self) -> KeyRing:
        return self._ring

    def _tag(self, kid: str, ctype: CanaryType, owner: str, nonce: str) -> str:
        key = self._ring.key(kid)
        if key is None:
            raise KeyError(f"unknown key id {kid!r}")
        mac = hmac.new(key, f"{kid}.{ctype.value}.{owner}.{nonce}".encode(), "sha256")
        return _b32(mac.digest()[:10])

    def mint(self, owner_id: str, ctype: CanaryType = CanaryType.TEXT) -> Canary:
        """Mint a canary for ``owner_id`` rendered as ``ctype``."""
        kid = self._ring.active_kid
        nonce = _b32(os.urandom(10))
        token = f"AUTHDIFF.v2.{kid}.{ctype.value}.{owner_id}.{nonce}.{self._tag(kid, ctype, owner_id, nonce)}"

        if ctype is CanaryType.TEXT:
            value = token
        elif ctype is CanaryType.EMAIL:
            value = f"{token}@authdiff.canary"  # token stays verbatim in local-part
        elif ctype is CanaryType.JSON:
            value = f'{{"authdiff_marker": "{token}"}}'
        elif ctype is CanaryType.NUMBER:
            # deterministic large int derived from the HMAC; registry-attributed
            digest = hmac.new(self._ring.key(kid) or b"", token.encode(), "sha256").digest()
            value = str(int.from_bytes(digest[:8], "big"))
            self._registry[value] = owner_id
        elif ctype is CanaryType.UUID:
            digest = hmac.new(self._ring.key(kid) or b"", token.encode(), "sha256").digest()
            value = str(uuid.UUID(bytes=digest[:16]))
            self._registry[value] = owner_id
        else:  # pragma: no cover - exhaustive
            raise ValueError(ctype)

        return Canary(token=token, owner_id=owner_id, ctype=ctype, value=value)

    def attribute_detailed(self, blob: str) -> list[tuple[str, str]]:
        """Return ``[(owner_id, evidence)]`` for every VALID canary found in ``blob``."""
        out: list[tuple[str, str]] = []
        for kid, ctype, owner, nonce, tag in _TOKEN_RE.findall(blob):
            try:
                expected = self._tag(kid, CanaryType(ctype), owner, nonce)
            except (KeyError, ValueError):
                continue
            if hmac.compare_digest(expected, tag):  # constant-time provenance check
                out.append((owner, f"AUTHDIFF.v2.{kid}.{ctype}.{owner}.{nonce}.{tag}"))
        # registry-backed (number/uuid) canaries: exact-value match
        for value, owner in self._registry.items():
            if value in blob:
                out.append((owner, value))
        return out

    def attribute(self, blob: str) -> set[str]:
        """Return the set of owner ids whose canaries appear in ``blob``."""
        return {owner for owner, _ in self.attribute_detailed(blob)}
