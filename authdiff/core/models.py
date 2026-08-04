"""Domain models shared across AuthDiff.

These are intentionally free of any network or third-party dependency so they can
be imported by the deterministic core, the parsers, and the reporters alike.
"""

from __future__ import annotations

import enum
import hashlib
from dataclasses import dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    """Finding severity, ordered from lowest to highest."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
        return order.index(self)


class Confidence(str, enum.Enum):
    """How the finding was established.

    ``PROVEN`` is reserved for canary/invariant witnesses — the deterministic,
    zero-false-positive path. ``HEURISTIC`` is used by softer signals (e.g. an
    unexpected 2xx on a privileged endpoint) that a human should confirm.
    """

    PROVEN = "proven"
    HEURISTIC = "heuristic"


class RequestTag(str, enum.Enum):
    """Coarse classification of an observed request."""

    READ = "read"
    WRITE = "write"
    DELETE = "delete"
    OBJECT_REF = "object_ref"


# HTTP methods considered state-changing; blocked in non-destructive mode.
WRITE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})


@dataclass(frozen=True)
class Identity:
    """An authenticated principal used in the differential matrix."""

    id: str
    tenant: str = ""
    role: str = "user"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ObservedRequest:
    """A single request captured (or synthesised) for one identity."""

    owner: Identity
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    tags: frozenset[RequestTag] = field(default_factory=frozenset)

    @property
    def is_write(self) -> bool:
        return self.method.upper() in WRITE_METHODS

    def fingerprint(self) -> str:
        """Stable hash used for de-duplication of near-identical requests."""
        norm = f"{self.method.upper()} {self.url.split('?', 1)[0]}"
        return hashlib.sha1(norm.encode()).hexdigest()  # noqa: S324 (dedup, not security)


@dataclass
class Finding:
    """A proven or heuristic authorization violation."""

    kind: str
    severity: Severity
    confidence: Confidence
    actor: str
    victim_owner: str
    method: str
    url: str
    status_code: int
    proof: list[str] = field(default_factory=list)
    evidence: dict[str, Any] = field(default_factory=dict)
    cvss: float | None = None

    @property
    def id(self) -> str:
        seed = f"{self.kind}|{self.actor}|{self.victim_owner}|{self.method}|{self.url}"
        return "ADF-" + hashlib.sha1(seed.encode()).hexdigest()[:12]  # noqa: S324

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "kind": self.kind,
            "severity": self.severity.value,
            "confidence": self.confidence.value,
            "actor": self.actor,
            "victim_owner": self.victim_owner,
            "method": self.method,
            "url": self.url,
            "status_code": self.status_code,
            "cvss": self.cvss,
            "proof": self.proof,
            "evidence": self.evidence,
        }

    def summary(self) -> str:
        return (
            f"[{self.severity.value.upper():8}] {self.kind}: {self.actor!r} -> "
            f"{self.victim_owner!r}  {self.method} {self.url} (HTTP {self.status_code})"
        )
