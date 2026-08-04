"""Core deterministic primitives: models, canaries, and oracles.

Everything in :mod:`authdiff.core` depends only on the Python standard library
so the deterministic guarantees can be verified with zero third-party packages.
"""

from __future__ import annotations

from authdiff.core.canary import Canary, CanaryMint, CanaryType, KeyRing
from authdiff.core.models import (
    Confidence,
    Finding,
    Identity,
    ObservedRequest,
    RequestTag,
    Severity,
)
from authdiff.core.oracles import (
    BflaOracle,
    BolaOracle,
    MassAssignmentOracle,
    Oracle,
    RaceInvariantOracle,
)

__all__ = [
    "Canary",
    "CanaryMint",
    "CanaryType",
    "KeyRing",
    "Confidence",
    "Finding",
    "Identity",
    "ObservedRequest",
    "RequestTag",
    "Severity",
    "Oracle",
    "BolaOracle",
    "BflaOracle",
    "MassAssignmentOracle",
    "RaceInvariantOracle",
]
