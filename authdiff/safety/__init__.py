"""Safety layer: the scope governor and kill-switch that gate every egress."""

from __future__ import annotations

from authdiff.safety.governor import (
    KillSwitchError,
    NonDestructiveError,
    OutOfScopeError,
    ScopeGovernor,
)

__all__ = [
    "ScopeGovernor",
    "OutOfScopeError",
    "NonDestructiveError",
    "KillSwitchError",
]
