"""Differential engine: matrix builder, async runner, and plugin system."""

from __future__ import annotations

from authdiff.engine.matrix import ReplayTask, build_matrix
from authdiff.engine.plugins import OracleRegistry, load_entrypoint_oracles
from authdiff.engine.runner import DifferentialRunner, RunResult

__all__ = [
    "ReplayTask",
    "build_matrix",
    "OracleRegistry",
    "load_entrypoint_oracles",
    "DifferentialRunner",
    "RunResult",
]
