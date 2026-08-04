"""Extensible oracle plugin system.

Third parties can register custom oracles either programmatically via
:class:`OracleRegistry` or by exposing an ``authdiff.oracles`` entry point in
their own package — no core modification required.
"""

from __future__ import annotations

from typing import Callable

from authdiff.core.oracles import Oracle


class OracleRegistry:
    """A mutable collection of oracles used by the runner."""

    def __init__(self) -> None:
        self._oracles: list[Oracle] = []

    def register(self, oracle: Oracle) -> None:
        self._oracles.append(oracle)

    def extend(self, oracles: list[Oracle]) -> None:
        self._oracles.extend(oracles)

    def __iter__(self):
        return iter(self._oracles)

    def __len__(self) -> int:
        return len(self._oracles)


def load_entrypoint_oracles(factory_kwargs: dict | None = None) -> list[Oracle]:
    """Load oracles advertised by installed packages via entry points."""
    oracles: list[Oracle] = []
    try:
        from importlib.metadata import entry_points

        eps = entry_points(group="authdiff.oracles")
    except Exception:  # noqa: BLE001 - tolerate older metadata APIs
        return oracles
    for ep in eps:
        factory: Callable[..., Oracle] = ep.load()
        oracles.append(factory(**(factory_kwargs or {})))
    return oracles
