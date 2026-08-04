"""Configuration loading from YAML / JSON / TOML with env + override support.

Secrets should be referenced via ``${ENV_VAR}`` placeholders so tokens live in
the environment, never in committed config files.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from authdiff.core.models import Identity

_ENV_RE = re.compile(r"\$\{([A-Z0-9_]+)\}")


def _expand_env(value: Any) -> Any:
    if isinstance(value, str):
        return _ENV_RE.sub(lambda m: os.environ.get(m.group(1), ""), value)
    if isinstance(value, dict):
        return {k: _expand_env(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_expand_env(v) for v in value]
    return value


def _load_raw(path: str) -> dict[str, Any]:
    text = open(path, encoding="utf-8").read()
    if path.endswith((".yaml", ".yml")):
        import yaml  # lazy: optional dependency

        return yaml.safe_load(text) or {}
    if path.endswith(".toml"):
        import tomllib  # stdlib 3.11+

        return tomllib.loads(text)
    return json.loads(text)


@dataclass
class ScopeConfig:
    allow_hosts: list[str] = field(default_factory=list)
    allow_cidrs: list[str] = field(default_factory=list)
    rate_per_sec: float = 5.0
    burst: int = 5
    max_concurrency: int = 8
    allow_writes: bool = False
    kill_switch_file: str | None = None


@dataclass
class Config:
    """Fully-resolved run configuration."""

    scope: ScopeConfig
    identities: dict[str, Identity]
    observed: list[dict[str, Any]] = field(default_factory=list)
    seed: dict[str, Any] | None = None
    race: dict[str, Any] | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def load(cls, path: str, overrides: dict[str, Any] | None = None) -> "Config":
        raw = _expand_env(_load_raw(path))
        if overrides:
            raw.update(overrides)

        sc = raw.get("scope", {})
        scope = ScopeConfig(
            allow_hosts=sc.get("allow_hosts", []),
            allow_cidrs=sc.get("allow_cidrs", []),
            rate_per_sec=sc.get("rate_per_sec", 5.0),
            burst=sc.get("burst", 5),
            max_concurrency=sc.get("max_concurrency", 8),
            allow_writes=sc.get("allow_writes", False),
            kill_switch_file=sc.get("kill_switch_file"),
        )

        identities: dict[str, Identity] = {}
        for item in raw.get("identities", []):
            identities[item["id"]] = Identity(
                id=item["id"], tenant=item.get("tenant", ""), role=item.get("role", "user"),
                headers=dict(item.get("headers", {})), cookies=dict(item.get("cookies", {})),
            )
        if len(identities) < 2:
            raise ValueError("at least two identities are required for a differential test")

        return cls(scope=scope, identities=identities, observed=raw.get("observed", []),
                   seed=raw.get("seed"), race=raw.get("race"), raw=raw)
