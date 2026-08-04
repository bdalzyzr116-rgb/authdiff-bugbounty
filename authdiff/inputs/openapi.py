"""OpenAPI 3.0/3.1 parser — used to discover seedable and write endpoints.

Returns both replayable requests and a list of *seed candidates*: write
operations that accept user-controlled string properties, which the canary
seeder and mass-assignment oracle target.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from authdiff.core.models import Identity, ObservedRequest
from authdiff.inputs.base import make_request

_WRITE_OPS = {"post", "put", "patch"}


@dataclass(frozen=True)
class SeedCandidate:
    method: str
    url: str
    string_fields: list[str]
    privileged_fields: list[str]


_PRIVILEGED_HINTS = ("role", "admin", "is_admin", "isadmin", "scope", "permission",
                     "credit", "balance", "owner", "tenant", "verified")


def _load(path: str) -> dict[str, Any]:
    text = open(path, encoding="utf-8").read()
    if path.endswith((".yaml", ".yml")):
        import yaml

        return yaml.safe_load(text)
    return json.loads(text)


def _string_props(schema: dict[str, Any]) -> list[str]:
    props = schema.get("properties", {}) if isinstance(schema, dict) else {}
    return [name for name, spec in props.items()
            if isinstance(spec, dict) and spec.get("type") == "string"]


def parse(path: str, owner: Identity, base_url: str | None = None
          ) -> tuple[list[ObservedRequest], list[SeedCandidate]]:
    """Return (replayable requests, seed candidates) derived from the spec."""
    spec = _load(path)
    servers = spec.get("servers") or [{"url": base_url or ""}]
    root = (base_url or servers[0].get("url", "")).rstrip("/")

    requests: list[ObservedRequest] = []
    seeds: list[SeedCandidate] = []
    for raw_path, item in spec.get("paths", {}).items():
        url = f"{root}{raw_path}"
        for method, op in item.items():
            if method.lower() not in ("get", *_WRITE_OPS):
                continue
            requests.append(make_request(owner, method, url))
            if method.lower() in _WRITE_OPS:
                schema = (op.get("requestBody", {}).get("content", {})
                          .get("application/json", {}).get("schema", {}))
                fields = _string_props(schema)
                priv = [f for f in schema.get("properties", {})
                        if any(h in f.lower() for h in _PRIVILEGED_HINTS)]
                if fields or priv:
                    seeds.append(SeedCandidate(method.upper(), url, fields, priv))
    return requests, seeds
