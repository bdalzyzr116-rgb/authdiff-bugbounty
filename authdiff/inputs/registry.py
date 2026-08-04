"""Format auto-detection and dispatch for traffic ingestion."""

from __future__ import annotations

import json

from authdiff.core.models import Identity, ObservedRequest
from authdiff.inputs import har, openapi, postman


def detect_format(path: str) -> str:
    """Best-effort detection: extension first, then content sniffing."""
    lower = path.lower()
    if lower.endswith(".har"):
        return "har"
    if lower.endswith((".yaml", ".yml")):
        return "openapi"
    try:
        head = json.load(open(path, encoding="utf-8"))
    except (ValueError, OSError):
        return "unknown"
    if "log" in head and "entries" in head.get("log", {}):
        return "har"
    if "openapi" in head or "swagger" in head:
        return "openapi"
    if "info" in head and "item" in head:
        return "postman"
    return "unknown"


def parse_file(path: str, owner: Identity, fmt: str | None = None) -> list[ObservedRequest]:
    """Parse ``path`` for ``owner`` using ``fmt`` or an auto-detected format."""
    fmt = fmt or detect_format(path)
    if fmt == "har":
        return har.parse(path, owner)
    if fmt == "openapi":
        requests, _seeds = openapi.parse(path, owner)
        return requests
    if fmt == "postman":
        return postman.parse(path, owner)
    raise ValueError(f"unsupported or undetected traffic format: {path}")


def detect_and_parse(path: str, owner: Identity) -> list[ObservedRequest]:
    return parse_file(path, owner, None)
