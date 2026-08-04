"""Postman collection v2.1 parser."""

from __future__ import annotations

import json
from typing import Any, Iterator

from authdiff.core.models import Identity, ObservedRequest
from authdiff.inputs.base import make_request


def _walk(items: list[dict[str, Any]]) -> Iterator[dict[str, Any]]:
    for item in items:
        if "item" in item:  # folder
            yield from _walk(item["item"])
        elif "request" in item:
            yield item["request"]


def _url(url_field: Any) -> str:
    if isinstance(url_field, str):
        return url_field
    if isinstance(url_field, dict):
        return url_field.get("raw", "")
    return ""


def parse(path: str, owner: Identity) -> list[ObservedRequest]:
    """Parse a Postman v2.1 collection into observed requests."""
    data = json.load(open(path, encoding="utf-8"))
    out: list[ObservedRequest] = []
    for req in _walk(data.get("item", [])):
        url = _url(req.get("url"))
        if not url:
            continue
        headers = {h["key"]: h["value"] for h in req.get("header", [])
                   if not h.get("disabled")}
        body_raw = (req.get("body") or {}).get("raw")
        body = body_raw.encode() if body_raw else None
        out.append(make_request(owner, req.get("method", "GET"), url, headers, body))
    return out
