"""HAR (HTTP Archive) 1.2+ parser.

Uses ``ijson`` for memory-efficient streaming of large captures when available,
falling back to the standard ``json`` module otherwise.
"""

from __future__ import annotations

from typing import Iterator

from authdiff.core.models import Identity, ObservedRequest
from authdiff.inputs.base import is_static, make_request


def _iter_entries(path: str) -> Iterator[dict]:
    try:
        import ijson  # optional: streaming for huge HARs

        with open(path, "rb") as fh:
            yield from ijson.items(fh, "log.entries.item")
    except ImportError:
        import json

        data = json.load(open(path, encoding="utf-8"))
        yield from data.get("log", {}).get("entries", [])


def parse(path: str, owner: Identity, *, skip_static: bool = True) -> list[ObservedRequest]:
    """Parse a HAR file into observed requests for ``owner``."""
    out: list[ObservedRequest] = []
    seen: set[str] = set()
    for entry in _iter_entries(path):
        req = entry.get("request", {})
        url = req.get("url", "")
        if not url or (skip_static and is_static(url)):
            continue
        headers = {h["name"]: h["value"] for h in req.get("headers", [])
                   if not h["name"].startswith(":")}
        post = req.get("postData") or {}
        body = post["text"].encode() if post.get("text") else None
        obs = make_request(owner, req.get("method", "GET"), url, headers, body)
        fp = obs.fingerprint()
        if fp in seen:
            continue
        seen.add(fp)
        out.append(obs)
    return out
