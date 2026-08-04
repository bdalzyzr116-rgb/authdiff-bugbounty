"""Shared parser helpers: URL normalisation and object-reference tagging."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from authdiff.core.models import Identity, ObservedRequest, RequestTag

_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".pdf")
_ID_RE = re.compile(r"/\d+(?:/|$)|/[0-9a-fA-F-]{8,}(?:/|$)")
_WRITE = {"POST", "PUT", "PATCH"}


def is_static(url: str) -> bool:
    return urlparse(url).path.lower().endswith(_STATIC_EXT)


def tag_request(method: str, url: str) -> frozenset[RequestTag]:
    """Classify a request as read/write/delete and whether it references an object."""
    tags: set[RequestTag] = set()
    m = method.upper()
    if m == "DELETE":
        tags.add(RequestTag.DELETE)
    elif m in _WRITE:
        tags.add(RequestTag.WRITE)
    else:
        tags.add(RequestTag.READ)
    p = urlparse(url)
    segments = [s for s in p.path.split("/") if s]
    # Object reference if: numeric/hex/uuid id, a query string, or a nested
    # resource path (>=2 segments, e.g. /profile/alice or /users/{slug}).
    if _ID_RE.search(p.path) or p.query or len(segments) >= 2:
        tags.add(RequestTag.OBJECT_REF)
    return frozenset(tags)


def make_request(owner: Identity, method: str, url: str,
                 headers: dict[str, str] | None = None,
                 body: bytes | None = None) -> ObservedRequest:
    return ObservedRequest(owner=owner, method=method.upper(), url=url,
                           headers=headers or {}, body=body,
                           tags=tag_request(method, url))
