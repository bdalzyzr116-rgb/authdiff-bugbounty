"""Async HTTP client with connection pooling, HTTP/2, and adaptive back-off.

Wraps :class:`httpx.AsyncClient`. Every call is gated by the
:class:`~authdiff.safety.governor.ScopeGovernor`, and 429 / ``Retry-After``
responses trigger a bounded, jittered back-off so we stay polite under load.
"""

from __future__ import annotations

import asyncio
import random
from dataclasses import dataclass

from authdiff.safety.governor import ScopeGovernor


@dataclass(frozen=True)
class HttpResponse:
    status_code: int
    text: str
    headers: dict[str, str]


class AsyncHttpClient:
    """Thin async wrapper that centralises safety, pooling, and retries."""

    def __init__(self, governor: ScopeGovernor, *, timeout: float = 20.0,
                 max_retries: int = 3):
        self._gov = governor
        self._timeout = timeout
        self._max_retries = max_retries
        self._client = None  # type: ignore[assignment]

    async def __aenter__(self) -> "AsyncHttpClient":
        import httpx  # lazy import keeps `core` dependency-free

        self._client = httpx.AsyncClient(
            http2=True, timeout=self._timeout, follow_redirects=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
        return self

    async def __aexit__(self, *exc: object) -> None:
        if self._client is not None:
            await self._client.aclose()

    async def request(self, method: str, url: str, *, headers: dict[str, str] | None = None,
                      cookies: dict[str, str] | None = None,
                      content: bytes | None = None) -> HttpResponse:
        """Send one request, honouring scope, rate limits, and 429 back-off."""
        assert self._client is not None, "use `async with AsyncHttpClient(...)`"
        attempt = 0
        while True:
            sem = await self._gov.guard(method, url)
            async with sem:
                resp = await self._client.request(method, url, headers=headers,
                                                  cookies=cookies, content=content)
            if resp.status_code == 429 and attempt < self._max_retries:
                delay = self._retry_after(resp) or (2 ** attempt + random.random())
                await asyncio.sleep(min(delay, 30))
                attempt += 1
                continue
            return HttpResponse(resp.status_code, resp.text, dict(resp.headers))

    @staticmethod
    def _retry_after(resp: object) -> float | None:
        try:
            value = resp.headers.get("retry-after")  # type: ignore[attr-defined]
            return float(value) if value else None
        except (TypeError, ValueError):
            return None
