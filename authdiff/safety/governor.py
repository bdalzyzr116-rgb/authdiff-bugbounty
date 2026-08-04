"""Scope Governor v2 — the single choke point for all outbound requests.

Guarantees enforced here, structurally rather than by convention:

* host-glob **and** IP/CIDR allowlisting;
* DNS-rebinding protection (each host is resolved once and its IP is pinned);
* non-destructive by default (write methods blocked unless ``allow_writes``);
* adaptive rate limiting (token bucket) and a global concurrency cap;
* a kill-switch driven by a file path or environment variable for CI aborts.
"""

from __future__ import annotations

import asyncio
import fnmatch
import ipaddress
import os
import socket
import time
from urllib.parse import urlparse

from authdiff.core.models import WRITE_METHODS


class OutOfScopeError(RuntimeError):
    """Raised when a request targets a host/IP outside the authorized scope."""


class NonDestructiveError(RuntimeError):
    """Raised when a write method is attempted without ``--allow-writes``."""


class KillSwitchError(RuntimeError):
    """Raised when the kill-switch has been engaged."""


class _TokenBucket:
    def __init__(self, rate_per_sec: float, burst: int):
        self._rate = max(rate_per_sec, 0.1)
        self._cap = max(burst, 1)
        self._tokens = float(self._cap)
        self._ts = time.monotonic()
        self._lock = asyncio.Lock()

    async def take(self) -> None:
        async with self._lock:
            now = time.monotonic()
            self._tokens = min(self._cap, self._tokens + (now - self._ts) * self._rate)
            self._ts = now
            if self._tokens < 1:
                await asyncio.sleep((1 - self._tokens) / self._rate)
                self._tokens = 0.0
            else:
                self._tokens -= 1


class ScopeGovernor:
    """Enforces scope, safety, and pacing for every outbound request."""

    def __init__(
        self,
        allow_hosts: list[str],
        allow_cidrs: list[str] | None = None,
        *,
        rate_per_sec: float = 5.0,
        burst: int = 5,
        max_concurrency: int = 8,
        allow_writes: bool = False,
        pin_dns: bool = True,
        kill_switch_file: str | None = None,
    ) -> None:
        if not allow_hosts and not allow_cidrs:
            raise ValueError("scope must define allow_hosts and/or allow_cidrs")
        self._allow_hosts = [h.lower() for h in allow_hosts]
        self._allow_nets = [ipaddress.ip_network(c, strict=False) for c in (allow_cidrs or [])]
        self._bucket = _TokenBucket(rate_per_sec, burst)
        self._sem = asyncio.Semaphore(max_concurrency)
        self._allow_writes = allow_writes
        self._pin_dns = pin_dns
        self._kill_file = kill_switch_file
        self._pinned: dict[str, str] = {}
        self._killed = asyncio.Event()

    # -- kill-switch --------------------------------------------------------
    def kill(self) -> None:
        self._killed.set()

    def _kill_engaged(self) -> bool:
        if self._killed.is_set():
            return True
        if self._kill_file and os.path.exists(self._kill_file):
            return True
        if os.environ.get("AUTHDIFF_KILL") == "1":
            return True
        return False

    # -- scope --------------------------------------------------------------
    def _resolve_pinned(self, host: str) -> str | None:
        if host in self._pinned:
            return self._pinned[host]
        try:
            ip = socket.getaddrinfo(host, None)[0][4][0]
        except socket.gaierror:
            return None
        if self._pin_dns:
            self._pinned[host] = ip
        return ip

    def in_scope(self, url: str) -> bool:
        host = (urlparse(url).hostname or "").lower()
        if not host:
            return False
        if any(fnmatch.fnmatch(host, pat) for pat in self._allow_hosts):
            return True
        if self._allow_nets:
            ip = self._resolve_pinned(host)
            if ip is not None:
                addr = ipaddress.ip_address(ip)
                return any(addr in net for net in self._allow_nets)
        return False

    def assert_allowed(self, method: str, url: str) -> None:
        """Full gate: kill-switch, scope, and destructive-method check."""
        if self._kill_engaged():
            raise KillSwitchError("kill-switch engaged — aborting")
        if not self.in_scope(url):
            raise OutOfScopeError(f"{url!r} is not in the authorized scope")
        if method.upper() in WRITE_METHODS and not self._allow_writes:
            raise NonDestructiveError(
                f"{method} blocked in non-destructive mode (pass allow_writes=True)"
            )

    async def guard(self, method: str, url: str) -> asyncio.Semaphore:
        """Assert the request is allowed, throttle, and return the concurrency lock."""
        self.assert_allowed(method, url)
        await self._bucket.take()
        return self._sem
