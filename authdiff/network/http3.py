"""HTTP/3 (QUIC) transport — ROADMAP stub.

Experimental HTTP/3 support is planned via ``aioquic`` (install the ``http3``
extra). It is intentionally not implemented yet so the core release stays lean
and fully tested. Track progress in the project roadmap.
"""

from __future__ import annotations


class Http3NotAvailable(RuntimeError):
    """Raised until the aioquic-backed HTTP/3 transport ships."""


async def race_http3(*_args: object, **_kwargs: object) -> None:  # pragma: no cover
    raise Http3NotAvailable(
        "HTTP/3 racer is on the roadmap; install the 'http3' extra once released"
    )
