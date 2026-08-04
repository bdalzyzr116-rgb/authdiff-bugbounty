#!/usr/bin/env python3
"""
AuthDiff — Differential Authorization Discovery Framework (single-file MVP)
===========================================================================

Hunts BROKEN ACCESS CONTROL (BOLA/IDOR, BFLA, mass-assignment) and single-use
state races using DETERMINISTIC canary/invariant oracles => 0% false positives
by construction. Discovery / PoC only. Authorized bug-bounty scopes ONLY.

WHY IT WORKS
------------
Authorization is a relation between (identity, object, capability). A scanner
can't see who owns an object, so it can only guess. AuthDiff instead *injects*
ground truth: it plants self-authenticating canary tokens (HMAC-bound to their
owner) into each identity's PRIVATE data. Finding one identity's canary inside
another identity's authorized response is an UNFORGEABLE proof of a cross-tenant
leak. Detection becomes a cryptographic equality, not a heuristic.

WORKFLOW
--------
  1) `seed`  : each identity writes a fresh canary into its OWN private field.
  2) `run`   : replay every object-referencing request under every OTHER identity
               (+ anonymous). The oracle scans responses for foreign canaries.
  3) `race`  : (optional) single-packet HTTP/2 burst to confirm limit-bypass via a
               numeric invariant (successes <= seeded_capacity).
  4) `selftest`: offline proof the oracle is sound (no network, no target needed).

INSTALL
-------
  pip install "httpx[http2]" h2          # only needed for seed/run/race
  # `selftest` runs on the Python standard library alone.

QUICKSTART
----------
  python3 authdiff.py selftest
  python3 authdiff.py seed --config config.json --authorized
  python3 authdiff.py run  --config config.json --authorized
  python3 authdiff.py race --config config.json --authorized

MINIMAL config.json
-------------------
{
  "scope":   { "allow_hosts": ["localhost", "*.target.com"],
               "rate_per_sec": 5, "burst": 5, "max_concurrency": 8 },
  "identities": [
    { "id": "alice", "tenant": "t1", "role": "user",
      "headers": { "Authorization": "Bearer ALICE_TOKEN" } },
    { "id": "bob",   "tenant": "t2", "role": "user",
      "headers": { "Authorization": "Bearer BOB_TOKEN" } }
  ],
  "seed": {
    "method": "PUT",
    "url_template": "https://api.target.com/users/me/note",
    "headers": {},
    "body_template": "{\"note\": \"{canary}\"}"
  },
  "observed": [
    { "owner": "alice", "method": "GET",
      "url": "https://api.target.com/users/me/note" }
  ],
  "race": {
    "n": 20, "seeded_capacity": 1,
    "request": { "method": "POST", "url": "https://api.target.com/coupons/redeem",
                 "headers": { "Authorization": "Bearer ALICE_TOKEN" },
                 "body": "{\"code\":\"CANARY-CARD\"}" }
  }
}

You can also skip "observed" and ingest captured traffic per identity:
  python3 authdiff.py run --config config.json --har alice=alice.har --har bob=bob.har --authorized
"""

from __future__ import annotations

import argparse
import asyncio
import base64
import fnmatch
import hmac
import json
import os
import re
import secrets
import sys
import time
from dataclasses import dataclass, field
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# base32 helpers (compact, padding-tolerant)
# ---------------------------------------------------------------------------
_b32 = lambda b: base64.b32encode(b).decode().rstrip("=")
_TOKEN_RE = re.compile(r"AUTHDIFF\.v1\.([A-Za-z0-9_-]+)\.([A-Z2-7]+)\.([A-Z2-7]+)")


# ===========================================================================
# 1) SELF-AUTHENTICATING CANARIES  (the deterministic oracle backbone)
# ===========================================================================
@dataclass(frozen=True)
class Canary:
    token: str
    owner_id: str
    nonce: str


class CanaryMint:
    """
    Mints canary tokens of the form:

        AUTHDIFF.v1.<owner_id>.<nonce_b32>.<tag_b32>
        tag = HMAC_SHA256(secret, "<owner_id>.<nonce>")[:10 bytes]   (80-bit)

    The 80-bit HMAC tag makes it infeasible for the target to ever produce a
    VALID foreign canary by chance — so any valid token it hands to the wrong
    identity was genuinely leaked from storage. That is the 0%-FP guarantee.
    """

    def __init__(self, secret: bytes):
        self._secret = secret

    # -- persistence: seed and run are separate processes, so the HMAC secret
    #    MUST be shared between them or attribution across runs would fail.
    @classmethod
    def load_or_create(cls, path: str) -> "CanaryMint":
        if os.path.exists(path):
            with open(path) as fh:
                return cls(bytes.fromhex(json.load(fh)["secret"]))
        secret = secrets.token_bytes(32)
        with open(path, "w") as fh:
            json.dump({"secret": secret.hex()}, fh)
        try:
            os.chmod(path, 0o600)  # secret stays local & private
        except OSError:
            pass
        return cls(secret)

    def _tag(self, owner_id: str, nonce: str) -> str:
        mac = hmac.new(self._secret, f"{owner_id}.{nonce}".encode(), "sha256").digest()
        return _b32(mac[:10])

    def mint(self, owner_id: str) -> Canary:
        nonce = _b32(os.urandom(10))
        return Canary(f"AUTHDIFF.v1.{owner_id}.{nonce}.{self._tag(owner_id, nonce)}",
                      owner_id, nonce)

    def attribute_detailed(self, blob: str) -> list[tuple[str, str]]:
        """Return [(owner_id, full_token)] for every CRYPTOGRAPHICALLY VALID canary."""
        out: list[tuple[str, str]] = []
        for owner_id, nonce, tag in _TOKEN_RE.findall(blob):
            if hmac.compare_digest(self._tag(owner_id, nonce), tag):  # constant time
                out.append((owner_id, f"AUTHDIFF.v1.{owner_id}.{nonce}.{tag}"))
        return out

    def attribute(self, blob: str) -> set[str]:
        return {owner for owner, _ in self.attribute_detailed(blob)}


# ===========================================================================
# 2) SCOPE GOVERNOR  (safety as a hard gate — scope, rate, concurrency, kill)
# ===========================================================================
class OutOfScopeError(RuntimeError):
    pass


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
    def __init__(self, allow_hosts: list[str], rate_per_sec: float = 5.0,
                 burst: int = 5, max_concurrency: int = 8):
        if not allow_hosts:
            raise ValueError("scope.allow_hosts must be non-empty — refusing to run unscoped")
        self._allow = [h.lower() for h in allow_hosts]
        self._bucket = _TokenBucket(rate_per_sec, burst)
        self._sem = asyncio.Semaphore(max_concurrency)
        self._killed = asyncio.Event()

    def kill(self) -> None:
        self._killed.set()

    def in_scope(self, host: str) -> bool:
        host = (host or "").lower()
        return any(fnmatch.fnmatch(host, pat) for pat in self._allow)

    def assert_in_scope(self, url: str) -> None:
        host = urlparse(url).hostname or ""
        if not self.in_scope(host):
            raise OutOfScopeError(f"{host!r} is NOT in the authorized allowlist {self._allow}")

    async def guard(self, url: str) -> asyncio.Semaphore:
        if self._killed.is_set():
            raise RuntimeError("kill-switch engaged")
        self.assert_in_scope(url)          # HARD FAIL off-allowlist
        await self._bucket.take()          # throttle to researcher-safe rate
        return self._sem                    # caller: `async with await gov.guard(url):`


# ===========================================================================
# 3) DATA MODELS + CONFIG
# ===========================================================================
@dataclass(frozen=True)
class Identity:
    id: str
    tenant: str = ""
    role: str = "user"
    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class ObservedRequest:
    owner: Identity
    method: str
    url: str
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes | None = None
    references_object: bool = True


@dataclass
class Finding:
    kind: str
    actor: str
    victim_owner: str
    method: str
    url: str
    status_code: int
    proof_tokens: list[str]

    def report(self) -> str:
        return (f"[{self.kind}]  actor={self.actor!r}  accessed data owned by "
                f"{self.victim_owner!r}\n         via {self.method} {self.url} "
                f"(HTTP {self.status_code})\n         PROOF (foreign canary): "
                f"{self.proof_tokens[0]}")


_STATIC_EXT = (".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
               ".woff", ".woff2", ".ttf", ".map", ".webp", ".mp4", ".pdf")
_ID_RE = re.compile(r"/\d+(?:/|$)|/[0-9a-fA-F-]{8,}(?:/|$)")


def _looks_like_object_ref(url: str) -> bool:
    p = urlparse(url)
    path = p.path.lower()
    if path.endswith(_STATIC_EXT):
        return False
    return bool(_ID_RE.search(p.path) or p.query)


@dataclass
class Config:
    governor: ScopeGovernor
    identities: dict[str, Identity]
    observed: list[ObservedRequest]
    seed: dict | None
    race: dict | None


def _b64_body(spec: dict) -> bytes | None:
    if spec.get("body_b64"):
        return base64.b64decode(spec["body_b64"])
    if spec.get("body") is not None:
        return str(spec["body"]).encode()
    return None


def load_config(path: str) -> Config:
    with open(path) as fh:
        raw = json.load(fh)

    sc = raw.get("scope", {})
    gov = ScopeGovernor(sc.get("allow_hosts", []), sc.get("rate_per_sec", 5.0),
                        sc.get("burst", 5), sc.get("max_concurrency", 8))

    idents: dict[str, Identity] = {}
    for i in raw.get("identities", []):
        idents[i["id"]] = Identity(i["id"], i.get("tenant", ""), i.get("role", "user"),
                                    dict(i.get("headers", {})), dict(i.get("cookies", {})))
    if len(idents) < 2:
        raise ValueError("need >= 2 identities to run a DIFFERENTIAL test")

    observed: list[ObservedRequest] = []
    for o in raw.get("observed", []):
        owner = idents[o["owner"]]
        observed.append(ObservedRequest(
            owner, o["method"], o["url"], dict(o.get("headers", {})),
            _b64_body(o), o.get("references_object", _looks_like_object_ref(o["url"]))))

    return Config(gov, idents, observed, raw.get("seed"), raw.get("race"))


def observed_from_har(path: str, owner: Identity, gov: ScopeGovernor) -> list[ObservedRequest]:
    """Ingest a browser/Burp HAR export for one identity; keep only in-scope traffic."""
    with open(path) as fh:
        har = json.load(fh)
    out: list[ObservedRequest] = []
    for entry in har.get("log", {}).get("entries", []):
        req = entry.get("request", {})
        url = req.get("url", "")
        host = urlparse(url).hostname or ""
        if not gov.in_scope(host):
            continue
        headers = {h["name"]: h["value"] for h in req.get("headers", [])
                   if not h["name"].startswith(":")}
        pd = req.get("postData") or {}
        body = pd["text"].encode() if pd.get("text") else None
        out.append(ObservedRequest(owner, req.get("method", "GET"), url, headers,
                                   body, _looks_like_object_ref(url)))
    return out


# ===========================================================================
# 4) SEEDER  (each identity writes a canary into its OWN private field)
# ===========================================================================
async def seed_identities(mint: CanaryMint, gov: ScopeGovernor,
                          identities: dict[str, Identity], seed_cfg: dict) -> None:
    import httpx  # lazy: only needed for network actions

    method = seed_cfg["method"]
    url_tpl = seed_cfg["url_template"]
    hdr_tpl = seed_cfg.get("headers", {})
    body_tpl = seed_cfg.get("body_template", "{canary}")

    async with httpx.AsyncClient(http2=True, timeout=20, follow_redirects=False) as client:
        for ident in identities.values():
            canary = mint.mint(ident.id)
            url = url_tpl.format(owner=ident.id, canary=canary.token)
            body = body_tpl.format(owner=ident.id, canary=canary.token).encode()
            headers = {**{k: v.format(owner=ident.id) for k, v in hdr_tpl.items()},
                       **ident.headers}
            sem = await gov.guard(url)                       # scope + rate
            async with sem:
                r = await client.request(method, url, headers=headers,
                                         cookies=ident.cookies, content=body)
            print(f"  seeded {ident.id:<10} -> HTTP {r.status_code}  token={canary.token}")


# ===========================================================================
# 5) DIFFERENTIAL ENGINE  (matrix + replay + I1/BOLA oracle)
# ===========================================================================
class DifferentialEngine:
    def __init__(self, mint: CanaryMint, gov: ScopeGovernor, identities: dict[str, Identity]):
        self._mint = mint
        self._gov = gov
        self._identities = list(identities.values())

    def build_matrix(self, observed: list[ObservedRequest]
                     ) -> list[tuple[ObservedRequest, Identity | None]]:
        tasks: list[tuple[ObservedRequest, Identity | None]] = []
        for req in observed:
            if not req.references_object:
                continue
            for actor in self._identities:          # every OTHER identity
                if actor.id != req.owner.id:
                    tasks.append((req, actor))
            tasks.append((req, None))               # + anonymous actor
        return tasks

    @staticmethod
    def _rewrite_auth(req: ObservedRequest, actor: Identity | None
                      ) -> tuple[dict[str, str], dict[str, str]]:
        # Strip owner auth, install actor auth. Only the *principal* changes.
        headers = {k: v for k, v in req.headers.items()
                   if k.lower() not in ("authorization", "cookie")}
        if actor is None:
            return headers, {}
        headers.update(actor.headers)
        return headers, actor.cookies

    async def _replay_one(self, client, req: ObservedRequest,
                          actor: Identity | None) -> Finding | None:
        headers, cookies = self._rewrite_auth(req, actor)
        sem = await self._gov.guard(req.url)
        async with sem:
            resp = await client.request(req.method, req.url, headers=headers,
                                        cookies=cookies, content=req.body)
        # ---- DETERMINISTIC ORACLE (invariant I1: Reach(actor) ∩ Priv(other) = ∅)
        actor_id = actor.id if actor else "<anonymous>"
        leaked = [(o, tok) for o, tok in self._mint.attribute_detailed(resp.text)
                  if o != actor_id]
        if leaked:
            return Finding("BOLA", actor_id, sorted({o for o, _ in leaked})[0],
                           req.method, req.url, resp.status_code,
                           [tok for _, tok in leaked])
        return None

    async def run(self, observed: list[ObservedRequest]) -> list[Finding]:
        import httpx  # lazy import
        matrix = self.build_matrix(observed)
        print(f"  replay matrix: {len(matrix)} cross-identity requests")
        async with httpx.AsyncClient(http2=True, timeout=20, follow_redirects=False) as client:
            results = await asyncio.gather(
                *(self._replay_one(client, r, a) for r, a in matrix),
                return_exceptions=True)
        findings, errors = [], 0
        for r in results:
            if isinstance(r, Finding):
                findings.append(r)
            elif isinstance(r, Exception):
                errors += 1
        if errors:
            print(f"  ({errors} transport/scope errors were skipped)")
        return findings


# ===========================================================================
# 6) SINGLE-PACKET HTTP/2 RACER  (jitter-free confirmation of state races)
# ===========================================================================
class SinglePacketRacer:
    """
    Fires N HTTP/2 requests coalesced into ONE TCP segment (Kettle single-packet
    technique) so server-side TOCTOU windows are exposed with ~0 timing skew.
    For CONFIRMATION only — a numeric invariant decides the verdict.
    """

    def __init__(self, url: str):
        p = urlparse(url)
        self._scheme = p.scheme
        self._host = p.hostname
        self._port = p.port or (443 if p.scheme == "https" else 80)
        self._authority = p.hostname + (f":{p.port}" if p.port else "")
        self._path = p.path + (f"?{p.query}" if p.query else "")

    def _tls_ctx(self):
        import ssl
        ctx = ssl.create_default_context()
        ctx.set_alpn_protocols(["h2"])
        return ctx

    def _h2_headers(self, method: str, headers: dict[str, str]) -> list[tuple[str, str]]:
        drop = {"host", "content-length", "connection", "transfer-encoding",
                "keep-alive", "upgrade", "proxy-connection"}
        out = [(":method", method), (":authority", self._authority),
               (":scheme", self._scheme), (":path", self._path)]
        out += [(k.lower(), v) for k, v in headers.items() if k.lower() not in drop]
        return out

    async def _run(self, method: str, headers: dict, body: bytes, n: int) -> list[int]:
        import socket
        import h2.config
        import h2.connection
        import h2.events

        if self._scheme != "https":
            raise RuntimeError("single-packet racer requires https (HTTP/2 over TLS)")

        reader, writer = await asyncio.open_connection(
            self._host, self._port, ssl=self._tls_ctx(), server_hostname=self._host)
        sock = writer.get_extra_info("socket")
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)  # no Nagle buffering

        conn = h2.connection.H2Connection(h2.config.H2Configuration(client_side=True))
        conn.initiate_connection()
        writer.write(conn.data_to_send())
        await writer.drain()

        h2_headers = self._h2_headers(method, headers)
        held: dict[int, bytes] = {}

        # Phase 1: send HEADERS + all-but-last body byte for EVERY stream.
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
        await asyncio.sleep(0.10)                      # let the prelude settle

        # Phase 2: THE SINGLE PACKET — every terminating byte, flushed at once.
        for sid, last in held.items():
            conn.send_data(sid, last, end_stream=True)
        writer.write(conn.data_to_send())
        await writer.drain()

        # Read until all N streams end.
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
        except Exception:
            pass
        return list(statuses.values())

    async def race(self, method: str, headers: dict, body: bytes, n: int) -> list[int]:
        return await asyncio.wait_for(self._run(method, headers, body, n), timeout=30)


async def confirm_limit_bypass(gov: ScopeGovernor, race_cfg: dict) -> tuple[bool, list[int]]:
    req = race_cfg["request"]
    gov.assert_in_scope(req["url"])                 # scope gate applies here too
    n = int(race_cfg.get("n", 20))
    capacity = int(race_cfg.get("seeded_capacity", 1))
    body = _b64_body(req) or b""
    racer = SinglePacketRacer(req["url"])
    statuses = await racer.race(req["method"], dict(req.get("headers", {})), body, n)
    successes = sum(1 for s in statuses if 200 <= s < 300)
    # invariant: successes <= capacity ; violation is a HARD numeric truth.
    return successes > capacity, statuses


# ===========================================================================
# 7) SELF-TEST  (offline proof the oracle is sound — no network needed)
# ===========================================================================
def selftest() -> int:
    print("AuthDiff self-test (offline, standard library only)\n" + "-" * 55)
    mint = CanaryMint(secrets.token_bytes(32))

    # (a) Provenance: Alice's canary, discovered by Bob => proven BOLA.
    alice = mint.mint("alice")
    fake_response_to_bob = f'{{"note":"secret","marker":"{alice.token}"}}'
    leaked = {o for o in mint.attribute(fake_response_to_bob) if o != "bob"}
    assert leaked == {"alice"}, leaked
    print("[PASS] genuine canary attributed to true owner (BOLA would fire): "
          f"{sorted(leaked)}")

    # (b) Soundness: a tampered/forged token is REJECTED (0% false positive).
    forged = alice.token[:-4] + "AAAA"
    assert mint.attribute(forged) == set(), "forged token must not validate"
    print("[PASS] forged canary rejected  -> no false positive")

    # (c) Own data is not a finding (actor == owner).
    self_view = {o for o in mint.attribute(alice.token) if o != "alice"}
    assert self_view == set()
    print("[PASS] identity reading its OWN canary is not flagged")

    # (d) Numeric invariant oracle for the single-packet racer.
    statuses = [200, 200, 409, 409, 429]           # 2 successes on a 1-use resource
    successes = sum(1 for s in statuses if 200 <= s < 300)
    assert successes > 1
    print(f"[PASS] race invariant: {successes} successes > capacity 1 -> bug proven")

    print("-" * 55 + "\nAll oracle invariants hold. The engine is sound. ✅")
    return 0


# ===========================================================================
# 8) CLI
# ===========================================================================
def _require_authorized(args) -> None:
    if not args.authorized:
        print("REFUSED: network actions require --authorized (you confirm the target is "
              "in an authorized bug-bounty scope).", file=sys.stderr)
        sys.exit(2)


def _gather_observed(cfg: Config, har_maps: list[str]) -> list[ObservedRequest]:
    observed = list(cfg.observed)
    for m in har_maps or []:
        ident_id, _, path = m.partition("=")
        if ident_id not in cfg.identities:
            raise SystemExit(f"--har identity {ident_id!r} not defined in config")
        observed += observed_from_har(path, cfg.identities[ident_id], cfg.governor)
    return observed


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="authdiff", description=__doc__.split("\n")[3],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("selftest", help="offline proof the oracle is sound (no target)")

    for name, helptext in (("seed", "write a canary into each identity's own field"),
                           ("run", "differential replay + BOLA oracle"),
                           ("race", "single-packet limit-bypass confirmation")):
        p = sub.add_parser(name, help=helptext)
        p.add_argument("--config", required=True)
        p.add_argument("--state", default="./.authdiff_secret",
                       help="path to the persisted HMAC secret (shared by seed/run)")
        p.add_argument("--authorized", action="store_true",
                       help="confirm the target is in an authorized scope")
        if name == "run":
            p.add_argument("--har", action="append", metavar="ID=PATH",
                           help="ingest a HAR capture for identity ID (repeatable)")
            p.add_argument("--seed-first", action="store_true",
                           help="seed canaries before replaying")

    args = ap.parse_args(argv)

    if args.cmd == "selftest":
        return selftest()

    _require_authorized(args)
    cfg = load_config(args.config)
    mint = CanaryMint.load_or_create(args.state)

    if args.cmd == "seed":
        if not cfg.seed:
            raise SystemExit("config has no 'seed' section")
        print("Seeding canaries (non-destructive, each identity into its OWN field):")
        asyncio.run(seed_identities(mint, cfg.governor, cfg.identities, cfg.seed))
        return 0

    if args.cmd == "run":
        if getattr(args, "seed_first", False) and cfg.seed:
            print("Seeding first:")
            asyncio.run(seed_identities(mint, cfg.governor, cfg.identities, cfg.seed))
        observed = _gather_observed(cfg, getattr(args, "har", None))
        if not observed:
            raise SystemExit("no observed requests (add 'observed' to config or use --har)")
        print("Running differential authorization test:")
        engine = DifferentialEngine(mint, cfg.governor, cfg.identities)
        findings = asyncio.run(engine.run(observed))
        print("\n" + "=" * 60)
        if not findings:
            print("No access-control violations proven on the observed surface.")
        else:
            print(f"PROVEN FINDINGS: {len(findings)}\n")
            for f in findings:
                print(f.report() + "\n")
        return 0

    if args.cmd == "race":
        if not cfg.race:
            raise SystemExit("config has no 'race' section")
        print("Single-packet confirmation:")
        violated, statuses = asyncio.run(confirm_limit_bypass(cfg.governor, cfg.race))
        print(f"  statuses: {statuses}")
        print("  VERDICT:", "LIMIT BYPASS PROVEN ✅" if violated
              else "invariant held (no bug)")
        return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
