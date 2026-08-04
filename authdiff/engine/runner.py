"""Async orchestrator that ties capture, replay, and oracles together."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from authdiff.core.canary import CanaryMint
from authdiff.core.models import Finding, Identity, ObservedRequest
from authdiff.core.oracles import ReplayObservation
from authdiff.engine.matrix import ReplayTask, build_matrix
from authdiff.engine.plugins import OracleRegistry
from authdiff.logging import get_logger
from authdiff.network.client import AsyncHttpClient
from authdiff.safety.governor import ScopeGovernor

_log = get_logger()


@dataclass
class RunResult:
    findings: list[Finding] = field(default_factory=list)
    tasks_run: int = 0
    errors: int = 0

    @property
    def exit_code(self) -> int:
        return 1 if self.findings else 0


class DifferentialRunner:
    """Executes the replay matrix and evaluates every oracle per observation."""

    def __init__(self, governor: ScopeGovernor, mint: CanaryMint,
                 oracles: OracleRegistry):
        self._gov = governor
        self._mint = mint
        self._oracles = oracles

    @staticmethod
    def _auth(req: ObservedRequest, actor: Identity | None) -> tuple[dict, dict]:
        headers = {k: v for k, v in req.headers.items()
                   if k.lower() not in ("authorization", "cookie")}
        if actor is None:
            return headers, {}
        return {**headers, **actor.headers}, dict(actor.cookies)

    async def _baseline(self, client: AsyncHttpClient, req: ObservedRequest) -> str | None:
        """Fetch the owner's own response to enable content-diff invariants."""
        try:
            resp = await client.request(req.method, req.url, headers=dict(req.headers),
                                        cookies=dict(req.owner.cookies), content=req.body)
            return resp.text
        except Exception:  # noqa: BLE001 - baseline is best-effort
            return None

    async def _run_task(self, client: AsyncHttpClient, task: ReplayTask,
                        baseline: str | None) -> list[Finding]:
        req, actor = task.request, task.actor
        actor_id = actor.id if actor else "<anonymous>"
        headers, cookies = self._auth(req, actor)
        resp = await client.request(req.method, req.url, headers=headers,
                                    cookies=cookies, content=req.body)
        obs = ReplayObservation(
            actor_id=actor_id, owner_id=req.owner.id, method=req.method, url=req.url,
            status_code=resp.status_code, body_text=resp.text,
            baseline_body_text=baseline,
        )
        out: list[Finding] = []
        for oracle in self._oracles:
            try:
                finding = oracle.evaluate(obs)
            except Exception as exc:  # noqa: BLE001 - one oracle must not kill the run
                _log.warning("oracle %s raised: %s", getattr(oracle, "name", "?"), exc)
                continue
            if finding is not None:
                out.append(finding)
        return out

    async def run(self, observed: list[ObservedRequest],
                  identities: list[Identity]) -> RunResult:
        matrix = build_matrix(observed, identities)
        _log.info("replay matrix: %d cross-identity tasks", len(matrix))
        result = RunResult(tasks_run=len(matrix))

        # Pre-compute baselines once per unique request (for content invariants).
        baselines: dict[str, str | None] = {}
        async with AsyncHttpClient(self._gov) as client:
            for req in {t.request.fingerprint(): t.request for t in matrix}.values():
                baselines[req.fingerprint()] = await self._baseline(client, req)

            async def worker(task: ReplayTask) -> list[Finding]:
                try:
                    return await self._run_task(client, task, baselines.get(task.request.fingerprint()))
                except Exception as exc:  # noqa: BLE001
                    _log.debug("task error: %s", exc)
                    result.errors += 1
                    return []

            for batch in await asyncio.gather(*(worker(t) for t in matrix)):
                result.findings.extend(batch)

        # De-duplicate findings by stable id.
        unique: dict[str, Finding] = {f.id: f for f in result.findings}
        result.findings = list(unique.values())
        _log.info("proven/heuristic findings: %d (errors: %d)", len(result.findings), result.errors)
        return result
