"""AuthDiff command-line interface (Typer).

Exit codes (for CI gating):
  0  no findings
  1  findings found
  2  configuration error
  3  scope / safety violation
"""

from __future__ import annotations

import asyncio
import json
import os
from typing import Optional

import typer

from authdiff import __version__
from authdiff.config import Config
from authdiff.core.canary import CanaryMint, KeyRing
from authdiff.core.oracles import BflaOracle, BolaOracle, MassAssignmentOracle
from authdiff.engine.plugins import OracleRegistry, load_entrypoint_oracles
from authdiff.engine.runner import DifferentialRunner
from authdiff.inputs import parse_file
from authdiff.logging import get_logger
from authdiff.outputs import write_html, write_jsonl, write_junit, write_sarif
from authdiff.safety.governor import (
    KillSwitchError,
    NonDestructiveError,
    OutOfScopeError,
    ScopeGovernor,
)

app = typer.Typer(add_completion=False, help="AuthDiff — authorization differential testing.")
_log = get_logger()

EXIT_OK, EXIT_FINDINGS, EXIT_CONFIG, EXIT_SCOPE = 0, 1, 2, 3


def _load_mint(state_path: str) -> CanaryMint:
    if os.path.exists(state_path):
        data = json.load(open(state_path, encoding="utf-8"))
        return CanaryMint(KeyRing.from_export(data["keys"], data["active"]))
    mint = CanaryMint()
    _save_mint(mint, state_path)
    return mint


def _save_mint(mint: CanaryMint, state_path: str) -> None:
    ring = mint.keyring
    with open(state_path, "w", encoding="utf-8") as fh:
        json.dump({"keys": ring.export(), "active": ring.active_kid}, fh)
    try:
        os.chmod(state_path, 0o600)
    except OSError:
        pass


def _governor(cfg: Config, allow_writes: bool) -> ScopeGovernor:
    s = cfg.scope
    return ScopeGovernor(
        s.allow_hosts, s.allow_cidrs, rate_per_sec=s.rate_per_sec, burst=s.burst,
        max_concurrency=s.max_concurrency, allow_writes=allow_writes or s.allow_writes,
        kill_switch_file=s.kill_switch_file,
    )


@app.command()
def version() -> None:
    """Print the AuthDiff version."""
    typer.echo(f"AuthDiff {__version__}")


@app.command()
def selftest() -> None:
    """Prove the oracles are sound offline (no target required)."""
    from authdiff.selftest import run_selftest

    raise typer.Exit(run_selftest())


@app.command()
def run(
    config: str = typer.Option(..., help="Path to YAML/JSON/TOML config"),
    state: str = typer.Option("./.authdiff_state.json", help="Persisted canary keyring"),
    authorized: bool = typer.Option(False, "--authorized", help="Confirm authorized scope"),
    allow_writes: bool = typer.Option(False, help="Permit POST/PUT/PATCH/DELETE"),
    inp: Optional[list[str]] = typer.Option(None, "--input", help="ID=PATH capture (repeatable)"),
    sarif: Optional[str] = typer.Option(None, help="Write SARIF report"),
    jsonl: Optional[str] = typer.Option(None, help="Write JSON-lines report"),
    junit: Optional[str] = typer.Option(None, help="Write JUnit XML report"),
    html: Optional[str] = typer.Option(None, help="Write HTML report"),
) -> None:
    """Run the differential authorization test and emit reports."""
    if not authorized:
        typer.secho("REFUSED: pass --authorized to confirm the target is in scope.", fg="red")
        raise typer.Exit(EXIT_SCOPE)
    try:
        cfg = Config.load(config)
    except (OSError, ValueError, KeyError) as exc:
        typer.secho(f"config error: {exc}", fg="red")
        raise typer.Exit(EXIT_CONFIG)

    mint = _load_mint(state)
    governor = _governor(cfg, allow_writes)

    observed = []
    for entry in cfg.observed:
        owner = cfg.identities[entry["owner"]]
        from authdiff.inputs.base import make_request

        observed.append(make_request(owner, entry["method"], entry["url"],
                                     dict(entry.get("headers", {})),
                                     (entry.get("body") or "").encode() or None))
    for mapping in inp or []:
        ident_id, _, path = mapping.partition("=")
        if ident_id not in cfg.identities:
            typer.secho(f"--input identity {ident_id!r} not in config", fg="red")
            raise typer.Exit(EXIT_CONFIG)
        observed += parse_file(path, cfg.identities[ident_id])

    if not observed:
        typer.secho("no observed requests (add 'observed' or --input)", fg="red")
        raise typer.Exit(EXIT_CONFIG)

    oracles = OracleRegistry()
    oracles.extend([BolaOracle(mint), MassAssignmentOracle(mint)])
    oracles.extend(load_entrypoint_oracles())
    runner = DifferentialRunner(governor, mint, oracles)

    try:
        result = asyncio.run(runner.run(observed, list(cfg.identities.values())))
    except (OutOfScopeError, NonDestructiveError, KillSwitchError) as exc:
        typer.secho(f"safety stop: {exc}", fg="red")
        raise typer.Exit(EXIT_SCOPE)

    for finding in result.findings:
        color = "red" if finding.severity.rank >= 3 else "yellow"
        typer.secho(finding.summary(), fg=color)
    if sarif:
        write_sarif(result.findings, sarif)
    if jsonl:
        write_jsonl(result.findings, jsonl)
    if junit:
        write_junit(result.findings, junit)
    if html:
        write_html(result.findings, html)

    typer.echo(f"\n{len(result.findings)} finding(s); {result.tasks_run} tasks; {result.errors} errors")
    raise typer.Exit(EXIT_FINDINGS if result.findings else EXIT_OK)


@app.command()
def bfla(
    config: str = typer.Option(...),
    state: str = typer.Option("./.authdiff_state.json"),
    authorized: bool = typer.Option(False, "--authorized"),
) -> None:
    """Test privileged endpoints (from config 'observed') with lower-role tokens."""
    if not authorized:
        typer.secho("REFUSED: pass --authorized.", fg="red")
        raise typer.Exit(EXIT_SCOPE)
    try:
        cfg = Config.load(config)
    except (OSError, ValueError, KeyError) as exc:
        typer.secho(f"config error: {exc}", fg="red")
        raise typer.Exit(EXIT_CONFIG)
    mint = _load_mint(state)
    governor = _governor(cfg, allow_writes=False)
    from authdiff.inputs.base import make_request

    observed = [make_request(cfg.identities[e["owner"]], e["method"], e["url"],
                             dict(e.get("headers", {}))) for e in cfg.observed]
    oracles = OracleRegistry()
    oracles.register(BflaOracle())
    runner = DifferentialRunner(governor, mint, oracles)
    result = asyncio.run(runner.run(observed, list(cfg.identities.values())))
    for f in result.findings:
        typer.secho(f.summary(), fg="yellow")
    raise typer.Exit(EXIT_FINDINGS if result.findings else EXIT_OK)


@app.command()
def seed(
    config: str = typer.Option(...),
    state: str = typer.Option("./.authdiff_state.json"),
    authorized: bool = typer.Option(False, "--authorized"),
) -> None:
    """Plant a canary into each identity's own private field (requires writes)."""
    if not authorized:
        typer.secho("REFUSED: pass --authorized.", fg="red")
        raise typer.Exit(EXIT_SCOPE)
    try:
        cfg = Config.load(config)
    except (OSError, ValueError, KeyError) as exc:
        typer.secho(f"config error: {exc}", fg="red")
        raise typer.Exit(EXIT_CONFIG)
    if not cfg.seed:
        typer.secho("config has no 'seed' section", fg="red")
        raise typer.Exit(EXIT_CONFIG)

    from authdiff.core.canary import CanaryType
    from authdiff.network.client import AsyncHttpClient

    mint = _load_mint(state)
    governor = _governor(cfg, allow_writes=True)  # seeding is a write operation
    seed_cfg = cfg.seed

    async def _seed() -> None:
        async with AsyncHttpClient(governor) as client:
            for ident in cfg.identities.values():
                canary = mint.mint(ident.id, CanaryType.TEXT)

                def _fill(tpl: str) -> str:
                    # plain replacement (not str.format) so JSON braces are safe
                    return tpl.replace("{canary}", canary.token).replace("{owner}", ident.id)

                url = _fill(seed_cfg["url_template"])
                body = _fill(seed_cfg.get("body_template", "{canary}")).encode()
                resp = await client.request(seed_cfg.get("method", "PUT"), url,
                                            headers=dict(ident.headers),
                                            cookies=dict(ident.cookies), content=body)
                typer.echo(f"  seeded {ident.id}: HTTP {resp.status_code}")

    try:
        asyncio.run(_seed())
    except (OutOfScopeError, NonDestructiveError, KillSwitchError) as exc:
        typer.secho(f"safety stop: {exc}", fg="red")
        raise typer.Exit(EXIT_SCOPE)
    _save_mint(mint, state)
    typer.secho("seeding complete; keyring persisted", fg="green")


@app.command()
def race(
    config: str = typer.Option(...),
    authorized: bool = typer.Option(False, "--authorized"),
) -> None:
    """Confirm a single-use limit bypass via the single-packet racer."""
    if not authorized:
        typer.secho("REFUSED: pass --authorized.", fg="red")
        raise typer.Exit(EXIT_SCOPE)
    try:
        cfg = Config.load(config)
    except (OSError, ValueError, KeyError) as exc:
        typer.secho(f"config error: {exc}", fg="red")
        raise typer.Exit(EXIT_CONFIG)
    if not cfg.race:
        typer.secho("config has no 'race' section", fg="red")
        raise typer.Exit(EXIT_CONFIG)

    from authdiff.core.oracles import RaceInvariantOracle
    from authdiff.network.racer import SinglePacketRacer

    governor = _governor(cfg, allow_writes=True)
    req = cfg.race["request"]
    governor.assert_allowed(req["method"], req["url"])
    try:
        racer = SinglePacketRacer(req["url"])
    except ValueError as exc:
        typer.secho(f"race unavailable: {exc}", fg="red")
        raise typer.Exit(EXIT_CONFIG)
    statuses = asyncio.run(racer.race(req["method"], dict(req.get("headers", {})),
                                      (req.get("body") or "").encode(),
                                      int(cfg.race.get("n", 20))))
    oracle = RaceInvariantOracle(int(cfg.race.get("seeded_capacity", 1)))
    finding = oracle.evaluate_statuses("actor", req["url"], statuses)
    typer.echo(f"statuses: {statuses}")
    if finding:
        typer.secho(finding.summary() + " | " + finding.proof[0], fg="red")
        raise typer.Exit(EXIT_FINDINGS)
    typer.secho("invariant held — no bug", fg="green")
    raise typer.Exit(EXIT_OK)


if __name__ == "__main__":  # pragma: no cover
    app()
