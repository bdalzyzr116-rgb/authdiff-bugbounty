from __future__ import annotations

import pytest

from authdiff.safety.governor import (
    NonDestructiveError,
    OutOfScopeError,
    ScopeGovernor,
)


def test_out_of_scope_blocked() -> None:
    gov = ScopeGovernor(["*.target.com"])
    with pytest.raises(OutOfScopeError):
        gov.assert_allowed("GET", "https://evil.example/x")


def test_in_scope_allowed() -> None:
    gov = ScopeGovernor(["*.target.com"])
    gov.assert_allowed("GET", "https://api.target.com/x")  # no raise


def test_non_destructive_default() -> None:
    gov = ScopeGovernor(["api.target.com"])
    with pytest.raises(NonDestructiveError):
        gov.assert_allowed("POST", "https://api.target.com/x")


def test_writes_allowed_when_enabled() -> None:
    gov = ScopeGovernor(["api.target.com"], allow_writes=True)
    gov.assert_allowed("DELETE", "https://api.target.com/x")


def test_cidr_allowlist_localhost() -> None:
    gov = ScopeGovernor([], ["127.0.0.0/8"])
    assert gov.in_scope("http://localhost:5000/x") is True


def test_kill_switch() -> None:
    gov = ScopeGovernor(["api.target.com"])
    gov.kill()
    from authdiff.safety.governor import KillSwitchError

    with pytest.raises(KillSwitchError):
        gov.assert_allowed("GET", "https://api.target.com/x")


@pytest.mark.asyncio
async def test_guard_returns_semaphore() -> None:
    gov = ScopeGovernor(["api.target.com"], rate_per_sec=1000, burst=10)
    sem = await gov.guard("GET", "https://api.target.com/x")
    async with sem:
        pass
