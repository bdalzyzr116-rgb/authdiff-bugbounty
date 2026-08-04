"""Chat webhook notifier for Slack / Discord / Microsoft Teams.

Sends a compact critical/high summary. Network egress still flows through the
caller's own httpx usage; this module only builds and posts the payload.
"""

from __future__ import annotations

from typing import Iterable

from authdiff.core.models import Finding, Severity


def build_payload(findings: Iterable[Finding], platform: str = "slack") -> dict:
    findings = [f for f in findings if f.severity.rank >= Severity.HIGH.rank]
    lines = [f"• *{f.kind}* {f.actor} → {f.victim_owner} ({f.url})" for f in findings]
    text = (f"AuthDiff found {len(findings)} high/critical authorization issue(s):\n"
            + "\n".join(lines)) if findings else "AuthDiff: no high/critical findings."
    if platform in ("teams",):
        return {"text": text}
    return {"content": text} if platform == "discord" else {"text": text}


async def notify(webhook_url: str, findings: Iterable[Finding], platform: str = "slack") -> int:
    """POST the finding summary to a webhook; returns the HTTP status code."""
    import httpx

    payload = build_payload(findings, platform)
    async with httpx.AsyncClient(timeout=15) as client:
        resp = await client.post(webhook_url, json=payload)
        return resp.status_code
