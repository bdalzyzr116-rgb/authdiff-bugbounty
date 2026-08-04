"""JUnit XML reporter for GitLab / Jenkins pipeline visibility.

Each replayed endpoint is a test case; a finding turns it into a failure so CI
dashboards surface authorization regressions natively.
"""

from __future__ import annotations

from typing import Iterable
from xml.sax.saxutils import escape

from authdiff.core.models import Finding


def build_junit(findings: Iterable[Finding]) -> str:
    findings = list(findings)
    cases: list[str] = []
    for f in findings:
        name = escape(f"{f.kind} {f.method} {f.url}")
        message = escape(f.summary())
        detail = escape("; ".join(f.proof))
        cases.append(
            f'    <testcase classname="authdiff.{f.kind}" name="{name}">\n'
            f'      <failure message="{message}">{detail}</failure>\n'
            f"    </testcase>"
        )
    body = "\n".join(cases)
    return (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<testsuite name="authdiff" tests="{len(findings)}" failures="{len(findings)}">\n'
        f"{body}\n"
        "</testsuite>\n"
    )


def write_junit(findings: Iterable[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(build_junit(findings))
