"""SARIF 2.1.0 reporter for GitHub Code Scanning."""

from __future__ import annotations

import json
from typing import Iterable

from authdiff import __version__
from authdiff.core.models import Finding, Severity

_LEVEL = {
    Severity.INFO: "note", Severity.LOW: "note", Severity.MEDIUM: "warning",
    Severity.HIGH: "error", Severity.CRITICAL: "error",
}


def build_sarif(findings: Iterable[Finding]) -> dict:
    findings = list(findings)
    rule_ids = sorted({f.kind for f in findings})
    rules = [{"id": rid, "name": rid,
              "shortDescription": {"text": f"AuthDiff {rid} finding"}} for rid in rule_ids]
    results = [{
        "ruleId": f.kind,
        "level": _LEVEL[f.severity],
        "message": {"text": f.summary() + " | " + "; ".join(f.proof)},
        "properties": {"confidence": f.confidence.value, "cvss": f.cvss, "id": f.id},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.url}}}],
    } for f in findings]
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "AuthDiff", "version": __version__,
                                "informationUri": "https://github.com/authdiff/authdiff",
                                "rules": rules}},
            "results": results,
        }],
    }


def write_sarif(findings: Iterable[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build_sarif(findings), fh, indent=2)
