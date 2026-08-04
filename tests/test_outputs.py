from __future__ import annotations

import json

from authdiff.core.models import Confidence, Finding, Severity
from authdiff.outputs.html import build_html
from authdiff.outputs.junit import build_junit
from authdiff.outputs.sarif import build_sarif
from authdiff.outputs.webhook import build_payload


def _finding() -> Finding:
    return Finding("BOLA", Severity.HIGH, Confidence.PROVEN, "bob", "alice",
                   "GET", "https://x/api/o/1", 200, proof=["AUTHDIFF..."], cvss=8.1)


def test_sarif_shape() -> None:
    doc = build_sarif([_finding()])
    assert doc["version"] == "2.1.0"
    assert doc["runs"][0]["results"][0]["ruleId"] == "BOLA"
    json.dumps(doc)  # serialisable


def test_junit_has_failure() -> None:
    xml = build_junit([_finding()])
    assert "<testsuite" in xml and "<failure" in xml


def test_html_contains_finding() -> None:
    html = build_html([_finding()])
    assert "BOLA" in html and "alice" in html


def test_webhook_payload_filters_high() -> None:
    payload = build_payload([_finding()], "slack")
    assert "BOLA" in payload["text"]
