"""Reporters: JSON-lines, SARIF, JUnit XML, HTML, and chat webhooks."""

from __future__ import annotations

from authdiff.outputs.html import write_html
from authdiff.outputs.jsonl import write_jsonl
from authdiff.outputs.junit import write_junit
from authdiff.outputs.sarif import write_sarif

__all__ = ["write_jsonl", "write_sarif", "write_junit", "write_html"]
