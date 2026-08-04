"""JSON-lines reporter for SIEM / Elastic ingestion."""

from __future__ import annotations

import json
from typing import Iterable

from authdiff.core.models import Finding


def write_jsonl(findings: Iterable[Finding], path: str) -> None:
    with open(path, "w", encoding="utf-8") as fh:
        for finding in findings:
            fh.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
