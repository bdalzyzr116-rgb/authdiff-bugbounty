"""Traffic ingestion parsers (HAR, OpenAPI, Postman) with auto-detection."""

from __future__ import annotations

from authdiff.inputs.registry import detect_and_parse, parse_file

__all__ = ["detect_and_parse", "parse_file"]
