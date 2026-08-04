"""Logging helpers with automatic secret redaction.

Tokens, cookies, and Authorization values must never reach logs. The
:class:`SecretRedactionFilter` scrubs common credential patterns from every
record regardless of where it originates.
"""

from __future__ import annotations

import logging
import re

_REDACTIONS = [
    re.compile(r"(?i)(authorization\"?\s*[:=]\s*\"?)(bearer\s+)?[A-Za-z0-9._\-]+"),
    re.compile(r"(?i)(cookie\"?\s*[:=]\s*)[^\s,}]+"),
    re.compile(r"(?i)(api[_-]?key\"?\s*[:=]\s*\"?)[A-Za-z0-9._\-]+"),
]


class SecretRedactionFilter(logging.Filter):
    """Redacts credential-looking substrings from log messages."""

    def filter(self, record: logging.LogRecord) -> bool:  # noqa: A003
        msg = record.getMessage()
        for pat in _REDACTIONS:
            msg = pat.sub(r"\1<redacted>", msg)
        record.msg = msg
        record.args = ()
        return True


def get_logger(name: str = "authdiff", level: int = logging.INFO) -> logging.Logger:
    """Return a configured logger with redaction installed exactly once."""
    logger = logging.getLogger(name)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)-7s %(name)s: %(message)s"))
        handler.addFilter(SecretRedactionFilter())
        logger.addHandler(handler)
        logger.setLevel(level)
        logger.propagate = False
    return logger
