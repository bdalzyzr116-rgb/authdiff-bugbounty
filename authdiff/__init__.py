"""AuthDiff — differential authorization testing framework.

A deterministic, canary-oracle based detector for broken access control
(BOLA/IDOR, BFLA, mass-assignment) and single-use state races. Discovery /
proof-of-concept only, for authorized security testing.
"""

from __future__ import annotations

__version__ = "2.0.0"
__all__ = ["__version__"]
