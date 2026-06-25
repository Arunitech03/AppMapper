"""Issue 10: shared confidence scoring.

A tiny, consistent vocabulary for how much to trust a finding, used across the
intelligence modules (response intelligence, directory hits, host/gateway
classification, sensitive functions, authorization candidates, attack surface).

Confidence is derived from *evidence strength*, never from severity — a finding
can be high-confidence and low-risk (or vice-versa).
"""

from __future__ import annotations

HIGH = "high"
MEDIUM = "medium"
LOW = "low"

ORDER = {LOW: 0, MEDIUM: 1, HIGH: 2}


def level(score: int) -> str:
    """Map an evidence count / strength score to a confidence level.

    >=2 corroborating signals -> high, exactly 1 -> medium, none -> low.
    """
    if score >= 2:
        return HIGH
    if score == 1:
        return MEDIUM
    return LOW


def strongest(*levels: str) -> str:
    """Return the highest confidence among the given levels (default low)."""
    best = LOW
    for level_ in levels:
        if ORDER.get(level_, 0) > ORDER.get(best, 0):
            best = level_
    return best
