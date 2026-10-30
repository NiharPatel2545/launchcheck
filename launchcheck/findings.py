"""A finding is one problem, written for a founder, not a security team: what is wrong, why it matters, how to fix it."""
from __future__ import annotations

from dataclasses import asdict, dataclass, field

SEVERITY_POINTS = {"high": 15, "medium": 7, "low": 3, "info": 0}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}


@dataclass
class Finding:
    id: str                 # stable short id, e.g. "csp-missing"
    title: str
    severity: str           # high | medium | low | info
    why: str                # why it matters, in plain words
    fix: str                # what to do; may contain a code or config snippet
    where: str = ""         # URL, file:line, header name
    evidence: str = ""      # what we saw (secrets always masked)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


def score(findings: list[Finding]) -> int:
    """100 minus points per finding; the same problem repeated (e.g. ten cookies without a flag) counts at most twice."""
    seen: dict[str, int] = {}
    total = 0
    for f in findings:
        seen[f.id] = seen.get(f.id, 0) + 1
        if seen[f.id] <= 2:
            total += SEVERITY_POINTS[f.severity]
    return max(0, 100 - total)


def grade(s: int) -> str:
    return "A" if s >= 90 else "B" if s >= 75 else "C" if s >= 60 else "D" if s >= 40 else "F"


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_ORDER[f.severity], f.id, f.where))


def mask(secret: str) -> str:
    """Never show a found secret in full: keep enough to recognise it."""
    if len(secret) <= 12:
        return secret[:3] + "…"
    return f"{secret[:6]}…{secret[-4:]} ({len(secret)} chars)"
