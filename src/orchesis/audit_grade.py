"""Grade calculation and display helpers for OpenClaw audits."""

from __future__ import annotations

from collections import Counter
from typing import Any
from urllib.parse import quote


_GREEN = "\033[92m"
_YELLOW = "\033[93m"
_RED = "\033[91m"
_RESET = "\033[0m"


def _severity_of(item: Any) -> str:
    if isinstance(item, dict):
        return str(item.get("severity", "")).lower()
    return str(getattr(item, "severity", "")).lower()


def _counts(findings: list[Any]) -> Counter:
    out: Counter = Counter()
    for item in findings:
        sev = _severity_of(item)
        if sev in {"low", "medium", "high", "critical"}:
            out[sev] += 1
    return out


def calculate_grade(findings: list[Any]) -> str:
    """Calculate audit grade from finding severities."""
    counts = _counts(findings)
    critical = int(counts.get("critical", 0))
    high = int(counts.get("high", 0))
    medium = int(counts.get("medium", 0))
    low = int(counts.get("low", 0))
    total = critical + high + medium + low

    if critical >= 1:
        return "F"
    if total == 0:
        return "A+"
    if high >= 4:
        return "D"
    if 2 <= high <= 3:
        return "C"
    if high == 1:
        return "C+"
    if 4 <= medium <= 5:
        return "C+"
    if 2 <= medium <= 3:
        return "B"
    if medium == 1:
        return "B+"
    if 3 <= low <= 5:
        return "B+"
    if 1 <= low <= 2:
        return "A"
    return "A+"


def get_ansi_color(grade: str) -> str:
    """Get ANSI color escape for a grade."""
    value = str(grade or "").upper()
    if value in {"A+", "A", "B+", "B"}:
        return _GREEN
    if value in {"C+", "C"}:
        return _YELLOW
    return _RED


def format_grade_box(grade: str, findings: list[Any]) -> str:
    """Render colored audit-grade box for terminal output."""
    counts = _counts(findings)
    total = sum(int(v) for v in counts.values())
    parts: list[str] = []
    for sev in ("critical", "high", "medium", "low"):
        value = int(counts.get(sev, 0))
        if value > 0:
            parts.append(f"{value} {sev}")
    breakdown = " · ".join(parts) if parts else "no issues"
    color = get_ansi_color(grade)
    colored_grade = f"{color}{grade}{_RESET}"

    width = 29

    def row(text: str) -> str:
        return f"│{text.center(width)}│"

    return "\n".join(
        [
            "┌─────────────────────────────┐",
            row("ORCHESIS AUDIT GRADE"),
            row(colored_grade),
            row(f"{total} issues found"),
            row(breakdown),
            "└─────────────────────────────┘",
        ]
    )


def format_badge_embed(grade: str) -> str:
    """Return shields.io markdown badge for embedding."""
    value = str(grade or "").upper()
    if value in {"A+", "A"}:
        color = "brightgreen"
    elif value in {"B+", "B"}:
        color = "green"
    elif value in {"C+", "C"}:
        color = "yellow"
    else:
        color = "red"
    encoded = quote(value, safe="")
    return f"![Orchesis Grade {value}](https://img.shields.io/badge/Orchesis-{encoded}-{color})"


def format_tweet(grade: str, findings: list[Any]) -> str:
    """Generate share-ready tweet text."""
    total = len(findings)
    value = str(grade or "").upper()
    return (
        f"I audited my AI agent with @orchesis_io. Score: {value}.\n"
        f"{total} issues found. Free scan → orchesis.io/audit"
    )

