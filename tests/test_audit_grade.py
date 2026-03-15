from __future__ import annotations

from orchesis.audit_grade import (
    calculate_grade,
    format_badge_embed,
    format_grade_box,
    format_tweet,
    get_ansi_color,
)


def _findings(low: int = 0, medium: int = 0, high: int = 0, critical: int = 0) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    rows.extend({"severity": "low"} for _ in range(low))
    rows.extend({"severity": "medium"} for _ in range(medium))
    rows.extend({"severity": "high"} for _ in range(high))
    rows.extend({"severity": "critical"} for _ in range(critical))
    return rows


def test_grade_a_plus() -> None:
    assert calculate_grade([]) == "A+"


def test_grade_a() -> None:
    assert calculate_grade(_findings(low=2)) == "A"


def test_grade_b_plus_low() -> None:
    assert calculate_grade(_findings(low=4)) == "B+"


def test_grade_b_plus_medium() -> None:
    assert calculate_grade(_findings(medium=1)) == "B+"


def test_grade_b() -> None:
    assert calculate_grade(_findings(medium=3)) == "B"


def test_grade_c_plus_medium() -> None:
    assert calculate_grade(_findings(medium=5)) == "C+"


def test_grade_c_plus_high() -> None:
    assert calculate_grade(_findings(high=1)) == "C+"


def test_grade_c() -> None:
    assert calculate_grade(_findings(high=2)) == "C"


def test_grade_d() -> None:
    assert calculate_grade(_findings(high=5)) == "D"


def test_grade_f() -> None:
    assert calculate_grade(_findings(critical=1)) == "F"


def test_badge_embed_output() -> None:
    badge = format_badge_embed("B+")
    assert "B%2B" in badge
    assert "https://img.shields.io/badge/Orchesis-B%2B-green" in badge


def test_tweet_text_generation() -> None:
    findings = _findings(medium=2, low=1)
    text = format_tweet("B", findings)
    assert "Score: B." in text
    assert "3 issues found." in text
    assert "orchesis.io/audit" in text


def test_colored_terminal() -> None:
    box = format_grade_box("C+", _findings(medium=4))
    assert "\033[" in box
    assert get_ansi_color("C+") in box
    assert "ORCHESIS AUDIT GRADE" in box
    assert "4 issues found" in box

