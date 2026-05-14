from __future__ import annotations

from orchesis.coverage_report import CoverageReportGenerator


def test_analysis_returns_counts() -> None:
    generator = CoverageReportGenerator()
    row = generator.analyze()
    assert "total_modules" in row
    assert "tested_modules" in row
    assert "untested_modules" in row
    assert row["total_modules"] >= row["tested_modules"]


def test_coverage_rate_0_to_1() -> None:
    generator = CoverageReportGenerator()
    row = generator.analyze()
    assert 0.0 <= row["coverage_rate"] <= 1.0


def test_grade_assigned() -> None:
    generator = CoverageReportGenerator()
    row = generator.analyze()
    assert row["grade"] in {"A", "B", "C"}


def test_untested_list_returned() -> None:
    generator = CoverageReportGenerator()
    rows = generator.get_untested()
    assert isinstance(rows, list)


def test_test_files_counted() -> None:
    generator = CoverageReportGenerator()
    row = generator.analyze()
    assert row["test_files"] > 0
