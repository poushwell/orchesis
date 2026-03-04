from __future__ import annotations

from orchesis.cost_reporter import CostReporter
from orchesis.cost_tracker import CostTracker
from orchesis.loop_detector import LoopDetector


def _build_reporter(with_loop: bool = True) -> CostReporter:
    tracker = CostTracker(tool_costs={"web_search": 0.5, "read_file": 0.1})
    tracker.record_call("web_search")
    tracker.record_call("read_file")
    loop = LoopDetector(warn_threshold=1, block_threshold=2) if with_loop else None
    if loop is not None:
        loop.check_request({"model": "test", "messages": [], "tool_calls": [{"name": "web_search"}], "content_text": "x"})
        loop.check_request({"model": "test", "messages": [], "tool_calls": [{"name": "web_search"}], "content_text": "x"})
    return CostReporter(tracker, loop_detector=loop)


def test_daily_summary_structure() -> None:
    reporter = _build_reporter()
    summary = reporter.daily_summary()
    assert "date" in summary
    assert "total_usd" in summary
    assert "top_tools" in summary
    assert "hourly_breakdown" in summary
    assert "total_calls" in summary


def test_console_format_contains_header() -> None:
    reporter = _build_reporter()
    text = reporter.format_console()
    assert "Orchesis Cost Report" in text
    assert "Top tools by cost" in text


def test_markdown_format_contains_table() -> None:
    reporter = _build_reporter()
    text = reporter.format_markdown()
    assert "| Tool | Cost |" in text
    assert "# Orchesis Cost Report" in text


def test_top_tools_sorted_by_cost() -> None:
    reporter = _build_reporter(with_loop=False)
    summary = reporter.daily_summary()
    top = summary["top_tools"]
    assert top[0]["cost_usd"] >= top[-1]["cost_usd"]


def test_hourly_breakdown_present() -> None:
    reporter = _build_reporter(with_loop=False)
    summary = reporter.daily_summary()
    assert isinstance(summary["hourly_breakdown"], dict)


def test_loop_stats_included_when_detector_present() -> None:
    reporter = _build_reporter(with_loop=True)
    summary = reporter.daily_summary()
    assert "loops" in summary
    assert "saved_by_loop_detection" in summary


def test_loop_stats_not_included_without_detector() -> None:
    reporter = _build_reporter(with_loop=False)
    summary = reporter.daily_summary()
    assert "loops" not in summary


def test_empty_data_handled_gracefully_console() -> None:
    reporter = CostReporter(CostTracker(), loop_detector=None)
    text = reporter.format_console()
    assert "(no calls)" in text


def test_empty_data_handled_gracefully_markdown() -> None:
    reporter = CostReporter(CostTracker(), loop_detector=None)
    text = reporter.format_markdown()
    assert "| (no calls) | $0.0000 |" in text


def test_daily_summary_total_matches_tracker() -> None:
    tracker = CostTracker(tool_costs={"x": 1.25})
    tracker.record_call("x")
    reporter = CostReporter(tracker)
    summary = reporter.daily_summary()
    assert summary["total_usd"] == 1.25


def test_console_includes_loop_lines_when_loops_exist() -> None:
    reporter = _build_reporter(with_loop=True)
    text = reporter.format_console()
    assert "Loop detection" in text
    assert "Saved by loop detection" in text


def test_markdown_includes_hourly_section_when_non_empty() -> None:
    reporter = _build_reporter()
    text = reporter.format_markdown()
    assert "## Hourly Breakdown" in text

