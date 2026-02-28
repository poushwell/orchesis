from __future__ import annotations

from pathlib import Path

from orchesis.config import load_policy
from orchesis.corpus import RegressionCorpus
from orchesis.coverage import CoverageTracker
from orchesis.fuzzer import SyntheticFuzzer
from orchesis.models import Decision


def _production_policy() -> dict:
    path = Path(__file__).resolve().parents[1] / "examples" / "production_policy.yaml"
    return load_policy(path)


def test_coverage_tracker_records_decisions() -> None:
    tracker = CoverageTracker()
    for _ in range(10):
        tracker.record(
            Decision(
                allowed=False, reasons=["file_access: denied"], rules_checked=["file_access"]
            ),
            category="path_traversal",
            agent_tier="INTERN",
            request={"tool": "read_file", "context": {"agent": "a1"}},
        )
    report = tracker.report(
        all_rules=["file_access"],
        all_categories=["path_traversal"],
        all_tiers=["INTERN"],
    )
    assert report.total_evaluations == 10
    assert report.rules_triggered["file_access"] == 10
    assert report.categories_tested["path_traversal"] == 10


def test_coverage_report_fields() -> None:
    tracker = CoverageTracker()
    tracker.record(Decision(allowed=True, reasons=[], rules_checked=[]))
    report = tracker.report(["budget_limit"], ["sql_injection"], ["OPERATOR"])
    assert isinstance(report.total_evaluations, int)
    assert isinstance(report.rules_triggered, dict)
    assert isinstance(report.rules_never_triggered, list)
    assert isinstance(report.rule_coverage_pct, float)
    assert isinstance(report.categories_tested, dict)
    assert isinstance(report.categories_missing, list)
    assert isinstance(report.category_coverage_pct, float)
    assert isinstance(report.tier_coverage, dict)
    assert isinstance(report.tiers_never_tested, list)
    assert isinstance(report.decision_distribution, dict)
    assert isinstance(report.unique_tools_tested, list)
    assert isinstance(report.unique_agents_tested, list)
    assert isinstance(report.reasons_seen, dict)
    assert isinstance(report.code_paths, dict)


def test_coverage_identifies_untriggered_rules() -> None:
    tracker = CoverageTracker()
    for rule in ["file_access", "sql_restriction", "budget_limit", "rate_limit", "regex_match"]:
        tracker.record(
            Decision(allowed=False, reasons=[f"{rule}: blocked"], rules_checked=[rule]),
            category="path_traversal",
        )
    report = tracker.report(
        all_rules=[
            "file_access",
            "sql_restriction",
            "budget_limit",
            "rate_limit",
            "regex_match",
            "context_rules",
            "composite",
        ],
        all_categories=["path_traversal"],
        all_tiers=["INTERN"],
    )
    assert set(report.rules_never_triggered) == {"context_rules", "composite"}


def test_coverage_identifies_missing_categories() -> None:
    tracker = CoverageTracker()
    tested = [
        "path_traversal",
        "sql_injection",
        "cost_manipulation",
        "identity_spoofing",
        "regex_evasion",
        "rate_limit",
    ]
    for category in tested:
        tracker.record(
            Decision(allowed=False, reasons=["x: y"], rules_checked=["x"]), category=category
        )
    report = tracker.report(
        all_rules=["x"],
        all_categories=tested + ["composite"],
        all_tiers=["INTERN"],
    )
    assert report.categories_missing == ["composite"]


def test_coverage_suggestions_generated() -> None:
    tracker = CoverageTracker()
    report = tracker.report(
        all_rules=["sql_restriction"],
        all_categories=["sql_injection"],
        all_tiers=["PRINCIPAL"],
    )
    suggestions = tracker.suggestions(report)
    assert suggestions


def test_adaptive_fuzzer_improves_coverage() -> None:
    policy = _production_policy()
    standard = SyntheticFuzzer(policy, seed=7).run(num_requests=12)
    adaptive = SyntheticFuzzer(policy, seed=7).run_adaptive(num_requests=12)
    assert standard.coverage is not None
    assert adaptive.coverage is not None
    assert len(adaptive.coverage.categories_missing) <= len(standard.coverage.categories_missing)


def test_fuzzer_attaches_coverage_to_report() -> None:
    report = SyntheticFuzzer(_production_policy(), seed=42).run(num_requests=100)
    assert report.coverage is not None
    assert report.coverage.total_evaluations == 100


def test_corpus_quality_report() -> None:
    corpus = RegressionCorpus(str(Path(__file__).parent / "corpus"))
    quality = corpus.quality_report()
    assert quality["total_entries"] >= 14
    assert "category_balance" in quality
    assert isinstance(quality["suggestions"], list)


def test_corpus_quality_gaps_identified(tmp_path: Path) -> None:
    corpus = RegressionCorpus(str(tmp_path / "corpus"))
    quality = corpus.quality_report()
    assert "rate_limit" in quality["gaps"]
    assert "composite" in quality["gaps"]


def test_corpus_quality_suggestions(tmp_path: Path) -> None:
    corpus = RegressionCorpus(str(tmp_path / "corpus"))
    entry = {
        "tool": "read_file",
        "params": {"path": "/etc/passwd"},
        "cost": 0.1,
    }
    from orchesis.fuzzer import FuzzResult

    corpus.add_bypass(
        FuzzResult(
            request=entry,
            decision_allowed=True,
            decision_reasons=[],
            expected_deny=True,
            is_bypass=True,
            category="cost_manipulation",
            mutation="one",
        )
    )
    quality = corpus.quality_report()
    assert quality["suggestions"]
