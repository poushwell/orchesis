from __future__ import annotations

from pathlib import Path

from orchesis.config import load_policy
from orchesis.fuzzer import FuzzReport, SyntheticFuzzer
from orchesis.scenarios import AdversarialScenarios


def _production_policy() -> dict:
    path = Path(__file__).resolve().parents[1] / "examples" / "production_policy.yaml"
    return load_policy(path)


def test_fuzzer_generates_requests() -> None:
    fuzzer = SyntheticFuzzer(_production_policy(), seed=42)
    generated = [fuzzer._generate_request()[0] for _ in range(100)]
    assert len(generated) == 100
    for request in generated:
        assert isinstance(request, dict)
        assert isinstance(request.get("tool"), str)
        assert isinstance(request.get("params"), dict)
        assert "cost" in request


def test_fuzzer_deterministic_with_seed() -> None:
    policy = _production_policy()
    first = SyntheticFuzzer(policy, seed=123)
    second = SyntheticFuzzer(policy, seed=123)
    report_a = first.run(num_requests=200)
    report_b = second.run(num_requests=200)
    assert report_a.total_requests == report_b.total_requests
    assert report_a.denied_correctly == report_b.denied_correctly
    assert report_a.allowed_correctly == report_b.allowed_correctly
    assert report_a.bypass_rate == report_b.bypass_rate
    assert [item.mutation for item in report_a.bypasses] == [item.mutation for item in report_b.bypasses]
    assert first.category_counts == second.category_counts


def test_fuzzer_finds_no_bypasses_on_production_policy() -> None:
    fuzzer = SyntheticFuzzer(_production_policy(), seed=42)
    report = fuzzer.run(num_requests=500)
    assert len(report.bypasses) == 0


def test_fuzzer_report_has_all_fields() -> None:
    report = SyntheticFuzzer(_production_policy(), seed=7).run(num_requests=50)
    assert isinstance(report, FuzzReport)
    assert isinstance(report.total_requests, int)
    assert isinstance(report.bypasses, list)
    assert isinstance(report.denied_correctly, int)
    assert isinstance(report.allowed_correctly, int)
    assert isinstance(report.bypass_rate, float)
    assert isinstance(report.categories_tested, list)
    assert isinstance(report.duration_seconds, float)


def test_fuzzer_covers_all_categories() -> None:
    fuzzer = SyntheticFuzzer(_production_policy(), seed=42)
    _ = fuzzer.run(num_requests=1000)
    expected = {
        "path_traversal",
        "sql_injection",
        "cost_manipulation",
        "identity_spoofing",
        "regex_evasion",
        "rate_limit",
        "composite",
    }
    assert set(fuzzer.category_counts.keys()) == expected


def test_scenario_escalation_no_bypass() -> None:
    scenarios = AdversarialScenarios(_production_policy())
    result = scenarios.escalation_attack()
    assert result.name == "escalation_attack"
    assert result.steps_total == 7
    assert len(result.bypasses) == 0
    assert result.success is True


def test_scenario_budget_drainer() -> None:
    scenarios = AdversarialScenarios(_production_policy())
    result = scenarios.budget_drainer()
    assert result.name == "budget_drainer"
    assert result.steps_denied > 0
    assert len(result.bypasses) == 0


def test_scenario_identity_rotation_documented() -> None:
    scenarios = AdversarialScenarios(_production_policy())
    result = scenarios.identity_rotation()
    assert result.name == "identity_rotation"
    assert "known limitation" in result.description.lower()
    assert result.success is False


def test_scenario_mixed_traffic_correct() -> None:
    scenarios = AdversarialScenarios(_production_policy())
    result = scenarios.mixed_legitimate_malicious()
    assert result.name == "mixed_legitimate_malicious"
    assert result.steps_total == 100
    assert len(result.bypasses) == 0
    assert result.steps_denied == 20
    assert result.steps_allowed == 80


def test_scenario_run_all() -> None:
    scenarios = AdversarialScenarios(_production_policy())
    results = scenarios.run_all()
    assert len(results) == 6
