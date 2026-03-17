from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.benchmark import (
    ORCHESIS_BENCHMARK_V1,
    BenchmarkCase,
    BenchmarkReport,
    BenchmarkSuite,
)


def test_v1_dataset_size() -> None:
    assert len(ORCHESIS_BENCHMARK_V1) >= 40


def test_v1_dataset_categories() -> None:
    categories = {case.category for case in ORCHESIS_BENCHMARK_V1}
    assert categories == {"security", "cost", "reliability", "compliance"}


def test_v1_case_ids_unique() -> None:
    case_ids = [case.id for case in ORCHESIS_BENCHMARK_V1]
    assert len(case_ids) == len(set(case_ids))


def test_run_returns_report() -> None:
    report = BenchmarkSuite().run()
    assert isinstance(report, BenchmarkReport)


def test_pass_rate_range() -> None:
    report = BenchmarkSuite().run()
    assert 0.0 <= report.pass_rate <= 1.0


def test_by_category_keys() -> None:
    report = BenchmarkSuite().run()
    assert set(report.by_category.keys()) == {"security", "cost", "reliability", "compliance"}


def test_by_severity_keys() -> None:
    report = BenchmarkSuite().run()
    assert {"critical", "high", "medium", "low"}.issubset(set(report.by_severity.keys()))


def test_run_category_filter() -> None:
    report = BenchmarkSuite().run_category("security")
    assert report.total == 15
    assert set(report.by_category.keys()) == {"security"}


def test_custom_evaluator() -> None:
    report = BenchmarkSuite().run(evaluator_fn=lambda _request, _policy: "block")
    assert all(result.actual_action == "block" for result in report.results)


def test_compare_delta() -> None:
    suite = BenchmarkSuite()
    a = suite.run(evaluator_fn=lambda _request, _policy: "allow")
    b = suite.run(evaluator_fn=lambda _request, _policy: "block")
    diff = suite.compare(a, b)
    assert "pass_rate_delta" in diff
    assert isinstance(diff["pass_rate_delta"], float)


def test_compare_regression_count() -> None:
    suite = BenchmarkSuite()
    report_a = suite.run(evaluator_fn=lambda _request, _policy: "allow")
    report_b = suite.run(evaluator_fn=lambda _request, _policy: "block")
    diff = suite.compare(report_a, report_b)
    assert diff["regression_count"] >= 0


def test_compare_improvement_count() -> None:
    suite = BenchmarkSuite()
    report_a = suite.run(evaluator_fn=lambda _request, _policy: "block")
    report_b = suite.run(evaluator_fn=lambda _request, _policy: "allow")
    diff = suite.compare(report_a, report_b)
    assert diff["improvement_count"] >= 0


def test_load_cases_from_jsonl(tmp_path: Path) -> None:
    payload = {
        "id": "X-001",
        "category": "security",
        "subcategory": "custom",
        "description": "custom case",
        "request": {"tool": "chat"},
        "expected_action": "allow",
        "severity": "low",
        "tags": ["custom"],
        "reference": "CUSTOM-1",
    }
    path = tmp_path / "cases.jsonl"
    path.write_text(json.dumps(payload, ensure_ascii=False) + "\n", encoding="utf-8")
    cases = BenchmarkSuite.load_cases_from_jsonl(str(path))
    assert len(cases) == 1
    assert cases[0].id == "X-001"


def test_export_json(tmp_path: Path) -> None:
    report = BenchmarkSuite().run()
    out = tmp_path / "report.json"
    BenchmarkSuite.export_report(report, str(out), fmt="json")
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["suite_name"] == "ORCHESIS_BENCHMARK_V1"


def test_export_csv(tmp_path: Path) -> None:
    report = BenchmarkSuite().run()
    out = tmp_path / "report.csv"
    BenchmarkSuite.export_report(report, str(out), fmt="csv")
    text = out.read_text(encoding="utf-8")
    assert "case_id,category,expected_action,actual_action,passed,latency_ms,details" in text


def test_default_evaluator_blocks_credential() -> None:
    action = BenchmarkSuite._default_evaluator({"message": "token sk-123"}, {})
    assert action == "block"


def test_default_evaluator_allows_safe() -> None:
    action = BenchmarkSuite._default_evaluator({"tool": "chat", "message": "hello", "cost": 1.0}, {})
    assert action == "allow"


def test_latency_measured() -> None:
    report = BenchmarkSuite().run()
    assert all(result.latency_ms > 0 for result in report.results)


def test_benchmark_case_fields() -> None:
    sample = ORCHESIS_BENCHMARK_V1[0]
    assert isinstance(sample, BenchmarkCase)
    assert sample.id
    assert sample.category
    assert sample.expected_action in {"block", "allow", "warn"}
    assert sample.severity in {"critical", "high", "medium", "low"}


def test_benchmark_report_totals() -> None:
    report = BenchmarkSuite().run()
    assert report.passed + report.failed == report.total


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules: []
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _make_app(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app


def test_compare_to_baseline_returns_score() -> None:
    suite = BenchmarkSuite()
    report = suite.run()
    payload = {
        "results": [
            {
                "case_id": row.case_id,
                "passed": row.passed,
            }
            for row in report.results
        ]
    }
    cmp = suite.compare_to_baseline(payload)
    assert isinstance(cmp["score"], float)
    assert 0.0 <= cmp["score"] <= 100.0
    assert 0.0 <= cmp["percentile"] <= 100.0


def test_export_results_json() -> None:
    suite = BenchmarkSuite()
    payload = {"results": [{"case_id": "SEC-001", "passed": True}]}
    text = suite.export_results(payload, format="json")
    parsed = json.loads(text)
    assert parsed["results"][0]["case_id"] == "SEC-001"


def test_export_results_csv() -> None:
    suite = BenchmarkSuite()
    payload = {
        "results": [
            {
                "case_id": "SEC-001",
                "category": "security",
                "expected_action": "block",
                "actual_action": "block",
                "passed": True,
                "latency_ms": 1.2,
                "details": "ok",
            }
        ]
    }
    text = suite.export_results(payload, format="csv")
    assert "case_id,category,expected_action,actual_action,passed,latency_ms,details" in text
    assert "SEC-001" in text


@pytest.mark.asyncio
async def test_api_cases_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    async with await _client(app) as client:
        res = await client.get("/api/v1/benchmark/cases", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["total"] == len(ORCHESIS_BENCHMARK_V1)
    assert len(payload["cases"]) == len(ORCHESIS_BENCHMARK_V1)


@pytest.mark.asyncio
async def test_api_run_case_endpoint(tmp_path: Path) -> None:
    app = _make_app(tmp_path)
    case_id = ORCHESIS_BENCHMARK_V1[0].id
    async with await _client(app) as client:
        res = await client.get(f"/api/v1/benchmark/run/{case_id}", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["total"] == 1
    assert isinstance(payload.get("comparison", {}).get("score"), float)

