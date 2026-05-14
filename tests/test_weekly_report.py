from __future__ import annotations

import re
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.weekly_report import WeeklyReportGenerator


def _client(tmp_path: Path, monkeypatch) -> TestClient:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    return TestClient(app)


def test_report_generated() -> None:
    gen = WeeklyReportGenerator()
    report = gen.generate({})
    assert report["period"] == "weekly"
    assert "report_id" in report
    assert "generated_at" in report


def test_all_sections_present() -> None:
    gen = WeeklyReportGenerator()
    report = gen.generate({})
    sections = report["sections"]
    assert "security" in sections
    assert "cost" in sections
    assert "compliance" in sections
    assert "competitive" in sections
    assert "research" in sections


def test_highlights_extracted() -> None:
    gen = WeeklyReportGenerator()
    report = gen.generate({"cost": {"savings": 12.5}, "security": {"blocked": 3}})
    assert any("Saved $12.50" in item for item in report["highlights"])
    assert any("Blocked 3 threats" in item for item in report["highlights"])


def test_actions_generated() -> None:
    gen = WeeklyReportGenerator()
    report = gen.generate({"compliance": {"eu_score": 0.72}})
    assert report["actions_required"]
    assert "score below 80%" in report["actions_required"][0]


def test_report_id_format() -> None:
    gen = WeeklyReportGenerator()
    report = gen.generate({})
    assert re.match(r"^weekly-\d{4}-W\d{2}$", report["report_id"])


def test_api_weekly_report_endpoint(tmp_path: Path, monkeypatch) -> None:
    client = _client(tmp_path, monkeypatch)
    response = client.get("/api/v1/weekly-report", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert payload["period"] == "weekly"
    assert "sections" in payload
