from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.token_yield_report import TokenYieldReportGenerator


def _event(
    *,
    hours_ago: int,
    agent_id: str,
    model: str,
    prompt_tokens: int,
    completion_tokens: int,
    unique_ratio: float,
    cache_hit: bool,
    cost: float,
) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return {
        "event_id": f"evt-{agent_id}-{hours_ago}",
        "timestamp": ts.isoformat().replace("+00:00", "Z"),
        "agent_id": agent_id,
        "tool": "shell.exec",
        "params_hash": "abc",
        "cost": float(cost),
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 100,
        "policy_version": "v1",
        "state_snapshot": {
            "session_id": f"s-{agent_id}",
            "model": model,
            "prompt_tokens": int(prompt_tokens),
            "completion_tokens": int(completion_tokens),
            "unique_content_ratio": float(unique_ratio),
            "cache_hit": bool(cache_hit),
        },
    }


def _sample_rows() -> list[dict]:
    return [
        {
            "session_id": "s1",
            "agent_id": "agent-a",
            "model": "gpt-4o-mini",
            "prompt_tokens": 100,
            "completion_tokens": 50,
            "unique_content_ratio": 0.7,
            "cache_hit": False,
            "cost": 0.2,
        },
        {
            "session_id": "s2",
            "agent_id": "agent-b",
            "model": "gpt-4o",
            "prompt_tokens": 120,
            "completion_tokens": 80,
            "unique_content_ratio": 0.5,
            "cache_hit": True,
            "cost": 0.6,
        },
    ]


def test_report_has_executive_summary() -> None:
    report = TokenYieldReportGenerator().generate(_sample_rows(), period="24h")
    summary = str(report["executive_summary"])
    assert summary
    assert "Token Yield" in summary


def test_metrics_computed() -> None:
    report = TokenYieldReportGenerator().generate(_sample_rows(), period="24h")
    metrics = report["metrics"]
    assert metrics["total_tokens_used"] > 0
    assert metrics["total_tokens_saved"] >= 0
    assert 0.0 <= metrics["avg_token_yield"] <= 1.0
    assert 0.0 <= metrics["cache_hit_rate"] <= 1.0


def test_text_export_readable() -> None:
    generator = TokenYieldReportGenerator()
    report = generator.generate(_sample_rows(), period="24h")
    text = generator.export_text(report)
    assert "TOKEN YIELD REPORT" in text
    assert "Executive Summary" in text
    assert "Recommendations" in text


def test_markdown_export_valid() -> None:
    generator = TokenYieldReportGenerator()
    report = generator.generate(_sample_rows(), period="7d")
    markdown = generator.export_markdown(report)
    assert markdown.startswith("# Token Yield Report")
    assert "## Metrics" in markdown
    assert "## Methodology" in markdown


def test_recommendations_generated() -> None:
    generator = TokenYieldReportGenerator()
    low_yield_rows = [
        {
            "session_id": "sx",
            "agent_id": "agent-x",
            "model": "gpt-4o-mini",
            "prompt_tokens": 200,
            "completion_tokens": 100,
            "unique_content_ratio": 0.2,
            "cache_hit": False,
            "cost": 0.3,
            "context_collapse": True,
        }
    ]
    report = generator.generate(low_yield_rows, period="24h")
    assert len(report["recommendations"]) >= 1


def test_api_report_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    decisions_log = tmp_path / "decisions.jsonl"
    events = [
        _event(
            hours_ago=1,
            agent_id="agent-a",
            model="gpt-4o-mini",
            prompt_tokens=100,
            completion_tokens=60,
            unique_ratio=0.7,
            cache_hit=False,
            cost=0.2,
        ),
        _event(
            hours_ago=2,
            agent_id="agent-b",
            model="gpt-4o",
            prompt_tokens=120,
            completion_tokens=80,
            unique_ratio=0.5,
            cache_hit=True,
            cost=0.6,
        ),
    ]
    decisions_log.write_text("\n".join(json.dumps(item, ensure_ascii=False) for item in events) + "\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(decisions_log))
    client = TestClient(app)

    response = client.get("/api/v1/token-yield/report?period=24h", headers={"Authorization": "Bearer test-token"})
    assert response.status_code == 200
    payload = response.json()
    assert "executive_summary" in payload
    assert "metrics" in payload
    assert "benchmark_comparison" in payload

    markdown = client.get("/api/v1/token-yield/report/markdown?period=24h", headers={"Authorization": "Bearer test-token"})
    assert markdown.status_code == 200
    md_payload = markdown.json()
    assert "markdown" in md_payload
    assert "# Token Yield Report" in md_payload["markdown"]

