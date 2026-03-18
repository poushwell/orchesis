from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.publisher import FindingsPublisher


def _decision(
    *,
    decision: str = "ALLOW",
    reason: str = "",
    minutes_ago: int = 10,
    eval_us: int = 5000,
) -> dict:
    ts = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return {
        "timestamp": ts.isoformat(),
        "agent_id": "agent_a",
        "tool": "chat",
        "decision": decision,
        "reasons": [reason] if reason else [],
        "evaluation_duration_us": eval_us,
        "cost": 0.1,
    }


def test_report_built_correctly() -> None:
    decisions = [
        _decision(decision="ALLOW"),
        _decision(decision="DENY", reason="prompt_injection: blocked"),
    ]
    report = FindingsPublisher().build_report(decisions, period_days=7)
    assert isinstance(report["report_id"], str) and report["report_id"]
    assert report["period_days"] == 7
    assert "generated_at" in report
    assert report["stats"]["total_requests"] == 2
    assert "findings" in report
    assert report["environment"]["pipeline_phases"] == 17


def test_anonymization_no_pii() -> None:
    decisions = [
        _decision(
            decision="DENY",
            reason="user@example.com: leaked sk-test-123 and SSN 111-22-3333",
        )
    ]
    report = FindingsPublisher().build_report(decisions, period_days=7)
    findings_blob = json.dumps(report["findings"], ensure_ascii=False)
    assert "user@example.com" not in findings_blob
    assert "111-22-3333" not in findings_blob
    assert "sk-test-123" not in findings_blob


def test_export_local_creates_file(tmp_path: Path) -> None:
    report = FindingsPublisher().build_report([_decision()], period_days=7)
    out = tmp_path / "report.json"
    FindingsPublisher().export_local(report, str(out))
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["report_id"] == report["report_id"]


def test_preview_mode_no_upload(monkeypatch) -> None:
    called = {"upload": False}

    def _fail_publish(self, report):  # noqa: ANN001
        called["upload"] = True
        raise AssertionError("publish() should not be called in preview mode")

    monkeypatch.setattr(FindingsPublisher, "publish", _fail_publish)
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("decisions.jsonl").write_text(
            json.dumps(_decision(decision="DENY", reason="prompt_injection: blocked")) + "\n",
            encoding="utf-8",
        )
        result = runner.invoke(main, ["publish", "--preview", "--upload"])
        assert result.exit_code == 0
        assert "\"report_id\"" in result.output
        assert called["upload"] is False


def test_stats_computed_correctly() -> None:
    decisions = [
        _decision(decision="ALLOW", eval_us=1000),
        _decision(decision="DENY", reason="ssrf: blocked", eval_us=3000),
        _decision(decision="DENY", reason="prompt_injection: blocked", eval_us=5000),
    ]
    report = FindingsPublisher().build_report(decisions, period_days=7)
    stats = report["stats"]
    assert stats["total_requests"] == 3
    assert abs(float(stats["blocked_percent"]) - 66.67) < 0.05
    assert abs(float(stats["avg_response_ms"]) - 3.0) < 1e-9
    assert len(stats["top_threat_categories"]) >= 1


def test_cli_publish_command() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        lines = [
            json.dumps(_decision(decision="ALLOW")),
            json.dumps(_decision(decision="DENY", reason="prompt_injection: blocked")),
        ]
        Path("decisions.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = runner.invoke(main, ["publish", "--period", "7", "--output", "report.json"])
        assert result.exit_code == 0
        assert Path("report.json").exists()
        assert "Saved report to report.json" in result.output
