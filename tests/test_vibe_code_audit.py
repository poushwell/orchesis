from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.cli import main
from orchesis.vibe_audit import VibeCodeAuditor
from tests.cli_test_utils import CliRunner


def test_hardcoded_secret_detected() -> None:
    auditor = VibeCodeAuditor()
    code = "API_KEY = 'sk-live-123456789'\nprint('ready')\n"
    report = auditor.audit_code(code, language="python")
    checks = {item["check"] for item in report["findings"]}
    assert "hardcoded_secrets" in checks


def test_sql_injection_detected() -> None:
    auditor = VibeCodeAuditor()
    code = "query = f\"SELECT * FROM users WHERE id = {user_id}\"\n"
    report = auditor.audit_code(code, language="python")
    checks = {item["check"] for item in report["findings"]}
    assert "sql_injection" in checks


def test_command_injection_detected() -> None:
    auditor = VibeCodeAuditor()
    code = "subprocess.run('ls ' + user_input, shell=True)\n"
    report = auditor.audit_code(code, language="python")
    checks = {item["check"] for item in report["findings"]}
    assert "command_injection" in checks


def test_clean_code_high_score() -> None:
    auditor = VibeCodeAuditor()
    code = "def add(a: int, b: int) -> int:\n    return a + b\n"
    report = auditor.audit_code(code, language="python")
    assert report["score"] >= 90.0


def test_grade_assigned_correctly() -> None:
    auditor = VibeCodeAuditor()
    risky = "API_KEY='secret'\nsubprocess.run('cat ' + user_input, shell=True)\n"
    safe = "def hello(name: str) -> str:\n    return f'hello {name}'\n"
    risky_grade = auditor.audit_code(risky, language="python")["grade"]
    safe_grade = auditor.audit_code(safe, language="python")["grade"]
    rank = {"D": 1, "C": 2, "B": 3, "B+": 4, "A": 5, "A+": 6}
    assert rank[safe_grade] >= rank[risky_grade]


def test_audit_file_reads_and_analyzes(tmp_path: Path) -> None:
    auditor = VibeCodeAuditor()
    path = tmp_path / "app.py"
    path.write_text("token = 'abc123secret'\n", encoding="utf-8")
    report = auditor.audit_file(str(path))
    assert report["file_path"] == str(path)
    assert report["findings"]


def test_fix_suggestion_generated() -> None:
    auditor = VibeCodeAuditor()
    fix = auditor.get_fix_suggestion({"check": "sql_injection"})
    assert "parameterized" in fix.lower()


def test_api_audit_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("API_TOKEN", raising=False)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    response = client.post(
        "/api/v1/vibe-audit/code",
        json={"code": "API_KEY='secret'", "language": "python"},
        headers={"Authorization": "Bearer test-token"},
    )
    assert response.status_code == 200
    payload = response.json()
    assert "findings" in payload
    assert payload["critical_count"] >= 1


def test_cli_vibe_audit_command(tmp_path: Path) -> None:
    runner = CliRunner()
    code = "query = f\"SELECT * FROM users WHERE id = {user_id}\""
    result_inline = runner.invoke(main, ["vibe-audit", "--code", code])
    assert result_inline.exit_code == 0
    assert "Findings:" in result_inline.output

    file_path = tmp_path / "app.py"
    file_path.write_text("API_KEY='secret'\n", encoding="utf-8")
    out_path = tmp_path / "report.json"
    result_file = runner.invoke(
        main,
        ["vibe-audit", "--file", str(file_path), "--format", "json", "--output", str(out_path)],
    )
    assert result_file.exit_code == 0
    assert out_path.exists()
    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert "findings" in data
