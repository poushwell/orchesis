from __future__ import annotations

import json
from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.verify import OrchesisVerifier


def test_verify_runs_all_checks(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("orchesis.yaml").write_text("loop_detection:\n  enabled: true\n", encoding="utf-8")
    verifier = OrchesisVerifier()
    result = verifier.run(policy_path="orchesis.yaml", proxy_url="http://localhost:65534")
    assert result["total"] == len(verifier.CHECKS)
    assert set(result["checks"]) == set(verifier.CHECKS)


def test_schema_injection_detected(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    cfg_dir = tmp_path / ".openclaw"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "config.json").write_text('{"includeConfigSchema": true}', encoding="utf-8")
    verifier = OrchesisVerifier()
    check = verifier._check_schema_injection()  # noqa: SLF001
    assert check["status"] == "FAIL"
    assert "overspend" in check["message"]


def test_schema_injection_clean(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    cfg_dir = tmp_path / ".openclaw"
    cfg_dir.mkdir(parents=True, exist_ok=True)
    (cfg_dir / "config.json").write_text('{"includeConfigSchema": false}', encoding="utf-8")
    verifier = OrchesisVerifier()
    check = verifier._check_schema_injection()  # noqa: SLF001
    assert check["status"] == "PASS"


def test_policy_valid_passes(tmp_path: Path) -> None:
    policy = tmp_path / "orchesis.yaml"
    policy.write_text("rules: []\n", encoding="utf-8")
    verifier = OrchesisVerifier()
    check = verifier._check_policy(str(policy))  # noqa: SLF001
    assert check["status"] == "PASS"


def test_policy_missing_warns(tmp_path: Path) -> None:
    verifier = OrchesisVerifier()
    check = verifier._check_policy(str(tmp_path / "missing.yaml"))  # noqa: SLF001
    assert check["status"] == "WARN"


def test_proxy_not_running_warns() -> None:
    verifier = OrchesisVerifier()
    check = verifier._check_proxy("http://localhost:65534")  # noqa: SLF001
    assert check["status"] == "WARN"


def test_format_report_generated() -> None:
    verifier = OrchesisVerifier()
    result = {
        "passed": 1,
        "failed": 1,
        "warnings": 0,
        "total": 2,
        "ready": False,
        "schema_injection_found": True,
        "checks": {
            "policy_valid": {"status": "PASS", "message": "ok"},
            "schema_injection_risk": {"status": "FAIL", "message": "bad"},
        },
    }
    text = verifier.format_report(result)
    assert "orchesis verify" in text
    assert "schema_injection_risk" in text
    assert "Savings: ~$270/month" in text


def test_cli_verify_command() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("orchesis.yaml").write_text(
            "loop_detection:\n  enabled: true\n"
            "budgets:\n  enabled: true\n"
            "recording:\n  enabled: true\n"
            "threat_intel:\n  enabled: true\n",
            encoding="utf-8",
        )
        Path(".openclaw").mkdir(parents=True, exist_ok=True)
        Path(".openclaw/config.json").write_text('{"includeConfigSchema": false}', encoding="utf-8")
        result = runner.invoke(main, ["verify", "--policy", "orchesis.yaml", "--proxy", "http://localhost:65534"])
        assert result.exit_code == 0
        assert "orchesis verify" in result.output


def test_json_output_flag() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("orchesis.yaml").write_text("rules: []\n", encoding="utf-8")
        Path(".openclaw").mkdir(parents=True, exist_ok=True)
        Path(".openclaw/config.json").write_text('{"includeConfigSchema": false}', encoding="utf-8")
        result = runner.invoke(main, ["verify", "--policy", "orchesis.yaml", "--json"])
        assert result.exit_code == 0
        payload = json.loads(result.output)
        assert "checks" in payload
        assert payload["total"] == 7


def test_ready_flag_false_on_fail(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    Path("orchesis.yaml").write_text("rules: []\n", encoding="utf-8")
    Path(".openclaw").mkdir(parents=True, exist_ok=True)
    Path(".openclaw/config.json").write_text('{"includeConfigSchema": true}', encoding="utf-8")
    verifier = OrchesisVerifier()
    result = verifier.run(policy_path="orchesis.yaml", proxy_url="http://localhost:65534")
    assert result["schema_injection_found"] is True
    assert result["ready"] is False
