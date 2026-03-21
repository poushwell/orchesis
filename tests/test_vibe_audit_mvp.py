from __future__ import annotations

from pathlib import Path

from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis.vibe_audit import VibeCodeAuditor


def test_llm_prompt_injection_detected() -> None:
    auditor = VibeCodeAuditor()
    code = 'prompt = f"system: {user_input}"\n'
    report = auditor.audit_code(code, language="python")
    checks = {item["check"] for item in report["findings"]}
    assert "llm_prompt_in_code" in checks


def test_no_output_validation_detected() -> None:
    auditor = VibeCodeAuditor()
    code = (
        "llm_response = client.responses.create(input='hello')\n"
        "answer = llm_response\n"
        "print(answer)\n"
    )
    report = auditor.audit_code(code, language="python")
    checks = {item["check"] for item in report["findings"]}
    assert "no_output_validation" in checks


def test_infinite_retry_detected() -> None:
    auditor = VibeCodeAuditor()
    code = "while True:\n    retry = client.responses.create(input='x')\n"
    report = auditor.audit_code(code, language="python")
    checks = {item["check"] for item in report["findings"]}
    assert "infinite_retry_loop" in checks


def test_score_v2_critical_penalty() -> None:
    auditor = VibeCodeAuditor()
    scored = auditor.compute_score_v2([{"severity": "critical"}, {"severity": "high"}])
    assert scored["penalty"] == 40
    assert scored["score"] == 60
    assert scored["grade"] == "D"


def test_score_v2_clean_code_100() -> None:
    auditor = VibeCodeAuditor()
    scored = auditor.compute_score_v2([])
    assert scored["score"] == 100
    assert scored["grade"] == "A"


def test_grade_assigned_correctly() -> None:
    auditor = VibeCodeAuditor()
    low = auditor.compute_score_v2([{"severity": "low"}])
    critical = auditor.compute_score_v2([{"severity": "critical"}])
    assert low["grade"] in {"A", "B"}
    assert critical["grade"] in {"C", "D", "F"}


def test_directory_summary_returned(tmp_path: Path) -> None:
    auditor = VibeCodeAuditor()
    (tmp_path / "a.py").write_text("API_KEY='secret'\n", encoding="utf-8")
    (tmp_path / "b.py").write_text("def add(a,b):\n    return a+b\n", encoding="utf-8")
    summary = auditor.audit_directory_summary(str(tmp_path))
    assert summary["files_audited"] == 2
    assert "worst_files" in summary
    assert "avg_score" in summary


def test_badge_text_generated() -> None:
    auditor = VibeCodeAuditor()
    report = auditor.audit_code("API_KEY='secret'\n", language="python")
    badge = auditor.format_badge_text(report)
    assert badge.startswith("Vibe Code Audit:")
    assert "/100" in badge


def test_ai_specific_checks_present() -> None:
    auditor = VibeCodeAuditor()
    for key in (
        "llm_prompt_in_code",
        "no_output_validation",
        "infinite_retry_loop",
        "token_count_ignored",
        "hallucination_unchecked",
        "agent_trust_escalation",
    ):
        assert key in auditor.AI_SPECIFIC_CHECKS


def test_cli_summary_flag(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text("API_KEY='secret'\n", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["vibe-audit", "--dir", str(tmp_path), "--summary"])
    assert result.exit_code == 0
    assert "Files audited:" in result.output
