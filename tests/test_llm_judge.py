from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from orchesis.cli import main
from orchesis.llm_config import load_llm_config
from orchesis.llm_judge import LLMJudge


def test_load_llm_config_none_without_api_key(monkeypatch) -> None:
    monkeypatch.delenv("ORCHESIS_LLM_API_KEY", raising=False)
    assert load_llm_config() is None


def test_load_llm_config_from_env(monkeypatch) -> None:
    monkeypatch.setenv("ORCHESIS_LLM_API_KEY", "k")
    monkeypatch.setenv("ORCHESIS_LLM_MODEL", "gpt-4o-mini")
    cfg = load_llm_config()
    assert cfg is not None
    assert cfg.model == "gpt-4o-mini"


def test_llm_judge_extracts_findings_from_response(monkeypatch) -> None:
    judge = LLMJudge(api_key="k")

    def fake_call(_system: str, _user: str) -> dict:
        return {
            "choices": [
                {
                    "message": {
                        "content": (
                            '{"findings":[{"severity":"high","category":"exfiltration_risk",'
                            '"description":"can exfiltrate","recommendation":"restrict"}]}'
                        )
                    }
                }
            ]
        }

    monkeypatch.setattr(judge, "_call_chat", fake_call)
    findings = judge.analyze_skill("content")
    assert findings
    assert findings[0]["source"] == "llm-judge"


def test_llm_judge_handles_malformed_response(monkeypatch) -> None:
    judge = LLMJudge(api_key="k")
    monkeypatch.setattr(judge, "_call_chat", lambda _system, _user: {"choices": [{"message": {"content": "not-json"}}]})
    findings = judge.analyze_policy("rules: []")
    assert findings == []


def test_cli_scan_llm_judge_warns_without_key() -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("SKILL.md").write_text("safe", encoding="utf-8")
        result = runner.invoke(main, ["scan", "SKILL.md", "--llm-judge"])
        assert result.exit_code == 0
        assert "ORCHESIS_LLM_API_KEY is not set" in result.output


def test_cli_scan_llm_judge_displays_section(monkeypatch) -> None:
    runner = CliRunner()
    with runner.isolated_filesystem():
        Path("SKILL.md").write_text("safe", encoding="utf-8")
        monkeypatch.setenv("ORCHESIS_LLM_API_KEY", "k")
        monkeypatch.setattr(
            LLMJudge,
            "analyze_skill",
            lambda self, _content: [  # noqa: ARG005
                {
                    "severity": "HIGH",
                    "category": "hidden_functionality",
                    "description": "suspicious hidden function",
                    "recommendation": "review",
                    "source": "llm-judge",
                }
            ],
        )
        result = runner.invoke(main, ["scan", "SKILL.md", "--llm-judge"])
        assert result.exit_code == 0
        assert "LLM Judge Findings:" in result.output
        assert "hidden_functionality" in result.output
