from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from orchesis.cli import main
from orchesis.yara_engine import ConditionEvaluator, YaraParser, load_yara_rules, scan_with_yara


RULES_TEXT = """
rule PromptInjection {
    meta:
        description = "Detect prompt injection"
        severity = "CRITICAL"
        category = "injection"
    strings:
        $a = "ignore previous instructions" nocase
        $b = "system prompt" nocase
        $c = /act as (admin|root)/ nocase
    condition:
        any of them
}

rule Exfil {
    meta:
        description = "Exfil risk"
        severity = "HIGH"
        category = "exfiltration"
    strings:
        $curl = "curl" nocase
        $endpoint = /\\/exfil|\\/upload/i
        $b64 = "base64" nocase
    condition:
        $curl and $b64 and any of ($endpoint)
}
"""


def test_parser_parses_multiple_rules() -> None:
    parser = YaraParser()
    rules = parser.parse_string(RULES_TEXT)
    assert len(rules) == 2
    assert rules[0].name == "PromptInjection"


def test_condition_evaluator_any_all_not() -> None:
    ev = ConditionEvaluator()
    assert ev.evaluate("any of them", {"$a"}, {"$a", "$b"}) is True
    assert ev.evaluate("all of them", {"$a"}, {"$a", "$b"}) is False
    assert ev.evaluate("not $b and $a", {"$a"}, {"$a", "$b"}) is True


def test_condition_evaluator_n_of_subset() -> None:
    ev = ConditionEvaluator()
    assert ev.evaluate("2 of ($a, $b, $c)", {"$a", "$c"}, {"$a", "$b", "$c"}) is True
    assert ev.evaluate("2 of ($a, $b, $c)", {"$a"}, {"$a", "$b", "$c"}) is False


def test_rule_match_returns_match() -> None:
    parser = YaraParser()
    rule = parser.parse_string(RULES_TEXT)[0]
    match = rule.match("Please IGNORE previous instructions right now")
    assert match is not None
    assert match.rule_name == "PromptInjection"


def test_rule_match_returns_none_when_condition_false() -> None:
    parser = YaraParser()
    rule = parser.parse_string(RULES_TEXT)[1]
    assert rule.match("curl http://safe.local/test") is None


def test_load_yara_rules_from_dir_and_file(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    f1 = rules_dir / "a.yar"
    f1.write_text(RULES_TEXT, encoding="utf-8")
    builtin_dir = tmp_path / "builtin"
    builtin_dir.mkdir()
    (builtin_dir / "b.yar").write_text(RULES_TEXT, encoding="utf-8")
    rules = load_yara_rules(str(rules_dir), builtin_dir)
    assert len(rules) >= 2


def test_scan_with_yara_collects_findings() -> None:
    parser = YaraParser()
    rules = parser.parse_string(RULES_TEXT)
    findings = scan_with_yara("curl /exfil and base64", rules)
    assert any(item.rule_name == "Exfil" for item in findings)


def test_cli_yara_validate(tmp_path: Path) -> None:
    f = tmp_path / "r.yar"
    f.write_text(RULES_TEXT, encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["yara", "validate", str(f)])
    assert result.exit_code == 0
    assert "OK:" in result.output


def test_cli_yara_test(tmp_path: Path) -> None:
    rule_file = tmp_path / "r.yar"
    target = tmp_path / "skill.md"
    rule_file.write_text(RULES_TEXT, encoding="utf-8")
    target.write_text("ignore previous instructions", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["yara", "test", str(rule_file), str(target)])
    assert result.exit_code == 0
    assert "Matches:" in result.output


def test_cli_yara_list(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r.yar").write_text(RULES_TEXT, encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["yara", "list", "--rules-dir", str(rules_dir)])
    assert result.exit_code == 0
    assert "PromptInjection" in result.output


def test_scan_command_with_yara_option(tmp_path: Path) -> None:
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    (rules_dir / "r.yar").write_text(RULES_TEXT, encoding="utf-8")
    target = tmp_path / "skill.md"
    target.write_text("ignore previous instructions", encoding="utf-8")
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(target), "--yara", str(rules_dir)])
    assert result.exit_code == 0
    assert "yara:" in result.output.lower()
