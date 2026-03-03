from __future__ import annotations

import json
from pathlib import Path

import pytest

from orchesis.mcp_tools import (
    _handle_cost_report,
    _handle_loop_stats,
    _handle_scan_config,
    _handle_scan_skill,
    build_tool_registry,
)


def _secure_config() -> str:
    return json.dumps(
        {
            "mcpServers": {
                "docs-search": {
                    "command": "uvx",
                    "args": ["mcp-docs-search==1.3.2"],
                    "description": "Search docs",
                    "allowedTools": ["search_docs"],
                    "env": {},
                }
            }
        }
    )


def test_scan_config_secure_scores_high() -> None:
    result = _handle_scan_config({"config_json": _secure_config()})
    assert result["score"] >= 80


def test_scan_config_hardcoded_secret_scores_low() -> None:
    result = _handle_scan_config(
        {
            "config_json": json.dumps(
                {"mcpServers": {"x": {"command": "node", "args": ["server.js"], "env": {"OPENAI_API_KEY": "sk-abcdefabcdefabcdefabcdef"}}}}
            )
        }
    )
    assert result["score"] <= 75
    assert any(item["severity"] == "CRITICAL" for item in result["findings"])


def test_scan_config_remote_http_scores_low() -> None:
    result = _handle_scan_config(
        {"config_json": json.dumps({"mcpServers": {"r": {"transport": "sse", "url": "http://evil.example/mcp"}}})}
    )
    assert result["score"] <= 75
    assert any("HTTP" in item["title"] or "http" in item["description"].lower() for item in result["findings"])


def test_scan_config_shell_interpreter_scores_low() -> None:
    result = _handle_scan_config({"config_json": json.dumps({"mcpServers": {"sh": {"command": "bash", "args": ["-c", "echo ok"]}}})})
    assert result["score"] <= 85
    assert any("shell interpreter" in item["title"].lower() for item in result["findings"])


def test_scan_config_shell_metacharacters_scores_low() -> None:
    result = _handle_scan_config({"config_json": json.dumps({"mcpServers": {"x": {"command": "node", "args": ["server.js; rm -rf /"]}}})})
    assert result["score"] <= 75
    assert any("metacharacters" in item["title"].lower() for item in result["findings"])


def test_scan_config_no_version_pinning_has_medium_finding() -> None:
    result = _handle_scan_config({"config_json": json.dumps({"mcpServers": {"x": {"command": "npx", "args": ["mcp-server-fetch"]}}})})
    assert any(item["severity"] == "MEDIUM" for item in result["findings"])


def test_scan_config_root_filesystem_access_has_high_finding() -> None:
    result = _handle_scan_config(
        {"config_json": json.dumps({"mcpServers": {"fs": {"command": "npx", "args": ["mcp-server-filesystem", "/"], "allowedDirectories": ["/"]}}})}
    )
    assert any(item["severity"] == "HIGH" for item in result["findings"])


def test_scan_config_invalid_json_returns_zero() -> None:
    result = _handle_scan_config({"config_json": "{bad}"})
    assert result["score"] == 0
    assert "error" in result


def test_scan_config_empty_servers_returns_100() -> None:
    result = _handle_scan_config({"config_json": json.dumps({"mcpServers": {}})})
    assert result["score"] == 100
    assert result["servers_scanned"] == 0


@pytest.mark.parametrize(
    "key",
    ["mcpServers", "servers", "mcp-servers"],
)
def test_scan_config_supports_multiple_formats(key: str) -> None:
    result = _handle_scan_config({"config_json": json.dumps({key: {"x": {"command": "node", "args": ["server.js"]}}})})
    assert result["servers_scanned"] == 1


def test_check_policy_allowed_tool_returns_allow(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
tool_access:
  mode: allowlist
  default: deny
  allowed:
    - read_file
""".strip(),
        encoding="utf-8",
    )
    handler = build_tool_registry(str(policy))["orchesis_check_policy"]["handler"]
    result = handler({"tool_name": "read_file", "params": {"path": "README.md"}})
    assert result["action"] == "allow"


def test_check_policy_denied_tool_returns_deny_with_reason(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
tool_access:
  mode: allowlist
  default: deny
  allowed:
    - read_file
""".strip(),
        encoding="utf-8",
    )
    handler = build_tool_registry(str(policy))["orchesis_check_policy"]["handler"]
    result = handler({"tool_name": "shell_execute", "params": {"command": "id"}})
    assert result["action"] == "deny"
    assert "tool_access" in result["reason"]


def test_check_policy_unknown_tool_name_missing_returns_error(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []", encoding="utf-8")
    handler = build_tool_registry(str(policy))["orchesis_check_policy"]["handler"]
    result = handler({"params": {}})
    assert result["action"] == "error"


def test_cost_report_returns_markdown_by_default() -> None:
    output = _handle_cost_report({})
    assert output.startswith("# Orchesis Cost Report:")


def test_cost_report_returns_json_when_requested() -> None:
    output = _handle_cost_report({"format": "json"})
    payload = json.loads(output)
    assert "total_usd" in payload


def test_cost_report_returns_console_when_requested() -> None:
    output = _handle_cost_report({"format": "console"})
    assert output.startswith("=== Orchesis Cost Report:")


def test_cost_status_handles_no_budgets_gracefully(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []", encoding="utf-8")
    handler = build_tool_registry(str(policy))["orchesis_cost_status"]["handler"]
    result = handler({})
    assert "daily_spent" in result


def test_cost_status_returns_budget_payload(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
budgets:
  daily: 10.0
""".strip(),
        encoding="utf-8",
    )
    handler = build_tool_registry(str(policy))["orchesis_cost_status"]["handler"]
    result = handler({})
    assert "daily_budget" in result


def test_scan_skill_clean_code_scores_high() -> None:
    result = _handle_scan_skill({"code": "def hello():\n    return 'ok'\n", "filename": "skill.py"})
    assert result["score"] >= 80
    assert result["verdict"] == "SAFE"


def test_scan_skill_eval_scores_low_and_critical() -> None:
    result = _handle_scan_skill({"code": "eval(user_input)", "filename": "bad.py"})
    assert result["score"] <= 75
    assert any(item["severity"] == "CRITICAL" for item in result["findings"])


def test_scan_skill_network_requests_get_high_finding() -> None:
    result = _handle_scan_skill({"code": "requests.get('https://example.com')"})
    assert any(item["severity"] == "HIGH" for item in result["findings"])


def test_scan_skill_env_access_gets_high_finding() -> None:
    result = _handle_scan_skill({"code": "token = os.environ.get('API_KEY')"})
    assert any(item["severity"] == "HIGH" for item in result["findings"])


def test_scan_skill_base64_gets_medium_finding() -> None:
    result = _handle_scan_skill({"code": "import base64\nx = base64.b64decode(data)"})
    assert any(item["severity"] == "MEDIUM" for item in result["findings"])


def test_scan_skill_pastebin_url_gets_critical_finding() -> None:
    result = _handle_scan_skill({"code": "url='https://pastebin.com/abc123'"})
    assert any(item["severity"] == "CRITICAL" for item in result["findings"])


def test_scan_skill_minified_code_gets_medium_finding() -> None:
    long_line = "x=" + ("a" * 700)
    result = _handle_scan_skill({"code": long_line})
    assert any("Minified" in item["title"] for item in result["findings"])


@pytest.mark.parametrize(
    ("code", "expected"),
    [
        ("def f():\n    return 1\n", "SAFE"),
        ("requests.get('https://x')\nos.environ.get('API_KEY')\n", "SUSPICIOUS"),
        ("eval('x')\nchild_process.exec('id')\nrequests.get('https://pastebin.com/x')\n", "DANGEROUS"),
    ],
)
def test_scan_skill_verdict_levels(code: str, expected: str) -> None:
    result = _handle_scan_skill({"code": code})
    assert result["verdict"] == expected


def test_loop_stats_returns_stats_when_available() -> None:
    result = _handle_loop_stats({})
    assert "total_loops_detected" in result


def test_loop_stats_returns_error_when_backend_raises(monkeypatch) -> None:
    import orchesis.engine

    def _boom() -> dict[str, object]:
        raise RuntimeError("no detector")

    monkeypatch.setattr(orchesis.engine, "get_loop_detector_stats", _boom)
    result = _handle_loop_stats({})
    assert result["error"] == "no detector"

