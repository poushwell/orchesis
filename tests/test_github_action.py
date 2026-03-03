from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path


def _load_action_modules():
    root = Path(__file__).resolve().parents[1]
    action_dir = root / ".github" / "actions" / "orchesis-scan"
    if str(action_dir) not in sys.path:
        sys.path.insert(0, str(action_dir))

    spec = importlib.util.spec_from_file_location("orchesis_scan_runner", action_dir / "scan_runner.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load scan_runner.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    import checks
    import sarif_formatter as sarif

    return module, checks, sarif


def _write_json(path: Path, payload: dict) -> None:
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")


def _danger_config() -> dict:
    return {
        "mcpServers": {
            "danger": {
                "command": "node",
                "args": ["server.js", "--allow-all", "echo hi; rm -rf /"],
                "url": "http://api.example.com/mcp",
                "allowed_paths": ["/"],
                "env": {"OPENAI_API_KEY": "sk-abcdefghijklmnopqrstuvwxyz123"},
                "package": "openclaw-mcp@1.2.0",
            }
        }
    }


def _policy_weak() -> str:
    return "rules: []\n"


def test_auto_detection_finds_openclaw_json(tmp_path: Path) -> None:
    runner, _checks, _sarif = _load_action_modules()
    _write_json(tmp_path / "openclaw.json", {"mcpServers": {}})
    cfg, pol = runner.autodetect_targets(tmp_path, "", "")
    assert any(path.name == "openclaw.json" for path in cfg)
    assert pol == []


def test_auto_detection_finds_claude_desktop_config(tmp_path: Path) -> None:
    runner, _checks, _sarif = _load_action_modules()
    _write_json(tmp_path / "claude_desktop_config.json", {"mcpServers": {}})
    cfg, _pol = runner.autodetect_targets(tmp_path, "", "")
    assert any(path.name == "claude_desktop_config.json" for path in cfg)


def test_config_check_detects_command_injection(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    _write_json(p, {"mcpServers": {"x": {"command": "bash -lc 'echo ok; rm -rf /'"}}})
    findings = checks.run_config_checks(str(p))
    assert any(item.id == "CFG_COMMAND_INJECTION" for item in findings)


def test_config_check_detects_env_secrets_exposure(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    _write_json(p, {"mcpServers": {"x": {"command": "node", "env": {"API_TOKEN": "super-secret-value"}}}})
    findings = checks.run_config_checks(str(p))
    assert any(item.id == "CFG_ENV_SECRET_EXPOSED" for item in findings)


def test_config_check_detects_http_url(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    _write_json(p, {"mcpServers": {"x": {"command": "node", "url": "http://evil.example.com"}}})
    findings = checks.run_config_checks(str(p))
    assert any(item.id == "CFG_INSECURE_HTTP" for item in findings)


def test_config_check_detects_overly_permissive_paths(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    _write_json(p, {"mcpServers": {"x": {"command": "node", "allowed_paths": ["/"]}}})
    findings = checks.run_config_checks(str(p))
    assert any(item.id == "CFG_OVERLY_PERMISSIVE_PATHS" for item in findings)


def test_policy_check_flags_missing_budget_section(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "policy.yaml"
    p.write_text(_policy_weak(), encoding="utf-8")
    findings = checks.run_policy_checks(str(p))
    assert any(item.id == "POL_BUDGETS_MISSING" for item in findings)


def test_policy_check_flags_missing_loop_detection(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "policy.yaml"
    p.write_text("default_action: deny\nbudgets:\n  daily: 10\n", encoding="utf-8")
    findings = checks.run_policy_checks(str(p))
    assert any(item.id == "POL_LOOP_DETECTION_MISSING" for item in findings)


def test_policy_check_flags_default_action_not_set(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "policy.yaml"
    p.write_text("budgets:\n  daily: 5\n", encoding="utf-8")
    findings = checks.run_policy_checks(str(p))
    assert any(item.id == "POL_DEFAULT_ACTION_MISSING" for item in findings)


def test_policy_check_flags_no_secret_scanning(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "policy.yaml"
    p.write_text("default_action: deny\nbudgets:\n  daily: 5\n", encoding="utf-8")
    findings = checks.run_policy_checks(str(p))
    assert any(item.id == "POL_SECRET_SCANNING_MISSING" for item in findings)


def test_dependency_check_flags_known_vulnerable_server(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    _write_json(p, {"mcpServers": {"x": {"command": "npx openclaw-mcp@1.0.0"}}})
    findings = checks.run_dependency_checks(str(p))
    assert any(item.id in {"DEP_VULNERABLE_NPX", "DEP_VULNERABLE_PACKAGE"} for item in findings)


def test_text_output_format_contains_findings_summary(tmp_path: Path) -> None:
    runner, _checks, _sarif = _load_action_modules()
    findings = runner.run_scan(tmp_path, [], [])
    out = runner.format_text(findings, "high")
    assert "Summary:" in out
    assert "No findings above threshold." in out


def test_json_output_format_is_valid_json_with_findings_array(tmp_path: Path, monkeypatch) -> None:
    runner, _checks, _sarif = _load_action_modules()
    mcp = tmp_path / "mcp.json"
    _write_json(mcp, _danger_config())
    monkeypatch.chdir(tmp_path)
    code = runner.main(["--format", "json", "--severity", "low", "--fail-on-findings", "false"])
    assert code == 0
    payload = json.loads((tmp_path / "orchesis-report.json").read_text(encoding="utf-8"))
    assert isinstance(payload.get("findings"), list)


def test_sarif_output_is_valid_v2_1_0(tmp_path: Path, monkeypatch) -> None:
    runner, _checks, _sarif = _load_action_modules()
    mcp = tmp_path / "mcp.json"
    _write_json(mcp, _danger_config())
    monkeypatch.chdir(tmp_path)
    runner.main(["--format", "sarif", "--severity", "low", "--fail-on-findings", "false"])
    payload = json.loads((tmp_path / "orchesis-report.sarif").read_text(encoding="utf-8"))
    assert payload["version"] == "2.1.0"
    assert "runs" in payload


def test_severity_filter_medium_skips_low_findings(tmp_path: Path) -> None:
    runner, _checks, _sarif = _load_action_modules()
    mcp = tmp_path / "mcp.json"
    _write_json(mcp, {"mcpServers": {"x": {"command": "node"}}})
    findings = runner.run_scan(tmp_path, [mcp], [])
    filtered = [item for item in findings if runner.severity_meets_threshold(item.severity, "medium")]
    assert all(item.severity in {"medium", "high", "critical"} for item in filtered)


def test_severity_filter_critical_only_critical(tmp_path: Path) -> None:
    runner, _checks, _sarif = _load_action_modules()
    mcp = tmp_path / "mcp.json"
    _write_json(mcp, _danger_config())
    findings = runner.run_scan(tmp_path, [mcp], [])
    filtered = [item for item in findings if runner.severity_meets_threshold(item.severity, "critical")]
    assert all(item.severity == "critical" for item in filtered)


def test_exit_code_1_when_findings_above_threshold(tmp_path: Path, monkeypatch) -> None:
    runner, _checks, _sarif = _load_action_modules()
    _write_json(tmp_path / "mcp.json", _danger_config())
    monkeypatch.chdir(tmp_path)
    code = runner.main(["--severity", "high", "--format", "text", "--fail-on-findings", "true"])
    assert code == 1


def test_exit_code_0_when_no_findings_above_threshold(tmp_path: Path, monkeypatch) -> None:
    runner, _checks, _sarif = _load_action_modules()
    _write_json(tmp_path / "mcp.json", {"mcpServers": {}})
    monkeypatch.chdir(tmp_path)
    code = runner.main(["--severity", "critical", "--format", "text", "--fail-on-findings", "true"])
    assert code == 0


def test_exit_code_0_when_fail_on_findings_false(tmp_path: Path, monkeypatch) -> None:
    runner, _checks, _sarif = _load_action_modules()
    _write_json(tmp_path / "mcp.json", _danger_config())
    monkeypatch.chdir(tmp_path)
    code = runner.main(["--severity", "low", "--format", "text", "--fail-on-findings", "false"])
    assert code == 0


def test_multiple_config_files_scanned_together(tmp_path: Path) -> None:
    runner, _checks, _sarif = _load_action_modules()
    c1 = tmp_path / "mcp.json"
    c2 = tmp_path / "openclaw.json"
    _write_json(c1, _danger_config())
    _write_json(c2, _danger_config())
    findings = runner.run_scan(tmp_path, [c1, c2], [])
    assert len(findings) > 5


def test_empty_config_directory_produces_clean_pass(tmp_path: Path, monkeypatch) -> None:
    runner, _checks, _sarif = _load_action_modules()
    monkeypatch.chdir(tmp_path)
    code = runner.main(["--severity", "high", "--fail-on-findings", "true"])
    assert code == 0
    assert (tmp_path / "orchesis-report.txt").exists()


def test_finding_has_all_required_fields(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    _write_json(p, _danger_config())
    findings = checks.run_config_checks(str(p))
    item = findings[0].to_dict()
    for key in ("id", "severity", "title", "description", "file", "line", "remediation"):
        assert key in item


def test_github_step_summary_output_formatted(tmp_path: Path, monkeypatch) -> None:
    runner, _checks, _sarif = _load_action_modules()
    _write_json(tmp_path / "mcp.json", _danger_config())
    summary = tmp_path / "summary.md"
    output = tmp_path / "output.txt"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.chdir(tmp_path)
    runner.main(["--severity", "high", "--fail-on-findings", "false"])
    text = summary.read_text(encoding="utf-8")
    assert "## Orchesis Security Scan" in text
    assert "Findings above threshold" in text


def test_handles_malformed_config_files_gracefully(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    p.write_text("{bad json", encoding="utf-8")
    findings = checks.run_config_checks(str(p))
    assert any(item.id == "CFG_MALFORMED_JSON" for item in findings)


def test_action_writes_github_outputs(tmp_path: Path, monkeypatch) -> None:
    runner, _checks, _sarif = _load_action_modules()
    _write_json(tmp_path / "mcp.json", _danger_config())
    output = tmp_path / "gh_output.txt"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.chdir(tmp_path)
    runner.main(["--severity", "high", "--fail-on-findings", "false"])
    data = output.read_text(encoding="utf-8")
    assert "findings-count=" in data
    assert "critical-count=" in data
    assert "report-path=" in data


def test_runner_scans_policy_and_config_together(tmp_path: Path) -> None:
    runner, _checks, _sarif = _load_action_modules()
    config = tmp_path / "mcp.json"
    policy = tmp_path / "policy.yaml"
    _write_json(config, _danger_config())
    policy.write_text(_policy_weak(), encoding="utf-8")
    findings = runner.run_scan(tmp_path, [config], [policy])
    assert any(item.id.startswith("CFG_") for item in findings)
    assert any(item.id.startswith("POL_") for item in findings)


def test_config_check_detects_path_traversal_args(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    _write_json(p, {"mcpServers": {"x": {"command": "node", "args": ["../../etc/passwd"]}}})
    findings = checks.run_config_checks(str(p))
    assert any(item.id == "CFG_PATH_TRAVERSAL" for item in findings)


def test_dependency_check_detects_latest_on_risky_server(tmp_path: Path) -> None:
    _runner, checks, _sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    _write_json(p, {"mcpServers": {"x": {"command": "npx openclaw-mcp@latest"}}})
    findings = checks.run_dependency_checks(str(p))
    assert any(item.id == "DEP_LATEST_TAG_ON_RISKY_SERVER" for item in findings)


def test_sarif_formatter_includes_rule_metadata(tmp_path: Path) -> None:
    _runner, checks, sarif = _load_action_modules()
    p = tmp_path / "mcp.json"
    _write_json(p, _danger_config())
    findings = checks.run_config_checks(str(p))
    payload = sarif.build_sarif(findings[:2])
    assert payload["runs"][0]["tool"]["driver"]["rules"]
