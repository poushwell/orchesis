from __future__ import annotations

import importlib
import re
import subprocess
import sys
from pathlib import Path

import pytest
from tests.cli_test_utils import CliRunner

from orchesis.cli import main
from orchesis import __version__

EXPECTED_MODULE_COUNT = "270"


def test_all_doc_files_exist() -> None:
    required = [
        Path("README.md"),
        Path("QUICK_START.md"),
        Path("docs/QUICKSTART.md"),
        Path("docs/configuration.md"),
        Path("docs/POLICY_REFERENCE.md"),
        Path("docs/TRUST_TIERS.md"),
        Path("docs/API_REFERENCE.md"),
        Path("docs/ARCHITECTURE.md"),
        Path("docs/SECURITY.md"),
        Path("docs/THREAT_MODEL.md"),
    ]
    for path in required:
        assert path.exists(), f"Missing documentation file: {path}"


def test_readme_has_required_sections() -> None:
    text = Path("README.md").read_text(encoding="utf-8")
    for section in (
        "## Installation",
        "## How it works",
        "## What Orchesis does",
        "## By the numbers",
        "## Free MCP Security Scanner",
    ):
        assert section in text


def test_readme_has_install_command() -> None:
    text = Path("README.md").read_text(encoding="utf-8")
    assert "pip install orchesis" in text


def test_readme_has_quick_start() -> None:
    text = Path("README.md").read_text(encoding="utf-8")
    assert "GET%20STARTED" in text


def test_readme_has_badge_tests() -> None:
    text = Path("README.md").read_text(encoding="utf-8")
    assert "img.shields.io/badge/tests-" in text
    assert "%20passing-22c55e" in text
    assert re.search(r"tests-\d+%20passing-22c55e", text) is not None


def test_readme_has_license_badge() -> None:
    text = Path("README.md").read_text(encoding="utf-8")
    assert "img.shields.io/badge/license-MIT-blue" in text


def test_quick_start_exists() -> None:
    assert Path("QUICK_START.md").exists()


def test_issue_templates_exist() -> None:
    assert Path(".github/ISSUE_TEMPLATE/bug_report.yml").exists()
    assert Path(".github/ISSUE_TEMPLATE/feature_request.yml").exists()


def test_pr_template_exists() -> None:
    assert Path(".github/PULL_REQUEST_TEMPLATE.md").exists()


def test_security_md_exists() -> None:
    assert Path("SECURITY.md").exists()


def test_security_md_has_email() -> None:
    text = Path("SECURITY.md").read_text(encoding="utf-8")
    assert "security@orchesis.io" in text


def test_security_md_has_response_timeline() -> None:
    text = Path("SECURITY.md").read_text(encoding="utf-8")
    assert "## Reporting a Vulnerability" in text
    assert "### Response Timeline" in text
    assert "within 48 hours" in text


def test_privacy_md_exists() -> None:
    assert Path("PRIVACY.md").exists()


def test_privacy_md_states_no_telemetry() -> None:
    text = Path("PRIVACY.md").read_text(encoding="utf-8")
    assert "Does not include telemetry" in text


def test_privacy_md_states_self_hosted() -> None:
    text = Path("PRIVACY.md").read_text(encoding="utf-8")
    assert "self-hosted" in text.lower()


def test_policy_reference_covers_all_rules() -> None:
    text = Path("docs/POLICY_REFERENCE.md").read_text(encoding="utf-8")
    for rule_name in (
        "file_access",
        "sql_restriction",
        "budget_limit",
        "rate_limit",
        "regex_match",
        "context_rules",
        "composite",
    ):
        assert rule_name in text


def test_api_reference_covers_all_endpoints() -> None:
    text = Path("docs/API_REFERENCE.md").read_text(encoding="utf-8")
    endpoints = (
        "/api/dashboard/overview",
        "/api/dashboard/agents",
        "/api/flow/sessions",
        "/api/flow/analyze",
        "/api/experiments",
        "/api/tasks/outcomes",
        "/api/threats",
        "/api/threats/stats",
        "/stats",
        "/v1/chat/completions",
    )
    for endpoint in endpoints:
        assert endpoint in text


def test_package_builds_cleanly(tmp_path: Path) -> None:
    try:
        importlib.import_module("build.__main__")
    except Exception:
        pytest.skip("build package not available")

    dist_dir = tmp_path / "dist"
    build_cmd = [sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(dist_dir)]
    result = subprocess.run(build_cmd, capture_output=True, text=True)
    if result.returncode != 0:
        output = (result.stdout or "") + (result.stderr or "")
        known_env_errors = (
            "No module named build.__main__",
            "'build' is a package and cannot be directly executed",
            "ModuleNotFoundError: No module named 'build.__main__'",
            "ERROR Backend subprocess exited when trying to invoke build_sdist",
            "[WinError 2]",
            "could not delete",
        )
        if any(marker in output for marker in known_env_errors):
            pytest.skip("build invocation unavailable in this environment")
    assert result.returncode == 0, result.stdout + result.stderr

    artifacts = sorted(dist_dir.glob("orchesis-*"))
    assert artifacts, "Build artifacts not found"

    twine_cmd = [sys.executable, "-m", "twine", "check", *[str(item) for item in artifacts]]
    check = subprocess.run(twine_cmd, capture_output=True, text=True)
    if check.returncode != 0 and "No module named twine" in (check.stderr or ""):
        pytest.skip("twine not available in this environment")
    assert check.returncode == 0, check.stdout + check.stderr


def test_all_cli_commands_have_help() -> None:
    runner = CliRunner()
    commands = [
        "init",
        "keygen",
        "verify",
        "validate",
        "audit",
        "agents",
        "fuzz",
        "scenarios",
        "mutate",
        "invariants",
        "replay",
        "forensic",
        "corpus",
        "serve",
        "reliability-report",
        "policy-history",
        "rollback",
    ]
    for command in commands:
        result = runner.invoke(main, [command, "--help"])
        assert result.exit_code == 0, f"--help failed for command: {command}"
        assert "Usage:" in result.output


def test_readme_metrics_are_updated() -> None:
    text = Path("README.md").read_text(encoding="utf-8")
    assert "| Tests passing | 4,219 |" in text
    assert f"| Modules | {EXPECTED_MODULE_COUNT} |" in text


def test_readme_has_research_whats_inside_section() -> None:
    text = Path("README.md").read_text(encoding="utf-8")
    assert "**Research (NLCE Layer 2+)**" in text
    for snippet in (
        "PAR Abductive Reasoning — T5 theorem implementation",
        "Criticality Control (H17-CC) — LQR Ψ∈[0.4,0.6]",
        "HGT Protocol stub — horizontal gene transfer (H42)",
        "IACS full discourse coherence — 0.40×FC + 0.35×EC + 0.25×HC",
    ):
        assert snippet in text
