from __future__ import annotations

import subprocess
import sys
from pathlib import Path

from click.testing import CliRunner

from orchesis.cli import main


def test_all_doc_files_exist() -> None:
    required = [
        Path("README.md"),
        Path("docs/QUICKSTART.md"),
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
        "## Quick Start",
        "## Architecture",
        "## Core Features",
        "## CLI Reference",
        "## License",
    ):
        assert section in text


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
        "/api/v1/policy",
        "/api/v1/policy/history",
        "/api/v1/policy/rollback",
        "/api/v1/policy/validate",
        "/api/v1/agents",
        "/api/v1/agents/{agent_id}",
        "/api/v1/agents/{agent_id}/tier",
        "/api/v1/status",
        "/api/v1/audit/stats",
        "/api/v1/audit/anomalies",
        "/api/v1/audit/timeline/{agent_id}",
        "/api/v1/reliability",
        "/api/v1/evaluate",
    )
    for endpoint in endpoints:
        assert endpoint in text
    assert "## Endpoints (14)" in text


def test_package_builds_cleanly(tmp_path: Path) -> None:
    dist_dir = tmp_path / "dist"
    build_cmd = [sys.executable, "-m", "build", "--sdist", "--wheel", "--outdir", str(dist_dir)]
    result = subprocess.run(build_cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr

    artifacts = sorted(dist_dir.glob("orchesis-0.6.0*"))
    assert artifacts, "Build artifacts for 0.6.0 not found"

    twine_cmd = [sys.executable, "-m", "twine", "check", *[str(item) for item in artifacts]]
    check = subprocess.run(twine_cmd, capture_output=True, text=True)
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
