from __future__ import annotations

import importlib
import subprocess
import sys
from pathlib import Path

import pytest
from click.testing import CliRunner

from orchesis.cli import main
from orchesis import __version__


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
        "## The Problem",
        "## Quick Start",
        "## What It Does",
        "## Architecture",
        "## Integrations",
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
        )
        if any(marker in output for marker in known_env_errors):
            pytest.skip("build invocation unavailable in this environment")
    assert result.returncode == 0, result.stdout + result.stderr

    artifacts = sorted(dist_dir.glob(f"orchesis-{__version__}*"))
    assert artifacts, f"Build artifacts for {__version__} not found"

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
