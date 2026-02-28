from __future__ import annotations

from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def test_contributing_exists() -> None:
    assert (ROOT / "CONTRIBUTING.md").exists()


def test_contributing_has_sections() -> None:
    content = (ROOT / "CONTRIBUTING.md").read_text(encoding="utf-8")
    assert "## Getting Started" in content
    assert "## Development Workflow" in content
    assert "## Testing" in content
    assert "## Adding a Plugin" in content


def test_security_has_disclosure() -> None:
    content = (ROOT / "docs" / "SECURITY.md").read_text(encoding="utf-8")
    assert "## Reporting Vulnerabilities" in content


def test_issue_templates_exist() -> None:
    issue_dir = ROOT / ".github" / "ISSUE_TEMPLATE"
    assert (issue_dir / "bug_report.md").exists()
    assert (issue_dir / "feature_request.md").exists()
    assert (issue_dir / "bypass_report.md").exists()


def test_pr_template_exists() -> None:
    assert (ROOT / ".github" / "PULL_REQUEST_TEMPLATE.md").exists()


def test_ci_workflow_valid_yaml() -> None:
    path = ROOT / ".github" / "workflows" / "ci.yml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert isinstance(data, dict)


def test_ci_tests_multiple_python_versions() -> None:
    content = (ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert '"3.11"' in content
    assert '"3.12"' in content


def test_readme_has_badges() -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "actions/workflows/ci.yml/badge.svg" in content
    assert "img.shields.io/badge/python-3.11%2B-blue" in content
    assert "img.shields.io/badge/license-MIT-green" in content
    assert "img.shields.io/badge/version-0.6.0-orange" in content


def test_readme_has_docker_section() -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Docker" in content
    assert "docker compose up -d" in content


def test_readme_has_project_status() -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Project Status" in content
    assert "| Tests | 364 |" in content
    assert "| Metric | Value |" in content
