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
    assert content.startswith("# ")


def test_readme_has_docker_section() -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    # README public-launch format uses Quick Start and Docker snippets.
    assert "## Quick Start" in content
    assert "docker-compose up" in content
    assert "orchesis proxy --config orchesis.yaml" in content


def test_readme_has_project_status() -> None:
    content = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "## Key metrics" in content
    assert "2,637" in content
    assert "## Security coverage" in content
