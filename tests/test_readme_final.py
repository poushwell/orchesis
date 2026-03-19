from __future__ import annotations

from pathlib import Path


def test_badge_reflects_current_tests() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "tests-4038%20passing" in readme


def test_modules_count_updated() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "| Tests passing | 4,038 |" in readme
    assert "| Modules | 100+ |" in readme
    assert "| API endpoints | 250+ |" in readme


def test_viral_tools_section_present() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert "**Viral Tools**" in readme
    assert "Agent Autopsy" in readme
    assert "Vibe Code Audit" in readme
    assert "ARC Certification" in readme
    assert "Weekly Intelligence Report" in readme


def test_readme_pypi_synced() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    pypi = Path("README-PYPI.md").read_text(encoding="utf-8")
    for marker in (
        "tests-4038%20passing",
        "| Modules | 100+ |",
        "| API endpoints | 250+ |",
        "**Viral Tools**",
        "Weekly Intelligence Report",
    ):
        assert marker in readme
        assert marker in pypi
