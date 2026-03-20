from __future__ import annotations

from pathlib import Path
import re


def test_badge_reflects_current_tests() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert re.search(r"tests-\d+%20passing", readme), "No test count badge found"


def test_modules_count_updated() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert re.search(r"\| Tests passing \| [\d,]+ \|", readme), "No test count row found"
    assert re.search(r"\| Modules \| \d+ \|", readme), "No modules row found"
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
    assert re.search(r"tests-\d+%20passing", readme), "No test count badge found in README"
    assert re.search(r"tests-\d+%20passing", pypi), "No test count badge found in README-PYPI"
    assert re.search(r"\| Tests passing \| [\d,]+ \|", readme), "No test count row in README"
    assert re.search(r"\| Tests passing \| [\d,]+ \|", pypi), "No test count row in README-PYPI"
    assert re.search(r"\| Modules \| \d+ \|", readme), "No modules row in README"
    assert re.search(r"\| Modules \| \d+ \|", pypi), "No modules row in README-PYPI"
    for marker in ("| API endpoints | 250+ |", "**Viral Tools**", "Weekly Intelligence Report"):
        assert marker in readme
        assert marker in pypi
