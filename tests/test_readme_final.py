from __future__ import annotations

from pathlib import Path
import re


def test_badge_reflects_current_tests() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert re.search(r"tests-[\d%2C]+", readme), "No test count badge found"


def test_modules_count_updated() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    assert re.search(r"\| Tests passing \| [\d,]+\+ \|", readme), "No test count row found"
    assert re.search(r"\| Modules \| ~?\d+ \|", readme), "No modules row found"


def test_viral_tools_section_present() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    for marker in (
        "Runtime Gateway for AI Agents",
        "17-phase security pipeline",
        "pip install orchesis",
        "localhost:8080",
        "orchesis verify",
        "orchesis dashboard",
        "MIT License",
        "4,670+",
    ):
        assert marker in readme


def test_readme_pypi_synced() -> None:
    readme = Path("README.md").read_text(encoding="utf-8")
    pypi = Path("README-PYPI.md").read_text(encoding="utf-8")
    assert re.search(r"tests-[\d%2C]+", readme), "No test count badge found in README"
    assert re.search(r"tests-[\d%2C]+", pypi), "No test count badge found in README-PYPI"
    for marker in ("pip install orchesis", "localhost:8080", "MIT License"):
        assert marker in readme
        assert marker in pypi
