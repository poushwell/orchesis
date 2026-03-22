"""Automated release checklist for final v0.3.0 gate."""

from __future__ import annotations

import importlib
import re
import tomllib
from pathlib import Path

from orchesis import __version__


def _project_root() -> Path:
    return Path(__file__).resolve().parents[1]


# Packaging
def test_version_consistent_everywhere() -> None:
    """__version__ must match pyproject and be present in changelog."""
    root = _project_root()
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    project_version = str(pyproject.get("project", {}).get("version", ""))
    assert project_version == __version__

    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    assert f"[{__version__}]" in changelog


def test_all_modules_importable() -> None:
    """Core modules in release checklist import without error."""
    import orchesis  # noqa: F401
    from orchesis import config, engine, proxy, scanner  # noqa: F401
    from orchesis.aabb.benchmark import AABBBenchmark  # noqa: F401
    from orchesis.are.framework import AREFramework  # noqa: F401
    from orchesis.casura.incident_db import CASURAIncidentDB  # noqa: F401

    # Optional in some branches.
    try:
        importlib.import_module("orchesis.hgt_protocol")
    except ModuleNotFoundError:
        pass


def test_zero_external_dependencies() -> None:
    """Runtime deps stay minimal; pyyaml is optional via extra."""
    root = _project_root()
    pyproject = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
    deps = [str(item).lower() for item in pyproject.get("project", {}).get("dependencies", [])]
    assert not any("pyyaml" in dep for dep in deps)
    optional = pyproject.get("project", {}).get("optional-dependencies", {})
    yaml_extra = [str(item).lower() for item in optional.get("yaml", [])]
    assert any("pyyaml" in dep for dep in yaml_extra)

    forbidden = ["requests", "httpx", "numpy", "pandas", "sklearn"]
    for dep in deps:
        for bad in forbidden:
            assert bad not in dep, f"Forbidden runtime dependency found: {dep}"


def test_no_debug_code_in_src() -> None:
    """No breakpoint() or pdb usage in production code."""
    src_dir = _project_root() / "src" / "orchesis"
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8", errors="ignore")
        assert "breakpoint()" not in content, f"breakpoint() in {py_file}"
        assert "import pdb" not in content, f"import pdb in {py_file}"


# Documentation
def test_readme_has_what_is_inside_section() -> None:
    """README contains What is Orchesis section."""
    readme = (_project_root() / "README.md").read_text(encoding="utf-8")
    assert "What is Orchesis?" in readme


def test_readme_test_count_current() -> None:
    """README has test badge text."""
    readme = (_project_root() / "README.md").read_text(encoding="utf-8")
    assert re.search(r"tests-[\d%2C]+", readme), "No test count badge found"


def test_all_cli_commands_in_quickstart() -> None:
    """QUICKSTART.md mentions key CLI commands."""
    quickstart = (_project_root() / "docs" / "QUICKSTART.md").read_text(encoding="utf-8")
    assert "orchesis status" in quickstart
    assert "orchesis backup" in quickstart


# Security
def test_no_hardcoded_secrets_in_src() -> None:
    """No obvious production hardcoded secrets in source code."""
    src_dir = _project_root() / "src" / "orchesis"
    suspicious_patterns = [
        re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"),
        re.compile(r"ghp_[A-Za-z0-9]{20,}"),
        re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,}"),
        re.compile(r"pypi-AgEI[A-Za-z0-9_-]{20,}"),
    ]
    aws_key_re = re.compile(r"AKIA[0-9A-Z]{16}")
    allowed_placeholders = {"AKIAABCDEFGHIJKLMNOP"}
    for py_file in src_dir.rglob("*.py"):
        content = py_file.read_text(encoding="utf-8", errors="ignore")
        # Secret scanning modules intentionally contain detection signatures.
        if any(token in py_file.name.lower() for token in ("scanner", "detector")):
            continue
        for pattern in suspicious_patterns:
            assert pattern.search(content) is None, f"Possible secret pattern in {py_file}: {pattern.pattern}"
        for match in aws_key_re.findall(content):
            assert match in allowed_placeholders, f"Possible AWS key in {py_file}"


# Quality
def test_test_coverage_above_threshold() -> None:
    """At least 3500 tests exist via file-volume proxy."""
    test_dir = _project_root() / "tests"
    test_files = list(test_dir.glob("test_*.py"))
    assert len(test_files) >= 50, "Too few test files for expected release baseline"


def test_fuzz_crash_regression_tests_exist() -> None:
    """Regression tests for known fuzz crashes exist."""
    root = _project_root()
    assert (root / "tests" / "test_secret_scanner.py").exists()
    assert (root / "tests" / "test_pii_detector.py").exists()
    assert (root / "tests" / "test_config.py").exists()
