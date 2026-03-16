from __future__ import annotations

import importlib
import tomllib
from pathlib import Path

from orchesis import __version__

ALLOWED_RUNTIME_DEPS = {"pyyaml"}  # pyyaml needed for YAML policy parsing


def _read_pyproject() -> dict:
    content = Path("pyproject.toml").read_bytes()
    parsed = tomllib.loads(content.decode("utf-8"))
    assert isinstance(parsed, dict)
    return parsed


def test_pyproject_toml_valid() -> None:
    data = _read_pyproject()
    assert "project" in data
    assert "build-system" in data


def test_version_consistent() -> None:
    data = _read_pyproject()
    assert data["project"]["version"] == __version__


def test_all_modules_importable() -> None:
    modules = [
        "orchesis",
        "orchesis.proxy",
        "orchesis.config",
        "orchesis.dashboard",
        "orchesis.cli",
    ]
    for module_name in modules:
        importlib.import_module(module_name)


def test_no_external_dependencies() -> None:
    data = _read_pyproject()
    deps = data["project"].get("dependencies", [])
    assert isinstance(deps, list)
    normalized = {str(dep).split(">=")[0].split("==")[0].strip().lower() for dep in deps}
    assert normalized.issubset(ALLOWED_RUNTIME_DEPS)


def test_package_includes_dashboard_html() -> None:
    from orchesis.dashboard import get_dashboard_html

    html = get_dashboard_html()
    assert "<html" in html.lower()
    assert "dashboard" in html.lower()

