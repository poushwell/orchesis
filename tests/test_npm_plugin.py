"""Validate npm plugin structure and content."""
from pathlib import Path
import json


def test_package_json_exists():
    assert Path("npm/orchesis-context/package.json").exists()


def test_package_json_valid():
    pkg = json.loads(Path("npm/orchesis-context/package.json").read_text())
    assert pkg["name"] == "orchesis-context"
    assert pkg["version"] == "0.1.0"
    assert pkg["license"] == "MIT"


def test_index_js_exists():
    assert Path("npm/orchesis-context/index.js").exists()


def test_index_js_has_main_classes():
    content = Path("npm/orchesis-context/index.js").read_text()
    assert "OrchesisContext" in content
    assert "OrchesisMiddleware" in content
    assert "checkQuality" in content
    assert "module.exports" in content


def test_readme_exists():
    assert Path("npm/orchesis-context/README.md").exists()


def test_no_external_deps_in_package():
    pkg = json.loads(Path("npm/orchesis-context/package.json").read_text())
    assert "dependencies" not in pkg or pkg.get("dependencies") == {}
