"""Launch readiness - final gate before Show HN."""

from __future__ import annotations


def test_zero_external_runtime_deps() -> None:
    import tomllib
    from pathlib import Path

    data = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    deps = [str(item).lower() for item in data.get("project", {}).get("dependencies", [])]
    assert deps == [], "project.dependencies must be empty; use optional-dependencies extras"
    joined = " ".join(deps)
    assert "pyyaml" not in joined
    optional = data.get("project", {}).get("optional-dependencies", {})
    yaml_extra = [str(item).lower() for item in optional.get("yaml", [])]
    assert any("pyyaml" in dep for dep in yaml_extra)
    server_extra = [str(item).lower() for item in optional.get("server", [])]
    assert any("fastapi" in dep for dep in server_extra)
    assert any("uvicorn" in dep for dep in server_extra)
    for dep in ["requests", "numpy", "aiohttp", "fastapi", "uvicorn"]:
        assert dep not in joined


def test_readme_has_all_key_sections() -> None:
    readme = open("README.md", encoding="utf-8").read()
    for section in ["What is Orchesis?", "Quickstart", "Why proxy, not SDK?"]:
        assert section in readme, f"Missing: {section}"


def test_tests_above_4000() -> None:
    import subprocess
    import sys

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "--co", "-q"],
        capture_output=True,
        text=True,
        timeout=60,
        check=False,
    )
    lines = result.stdout.strip().split("\n")
    last = lines[-1] if lines else ""
    count = int(last.split()[0]) if last and last[0].isdigit() else 0
    assert count >= 4000, f"Only {count} tests collected"


def test_no_broken_imports() -> None:
    import subprocess
    import sys

    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import orchesis; from orchesis.api import create_api_app; "
            "from orchesis.cli import main; print('OK')",
        ],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0
    assert "OK" in result.stdout


def test_proxy_starts_without_error() -> None:
    from orchesis.proxy import LLMHTTPProxy

    p = LLMHTTPProxy(policy_path=None)
    assert p is not None


def test_api_creates_without_error() -> None:
    from orchesis.api import create_api_app

    app = create_api_app(policy_path="policy.yaml")
    assert app is not None


def test_viral_features_ready() -> None:
    from orchesis.agent_autopsy import AgentAutopsy
    from orchesis.vibe_audit import VibeCodeAuditor
    from orchesis.arc_readiness import AgentReadinessCertifier

    a = AgentAutopsy()
    v = VibeCodeAuditor()
    arc = AgentReadinessCertifier()
    assert all([a, v, arc])


def test_documentation_complete() -> None:
    from pathlib import Path

    assert Path("README.md").exists()
    assert Path("README-PYPI.md").exists()
    assert Path("docs/QUICKSTART.md").exists()
    assert Path("docs/ARCHITECTURE.md").exists()
    assert Path("CHANGELOG.md").exists()

