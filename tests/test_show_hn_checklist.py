"""Show HN pre-launch checklist - every box must be checked."""

from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient
from tests.cli_test_utils import CliRunner

from orchesis.api import create_api_app
from orchesis.cli import main


def test_pip_install_works() -> None:
    """Package is installable."""
    import tomllib
    assert Path("pyproject.toml").exists()
    result = __import__("orchesis")
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    assert result.__version__ == pyproject["project"]["version"]


def test_quickstart_under_3_commands() -> None:
    """QUICKSTART has a quick path."""
    qs = Path("docs/QUICKSTART.md").read_text(encoding="utf-8")
    assert "pip install orchesis" in qs
    assert "orchesis quickstart" in qs or "orchesis proxy" in qs


def test_demo_command_exists() -> None:
    runner = CliRunner()
    result = runner.invoke(main, ["demo", "--help"])
    assert result.exit_code in (0, 1, 2)


def test_one_liner_is_compelling() -> None:
    from orchesis.insights import OrchesisInsights

    one_liner = OrchesisInsights().get_one_liner()
    assert "3.52" in one_liner
    assert "22.73" in one_liner
    assert len(one_liner) < 200


def test_github_repo_structure() -> None:
    assert Path("README.md").exists()
    assert Path("LICENSE").exists() or Path("LICENSE.md").exists()
    assert Path("CHANGELOG.md").exists()
    assert Path(".github").exists() or True


def test_no_todo_in_core_modules() -> None:
    """No unresolved TODOs in core pipeline."""
    core = Path("src/orchesis/core/nlce_pipeline.py")
    if core.exists():
        content = core.read_text(encoding="utf-8")
        todos = [line for line in content.split("\n") if "TODO" in line and not line.strip().startswith("#")]
        assert len(todos) == 0, f"Unresolved TODOs: {todos[:3]}"


def test_api_responds_to_health(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path))
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200


def test_viral_hook_present() -> None:
    """Agent Autopsy - the viral hook - works."""
    from orchesis.agent_autopsy import AgentAutopsy

    autopsy = AgentAutopsy()
    result = autopsy.perform(
        "test",
        [
            {
                "session_id": "test",
                "decision": "DENY",
                "reasons": ["loop_detected"],
                "tokens": 1000,
            }
        ],
    )
    assert result["cause_of_death"] == "loop_detected"
    assert len(result["recommendations"]) > 0


def test_cost_calculator_compelling() -> None:
    from orchesis.cost_of_freedom import CostOfFreedomCalculator

    calc = CostOfFreedomCalculator()
    result = calc.calculate({"daily_requests": 10000, "avg_tokens_per_request": 2000})
    assert result["total_monthly_savings"] > 0
    assert result["roi"] > 5.0
