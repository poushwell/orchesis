"""Final system test - complete validation of all subsystems."""

from __future__ import annotations

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:  # Python < 3.11
    import tomli as tomllib  # type: ignore[no-redef,import-untyped]


def test_all_major_modules_importable() -> None:
    """Every major module added in sprints A-BB imports cleanly."""
    import orchesis

    _ = orchesis

    from orchesis.core.pipeline_engine import AgentState, PipelineEngine
    from orchesis.content_ranker import ContentRanker
    from orchesis.pid_controller_v2 import PIDControllerV2
    from orchesis.quality_control import QualityController
    from orchesis.injection_protocol import ContextInjectionProtocol
    from orchesis.fleet_consensus import FleetConsensus
    from orchesis.byzantine_detector import ByzantineDetector
    from orchesis.context_sync import ContextSyncManager
    from orchesis.bandit_sampler import BanditSampler
    from orchesis.casura.incident_db import CASURAIncidentDB
    from orchesis.aabb.benchmark import AABBBenchmark
    from orchesis.are.framework import AREFramework
    from orchesis.fallback_reasoner import FallbackReasoner
    from orchesis.efficiency_metric import EfficiencyMetricCalculator
    from orchesis.adversarial_tracker import RedQueenMonitor
    from orchesis.content_importance import ContentImportance
    from orchesis.agent_diagnostics import AgentDiagnostics
    from orchesis.threat_history import ThreatHistory
    from orchesis.state_balancer import StateBalancer
    from orchesis.adaptive_learning import DoubleLoopLearner
    from orchesis.sdk import OrchesisClient

    _ = (
        AgentState,
        PipelineEngine,
        ContentRanker,
        PIDControllerV2,
        QualityController,
        ContextInjectionProtocol,
        FleetConsensus,
        ByzantineDetector,
        ContextSyncManager,
        BanditSampler,
        CASURAIncidentDB,
        AABBBenchmark,
        AREFramework,
        FallbackReasoner,
        EfficiencyMetricCalculator,
        RedQueenMonitor,
        ContentImportance,
        AgentDiagnostics,
        ThreatHistory,
        StateBalancer,
        DoubleLoopLearner,
        OrchesisClient,
    )
    assert True


def test_pipeline_engine_full_run() -> None:
    """PipelineEngine state is initialized with expected fields."""
    from orchesis.core.pipeline_engine import AgentState, PipelineEngine

    _ = PipelineEngine({})
    state = AgentState()
    assert hasattr(state, "psi")
    assert hasattr(state, "phase")
    assert hasattr(state, "slope_alert")
    assert state.phase in ["GAS", "LIQUID", "CRYSTAL"]


def test_agent_diagnostics_no_crash() -> None:
    """AgentDiagnostics handles empty log gracefully."""
    from orchesis.agent_diagnostics import AgentDiagnostics

    autopsy = AgentDiagnostics()
    result = autopsy.perform("test-session", [])
    assert "error" in result


def test_sdk_client_no_crash() -> None:
    """OrchesisClient initializes without error."""
    from orchesis.sdk import OrchesisClient

    client = OrchesisClient(token="test")
    assert client.api_url == "http://localhost:8080"
    assert client.is_connected() is False


def test_casura_aabb_are_integrated() -> None:
    """CASURA, AABB, ARE all initialize correctly."""
    from orchesis.casura.incident_db import CASURAIncidentDB
    from orchesis.aabb.benchmark import AABBBenchmark
    from orchesis.are.framework import AREFramework

    db = CASURAIncidentDB()
    bench = AABBBenchmark()
    _ = AREFramework()
    assert db.AISS_VERSION == "2.0"
    assert len(bench.BENCHMARK_CATEGORIES) == 4


def test_research_modules_no_crash() -> None:
    """All Tier 1-3 research modules initialize without error."""
    from orchesis.fallback_reasoner import FallbackReasoner
    from orchesis.quality_control import QualityController
    from orchesis.content_importance import ContentImportance
    from orchesis.efficiency_metric import EfficiencyMetricCalculator

    for cls in [
        FallbackReasoner,
        QualityController,
        ContentImportance,
        EfficiencyMetricCalculator,
    ]:
        obj = cls()
        assert obj is not None


def test_immune_state_balancer_integrated() -> None:
    from orchesis.threat_history import ThreatHistory
    from orchesis.state_balancer import StateBalancer

    im = ThreatHistory()
    hc = StateBalancer()
    result = im.expose("test-threat", 0.5)
    assert result["primary_response"] is True
    measure = hc.measure(0.75)
    assert measure["in_band"] is True


def test_all_api_endpoints_registered(tmp_path: Path) -> None:
    """API app has expected number of routes."""
    from orchesis.api import create_api_app

    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text("rules: []\napi:\n  token: test-token\n", encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path))
    routes = [route.path for route in app.routes]
    assert len(routes) > 100, f"Expected >100 routes, got {len(routes)}"


def test_version_matches_pyproject() -> None:
    """Package version matches pyproject.toml."""
    from orchesis import __version__

    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    expected = str(pyproject.get("project", {}).get("version", "")).strip()
    assert expected
    assert __version__ == expected
