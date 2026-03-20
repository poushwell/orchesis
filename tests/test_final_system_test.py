"""Final system test - complete validation of all subsystems."""

from __future__ import annotations

import tomllib
from pathlib import Path


def test_all_major_modules_importable() -> None:
    """Every major module added in sprints A-BB imports cleanly."""
    import orchesis

    _ = orchesis

    from orchesis.core.nlce_pipeline import AgentState, NLCEPipeline
    from orchesis.uci_compression import UCICompressor
    from orchesis.pid_controller_v2 import PIDControllerV2
    from orchesis.criticality_control import CriticalityController
    from orchesis.injection_protocol import ContextInjectionProtocol
    from orchesis.quorum_sensing import QuorumSensor
    from orchesis.byzantine_detector import ByzantineDetector
    from orchesis.raft_context import RaftContextProtocol
    from orchesis.thompson_sampling import ThompsonSampler
    from orchesis.casura.incident_db import CASURAIncidentDB
    from orchesis.aabb.benchmark import AABBBenchmark
    from orchesis.are.framework import AREFramework
    from orchesis.par_reasoning import PARReasoner
    from orchesis.carnot_efficiency import CarnotEfficiencyCalculator
    from orchesis.red_queen import RedQueenMonitor
    from orchesis.kolmogorov_importance import KolmogorovImportance
    from orchesis.agent_autopsy import AgentAutopsy
    from orchesis.immune_memory import ImmuneMemory
    from orchesis.homeostasis import HomeostasisController
    from orchesis.double_loop_learning import DoubleLoopLearner
    from orchesis.sdk import OrchesisClient

    _ = (
        AgentState,
        NLCEPipeline,
        UCICompressor,
        PIDControllerV2,
        CriticalityController,
        ContextInjectionProtocol,
        QuorumSensor,
        ByzantineDetector,
        RaftContextProtocol,
        ThompsonSampler,
        CASURAIncidentDB,
        AABBBenchmark,
        AREFramework,
        PARReasoner,
        CarnotEfficiencyCalculator,
        RedQueenMonitor,
        KolmogorovImportance,
        AgentAutopsy,
        ImmuneMemory,
        HomeostasisController,
        DoubleLoopLearner,
        OrchesisClient,
    )
    assert True


def test_nlce_pipeline_full_run() -> None:
    """NLCEPipeline state is initialized with expected fields."""
    from orchesis.core.nlce_pipeline import AgentState, NLCEPipeline

    _ = NLCEPipeline({})
    state = AgentState()
    assert hasattr(state, "psi")
    assert hasattr(state, "phase")
    assert hasattr(state, "slope_alert")
    assert state.phase in ["GAS", "LIQUID", "CRYSTAL"]


def test_agent_autopsy_no_crash() -> None:
    """AgentAutopsy handles empty log gracefully."""
    from orchesis.agent_autopsy import AgentAutopsy

    autopsy = AgentAutopsy()
    result = autopsy.perform("test-session", [])
    assert "error" in result


def test_sdk_client_no_crash() -> None:
    """OrchesisClient initializes without error."""
    from orchesis.sdk import OrchesisClient

    client = OrchesisClient(token="test")
    assert client.api_url == "http://localhost:8090"
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
    from orchesis.par_reasoning import PARReasoner
    from orchesis.criticality_control import CriticalityController
    from orchesis.kolmogorov_importance import KolmogorovImportance
    from orchesis.carnot_efficiency import CarnotEfficiencyCalculator

    for cls in [PARReasoner, CriticalityController, KolmogorovImportance, CarnotEfficiencyCalculator]:
        obj = cls()
        assert obj is not None


def test_immune_homeostasis_integrated() -> None:
    from orchesis.immune_memory import ImmuneMemory
    from orchesis.homeostasis import HomeostasisController

    im = ImmuneMemory()
    hc = HomeostasisController()
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
