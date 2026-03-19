"""Complete integration - every subsystem works together."""

from __future__ import annotations


def test_full_ecosystem_initializes() -> None:
    from orchesis.casura.incident_db import CASURAIncidentDB
    from orchesis.aabb.benchmark import AABBBenchmark
    from orchesis.are.framework import AREFramework
    from orchesis.agent_autopsy import AgentAutopsy
    from orchesis.system_health_report import SystemHealthReport

    db = CASURAIncidentDB()
    bench = AABBBenchmark()
    are = AREFramework()
    autopsy = AgentAutopsy()
    health = SystemHealthReport()
    assert all([db, bench, are, autopsy, health])


def test_research_modules_all_work() -> None:
    from orchesis.carnot_efficiency import CarnotEfficiencyCalculator
    from orchesis.red_queen import RedQueenMonitor
    from orchesis.immune_memory import ImmuneMemory
    from orchesis.homeostasis import HomeostasisController
    from orchesis.complement_cascade import ComplementCascade
    from orchesis.double_loop_learning import DoubleLoopLearner

    cc_calc = CarnotEfficiencyCalculator()
    rq = RedQueenMonitor()
    im = ImmuneMemory()
    hc = HomeostasisController()
    cascade = ComplementCascade()
    dl = DoubleLoopLearner()
    assert all([cc_calc, rq, im, hc, cascade, dl])

    result = cascade.activate(0.95, "injection")
    assert result["terminal_attack"] is True

    measure = hc.measure(0.75)
    assert measure["in_band"] is True


def test_nlce_layer2_complete() -> None:
    from orchesis.uci_compression import UCICompressor
    from orchesis.criticality_control import CriticalityController
    from orchesis.par_reasoning import PARReasoner
    from orchesis.kolmogorov_importance import KolmogorovImportance

    uc = UCICompressor()
    cc = CriticalityController()
    par = PARReasoner()
    ki = KolmogorovImportance()
    assert all([uc, cc, par, ki])

    control = cc.compute_control(0.2)
    assert control["action"] == "crystallize"

    k = ki.estimate_k("test content for Kolmogorov")
    assert k > 0.0


def test_sdk_covers_all_subsystems() -> None:
    from orchesis.sdk import OrchesisClient

    client = OrchesisClient()
    methods = [m for m in dir(client) if not m.startswith("_")]
    assert "get_casura_incidents" in methods
    assert "get_aabb_leaderboard" in methods
    assert "run_autopsy" in methods
    assert "get_nlce_metrics" in methods


def test_config_validator_full_policy() -> None:
    from orchesis.config_validator import ConfigValidator

    cv = ConfigValidator()
    full_policy = {
        "proxy": {"host": "0.0.0.0", "port": 8080},
        "security": {"enabled": True},
        "semantic_cache": {"enabled": True},
        "recording": {"enabled": True},
        "loop_detection": {"enabled": True},
        "budgets": {"daily": 10.0},
        "threat_intel": {"enabled": True},
    }
    result = cv.validate(full_policy)
    assert result["valid"] is True
    assert result["score"] >= 0.7


def test_weekly_report_complete() -> None:
    from orchesis.weekly_report import WeeklyReportGenerator

    gen = WeeklyReportGenerator()
    report = gen.generate(
        {
            "security": {"blocked": 42, "new_sigs": 3},
            "cost": {"savings": 5.50},
        }
    )
    assert len(report["sections"]) == 5
    assert "Blocked 42 threats" in report["highlights"]


def test_module_registry_complete() -> None:
    from pathlib import Path

    modules = list(Path("src/orchesis").rglob("*.py"))
    assert len(modules) >= 50
    categories = {p.parent.name for p in modules if p.parent != Path("src/orchesis")}
    assert "core" in categories


def test_version_and_package_consistent() -> None:
    from pathlib import Path

    from orchesis import __version__

    assert __version__ == "0.4.0"
    pyproject = Path("pyproject.toml").read_text(encoding="utf-8")
    assert 'version = "0.4.0"' in pyproject

