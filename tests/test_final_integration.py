"""Integration tests verifying all major subsystems work together."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from orchesis.aabb.benchmark import AABBBenchmark
from orchesis.apoptosis import ApoptosisEngine
from orchesis.arc_readiness import AgentReadinessCertifier
from orchesis.are.framework import AREFramework
from orchesis.budget_advisor import BudgetAdvisor
from orchesis.casura.incident_db import CASURAIncidentDB
from orchesis.compliance_checker import RealTimeComplianceChecker
from orchesis.context_compression_v2 import ContextCompressionV2
from orchesis.cost_analytics import CostAnalytics
from orchesis.cost_attribution import CostAttributionEngine
from orchesis.engine import evaluate
from orchesis.evidence_record import EvidenceRecord
from orchesis.fleet_coordinator import FleetCoordinator
from orchesis.gossip_protocol import GossipProtocol
from orchesis.injection_protocol import ContextInjectionProtocol
from orchesis.kalman_estimator import KalmanStateEstimator
from orchesis.monitoring.competitive import CompetitiveMonitor
from orchesis.monitoring.parsers import SocialMonitoringParsers
from orchesis.pid_controller_v2 import PIDControllerV2
from orchesis.proxy import LLMHTTPProxy
from orchesis.quorum_sensing import QuorumSensor
from orchesis.raft_context import RaftContextProtocol
from orchesis.thompson_sampling import ThompsonSampler
from orchesis.token_yield import TokenYieldTracker
from orchesis.byzantine_detector import ByzantineDetector
from orchesis.vickrey_allocator import VickreyBudgetAllocator
from orchesis.cli import main


def test_full_pipeline_with_all_modules(tmp_path: Path) -> None:
    """Proxy pipeline runs with context_router + cost_optimizer +
    uci_compression + apoptosis + injection_protocol all enabled."""
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        (
            "rules: []\n"
            "model_routing:\n  enabled: true\n"
            "cost_optimizer:\n  enabled: true\n"
            "context_compression_v2:\n  enabled: true\n"
            "apoptosis:\n  enabled: true\n"
            "injection_protocol:\n  enabled: true\n"
        ),
        encoding="utf-8",
    )
    proxy = LLMHTTPProxy(policy_path=str(policy))
    try:
        assert proxy._context_router is not None
        assert proxy._cost_optimizer is not None
        assert proxy._compression_v2 is not None
        assert proxy._apoptosis is not None
        assert proxy._injection_protocol is not None
        _ = proxy.stats
    finally:
        proxy.stop()


def test_nlce_layer2_complete() -> None:
    """UCI -> PID -> Kalman -> Injection -> Thompson all work together."""
    messages = [
        {"role": "system", "content": "Follow safety policy."},
        {"role": "assistant", "content": "Previous summary context."},
        {"role": "user", "content": "Please continue the analysis."},
    ]
    compression = ContextCompressionV2({"algorithm": "importance_scoring", "target_ratio": 0.7})
    compressed = compression.compress(messages * 3, budget_tokens=1000)
    assert compressed["compressed_count"] > 0

    pid = PIDControllerV2()
    warning = pid.get_warning_level(
        "s-1",
        {"values": [1, 2, 3, 4, 5, 6], "token_frequencies": [10, 9, 8, 7], "latencies_ms": [100, 110, 95, 260]},
    )
    assert warning["level"] in {"yellow", "orange", "red", "green"}

    kalman = KalmanStateEstimator()
    kalman.predict("s-1")
    state = kalman.update("s-1", {"tokens_used": 4000, "response_quality": 0.75, "latency_ms": 600})
    assert 0.0 <= state["coherence"] <= 1.0

    injector = ContextInjectionProtocol({"enabled": True, "strategy": "adaptive"})
    decision = injector.should_inject({"request_count": 5}, {"quality_score": 0.55, "budget_level": "L1"})
    selected = injector.select_content(messages, budget=300)
    injected = injector.inject(messages, selected if decision["inject"] else [])
    assert "messages" in injected

    th = ThompsonSampler({"seed": 42, "explore_rate": 0.0})
    arm = th.sample("analysis", list(ThompsonSampler.ARMS.keys()))
    th.update(arm, "analysis", 0.8)
    assert th.get_best_arm("analysis") in ThompsonSampler.ARMS


def test_fleet_intelligence_complete() -> None:
    """Quorum sensing -> Gossip -> Raft -> Byzantine -> Vickrey auction."""
    quorum = QuorumSensor({"n_star": 3, "similarity": 0.7})
    quorum.register_task("a1", "summarize incident response")
    quorum.register_task("a2", "summarize incident responses")
    quorum.register_task("a3", "summarize incident report")
    rows = quorum.detect_quorum()
    assert rows and len(rows[0]["agents"]) == 3

    gossip = GossipProtocol({"fanout": 2, "ttl_rounds": 3})
    _ = gossip.broadcast("ctx:key", "critical hint", "a1")
    delivered = gossip.receive("a2")
    _ = gossip.propagate()
    assert isinstance(delivered, list)

    raft = RaftContextProtocol()
    appended = raft.append_entry("ctx:key", "critical hint", "a1")
    _ = raft.acknowledge("a1", appended["index"])
    _ = raft.acknowledge("a2", appended["index"])
    consistent = raft.get_consistent_context("a2")
    assert consistent["committed_index"] >= 1

    byz = ByzantineDetector({"threshold": 0.7})
    for idx in range(5):
        byz.observe(
            f"agent-{idx}",
            {
                "behavior_drift": 0.95 if idx == 0 else 0.1,
                "response_inconsistency": 0.9 if idx == 0 else 0.1,
                "cost_anomaly": 0.85 if idx == 0 else 0.1,
                "timing_anomaly": 0.8 if idx == 0 else 0.1,
                "tool_abuse": 0.9 if idx == 0 else 0.1,
            },
        )
    detected = byz.detect()
    assert any(row["agent_id"] == "agent-0" for row in detected)

    auction = VickreyBudgetAllocator({"total_budget": 1000})
    _ = auction.submit_bid("a1", 500, "high")
    _ = auction.submit_bid("a2", 300, "medium")
    run = auction.run_auction()
    assert run["total_allocated"] > 0


def test_compliance_complete_flow(tmp_path: Path) -> None:
    """Evidence Record -> Compliance Checker -> ARC Certification -> CASURA."""
    decisions = [
        {
            "event_id": "evt-1",
            "timestamp": "2026-03-18T00:00:00Z",
            "agent_id": "agent-sec",
            "tool": "web_search",
            "cost": 0.05,
            "decision": "ALLOW",
            "reasons": [],
            "policy_version": "v1",
            "state_snapshot": {"session_id": "sess-1"},
        }
    ]
    record = EvidenceRecord().build("sess-1", decisions)
    assert record["summary"]["total_requests"] == 1

    policy = {
        "recording": {"enabled": True},
        "threat_intel": {"enabled": True},
        "rules": [{"name": "rate_limit"}, {"name": "regex_match"}],
        "api_rate_limit": {"enabled": True},
        "loop_detection": {"enabled": True},
    }
    compliance = RealTimeComplianceChecker().check_policy(policy)
    assert compliance["score"] >= 60.0

    arc = AgentReadinessCertifier().certify(
        "agent-sec",
        {"error_rate": 0.01, "uptime": 0.999, "latency_ms": 120, "budget_limit": 1.0, "cost": 0.2, "cache_hit_rate": 0.5},
        policy,
    )
    assert arc["score"] >= 70.0

    casura = CASURAIncidentDB(storage_path=str(tmp_path / "casura"))
    incident = casura.create_incident(
        {
            "title": "Prompt injection attempt blocked",
            "description": "Detected injection and policy override pattern.",
            "tags": ["prompt", "injection", "policy"],
            "attack_vector": 0.8,
            "impact": 0.7,
            "exploitability": 0.6,
        }
    )
    assert incident["incident_id"].startswith("CASURA-")


def test_cost_optimization_complete() -> None:
    """Token Yield -> Cost Analytics -> Budget Advisor -> Cost Attribution."""
    tracker = TokenYieldTracker()
    tracker.record("s-1", 100, 50, False, 0.7)
    tracker.record("s-1", 120, 80, True, 0.8)
    yield_stats = tracker.get_yield("s-1")
    assert 0.0 <= yield_stats["token_yield"] <= 1.0

    now_iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    events = [
        {
            "timestamp": now_iso,
            "agent_id": "agent-a",
            "cost": 0.2,
            "state_snapshot": {"session_id": "s-1", "model": "gpt-4o", "cache_hit_rate": 0.5},
        },
        {
            "timestamp": now_iso,
            "agent_id": "agent-b",
            "cost": 0.4,
            "state_snapshot": {"session_id": "s-2", "model": "gpt-4o-mini", "loop_detected": True},
        },
    ]
    analytics = CostAnalytics().compute(events, period_hours=24)
    assert analytics["total_cost"] > 0.0

    advice = BudgetAdvisor().analyze(events, {"daily_limit_usd": 1.0})
    assert isinstance(advice["recommendations"], list) and advice["recommendations"]

    attribution = CostAttributionEngine(
        {"rules": [{"agent_pattern": "agent-a", "team": "red"}, {"agent_pattern": "agent-b", "team": "blue"}]}
    ).attribute(events)
    assert "by_team" in attribution and attribution["total"] > 0.0


def test_monitoring_complete() -> None:
    """Social parsers -> Competitive monitor -> Weekly report generated."""
    parser = SocialMonitoringParsers()
    monitor = CompetitiveMonitor()
    hn_item = parser.parse_hn_item(
        {
            "id": 1,
            "title": "New AI agent proxy launch with strong prompt injection defense",
            "text": "This LLM proxy focuses on context governance.",
            "score": 120,
            "descendants": 30,
            "time": 1710000000,
        }
    )
    reddit_item = parser.parse_reddit_post(
        {
            "id": "r1",
            "title": "How to harden MCP server for agent security?",
            "selftext": "Need guidance on AI governance and rate limiting.",
            "score": 50,
            "num_comments": 10,
            "created_utc": 1710000001,
        }
    )
    opportunities = parser.extract_opportunities([hn_item, reddit_item])
    report = monitor.generate_weekly_report(
        {
            "competitors": {"openguard": {"stars": 150, "weekly_growth": 12}},
            "feed": [
                {"title": "OpenAI launches new gateway for agents", "source": "news"},
                {"title": "Major AI incident in production", "source": "news"},
            ],
        }
    )
    assert opportunities
    assert "week" in report
    assert isinstance(report["actions"], list)


def test_aabb_are_integration() -> None:
    """AABB benchmark results feed into ARE SLI tracking."""
    bench = AABBBenchmark()
    run = bench.run_suite("agent-1", proxy_url="http://localhost:8100")
    assert run["overall_score"] >= 0.0

    are = AREFramework()
    _ = are.define_slo("agent_reliability", "availability", target=0.95, window_days=7)
    are.record_sli("agent_reliability", min(1.0, max(0.0, run["overall_score"] / 100.0)))
    report = are.get_reliability_report()
    assert report["total_slos"] == 1
    assert report["slos"][0]["current"] >= 0.0


def test_all_cli_commands_importable() -> None:
    """Every CLI command added in A-X sprint loads without error."""
    commands = set(main.commands.keys())
    expected = {
        "experiment",
        "nlce-export",
        "nlce-paper",
        "arxiv-validate",
        "arxiv-package",
        "vibe-audit",
        "benchmark",
        "update",
        "replay",
        "ari-check",
    }
    assert expected.issubset(commands)
