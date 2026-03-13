from __future__ import annotations

import threading
import time

from orchesis.agent_discovery import AgentDiscovery


def _req(model: str = "gpt-4o", session_id: str = "s1"):
    return {"model": model, "session_id": session_id}


# Agent recording
def test_record_first_request_creates_agent() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req(), model="gpt-4o", tokens=100)
    assert d.get_agent("a1") is not None


def test_record_subsequent_updates_stats() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req(), tokens=10, cost=0.1)
    d.record_request("a1", _req(), tokens=20, cost=0.2)
    p = d.get_agent("a1")
    assert p is not None
    assert p.total_requests == 2
    assert p.total_tokens == 30


def test_record_tracks_models_used() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req("gpt-4o"), model="gpt-4o")
    d.record_request("a1", _req("gpt-4o-mini"), model="gpt-4o-mini")
    p = d.get_agent("a1")
    assert p is not None
    assert sorted(p.models_used) == ["gpt-4o", "gpt-4o-mini"]


def test_record_tracks_tools_used() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req(), tools=["read_file", "web_search"])
    p = d.get_agent("a1")
    assert p is not None
    assert sorted(p.tools_used) == ["read_file", "web_search"]
    assert p.tool_call_count == 2


def test_record_calculates_averages() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req(), tokens=100, cost=1.0, latency_ms=200)
    d.record_request("a1", _req(), tokens=300, cost=3.0, latency_ms=600)
    p = d.get_agent("a1")
    assert p is not None
    assert p.avg_tokens_per_request == 200.0
    assert p.avg_cost_per_request == 2.0
    assert p.avg_latency_ms == 400.0


# Agent retrieval
def test_get_agent_found() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    assert d.get_agent("a1") is not None


def test_get_agent_not_found() -> None:
    d = AgentDiscovery()
    assert d.get_agent("missing") is None


def test_get_all_agents_sorted_by_last_seen() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    time.sleep(0.01)
    d.record_request("a2", _req())
    all_agents = d.get_all_agents()
    assert [a.agent_id for a in all_agents][:2] == ["a2", "a1"]


def test_get_summary_counts() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    d.record_request("a2", _req())
    s = d.get_summary()
    assert s["total_agents"] == 2
    assert s["active_agents"] >= 2


def test_get_summary_top_by_cost() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req(), cost=5.0)
    d.record_request("a2", _req(), cost=1.0)
    s = d.get_summary()
    assert s["top_agents_by_cost"][0]["agent_id"] == "a1"


def test_get_summary_top_by_risk() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    d.record_request("a2", _req())
    d.record_detection("a2", anomaly_score=90)
    s = d.get_summary()
    assert s["top_agents_by_risk"][0]["agent_id"] == "a2"


# Health assessment
def test_health_healthy_low_anomaly_rate() -> None:
    d = AgentDiscovery()
    for _ in range(20):
        d.record_request("a1", _req())
    p = d.get_agent("a1")
    assert p is not None
    assert p.health == "healthy"


def test_health_warning_moderate_anomaly_rate() -> None:
    d = AgentDiscovery({"health_thresholds": {"warning_anomaly_rate": 0.1, "critical_anomaly_rate": 0.5}})
    for _ in range(10):
        d.record_request("a1", _req())
    for _ in range(2):
        d.record_detection("a1", anomaly_score=50, risk_level="high")
    p = d.get_agent("a1")
    assert p is not None
    assert p.health == "warning"


def test_health_critical_high_anomaly_rate() -> None:
    d = AgentDiscovery({"health_thresholds": {"warning_anomaly_rate": 0.1, "critical_anomaly_rate": 0.3}})
    for _ in range(10):
        d.record_request("a1", _req())
    for _ in range(4):
        d.record_detection("a1", anomaly_score=80, risk_level="critical")
    p = d.get_agent("a1")
    assert p is not None
    assert p.health == "critical"


# Detection recording
def test_record_detection_updates_ars() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    d.record_detection("a1", ars_grade="B", ars_score=88.2)
    p = d.get_agent("a1")
    assert p is not None
    assert p.ars_grade == "B"
    assert p.ars_score == 88.2


def test_record_detection_counts_anomalies() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    d.record_detection("a1", anomaly_score=10)
    d.record_detection("a1", anomaly_score=0)
    p = d.get_agent("a1")
    assert p is not None
    assert p.anomaly_count == 1


def test_record_detection_cron_flag() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    d.record_detection("a1", is_cron=True)
    p = d.get_agent("a1")
    assert p is not None
    assert p.is_cron is True


def test_record_detection_mast_findings_count() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    d.record_detection("a1", mast_findings=3)
    p = d.get_agent("a1")
    assert p is not None
    assert p.mast_findings_count == 3


def test_record_detection_blocked_status() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    d.record_detection("a1", status="blocked")
    p = d.get_agent("a1")
    assert p is not None
    assert p.status == "blocked"


# Cleanup
def test_cleanup_removes_old_agents() -> None:
    d = AgentDiscovery({"retention_hours": 1})
    d.record_request("old", _req())
    with d._lock:  # noqa: SLF001
        d._agents["old"]["last_seen"] = time.time() - 7200  # noqa: SLF001
    removed = d.cleanup()
    assert removed == 1
    assert d.get_agent("old") is None


def test_cleanup_keeps_recent_agents() -> None:
    d = AgentDiscovery({"retention_hours": 1})
    d.record_request("a1", _req())
    removed = d.cleanup()
    assert removed == 0
    assert d.get_agent("a1") is not None


# Edge cases
def test_empty_no_agents() -> None:
    d = AgentDiscovery()
    assert d.get_all_agents() == []
    assert d.get_summary()["total_agents"] == 0


def test_concurrent_recording() -> None:
    d = AgentDiscovery()
    errs = []

    def worker(name: str) -> None:
        try:
            for _ in range(50):
                d.record_request(name, _req(), tokens=10, cost=0.01)
                d.record_detection(name, anomaly_score=1)
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    threads = [threading.Thread(target=worker, args=(f"a{i}",)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errs == []
    assert d.get_summary()["total_agents"] == 6


def test_reset_clears_all() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    d.reset()
    assert d.get_summary()["total_agents"] == 0


def test_status_idle_after_hour() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req())
    with d._lock:  # noqa: SLF001
        d._agents["a1"]["last_seen"] = time.time() - 3700  # noqa: SLF001
    p = d.get_agent("a1")
    assert p is not None
    assert p.status == "idle"


def test_session_count_tracks_unique_sessions() -> None:
    d = AgentDiscovery()
    d.record_request("a1", _req(session_id="s1"))
    d.record_request("a1", _req(session_id="s2"))
    p = d.get_agent("a1")
    assert p is not None
    assert p.session_count == 2

