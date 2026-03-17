from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request as UrlRequest, urlopen

import httpx
import pytest

from orchesis.api import create_api_app
from orchesis.config import load_policy
from orchesis.flow_xray import EdgeType, FlowAnalyzer, FlowXRayConfig, NodeType, PatternType
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy


def _enabled_cfg(**overrides) -> FlowXRayConfig:
    base = FlowXRayConfig(enabled=True)
    for key, value in overrides.items():
        setattr(base, key, value)
    return base


def _mk_analyzer(**overrides) -> FlowAnalyzer:
    return FlowAnalyzer(_enabled_cfg(**overrides))


def _record_llm(
    analyzer: FlowAnalyzer,
    *,
    sid: str = "s1",
    model: str = "gpt-4o",
    content: str = "hello",
    status: str = "ok",
    tool_calls: list[dict] | None = None,
    tokens_in: int = 10,
    tokens_out: int = 10,
    cost: float = 0.01,
    latency_ms: float = 20.0,
) -> str:
    node_id = analyzer.record_request(
        session_id=sid,
        model=model,
        messages=[{"role": "user", "content": content}],
        tools=[],
    )
    analyzer.record_response(
        session_id=sid,
        node_id=node_id,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        cost_usd=cost,
        latency_ms=latency_ms,
        status=status,
        tool_calls=tool_calls or [],
    )
    return node_id


@pytest.mark.parametrize("sid", ["s1", "s2", "alpha", "beta"])
def test_empty_graph(sid: str) -> None:
    analyzer = _mk_analyzer()
    assert analyzer.get_session_graph(sid) is None


@pytest.mark.parametrize("model", ["gpt-4o", "claude-haiku-4", "claude-sonnet-4", "claude-opus-4", "gpt-4o-mini"])
def test_record_single_request(model: str) -> None:
    analyzer = _mk_analyzer()
    node_id = analyzer.record_request("s1", model=model, messages=[{"role": "user", "content": "q"}], tools=["read_file"])
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    assert node_id in graph.nodes
    assert graph.nodes[node_id].node_type == NodeType.LLM_CALL


@pytest.mark.parametrize("tokens_in,tokens_out", [(5, 1), (20, 3), (100, 10), (50, 0), (1, 1)])
def test_record_request_response(tokens_in: int, tokens_out: int) -> None:
    analyzer = _mk_analyzer()
    node_id = analyzer.record_request("s1", model="gpt-4o", messages=[{"role": "user", "content": "q"}], tools=[])
    created = analyzer.record_response("s1", node_id, tokens_in, tokens_out, 0.02, 12.5, status="ok")
    assert created == []
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    node = graph.nodes[node_id]
    assert node.tokens_in == tokens_in
    assert node.tokens_out == tokens_out


@pytest.mark.parametrize("tool_name", ["read_file", "write_file", "web_search", "http_request", "database_query"])
def test_record_tool_calls(tool_name: str) -> None:
    analyzer = _mk_analyzer()
    llm = analyzer.record_request("s1", model="gpt-4o", messages=[{"role": "user", "content": "q"}], tools=[])
    created = analyzer.record_response(
        "s1",
        llm,
        10,
        20,
        0.03,
        40.0,
        tool_calls=[{"name": tool_name, "input": {"x": 1}}],
    )
    assert len(created) == 1
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    tool_node = graph.nodes[created[0]]
    assert tool_node.node_type == NodeType.TOOL_USE
    assert any(e.edge_type == EdgeType.TRIGGERS and e.source_id == llm and e.target_id == created[0] for e in graph.edges)


def test_record_tool_result() -> None:
    analyzer = _mk_analyzer()
    llm = _record_llm(analyzer, tool_calls=[{"name": "read_file", "input": {"path": "/tmp/a"}}])
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    tool_nodes = [n.node_id for n in graph.nodes.values() if n.node_type == NodeType.TOOL_USE]
    rid = analyzer.record_tool_result("s1", tool_nodes[0], result_size=128)
    graph2 = analyzer.get_session_graph("s1")
    assert graph2 is not None
    assert rid in graph2.nodes
    assert graph2.nodes[rid].node_type == NodeType.TOOL_RESULT
    assert any(e.edge_type == EdgeType.RESPONDS_TO and e.source_id == tool_nodes[0] and e.target_id == rid for e in graph2.edges)
    _ = llm


def test_multiple_sessions_isolated() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1", content="a")
    _record_llm(analyzer, sid="s2", content="b")
    g1 = analyzer.get_session_graph("s1")
    g2 = analyzer.get_session_graph("s2")
    assert g1 is not None and g2 is not None
    assert g1.session_id != g2.session_id


def test_node_sequence_ordering() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1", content="1")
    time.sleep(0.01)
    _record_llm(analyzer, sid="s1", content="2")
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    seq = graph.get_node_sequence()
    assert seq[0].timestamp <= seq[-1].timestamp


def test_adjacency_list() -> None:
    analyzer = _mk_analyzer()
    n1 = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "a"}], [])
    n2 = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "b"}], [])
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    adj = graph.get_adjacency()
    assert n2 in adj.get(n1, [])


def test_model_escalation_edge() -> None:
    analyzer = _mk_analyzer()
    analyzer.record_request("s1", "claude-haiku-4", [{"role": "user", "content": "same"}], [])
    analyzer.record_request("s1", "claude-sonnet-4", [{"role": "user", "content": "same"}], [])
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    assert any(e.edge_type == EdgeType.ESCALATION for e in graph.edges)


def test_retry_edge() -> None:
    analyzer = _mk_analyzer()
    analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "same"}], [])
    analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "same"}], [])
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    assert any(e.edge_type == EdgeType.RETRY for e in graph.edges)


@pytest.mark.parametrize("repetitions", [2, 3, 4, 5, 6, 7, 8, 9])
def test_detect_redundant_tools_exact(repetitions: int) -> None:
    analyzer = _mk_analyzer()
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    for _ in range(repetitions):
        analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "read_file", "input": {"path": "/tmp/a"}}])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert any(p.pattern_type == PatternType.REDUNDANT_TOOL_CALLS for p in analysis.patterns)


@pytest.mark.parametrize("window", [5.0, 10.0, 20.0, 30.0, 45.0, 60.0])
def test_detect_redundant_tools_fuzzy(window: float) -> None:
    analyzer = _mk_analyzer(redundancy_window_seconds=window)
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "web_search", "input": {"q": "x"}}])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "web_search", "input": {"q": "y"}}])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "web_search", "input": {"q": "z"}}])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert any(p.pattern_type == PatternType.REDUNDANT_TOOL_CALLS for p in analysis.patterns)


def test_no_false_positive_different_tools() -> None:
    analyzer = _mk_analyzer()
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "read_file", "input": {"path": "/a"}}])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "web_search", "input": {"q": "a"}}])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert sum(1 for p in analysis.patterns if p.pattern_type == PatternType.REDUNDANT_TOOL_CALLS) <= 1


@pytest.mark.parametrize("reps", [3, 4, 5, 6, 7, 8])
def test_detect_ping_pong(reps: int) -> None:
    analyzer = _mk_analyzer(ping_pong_min_repetitions=3)
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    calls = []
    for i in range(reps * 2):
        tool = "read_file" if i % 2 == 0 else "web_search"
        calls.append({"name": tool, "input": {"i": i}})
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=calls)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert any(p.pattern_type == PatternType.PING_PONG for p in analysis.patterns)


@pytest.mark.parametrize("reps", [1, 2])
def test_ping_pong_min_repetitions(reps: int) -> None:
    analyzer = _mk_analyzer(ping_pong_min_repetitions=3)
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    calls = []
    for i in range(reps * 2):
        calls.append({"name": "read_file" if i % 2 == 0 else "web_search", "input": {"i": i}})
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=calls)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert not any(p.pattern_type == PatternType.PING_PONG for p in analysis.patterns)


@pytest.mark.parametrize("gap", [31.0, 45.0, 60.0, 90.0])
def test_detect_context_loss(gap: float) -> None:
    analyzer = _mk_analyzer(redundancy_window_seconds=30.0)
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "read_file", "input": {"path": "/a"}}])
    with analyzer._lock:  # test setup for deterministic timestamps
        graph = analyzer._session_graphs["s1"]
        tools = [n for n in graph.nodes.values() if n.node_type == NodeType.TOOL_USE]
        if tools:
            tools[0].timestamp = time.monotonic() - gap
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "read_file", "input": {"path": "/a"}}])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert any(p.pattern_type == PatternType.CONTEXT_LOSS for p in analysis.patterns)


@pytest.mark.parametrize("retries", [4, 5, 6, 7, 8, 9])
def test_detect_excessive_retries(retries: int) -> None:
    analyzer = _mk_analyzer(retry_threshold=3)
    for _ in range(retries):
        _record_llm(analyzer, sid="s1", status="error")
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert any(p.pattern_type == PatternType.EXCESSIVE_RETRIES for p in analysis.patterns)


@pytest.mark.parametrize("retries", [1, 2, 3])
def test_retries_within_threshold_ok(retries: int) -> None:
    analyzer = _mk_analyzer(retry_threshold=3)
    for _ in range(retries):
        _record_llm(analyzer, sid="s1", status="error")
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert not any(p.pattern_type == PatternType.EXCESSIVE_RETRIES for p in analysis.patterns)


@pytest.mark.parametrize("tokens", [500, 800, 1200, 1500, 2000])
def test_detect_token_waste(tokens: int) -> None:
    analyzer = _mk_analyzer()
    for _ in range(3):
        _record_llm(analyzer, sid="s1", tokens_in=20, tokens_out=15)
    _record_llm(analyzer, sid="s1", tokens_in=tokens, tokens_out=1, cost=1.5)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert any(p.pattern_type == PatternType.TOKEN_WASTE for p in analysis.patterns)


def test_detect_dead_end() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1", tool_calls=[{"name": "read_file", "input": {"path": "/x"}}])
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    tool_node = [n.node_id for n in graph.nodes.values() if n.node_type == NodeType.TOOL_USE][0]
    analyzer.record_tool_result("s1", tool_node, result_size=12)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert any(p.pattern_type == PatternType.DEAD_END for p in analysis.patterns)


def test_no_dead_end_when_used() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1", tool_calls=[{"name": "read_file", "input": {"path": "/x"}}])
    graph = analyzer.get_session_graph("s1")
    assert graph is not None
    tool_node = [n.node_id for n in graph.nodes.values() if n.node_type == NodeType.TOOL_USE][0]
    result_id = analyzer.record_tool_result("s1", tool_node, result_size=12)
    llm2 = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "next"}], [])
    with analyzer._lock:
        analyzer._session_graphs["s1"].nodes[llm2].metadata["tool_result_refs"] = [result_id]
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert not any(result_id in p.affected_nodes and p.pattern_type == PatternType.DEAD_END for p in analysis.patterns)


@pytest.mark.parametrize(
    "chain",
    [
        ["read_file", "write_file"],
        ["read_file", "http_request"],
        ["list_directory", "read_file", "write_file"],
        ["database_query", "http_request"],
        ["get_secret", "http_request"],
    ],
)
def test_detect_tool_chain_patterns(chain: list[str]) -> None:
    analyzer = _mk_analyzer(suspicious_tool_chains=[chain], enable_security_patterns=True)
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": name, "input": {}} for name in chain])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert any(p.pattern_type == PatternType.TOOL_CHAIN_INJECTION for p in analysis.patterns)


def test_no_false_positive_safe_chain() -> None:
    analyzer = _mk_analyzer(suspicious_tool_chains=[["read_file", "http_request"]])
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "read_file", "input": {}}, {"name": "summarize", "input": {}}])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert not any(p.pattern_type == PatternType.TOOL_CHAIN_INJECTION for p in analysis.patterns)


def test_security_patterns_disabled() -> None:
    analyzer = _mk_analyzer(enable_security_patterns=False, suspicious_tool_chains=[["read_file", "http_request"]])
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "read_file", "input": {}}, {"name": "http_request", "input": {}}])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert not any(p.pattern_type == PatternType.TOOL_CHAIN_INJECTION for p in analysis.patterns)


@pytest.mark.parametrize("spike_ratio", [0.51, 0.6, 0.7, 0.8, 0.9, 0.95])
def test_detect_latency_spike(spike_ratio: float) -> None:
    analyzer = _mk_analyzer(latency_spike_threshold=0.5)
    total = 1000.0
    _record_llm(analyzer, sid="s1", latency_ms=total * (1.0 - spike_ratio))
    _record_llm(analyzer, sid="s1", latency_ms=total * spike_ratio)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert any(p.pattern_type == PatternType.LATENCY_SPIKE for p in analysis.patterns)


def test_no_spike_when_balanced() -> None:
    analyzer = _mk_analyzer(latency_spike_threshold=0.7)
    _record_llm(analyzer, sid="s1", latency_ms=100)
    _record_llm(analyzer, sid="s1", latency_ms=110)
    _record_llm(analyzer, sid="s1", latency_ms=90)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert not any(p.pattern_type == PatternType.LATENCY_SPIKE for p in analysis.patterns)


def test_latency_spike_suggestion() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1", latency_ms=10)
    _record_llm(analyzer, sid="s1", latency_ms=1000)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    spikes = [p for p in analysis.patterns if p.pattern_type == PatternType.LATENCY_SPIKE]
    assert spikes and "cache" in spikes[0].suggestion.lower()


def test_topology_depth() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1", content="1")
    _record_llm(analyzer, sid="s1", content="2")
    _record_llm(analyzer, sid="s1", content="3")
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert analysis.topology.depth >= 1


def test_topology_width() -> None:
    analyzer = _mk_analyzer()
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "a", "input": {}}, {"name": "b", "input": {}}, {"name": "c", "input": {}}])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert analysis.topology.width >= 1


@pytest.mark.parametrize("edge_count", [1, 2, 3, 4, 5, 6])
def test_topology_density(edge_count: int) -> None:
    analyzer = _mk_analyzer()
    for i in range(edge_count + 1):
        analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": str(i)}], [])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert 0.0 <= analysis.topology.density <= 1.0


def test_tool_diversity() -> None:
    analyzer = _mk_analyzer()
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "a", "input": {}}, {"name": "a", "input": {}}, {"name": "b", "input": {}}])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert 0.0 <= analysis.topology.tool_diversity <= 1.0


def test_model_switches() -> None:
    analyzer = _mk_analyzer()
    analyzer.record_request("s1", "claude-haiku-4", [{"role": "user", "content": "a"}], [])
    analyzer.record_request("s1", "claude-sonnet-4", [{"role": "user", "content": "b"}], [])
    analyzer.record_request("s1", "claude-opus-4", [{"role": "user", "content": "c"}], [])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert analysis.topology.model_switches >= 2


def test_total_cost_aggregation() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1", cost=0.2)
    _record_llm(analyzer, sid="s1", cost=0.3)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert analysis.topology.total_cost_usd == pytest.approx(0.5)


def test_critical_path() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1", latency_ms=5)
    _record_llm(analyzer, sid="s1", latency_ms=100)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert len(analysis.topology.critical_path) >= 1


def test_analyze_healthy_session() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1", latency_ms=10, tokens_in=10, tokens_out=8)
    _record_llm(analyzer, sid="s1", latency_ms=12, tokens_in=12, tokens_out=10)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert analysis.summary.health_score >= 0.6


def test_analyze_problematic_session() -> None:
    analyzer = _mk_analyzer()
    for _ in range(6):
        _record_llm(analyzer, sid="s1", status="error", tokens_in=1000, tokens_out=1, latency_ms=1000)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert analysis.summary.health_score <= 0.85
    assert analysis.summary.total_patterns >= 1


def test_flow_summary_waste_estimation() -> None:
    analyzer = _mk_analyzer()
    for _ in range(3):
        _record_llm(analyzer, sid="s1", tokens_in=800, tokens_out=1, cost=0.5, latency_ms=500)
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert analysis.summary.estimated_waste_usd >= 0.0
    assert analysis.summary.estimated_waste_ms >= 0.0


def test_flow_summary_recommendations() -> None:
    analyzer = _mk_analyzer()
    llm = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "q"}], [])
    analyzer.record_response("s1", llm, 10, 10, 0.01, 10.0, tool_calls=[{"name": "read_file", "input": {}}, {"name": "web_search", "input": {}}, {"name": "read_file", "input": {}}])
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    assert isinstance(analysis.summary.recommendations, list)


def test_analyze_from_recording() -> None:
    analyzer = _mk_analyzer()
    recording = [
        {
            "session_id": "s-rec",
            "model": "gpt-4o",
            "request": {"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]},
            "response": {"usage": {"prompt_tokens": 5, "completion_tokens": 2}},
            "status_code": 200,
            "cost": 0.02,
            "latency_ms": 30.0,
        }
    ]
    analysis = analyzer.analyze_from_recording(recording)
    assert analysis.session_id == "s-rec"
    assert analysis.topology.total_llm_calls >= 1


def test_to_dict_serialization() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1")
    analysis = analyzer.analyze_session("s1")
    assert analysis is not None
    payload = analysis.to_dict()
    assert isinstance(payload, dict)
    json.dumps(payload)


def test_export_graph_json() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1")
    payload = analyzer.export_graph_json("s1")
    assert payload
    loaded = json.loads(payload)
    assert loaded["session_id"] == "s1"


def test_thread_safe_concurrent_recording() -> None:
    analyzer = _mk_analyzer()

    def worker(i: int) -> None:
        for j in range(50):
            _record_llm(analyzer, sid=f"s{i%4}", content=f"{i}-{j}")

    with ThreadPoolExecutor(max_workers=8) as pool:
        for i in range(8):
            pool.submit(worker, i)
    stats = analyzer.get_stats()
    assert stats["sessions_tracked"] >= 1


def test_max_sessions_eviction() -> None:
    analyzer = _mk_analyzer(max_sessions=3)
    _record_llm(analyzer, sid="s1")
    _record_llm(analyzer, sid="s2")
    _record_llm(analyzer, sid="s3")
    _record_llm(analyzer, sid="s4")
    assert analyzer.get_session_graph("s1") is None
    assert analyzer.get_session_graph("s4") is not None


def test_get_stats_aggregation() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1")
    analyzer.analyze_session("s1")
    stats = analyzer.get_stats()
    assert "pattern_counts" in stats
    assert "sessions_tracked" in stats


def test_list_sessions() -> None:
    analyzer = _mk_analyzer()
    _record_llm(analyzer, sid="s1")
    _record_llm(analyzer, sid="s2")
    sessions = analyzer.list_sessions()
    assert len(sessions) == 2
    assert {"id", "node_count", "start_time"}.issubset(sessions[0].keys())


def test_config_normalization_flow_xray(tmp_path: Path) -> None:
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
flow_xray:
  enabled: true
  max_sessions: 10
  redundancy_window_seconds: 25
  retry_threshold: 4
  ping_pong_min_repetitions: 3
  security_patterns: true
  efficiency_patterns: true
  performance_patterns: false
  suspicious_tool_chains:
    - ["read_file", "http_request"]
""".strip(),
        encoding="utf-8",
    )
    loaded = load_policy(policy)
    cfg = loaded["flow_xray"]
    assert cfg["enabled"] is True
    assert cfg["max_sessions"] == 10
    assert cfg["enable_performance_patterns"] is False


def test_disabled_flow_xray() -> None:
    analyzer = FlowAnalyzer(FlowXRayConfig(enabled=False))
    node = analyzer.record_request("s1", "gpt-4o", [{"role": "user", "content": "x"}], [])
    assert isinstance(node, str)


class _FlowUpstreamHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length)
        payload = {
            "model": "gpt-4o-mini",
            "usage": {"prompt_tokens": 5, "completion_tokens": 3},
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        }
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        _ = (fmt, args)


def _start_http_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[HTTPServer, threading.Thread]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _pick_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    p = int(sock.getsockname()[1])
    sock.close()
    return p


def _post(port: int) -> dict[str, str]:
    req = UrlRequest(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}]}).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer x"},
        method="POST",
    )
    with urlopen(req, timeout=5) as resp:
        _ = resp.read()
        return dict(resp.headers.items())


def test_proxy_integration_records_flow(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_FlowUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\nflow_xray:\n  enabled: true\n", encoding="utf-8")
    port = _pick_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        _post(port)
        with urlopen(f"http://127.0.0.1:{port}/api/flow/sessions", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert isinstance(payload.get("sessions"), list)
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_flow_endpoints(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_FlowUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\nflow_xray:\n  enabled: true\n", encoding="utf-8")
    port = _pick_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        _post(port)
        with urlopen(f"http://127.0.0.1:{port}/api/flow/sessions", timeout=5) as resp:
            sessions = json.loads(resp.read().decode("utf-8")).get("sessions", [])
        if sessions:
            sid = sessions[0]["id"]
            with urlopen(f"http://127.0.0.1:{port}/api/flow/analyze/{sid}", timeout=5) as resp:
                analysis = json.loads(resp.read().decode("utf-8"))
            assert "topology" in analysis
            with urlopen(f"http://127.0.0.1:{port}/api/flow/graph/{sid}", timeout=5) as resp:
                graph = json.loads(resp.read().decode("utf-8"))
            assert graph.get("session_id") == sid
        with urlopen(f"http://127.0.0.1:{port}/api/flow/patterns", timeout=5) as resp:
            stats = json.loads(resp.read().decode("utf-8"))
        assert "sessions_tracked" in stats
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_stats_contains_flow_xray(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_FlowUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\nflow_xray:\n  enabled: true\n", encoding="utf-8")
    port = _pick_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        _post(port)
        with urlopen(f"http://127.0.0.1:{port}/stats", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert "flow_xray" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_flow_disabled_endpoints(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_FlowUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\n", encoding="utf-8")
    port = _pick_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        with urlopen(f"http://127.0.0.1:{port}/api/flow/sessions", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload.get("sessions") == []
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def _api_policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules:
  - name: budget_limit
    max_cost_per_call: 0.05
    daily_budget: 10.0
  - name: rate_limit
    max_requests_per_minute: 100
""".strip()


def _api_auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _api_client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


@pytest.mark.asyncio
async def test_flow_export_returns_valid_json(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_api_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _api_client(app) as client:
        await client.post(
            "/api/v1/evaluate",
            headers=_api_auth(),
            json={"session_id": "flow-s1", "tool_name": "read_file", "params": {"path": "/tmp/a"}, "cost": 0.01},
        )
        resp = await client.get("/api/v1/flow/flow-s1/export", headers=_api_auth())
    assert resp.status_code == 200
    payload = resp.json()
    assert payload["session_id"] == "flow-s1"
    assert isinstance(payload.get("exported_at"), str)
    assert isinstance(payload.get("pipeline_phases"), list)
    assert isinstance(payload.get("decisions"), list)
    assert isinstance(payload.get("summary"), dict)
    assert isinstance(payload.get("share_url"), str)


@pytest.mark.asyncio
async def test_flow_share_token_generated(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_api_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _api_client(app) as client:
        resp = await client.get("/api/v1/flow/flow-s2/share-token", headers=_api_auth())
    assert resp.status_code == 200
    payload = resp.json()
    assert isinstance(payload.get("token"), str)
    assert len(payload["token"]) == 8
    assert payload["url"].endswith(payload["token"])


@pytest.mark.asyncio
async def test_flow_export_includes_all_phases(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_api_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _api_client(app) as client:
        await client.post(
            "/api/v1/evaluate",
            headers=_api_auth(),
            json={"session_id": "flow-s3", "tool_name": "read_file", "params": {"path": "/tmp/a"}, "cost": 0.01},
        )
        await client.post(
            "/api/v1/evaluate",
            headers=_api_auth(),
            json={"session_id": "flow-s3", "tool_name": "sql_query", "params": {"q": "DROP table t"}, "cost": 0.2},
        )
        resp = await client.get("/api/v1/flow/flow-s3/export", headers=_api_auth())
    assert resp.status_code == 200
    payload = resp.json()
    phases = payload.get("pipeline_phases", [])
    assert isinstance(phases, list)
    assert phases
    assert all(isinstance(item.get("phase"), str) for item in phases if isinstance(item, dict))
    assert payload["summary"]["total_requests"] >= 2
    assert payload["summary"]["blocked"] >= 1


@pytest.mark.asyncio
async def test_flow_share_link_format(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_api_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(tmp_path / "decisions.jsonl"),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    async with await _api_client(app) as client:
        await client.post(
            "/api/v1/evaluate",
            headers=_api_auth(),
            json={"session_id": "flow-s4", "tool_name": "read_file", "params": {"path": "/tmp/a"}, "cost": 0.01},
        )
        resp = await client.get("/api/v1/flow/flow-s4/export", headers=_api_auth())
    assert resp.status_code == 200
    share_url = str(resp.json().get("share_url", ""))
    assert share_url.startswith("http://localhost:8080/flow/")
    token = share_url.rsplit("/", 1)[-1]
    assert len(token) == 8
    assert all(ch in "0123456789abcdef" for ch in token)
