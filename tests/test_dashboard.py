from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

import pytest

from orchesis.dashboard import get_dashboard_html
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy


class _DashboardUpstreamHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length)
        payload = {
            "model": "gpt-4o-mini",
            "usage": {"prompt_tokens": 6, "completion_tokens": 4},
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


def _make_proxy(tmp_path: Path, policy_text: str) -> tuple[LLMHTTPProxy, HTTPServer]:
    upstream, _ = _start_http_server(_DashboardUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text(policy_text, encoding="utf-8")
    port = _pick_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={
                "openai": f"http://127.0.0.1:{upstream.server_address[1]}",
                "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}",
            },
        ),
    )
    proxy.start(blocking=False)
    return proxy, upstream


def _get_json(port: int, path: str) -> tuple[int, dict]:
    with urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as resp:
        return int(resp.status), json.loads(resp.read().decode("utf-8"))


def _get_text(port: int, path: str) -> tuple[int, str, str]:
    with urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as resp:
        body = resp.read().decode("utf-8")
        ctype = str(resp.headers.get("Content-Type", ""))
        return int(resp.status), ctype, body


def _post_chat(port: int, *, agent_id: str | None = None) -> None:
    headers = {"Content-Type": "application/json", "Authorization": "Bearer x"}
    if agent_id:
        headers["X-Agent-Id"] = agent_id
    req = UrlRequest(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "hello"}]}).encode("utf-8"),
        headers=headers,
        method="POST",
    )
    with urlopen(req, timeout=5) as resp:
        _ = resp.read()


# HTML generation tests (5)
def test_dashboard_html_returns_valid_html_string() -> None:
    html = get_dashboard_html()
    assert isinstance(html, str)
    assert "<html" in html.lower()
    assert "</html>" in html.lower()


def test_dashboard_html_contains_expected_tabs() -> None:
    html = get_dashboard_html().lower()
    assert "shield" in html
    assert "agents" in html
    assert "sessions" in html
    assert "flow x-ray" in html


def test_dashboard_html_contains_css_styles() -> None:
    html = get_dashboard_html()
    assert "<style>" in html
    assert "#0A0A12" in html
    assert "backdrop-filter" in html


def test_dashboard_html_contains_javascript() -> None:
    html = get_dashboard_html()
    assert "<script>" in html
    assert "POLL_INTERVAL" in html
    assert "fetchData(" in html
    assert html.count("const ratio =") == 1
    assert "const poolHitRatio =" in html


def test_dashboard_html_size_reasonable() -> None:
    html = get_dashboard_html()
    assert len(html) > 5_000
    assert len(html) < 500_000


# Dashboard v2 tests (10)
def test_dashboard_html_contains_experiments_tab() -> None:
    html = get_dashboard_html()
    assert "Experiments" in html or "experiments" in html


def test_dashboard_html_contains_threats_tab() -> None:
    html = get_dashboard_html()
    assert "Threats" in html or "threats" in html


def test_dashboard_html_contains_cache_tab() -> None:
    html = get_dashboard_html()
    assert "Cache" in html or "cache" in html


def test_dashboard_experiments_section_ids() -> None:
    html = get_dashboard_html()
    assert "exp-active" in html
    assert "exp-cards" in html
    assert "exp-correlations" in html


def test_dashboard_threats_section_ids() -> None:
    html = get_dashboard_html()
    assert "th-sigs" in html
    assert "th-scans" in html
    assert "th-matches" in html
    assert "th-blocks" in html


def test_dashboard_cache_section_ids() -> None:
    html = get_dashboard_html()
    assert "c-hit-rate" in html
    assert "c-tokens" in html
    assert "c-cost" in html
    assert "c-entries" in html


def test_dashboard_shield_new_metrics() -> None:
    html = get_dashboard_html()
    assert "m-threats" in html
    assert "m-cache-rate" in html
    assert "m-experiments" in html
    assert "m-task-success" in html


def test_dashboard_poll_functions_exist() -> None:
    html = get_dashboard_html()
    assert "pollExperiments" in html
    assert "pollThreats" in html
    assert "pollCache" in html


def test_dashboard_severity_css_classes() -> None:
    html = get_dashboard_html()
    assert "sev-critical" in html
    assert "sev-high" in html
    assert "sev-medium" in html
    assert "sev-low" in html


def test_dashboard_variant_card_css() -> None:
    html = get_dashboard_html()
    assert "variant-card" in html
    assert "variant-pair" in html


# Overview endpoint tests (8)
def test_dashboard_overview_returns_expected_keys(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        code, payload = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert code == 200
        for key in (
            "status",
            "uptime_seconds",
            "total_requests",
            "blocked_requests",
            "total_cost_usd",
            "active_agents",
            "circuit_breakers",
            "recent_events",
            "cost_timeline",
        ):
            assert key in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_overview_status_clear_without_blocks(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        _, payload = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert payload["status"] == "clear"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_overview_status_monitoring_with_recent_blocks(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        proxy._add_dashboard_event("blocked", "medium", "blocked test")
        _, payload = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert payload["status"] == "monitoring"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_overview_status_alert_with_circuit_open(tmp_path: Path) -> None:
    policy = "rules: []\ncircuit_breaker:\n  enabled: true\n"
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        with proxy._circuit_breaker._lock:  # noqa: SLF001
            proxy._circuit_breaker._state = proxy._circuit_breaker.STATE_OPEN  # noqa: SLF001
        _, payload = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert payload["status"] == "alert"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_overview_cost_timeline_list(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        _, payload = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert isinstance(payload["cost_timeline"], list)
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_overview_recent_events_list(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        _, payload = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert isinstance(payload["recent_events"], list)
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_overview_budget_present_when_configured(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\nbudgets:\n  daily: 10\n")
    try:
        _, payload = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert payload["budget"]["limit_usd"] == 10.0
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_overview_budget_zero_when_not_configured(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        _, payload = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert payload["budget"]["limit_usd"] == 0.0
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


# Agents endpoint tests (5)
def test_dashboard_agents_returns_agents_key(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        _, payload = _get_json(proxy._config.port, "/api/dashboard/agents")
        assert "agents" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_agents_empty_when_detector_disabled(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        _, payload = _get_json(proxy._config.port, "/api/dashboard/agents")
        assert payload["agents"] == []
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_agents_contains_expected_fields(tmp_path: Path) -> None:
    policy = "rules: []\nbehavioral_fingerprint:\n  enabled: true\n  learning_window: 1\n"
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        _post_chat(proxy._config.port, agent_id="agent-a")
        _, payload = _get_json(proxy._config.port, "/api/dashboard/agents")
        assert payload["agents"]
        agent = payload["agents"][0]
        for key in ("agent_id", "total_requests", "avg_tokens", "anomaly_score", "tools_used", "last_seen"):
            assert key in agent
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_agents_multiple_agents(tmp_path: Path) -> None:
    policy = "rules: []\nbehavioral_fingerprint:\n  enabled: true\n  learning_window: 1\n"
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        _post_chat(proxy._config.port, agent_id="agent-a")
        _post_chat(proxy._config.port, agent_id="agent-b")
        _, payload = _get_json(proxy._config.port, "/api/dashboard/agents")
        ids = {item["agent_id"] for item in payload["agents"]}
        assert "agent-a" in ids and "agent-b" in ids
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_agents_anomaly_scores_present(tmp_path: Path) -> None:
    policy = "rules: []\nbehavioral_fingerprint:\n  enabled: true\n  learning_window: 1\n"
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        _post_chat(proxy._config.port, agent_id="agent-a")
        _, payload = _get_json(proxy._config.port, "/api/dashboard/agents")
        assert "anomaly_score" in payload["agents"][0]
        assert "anomaly_scores" in payload["agents"][0]
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


# Proxy route handling (5)
def test_dashboard_route_returns_html(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        code, ctype, _ = _get_text(proxy._config.port, "/dashboard")
        assert code == 200
        assert "text/html" in ctype
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_trailing_slash_returns_html(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        code, ctype, _ = _get_text(proxy._config.port, "/dashboard/")
        assert code == 200
        assert "text/html" in ctype
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_html_response_non_empty(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        _, _, body = _get_text(proxy._config.port, "/dashboard")
        assert len(body) > 0
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_unknown_subpath_returns_404(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        with pytest.raises(HTTPError) as err:
            _get_text(proxy._config.port, "/dashboard/xxx")
        assert err.value.code == 404
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_accessible_without_sessions(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        code, _, _ = _get_text(proxy._config.port, "/dashboard")
        assert code == 200
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_favicon_path_returns_no_content(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        req = UrlRequest(f"http://127.0.0.1:{proxy._config.port}/favicon.ico")
        with urlopen(req, timeout=5) as resp:
            assert int(resp.status) == 204
            assert resp.read() == b""
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


# Integration (5)
def test_overview_reflects_proxy_stats_after_requests(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        _post_chat(proxy._config.port)
        _post_chat(proxy._config.port)
        _, payload = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert payload["total_requests"] >= 2
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_agent_list_updates_after_behavioral_recording(tmp_path: Path) -> None:
    policy = "rules: []\nbehavioral_fingerprint:\n  enabled: true\n  learning_window: 1\n"
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        _post_chat(proxy._config.port, agent_id="agent-z")
        _, payload = _get_json(proxy._config.port, "/api/dashboard/agents")
        assert any(item["agent_id"] == "agent-z" for item in payload["agents"])
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_flow_xray_data_accessible_from_dashboard_paths(tmp_path: Path) -> None:
    policy = "rules: []\nflow_xray:\n  enabled: true\n"
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        _post_chat(proxy._config.port)
        _, overview = _get_json(proxy._config.port, "/api/dashboard/overview")
        assert "flow_xray" in overview
        _, flow_sessions = _get_json(proxy._config.port, "/api/flow/sessions")
        assert "sessions" in flow_sessions
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_sessions_list_consistent_between_api_paths(tmp_path: Path) -> None:
    policy = "rules: []\nrecording:\n  enabled: true\n"
    cwd = Path.cwd()
    os.chdir(tmp_path)
    proxy, upstream = _make_proxy(tmp_path, policy)
    try:
        _post_chat(proxy._config.port)
        _, a = _get_json(proxy._config.port, "/sessions")
        _, b = _get_json(proxy._config.port, "/api/sessions")
        assert len(a.get("sessions", [])) == len(b.get("sessions", []))
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        os.chdir(cwd)


def test_stats_endpoint_still_works(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        code, payload = _get_json(proxy._config.port, "/stats")
        assert code == 200
        assert "requests" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
