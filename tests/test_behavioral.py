from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
import random
import time
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

import pytest

from orchesis.behavioral import (
    BehavioralDetector,
    BehavioralFingerprint,
    RunningStats,
    extract_agent_id,
)
from orchesis.config import load_policy
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy


def test_running_stats_empty() -> None:
    s = RunningStats()
    assert s.count == 0
    assert s.mean == 0.0
    assert s.std == 0.0


def test_running_stats_single_value() -> None:
    s = RunningStats()
    s.update(10.0)
    assert s.count == 1
    assert s.mean == 10.0
    assert s.std == 0.0


def test_running_stats_known_dataset() -> None:
    s = RunningStats()
    values = [2.0, 4.0, 4.0, 4.0, 5.0, 5.0, 7.0, 9.0]
    for v in values:
        s.update(v)
    assert round(s.mean, 3) == 5.0
    assert round(s.variance, 3) == 4.571


def test_running_stats_z_score() -> None:
    s = RunningStats()
    for v in [1.0, 2.0, 3.0, 4.0, 5.0]:
        s.update(v)
    assert round(s.z_score(s.mean), 6) == 0.0
    assert s.z_score(s.mean + (2 * s.std)) == pytest.approx(2.0, rel=1e-2)


def test_running_stats_large_dataset_stability() -> None:
    s = RunningStats()
    for i in range(100_000):
        s.update(float(i % 100))
    assert s.count == 100_000
    assert 45.0 < s.mean < 55.0


def test_running_stats_thread_safety() -> None:
    s = RunningStats()

    def worker() -> None:
        for _ in range(10_000):
            s.update(1.0)

    with ThreadPoolExecutor(max_workers=10) as pool:
        for _ in range(10):
            pool.submit(worker)
    assert s.count == 100_000


def test_fingerprint_learning_mode() -> None:
    f = BehavioralFingerprint(learning_window=3)
    f.update({"model": "gpt-4o", "messages": [], "tools": [], "estimated_cost": 0.0})
    assert f.is_learning() is True


def test_fingerprint_transition_to_monitoring() -> None:
    f = BehavioralFingerprint(learning_window=2)
    f.update({"model": "gpt-4o", "messages": [], "tools": [], "estimated_cost": 0.0})
    f.update({"model": "gpt-4o", "messages": [], "tools": [], "estimated_cost": 0.0})
    assert f.is_learning() is False


def test_fingerprint_profile_contains_dimensions() -> None:
    f = BehavioralFingerprint(learning_window=1)
    f.update({"model": "gpt-4o", "messages": [{"role": "user", "content": "hi"}], "tools": [], "estimated_cost": 0.1})
    profile = f.get_profile()
    assert "dimensions" in profile
    assert "prompt_tokens" in profile["dimensions"]


def test_fingerprint_tracks_model_distribution() -> None:
    f = BehavioralFingerprint(learning_window=1)
    f.update({"model": "m1", "messages": [], "tools": [], "estimated_cost": 0.0})
    f.update({"model": "m1", "messages": [], "tools": [], "estimated_cost": 0.0})
    assert f.get_profile()["model_distribution"]["m1"] == 2


def test_fingerprint_tracks_tool_distribution() -> None:
    f = BehavioralFingerprint(learning_window=1)
    f.update({"model": "m1", "messages": [], "tools": [{"name": "web_search"}], "estimated_cost": 0.0})
    assert f.get_profile()["tool_distribution"]["web_search"] == 1


def test_fingerprint_request_frequency_calculation() -> None:
    f = BehavioralFingerprint(learning_window=1)
    f.update({"model": "m1", "messages": [], "tools": [], "estimated_cost": 0.0})
    time.sleep(0.01)
    f.update({"model": "m1", "messages": [], "tools": [], "estimated_cost": 0.0})
    assert f.request_frequency.count >= 1


def test_fingerprint_token_estimation() -> None:
    f = BehavioralFingerprint(learning_window=1)
    f.update({"model": "m1", "messages": [{"role": "user", "content": "x" * 100}], "tools": [], "estimated_cost": 0.0})
    assert f.prompt_tokens.mean > 0


def test_fingerprint_thread_safety() -> None:
    f = BehavioralFingerprint(learning_window=1000)

    def worker() -> None:
        for _ in range(100):
            f.update({"model": "m1", "messages": [], "tools": [], "estimated_cost": 0.0})

    with ThreadPoolExecutor(max_workers=8) as pool:
        for _ in range(8):
            pool.submit(worker)
    assert f.total_requests == 800


def _detector_cfg() -> dict:
    return {
        "enabled": True,
        "learning_window": 5,
        "dimensions": {
            "request_frequency": {"z_threshold": 3.0, "action": "warn"},
            "prompt_tokens": {"z_threshold": 1.5, "action": "warn"},
            "cost_per_request": {"z_threshold": 1.5, "action": "block"},
            "tool_count": {"z_threshold": 3.0, "action": "warn"},
            "error_rate": {"z_threshold": 3.0, "action": "warn"},
        },
    }


def _req(prompt_len: int = 40, cost: float = 0.01, model: str = "gpt-4o", tools: list | None = None) -> dict:
    return {
        "model": model,
        "messages": [{"role": "user", "content": "x" * prompt_len}],
        "tools": tools or [],
        "estimated_cost": cost,
        "headers": {"x-agent-id": "agent-1"},
    }


def test_detector_new_agent_learning() -> None:
    d = BehavioralDetector(_detector_cfg())
    decision = d.check_request("a1", _req())
    assert decision.action == "learning"


def test_detector_transition_to_monitoring() -> None:
    d = BehavioralDetector(_detector_cfg())
    for _ in range(5):
        d.check_request("a1", _req())
    decision = d.check_request("a1", _req())
    assert decision.state == "monitoring"


def test_detector_normal_request_allow() -> None:
    d = BehavioralDetector(_detector_cfg())
    for i in range(6):
        d.check_request("a1", _req(prompt_len=30 + i))
    decision = d.check_request("a1", _req(prompt_len=35))
    assert decision.action in {"allow", "warn"}
    assert decision.anomaly_score >= 0.0


def test_detector_prompt_tokens_anomaly_warn() -> None:
    d = BehavioralDetector(_detector_cfg())
    for i in range(6):
        d.check_request("a1", _req(prompt_len=20 + i))
    decision = d.check_request("a1", _req(prompt_len=4000))
    assert decision.action in {"warn", "block"}
    assert decision.anomaly_score > 0.0


def test_detector_cost_spike_block() -> None:
    d = BehavioralDetector(_detector_cfg())
    for i in range(6):
        d.check_request("a1", _req(cost=0.01 + i * 0.001, prompt_len=40 + i))
    decision = d.check_request("a1", _req(cost=100.0, prompt_len=45))
    assert decision.action == "block"


def test_detector_multiple_anomalies_highest_wins() -> None:
    d = BehavioralDetector(_detector_cfg())
    for i in range(6):
        d.check_request("a1", _req(cost=0.01 + i * 0.001, prompt_len=30 + i))
    decision = d.check_request("a1", _req(cost=100.0, prompt_len=3000))
    assert decision.action == "block"
    assert len(decision.anomalies) >= 1


def test_detector_agents_independent() -> None:
    d = BehavioralDetector(_detector_cfg())
    for _ in range(6):
        d.check_request("a1", _req(prompt_len=20))
    decision_a2 = d.check_request("a2", _req(prompt_len=2000))
    assert decision_a2.state == "learning"


def test_detector_get_agent_profile() -> None:
    d = BehavioralDetector(_detector_cfg())
    d.check_request("a1", _req())
    profile = d.get_agent_profile("a1")
    assert profile is not None
    assert "dimensions" in profile


def test_detector_stats_counts() -> None:
    d = BehavioralDetector(_detector_cfg())
    d.check_request("a1", _req())
    stats = d.get_stats()
    assert "agents_learning" in stats
    assert "total_anomalies_detected" in stats


def test_detector_reset_single_agent() -> None:
    d = BehavioralDetector(_detector_cfg())
    d.check_request("a1", _req())
    d.reset("a1")
    assert d.get_agent_profile("a1") is None


def test_detector_reset_all_agents() -> None:
    d = BehavioralDetector(_detector_cfg())
    d.check_request("a1", _req())
    d.check_request("a2", _req())
    d.reset()
    assert d.get_stats()["agents_learning"] == 0


def test_detector_record_response_updates_error_and_completion() -> None:
    d = BehavioralDetector(_detector_cfg())
    d.check_request("a1", _req())
    d.record_response("a1", is_error=True, completion_tokens=100)
    profile = d.get_agent_profile("a1")
    assert profile is not None
    assert profile["dimensions"]["completion_tokens"]["count"] >= 1


def test_config_validation_bad_action(tmp_path: Path) -> None:
    policy = tmp_path / "policy_bad_action.yaml"
    policy.write_text(
        """
rules: []
behavioral_fingerprint:
  enabled: true
  learning_window: 5
  dimensions:
    request_frequency:
      z_threshold: 3.0
      action: nope
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(Exception):
        load_policy(policy)


def test_config_validation_negative_threshold(tmp_path: Path) -> None:
    policy = tmp_path / "policy_bad_threshold.yaml"
    policy.write_text(
        """
rules: []
behavioral_fingerprint:
  enabled: true
  learning_window: 5
  dimensions:
    request_frequency:
      z_threshold: -1
      action: warn
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(Exception):
        load_policy(policy)


def test_extract_agent_id_header_priority() -> None:
    rid = extract_agent_id({"headers": {"X-Agent-Id": "abc123"}, "model": "gpt-4o"})
    assert rid == "abc123"


def test_extract_agent_id_api_key_fallback() -> None:
    rid = extract_agent_id({"headers": {"Authorization": "Bearer TESTTOKEN12345"}, "model": "gpt-4o"})
    assert rid.startswith("TESTTOKE")


def test_extract_agent_id_default_fallback() -> None:
    assert extract_agent_id({"headers": {}, "model": "gpt-4o"}) == "default"


class _BehaviorUpstreamHandler(BaseHTTPRequestHandler):
    response_status = 200

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length)
        payload = {
            "model": "gpt-4o-mini",
            "usage": {"prompt_tokens": 10, "completion_tokens": 5},
            "choices": [{"message": {"content": "ok"}, "finish_reason": "stop"}],
        }
        data = json.dumps(payload).encode("utf-8")
        self.send_response(self.__class__.response_status)
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


def _pick_free_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    return port


def _make_policy(tmp_path: Path, extra: str = "") -> Path:
    policy = tmp_path / f"policy_{random.randint(1, 999999)}.yaml"
    policy.write_text(
        (
            """
rules: []
behavioral_fingerprint:
  enabled: true
  learning_window: 3
  dimensions:
    request_frequency: { z_threshold: 10.0, action: warn }
    prompt_tokens: { z_threshold: 1.0, action: warn }
    cost_per_request: { z_threshold: 1.0, action: block }
    tool_count: { z_threshold: 10.0, action: warn }
    error_rate: { z_threshold: 10.0, action: warn }
"""
            + extra
        ).strip(),
        encoding="utf-8",
    )
    return policy


def _post_proxy(port: int, content: str) -> tuple[int, dict[str, str], dict]:
    req = UrlRequest(
        f"http://127.0.0.1:{port}/v1/chat/completions",
        data=json.dumps(
            {
                "model": "gpt-4o",
                "messages": [{"role": "user", "content": content}],
            }
        ).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": "Bearer x", "X-Agent-Id": "agent-test"},
        method="POST",
    )
    with urlopen(req, timeout=5) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
        return int(resp.status), dict(resp.headers.items()), payload


def test_proxy_learning_header(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_BehaviorUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(_make_policy(tmp_path)),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        _, headers, _ = _post_proxy(port, "short text")
        assert headers.get("X-Orchesis-Behavior") == "learning"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_normal_header_after_learning(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_BehaviorUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(_make_policy(tmp_path)),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        _post_proxy(port, "a")
        _post_proxy(port, "aa")
        _post_proxy(port, "aaa")
        _, headers, _ = _post_proxy(port, "aaaa")
        assert headers.get("X-Orchesis-Behavior") in {"normal", "anomaly"}
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_anomaly_headers_present(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_BehaviorUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(_make_policy(tmp_path)),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        _post_proxy(port, "x")
        _post_proxy(port, "xx")
        _post_proxy(port, "xxx")
        _, headers, _ = _post_proxy(port, "x" * 5000)
        if headers.get("X-Orchesis-Behavior") == "anomaly":
            assert headers.get("X-Orchesis-Anomaly-Score")
            assert headers.get("X-Orchesis-Anomaly-Dimensions")
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_behavioral_block_429(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_BehaviorUpstreamHandler)
    extra = """
behavioral_fingerprint:
  enabled: true
  learning_window: 3
  dimensions:
    request_frequency: { z_threshold: 10.0, action: warn }
    prompt_tokens: { z_threshold: 1.0, action: block }
    cost_per_request: { z_threshold: 10.0, action: warn }
    tool_count: { z_threshold: 10.0, action: warn }
    error_rate: { z_threshold: 10.0, action: warn }
"""
    policy = tmp_path / "policy_block.yaml"
    policy.write_text("rules: []\n" + extra, encoding="utf-8")
    port = _pick_free_port()
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
        for item in ("a", "aa", "aaa"):
            try:
                _post_proxy(port, item)
            except HTTPError:
                pass
        req = UrlRequest(
            f"http://127.0.0.1:{port}/v1/chat/completions",
            data=json.dumps({"model": "gpt-4o", "messages": [{"role": "user", "content": "x" * 10000}]}).encode("utf-8"),
            headers={"Content-Type": "application/json", "Authorization": "Bearer x", "X-Agent-Id": "agent-test"},
            method="POST",
        )
        with pytest.raises(HTTPError) as err:
            urlopen(req, timeout=5)
        assert err.value.code == 429
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_stats_contains_behavioral_detector(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_BehaviorUpstreamHandler)
    port = _pick_free_port()
    proxy = LLMHTTPProxy(
        policy_path=str(_make_policy(tmp_path)),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={"openai": f"http://127.0.0.1:{upstream.server_address[1]}", "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}"},
        ),
    )
    proxy.start(blocking=False)
    try:
        _post_proxy(port, "hello")
        with urlopen(f"http://127.0.0.1:{port}/stats", timeout=3) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert "behavioral_detector" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_behavioral_disabled_by_default(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_BehaviorUpstreamHandler)
    policy = tmp_path / "policy_none.yaml"
    policy.write_text("rules: []\n", encoding="utf-8")
    port = _pick_free_port()
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
        _, headers, _ = _post_proxy(port, "hello")
        assert "X-Orchesis-Behavior" not in headers
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
