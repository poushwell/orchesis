from __future__ import annotations

from datetime import datetime
import gzip
import json
from pathlib import Path
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

import pytest

from orchesis.air_export import (
    air_summary_from_turns,
    export_session_to_air,
    export_session_to_air_file,
    validate_air,
)
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy
from orchesis.recorder import SessionRecord, SessionRecorder


def _make_recorder(tmp_path: Path) -> SessionRecorder:
    return SessionRecorder(storage_path=str(tmp_path / "sessions"), compress=False)


def _seed_session(recorder: SessionRecorder, session_id: str = "sess-1", *, agent_id: str = "agent-1") -> None:
    now = time.time()
    recorder.record(
        SessionRecord(
            request_id="r1",
            session_id=session_id,
            timestamp=now,
            request={
                "model": "gpt-4o-mini",
                "messages": [{"role": "user", "content": "hello world"}],
                "tools": [{"name": "web_search", "input_schema": {"type": "object"}}],
                "temperature": 0.2,
            },
            response={
                "usage": {"prompt_tokens": 10, "completion_tokens": 7},
                "choices": [{"finish_reason": "stop"}],
                "content": [
                    {"type": "tool_use", "name": "web_search", "input": {"q": "hello"}, "output": {"ok": True}}
                ],
            },
            status_code=200,
            provider="openai",
            model="gpt-4o-mini",
            latency_ms=123.4,
            cost=0.031,
            error=None,
            metadata={"agent_id": agent_id},
        )
    )
    recorder.record(
        SessionRecord(
            request_id="r2",
            session_id=session_id,
            timestamp=now + 1.5,
            request={"model": "gpt-4o", "messages": [{"role": "user", "content": "second"}], "tools": []},
            response={"usage": {"prompt_tokens": 8, "completion_tokens": 3}, "choices": [{"finish_reason": "stop"}]},
            status_code=200,
            provider="openai",
            model="gpt-4o",
            latency_ms=88.0,
            cost=0.022,
            error=None,
            metadata={"agent_id": agent_id},
        )
    )


class _FakeFlowAnalysis:
    def to_dict(self) -> dict:
        return {
            "summary": {
                "health_score": 0.72,
                "total_patterns": 2,
                "critical_patterns": 1,
                "estimated_waste_usd": 1.2,
                "estimated_waste_ms": 1200.0,
                "top_issue": "token_waste",
            },
            "topology": {"depth": 4, "width": 2, "density": 0.2, "tool_diversity": 0.5},
            "patterns": [{"pattern_type": "token_waste", "severity": "high"}],
        }


class _FakeFlowAnalyzer:
    def analyze_session(self, session_id: str):  # noqa: ANN001
        if session_id == "missing":
            return None
        return _FakeFlowAnalysis()


class _FakeBehavioralDetector:
    def get_agent_profile(self, agent_id: str):  # noqa: ANN001
        if agent_id == "none":
            return None
        return {
            "total_requests": 5,
            "tool_distribution": {"web_search": 3, "read_file": 2},
            "dimensions": {
                "request_frequency": {"mean": 4.2},
                "prompt_tokens": {"mean": 120.0},
                "completion_tokens": {"mean": 45.0},
                "error_rate": {"mean": 0.15},
            },
        }


# Format tests (10)
def test_air_document_has_required_fields(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder)
    for key in ("air", "id", "created", "creator", "summary", "turns"):
        assert key in doc


def test_air_version_is_1_0(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    assert export_session_to_air("sess-1", recorder)["air"] == "1.0"


def test_air_creator_has_name_and_version(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    creator = export_session_to_air("sess-1", recorder)["creator"]
    assert creator["name"] == "orchesis"
    assert isinstance(creator["version"], str)


def test_air_turns_have_required_fields(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    turns = export_session_to_air("sess-1", recorder)["turns"]
    assert turns
    for turn in turns:
        for key in ("turn_id", "sequence", "timestamp", "type", "request", "response", "timing"):
            assert key in turn


def test_air_turn_sequence_is_ordered(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    turns = export_session_to_air("sess-1", recorder)["turns"]
    assert [t["sequence"] for t in turns] == [1, 2]


def test_air_summary_computed_correctly(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    summary = export_session_to_air("sess-1", recorder)["summary"]
    assert summary["total_turns"] == 2
    assert summary["total_tokens"]["input"] == 18
    assert summary["total_tokens"]["output"] == 10


def test_air_summary_models_used(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    models = export_session_to_air("sess-1", recorder)["summary"]["models_used"]
    assert "gpt-4o-mini" in models and "gpt-4o" in models


def test_air_summary_tools_used(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    tools = export_session_to_air("sess-1", recorder)["summary"]["tools_used"]
    assert "web_search" in tools


def test_air_id_matches_session_id(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder, session_id="session-xyz")
    assert export_session_to_air("session-xyz", recorder)["id"] == "session-xyz"


def test_air_created_is_iso_timestamp(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    created = export_session_to_air("sess-1", recorder)["created"]
    parsed = datetime.fromisoformat(created)
    assert isinstance(parsed, datetime)


# Content level tests (6)
def test_content_level_full_includes_messages(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder, content_level="full")
    assert "messages" in doc["turns"][0]["request"]
    assert doc["turns"][0]["request"]["messages"][0]["content"] == "hello world"


def test_content_level_structure_omits_message_content(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder, content_level="structure")
    msg = doc["turns"][0]["request"]["messages"][0]
    assert "role" in msg
    assert "content" not in msg


def test_content_level_metadata_minimal(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder, content_level="metadata")
    turn = doc["turns"][0]
    assert list(turn["request"].keys()) == ["model"]
    assert turn["tool_results"] == []


def test_content_level_default_is_structure(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder)
    assert doc["content_level"] == "structure"


def test_content_level_invalid_raises_error(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    with pytest.raises(ValueError):
        export_session_to_air("sess-1", recorder, content_level="bad-level")


def test_content_level_full_includes_tool_inputs(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder, content_level="full")
    assert doc["turns"][0]["tool_results"][0]["input"]["q"] == "hello"


# Enrichment tests (6)
def test_flow_xray_enrichment(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder, flow_analyzer=_FakeFlowAnalyzer())
    assert "flow_xray" in doc["extensions"]["orchesis"]


def test_flow_xray_enrichment_has_health_score(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder, flow_analyzer=_FakeFlowAnalyzer())
    assert doc["extensions"]["orchesis"]["flow_xray"]["health_score"] == 0.72


def test_agent_dna_enrichment(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder, behavioral_detector=_FakeBehavioralDetector())
    assert "agent_dna" in doc["extensions"]["orchesis"]


def test_no_enrichment_without_analyzers(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder)
    assert doc["extensions"]["orchesis"] == {}


def test_flow_xray_patterns_included(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder, flow_analyzer=_FakeFlowAnalyzer())
    assert isinstance(doc["extensions"]["orchesis"]["flow_xray"]["patterns"], list)
    assert doc["extensions"]["orchesis"]["flow_xray"]["patterns"][0]["pattern_type"] == "token_waste"


def test_agent_dna_anomaly_scores(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder, behavioral_detector=_FakeBehavioralDetector())
    assert "anomaly_scores" in doc["extensions"]["orchesis"]["agent_dna"]


# Validation tests (5)
def test_validate_valid_document(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    doc = export_session_to_air("sess-1", recorder)
    assert validate_air(doc) == []


def test_validate_missing_air_version() -> None:
    errors = validate_air({"id": "x", "turns": []})
    assert any("air" in e for e in errors)


def test_validate_missing_turns() -> None:
    errors = validate_air({"air": "1.0", "id": "x", "created": "now", "creator": {}, "summary": {}})
    assert any("turns" in e for e in errors)


def test_validate_invalid_turn_missing_type() -> None:
    errors = validate_air(
        {
            "air": "1.0",
            "id": "x",
            "created": "now",
            "creator": {},
            "summary": {},
            "turns": [{"turn_id": "t1", "sequence": 1, "timestamp": "x", "request": {}, "response": {}, "timing": {}}],
        }
    )
    assert any("type" in e for e in errors)


def test_validate_unknown_version() -> None:
    errors = validate_air({"air": "9.9", "id": "x", "created": "now", "creator": {}, "summary": {}, "turns": []})
    assert any("unknown AIR version" in e for e in errors)


# File export tests (4)
def test_export_to_file_creates_json(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    out = export_session_to_air_file("sess-1", str(tmp_path / "session_export"), recorder)
    assert Path(out).exists()
    data = json.loads(Path(out).read_text(encoding="utf-8"))
    assert data["id"] == "sess-1"


def test_export_to_file_with_air_extension(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    out = export_session_to_air_file("sess-1", str(tmp_path / "my_session"), recorder)
    assert out.endswith(".air")


def test_export_compressed_creates_gzip(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    out = export_session_to_air_file("sess-1", str(tmp_path / "compressed"), recorder, compress=True)
    assert out.endswith(".air.gz")
    with gzip.open(out, "rt", encoding="utf-8") as fh:
        data = json.load(fh)
    assert data["air"] == "1.0"


def test_export_file_roundtrip(tmp_path: Path) -> None:
    recorder = _make_recorder(tmp_path)
    _seed_session(recorder)
    out = export_session_to_air_file("sess-1", str(tmp_path / "roundtrip"), recorder)
    loaded = json.loads(Path(out).read_text(encoding="utf-8"))
    assert validate_air(loaded) == []


class _ProxyUpstreamHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length)
        payload = {
            "model": "gpt-4o-mini",
            "usage": {"prompt_tokens": 4, "completion_tokens": 2},
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
    upstream, _ = _start_http_server(_ProxyUpstreamHandler)
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


def _get_json(port: int, path: str) -> tuple[int, dict, Any]:
    with urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as resp:
        return int(resp.status), json.loads(resp.read().decode("utf-8")), resp.headers


# Proxy integration tests (5)
def test_export_endpoint_returns_json(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\nrecording:\n  enabled: true\n")
    try:
        assert proxy._recorder is not None
        _seed_session(proxy._recorder, "proxy-s1")
        code, payload, _ = _get_json(proxy._config.port, "/api/sessions/proxy-s1/export")
        assert code == 200
        assert payload["air"] == "1.0"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_export_endpoint_download_header(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\nrecording:\n  enabled: true\n")
    try:
        assert proxy._recorder is not None
        _seed_session(proxy._recorder, "proxy-s2")
        code, payload, headers = _get_json(proxy._config.port, "/api/sessions/proxy-s2/export?download=true")
        assert code == 200
        assert payload["id"] == "proxy-s2"
        assert "attachment;" in str(headers.get("Content-Disposition", ""))
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_export_endpoint_content_level_param(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\nrecording:\n  enabled: true\n")
    try:
        assert proxy._recorder is not None
        _seed_session(proxy._recorder, "proxy-s3")
        _, payload, _ = _get_json(proxy._config.port, "/api/sessions/proxy-s3/export?content_level=metadata")
        assert payload["content_level"] == "metadata"
        assert list(payload["turns"][0]["request"].keys()) == ["model"]
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_export_endpoint_nonexistent_session(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\nrecording:\n  enabled: true\n")
    try:
        with pytest.raises(HTTPError) as err:
            _get_json(proxy._config.port, "/api/sessions/not-found/export")
        assert err.value.code == 404
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_export_endpoint_default_format(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\nrecording:\n  enabled: true\n")
    try:
        assert proxy._recorder is not None
        _seed_session(proxy._recorder, "proxy-s4")
        _, payload, _ = _get_json(proxy._config.port, "/api/sessions/proxy-s4/export")
        assert payload["air"] == "1.0"
        assert payload["content_level"] == "structure"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_air_summary_from_turns_empty() -> None:
    summary = air_summary_from_turns([])
    assert summary["total_turns"] == 0
    assert summary["outcome"] == "empty"

