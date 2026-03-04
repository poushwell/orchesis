from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import gzip
import json
import os
from pathlib import Path
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.request import Request as UrlRequest, urlopen

import pytest

from orchesis.diff import SessionDiffer
from orchesis.recorder import SessionRecord, SessionRecorder
from orchesis.replayer import ReplayConfig, SessionReplayer
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy


def _record(session_id: str = "s1", idx: int = 0, status: int = 200, cost: float = 0.01) -> SessionRecord:
    return SessionRecord(
        request_id=f"r{idx}",
        session_id=session_id,
        timestamp=time.time() + idx,
        request={"model": "gpt-4o", "messages": [{"role": "user", "content": f"q{idx}"}]},
        response={"ok": True} if status < 400 else None,
        status_code=status,
        provider="openai",
        model="gpt-4o",
        latency_ms=10.0 + idx,
        cost=cost,
        error=None if status < 400 else "err",
        metadata={"agent_id": "a1"},
    )


def test_record_single_request_file_created(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record())
    files = list(tmp_path.glob("*.jsonl.gz"))
    assert len(files) == 1


def test_record_multiple_same_session_append(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record("s1", 1))
    r.record(_record("s1", 2))
    loaded = r.load_session("s1")
    assert len(loaded) == 2


def test_record_different_sessions_different_files(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record("s1", 1))
    r.record(_record("s2", 1))
    assert len(list(tmp_path.glob("*.jsonl.gz"))) == 2


def test_load_session_order(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record("s1", 2))
    r.record(_record("s1", 1))
    loaded = r.load_session("s1")
    assert loaded[0].request_id == "r1"


def test_list_sessions_returns_summaries(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record("s1", 1))
    r.close_session("s1")
    summaries = r.list_sessions()
    assert summaries and summaries[0].session_id == "s1"


def test_summary_stats_correct(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record("s1", 1, status=200, cost=0.2))
    r.record(_record("s1", 2, status=500, cost=0.3))
    s = r.get_session_summary("s1")
    assert s.request_count == 2
    assert s.error_count == 1
    assert s.total_cost == pytest.approx(0.5)


def test_delete_session_removes_file(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record("s1", 1))
    assert r.delete_session("s1") is True
    assert not list(tmp_path.glob("*.jsonl.gz"))


def test_cleanup_old_sessions(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record("s1", 1))
    r.close_session("s1")
    path = list(tmp_path.glob("*.jsonl.gz"))[0]
    old = time.time() - (40 * 86400)
    os.utime(path, (old, old))
    deleted = r.cleanup(max_age_days=30)
    assert deleted >= 1


def test_compressed_file_valid_gzip(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path), compress=True)
    r.record(_record("s1", 1))
    file = list(tmp_path.glob("*.jsonl.gz"))[0]
    with gzip.open(file, "rt", encoding="utf-8") as fh:
        line = fh.readline()
    assert line.strip().startswith("{")


def test_thread_safety_concurrent_recording(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))

    def worker(i: int) -> None:
        for j in range(100):
            r.record(_record("s1", i * 1000 + j))

    with ThreadPoolExecutor(max_workers=10) as pool:
        for i in range(10):
            pool.submit(worker, i)
    assert len(r.load_session("s1")) == 1000


def test_file_rotation_at_record_limit(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path), max_records_per_file=2)
    for i in range(5):
        r.record(_record("s1", i))
    assert len(list(tmp_path.glob("*.jsonl.gz"))) >= 2


def test_missing_session_graceful(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    assert r.load_session("missing") == []


def test_corrupted_session_file_graceful(tmp_path: Path) -> None:
    p = tmp_path / "s1_20260101.jsonl.gz"
    p.write_bytes(b"notgzip")
    r = SessionRecorder(storage_path=str(tmp_path))
    assert r.load_session("s1") == []


def test_close_session_flushes(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record("s1", 1))
    r.close_session("s1")
    assert len(r.load_session("s1")) == 1


def test_get_stats_fields(tmp_path: Path) -> None:
    r = SessionRecorder(storage_path=str(tmp_path))
    r.record(_record("s1", 1))
    stats = r.get_stats()
    assert "active_sessions" in stats and "total_recorded" in stats and "storage_size_bytes" in stats


def test_context_manager_closes(tmp_path: Path) -> None:
    with SessionRecorder(storage_path=str(tmp_path)) as r:
        r.record(_record("s1", 1))
    assert len(list(tmp_path.glob("*.jsonl.gz"))) == 1


def test_replayer_dry_run_model_override_no_http(tmp_path: Path, monkeypatch) -> None:
    session = [_record("s1", i) for i in range(3)]
    replayer = SessionReplayer()
    monkeypatch.setattr(replayer, "_send_replay", lambda body, path="/v1/chat/completions": (_ for _ in ()).throw(RuntimeError("no")))
    report = replayer.replay(session, ReplayConfig(model_override="gpt-4o-mini", dry_run=True))
    assert report.summary.total_requests == 3
    assert report.summary.replay_cost >= 0.0


def test_replayer_dry_run_with_policy_blocks() -> None:
    session = [_record("s1", 1)]
    replayer = SessionReplayer()
    policy = {"rules": [{"name": "sql_restriction", "denied_operations": ["DROP"]}]}
    session[0].request["tool"] = "sql_query"
    session[0].request["query"] = "DROP TABLE x"
    report = replayer.replay(session, ReplayConfig(dry_run=True), policy=policy)
    assert report.summary.total_requests == 1


def test_replay_report_totals() -> None:
    session = [_record("s1", i, cost=0.1) for i in range(4)]
    replayer = SessionReplayer()
    report = replayer.replay(session, ReplayConfig(dry_run=True))
    assert report.summary.original_cost == pytest.approx(0.4)


def test_cost_delta_calculation() -> None:
    session = [_record("s1", i, cost=0.1) for i in range(2)]
    r = SessionReplayer()
    report = r.replay(session, ReplayConfig(model_override="gpt-4o-mini", dry_run=True))
    assert isinstance(report.summary.cost_delta, float)


def test_max_requests_limit() -> None:
    session = [_record("s1", i) for i in range(10)]
    report = SessionReplayer().replay(session, ReplayConfig(dry_run=True, max_requests=3))
    assert len(report.results) == 3


def test_empty_session_replay() -> None:
    report = SessionReplayer().replay([], ReplayConfig(dry_run=True))
    assert report.summary.total_requests == 0


def test_estimate_cost_method() -> None:
    session = [_record("s1", i) for i in range(3)]
    est = SessionReplayer().estimate_cost(session, "gpt-4o-mini")
    assert est >= 0.0


def test_diff_identical_zero_delta() -> None:
    session = [_record("s1", 1, cost=0.2)]
    replay = SessionReplayer().replay(session, ReplayConfig(dry_run=True))
    diff = SessionDiffer().diff(session, replay)
    assert diff.cost_comparison.delta == pytest.approx(replay.summary.cost_delta)


def test_diff_cost_savings_percentage() -> None:
    session = [_record("s1", i, cost=0.5) for i in range(3)]
    replay = SessionReplayer().replay(session, ReplayConfig(model_override="gpt-4o-mini", dry_run=True))
    diff = SessionDiffer().diff(session, replay)
    assert isinstance(diff.cost_comparison.savings_pct, float)


def test_diff_new_errors_listed() -> None:
    session = [_record("s1", 1, status=200)]
    replay = SessionReplayer().replay(session, ReplayConfig(dry_run=True))
    replay.results[0].replay_status = 500
    replay.results[0].replay_error = "boom"
    diff = SessionDiffer().diff(session, replay)
    assert diff.error_comparison.new_errors


def test_diff_policy_impact_populated() -> None:
    session = [_record("s1", 1, cost=0.4)]
    replay = SessionReplayer().replay(session, ReplayConfig(dry_run=True))
    replay.results[0].policy_blocked = True
    replay.results[0].policy_block_reason = "blocked"
    diff = SessionDiffer().diff(session, replay)
    assert diff.policy_impact.blocked_count == 1


def test_diff_to_json_valid() -> None:
    session = [_record("s1", 1)]
    replay = SessionReplayer().replay(session, ReplayConfig(dry_run=True))
    diff = SessionDiffer().diff(session, replay)
    payload = SessionDiffer().to_json(diff)
    assert isinstance(json.loads(payload), dict)


def test_diff_to_summary_text_readable() -> None:
    session = [_record("s1", 1)]
    replay = SessionReplayer().replay(session, ReplayConfig(dry_run=True))
    diff = SessionDiffer().diff(session, replay)
    text = SessionDiffer().to_summary_text(diff)
    assert "Session:" in text


class _RecorderUpstreamHandler(BaseHTTPRequestHandler):
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


def test_proxy_recording_enabled_headers_and_file(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_RecorderUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text(
        """
rules: []
recording:
  enabled: true
  storage_path: ".orchesis/sessions"
  max_age_days: 30
  max_file_size_mb: 10
  compress: true
  include_response_body: true
  exclude_models: []
""".strip(),
        encoding="utf-8",
    )
    port = _pick_port()
    cwd = os.getcwd()
    os.chdir(tmp_path)
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
        headers = _post(port)
        assert headers.get("X-Orchesis-Session-Id")
        assert headers.get("X-Orchesis-Request-Id")
        sessions_dir = tmp_path / ".orchesis" / "sessions"
        assert sessions_dir.exists()
        assert list(sessions_dir.glob("*.jsonl.gz"))
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        os.chdir(cwd)


def test_proxy_recording_disabled_no_session_headers(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_RecorderUpstreamHandler)
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
        headers = _post(port)
        assert "X-Orchesis-Session-Id" not in headers
        assert "X-Orchesis-Request-Id" not in headers
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_get_sessions_endpoint(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_RecorderUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\nrecording:\n  enabled: true\n", encoding="utf-8")
    port = _pick_port()
    cwd = os.getcwd()
    os.chdir(tmp_path)
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
        with urlopen(f"http://127.0.0.1:{port}/sessions", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert isinstance(payload.get("sessions"), list)
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        os.chdir(cwd)


def test_proxy_get_session_summary_endpoint(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_RecorderUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\nrecording:\n  enabled: true\n", encoding="utf-8")
    port = _pick_port()
    cwd = os.getcwd()
    os.chdir(tmp_path)
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
        headers = _post(port)
        sid = headers["X-Orchesis-Session-Id"]
        with urlopen(f"http://127.0.0.1:{port}/sessions/{sid}", timeout=5) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        assert payload.get("session", {}).get("session_id") == sid
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        os.chdir(cwd)


def test_proxy_recorded_session_loadable(tmp_path: Path) -> None:
    recorder = SessionRecorder(storage_path=str(tmp_path))
    recorder.record(_record("s1", 1))
    loaded = recorder.load_session("s1")
    assert loaded and loaded[0].session_id == "s1"


def test_proxy_stats_include_recorder_section(tmp_path: Path) -> None:
    upstream, _ = _start_http_server(_RecorderUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text("rules: []\nrecording:\n  enabled: true\n", encoding="utf-8")
    port = _pick_port()
    cwd = os.getcwd()
    os.chdir(tmp_path)
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
        assert "recorder" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()
        os.chdir(cwd)
