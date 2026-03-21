from __future__ import annotations

import threading
import time
from pathlib import Path

from orchesis.tracing.session_tracer import SessionTracer


def _make_tracer(tmp_path: Path) -> SessionTracer:
    return SessionTracer(db_path=str(tmp_path / "traces.db"))


def test_start_session(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1", metadata={"framework": "paperclip"})
    assert session_id.startswith("sess-")
    tracer.close()


def test_end_session(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")
    tracer.end_session(session_id)
    rows = tracer.list_sessions()
    row = next(item for item in rows if item["session_id"] == session_id)
    assert row["status"] == "ended"
    assert float(row["end_time"]) > 0.0
    tracer.close()


def test_list_sessions(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    tracer.start_session(agent_id="a1")
    tracer.start_session(agent_id="a2")
    tracer.start_session(agent_id="a3")
    assert len(tracer.list_sessions(limit=10)) == 3
    tracer.close()


def test_list_sessions_by_agent(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    tracer.start_session(agent_id="agent-x")
    tracer.start_session(agent_id="agent-x")
    tracer.start_session(agent_id="agent-y")
    filtered = tracer.list_sessions(agent_id="agent-x", limit=10)
    assert len(filtered) == 2
    assert all(item["agent_id"] == "agent-x" for item in filtered)
    tracer.close()


def test_record_request(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")
    request_id = tracer.record_request(session_id, {"agent_id": "agent-1", "prompt": "hello"})
    timeline = tracer.get_session_timeline(session_id)
    assert request_id.startswith("req-")
    assert len(timeline) == 1
    assert timeline[0].event_type == "request"
    tracer.close()


def test_record_response(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")
    request_id = tracer.record_request(session_id, {"agent_id": "agent-1"})
    tracer.record_response(session_id, request_id, {"ok": True})
    timeline = tracer.get_session_timeline(session_id)
    response = [event for event in timeline if event.event_type == "response"][0]
    assert response.request_id == request_id
    tracer.close()


def test_record_tool_call(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")
    request_id = tracer.record_request(session_id, {"agent_id": "agent-1"})
    tracer.record_tool_call(session_id, request_id, "shell", {"command": "echo hi"}, result={"status": "ok"})
    timeline = tracer.get_session_timeline(session_id)
    tool_event = [event for event in timeline if event.event_type == "tool_call"][0]
    assert tool_event.data["tool"] == "shell"
    assert tool_event.data["args"]["command"] == "echo hi"
    tracer.close()


def test_record_cost(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")
    request_id = tracer.record_request(session_id, {"agent_id": "agent-1"})
    tracer.record_cost(session_id, request_id, 1.23, {"input": 10, "output": 20})
    timeline = tracer.get_session_timeline(session_id)
    cost_event = [event for event in timeline if event.event_type == "cost"][0]
    assert cost_event.data["cost_usd"] == 1.23
    tracer.close()


def test_record_security_finding(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")
    tracer.record_security_finding(session_id, {"rule": "INJECT-001"})
    timeline = tracer.get_session_timeline(session_id)
    assert any(event.event_type == "security_finding" for event in timeline)
    tracer.close()


def test_get_timeline(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")
    request_id = tracer.record_request(session_id, {"agent_id": "agent-1"})
    time.sleep(0.001)
    tracer.record_response(session_id, request_id, {"ok": True})
    time.sleep(0.001)
    tracer.record_tool_call(session_id, request_id, "shell", {"x": 1})
    time.sleep(0.001)
    tracer.record_cost(session_id, request_id, 0.2)
    time.sleep(0.001)
    tracer.record_security_finding(session_id, {"kind": "warning"})

    timeline = tracer.get_session_timeline(session_id)
    assert len(timeline) == 5
    timestamps = [event.timestamp for event in timeline]
    assert timestamps == sorted(timestamps)
    tracer.close()


def test_get_summary_counts(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")

    req1 = tracer.record_request(session_id, {"agent_id": "agent-1"})
    req2 = tracer.record_request(session_id, {"agent_id": "agent-1"})
    req3 = tracer.record_request(session_id, {"agent_id": "agent-1"})
    tracer.record_tool_call(session_id, req1, "shell", {})
    tracer.record_tool_call(session_id, req2, "read_file", {})
    tracer.record_cost(session_id, req3, 0.5)

    summary = tracer.get_session_summary(session_id)
    assert summary.request_count == 3
    assert summary.tool_call_count == 2
    assert summary.total_cost_usd == 0.5
    tracer.close()


def test_get_summary_total_cost(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")
    request_id = tracer.record_request(session_id, {"agent_id": "agent-1"})
    tracer.record_cost(session_id, request_id, 1.0)
    tracer.record_cost(session_id, request_id, 2.5)
    tracer.record_cost(session_id, request_id, 0.5)

    summary = tracer.get_session_summary(session_id)
    assert summary.total_cost_usd == 4.0
    tracer.close()


def test_get_summary_empty_session(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-empty", metadata={"k": "v"})
    summary = tracer.get_session_summary(session_id)
    assert summary.session_id == session_id
    assert summary.request_count == 0
    assert summary.tool_call_count == 0
    assert summary.total_cost_usd == 0.0
    assert summary.security_findings == 0
    assert summary.error_count == 0
    tracer.close()


def test_delete_session(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="agent-1")
    tracer.record_request(session_id, {"agent_id": "agent-1"})
    tracer.record_security_finding(session_id, {"type": "x"})
    tracer.delete_session(session_id)
    assert tracer.get_session_timeline(session_id) == []
    summary = tracer.get_session_summary(session_id)
    assert summary.agent_id == ""
    tracer.close()


def test_thread_safety(tmp_path: Path) -> None:
    tracer = _make_tracer(tmp_path)
    session_id = tracer.start_session(agent_id="threaded")
    errors: list[Exception] = []

    def worker(worker_id: int) -> None:
        try:
            for i in range(20):
                tracer.record_event(
                    session_id=session_id,
                    event_type="request",
                    data={"worker": worker_id, "index": i},
                )
        except Exception as exc:  # pragma: no cover
            errors.append(exc)

    t1 = threading.Thread(target=worker, args=(1,))
    t2 = threading.Thread(target=worker, args=(2,))
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert not errors
    timeline = tracer.get_session_timeline(session_id)
    assert len(timeline) == 40
    tracer.close()


def test_close_and_reopen(tmp_path: Path) -> None:
    db_path = tmp_path / "traces.db"

    tracer1 = SessionTracer(db_path=str(db_path))
    session_id = tracer1.start_session(agent_id="agent-1")
    tracer1.record_request(session_id, {"agent_id": "agent-1", "prompt": "persist"})
    tracer1.close()

    tracer2 = SessionTracer(db_path=str(db_path))
    timeline = tracer2.get_session_timeline(session_id)
    assert len(timeline) == 1
    assert timeline[0].event_type == "request"
    tracer2.close()
