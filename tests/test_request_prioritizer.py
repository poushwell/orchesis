from __future__ import annotations

import io
import time

from orchesis.request_prioritizer import RequestPrioritizer
from orchesis.proxy import LLMHTTPProxy, _RequestContext


def _msg(role: str, content: str) -> dict:
    return {"role": role, "content": content}


def test_critical_priority_first() -> None:
    p = RequestPrioritizer({"default": "normal"})
    p.enqueue({"content": "background sync"}, priority="normal")
    p.enqueue({"content": "safety check system prompt"}, priority="critical")
    first = p.dequeue()
    assert first is not None
    assert "safety" in str(first.get("content", "")).lower()


def test_priority_assigned_by_content() -> None:
    p = RequestPrioritizer({})
    pr = p.assign_priority({"messages": [_msg("user", "please run safety guardrail check")]})
    assert pr == "critical"


def test_enqueue_dequeue_order() -> None:
    p = RequestPrioritizer({})
    p.enqueue({"id": "a"}, priority="low")
    p.enqueue({"id": "b"}, priority="high")
    p.enqueue({"id": "c"}, priority="normal")
    assert p.dequeue()["id"] == "b"
    assert p.dequeue()["id"] == "c"
    assert p.dequeue()["id"] == "a"


def test_queue_stats_tracked() -> None:
    p = RequestPrioritizer({})
    p.enqueue({"id": "a"}, priority="normal")
    time.sleep(0.01)
    stats = p.get_queue_stats()
    assert stats["total"] == 1
    assert stats["by_priority"]["normal"] == 1
    assert float(stats["avg_wait_ms"]) > 0.0


def test_rate_limit_per_priority() -> None:
    p = RequestPrioritizer({})
    p.set_rate_limit("high", 0.0001)
    first = p.enqueue({"id": "a"}, priority="high")
    second = p.enqueue({"id": "b"}, priority="high")
    assert first >= 0
    assert second == -1


def test_bulk_lowest_priority() -> None:
    p = RequestPrioritizer({})
    assert p.assign_priority({"bulk": True, "batch_size": 500}) == "bulk"


def test_proxy_priority_header() -> None:
    class FakeHandler:
        def __init__(self) -> None:
            self.headers_sent: dict[str, str] = {}
            self.wfile = io.BytesIO()

        def send_response(self, _code: int) -> None:
            return

        def send_header(self, name: str, value: str) -> None:
            self.headers_sent[str(name)] = str(value)

        def end_headers(self) -> None:
            return

    proxy = LLMHTTPProxy(policy_path=None)
    proxy._context_engine = None
    handler = FakeHandler()
    ctx = _RequestContext(
        handler=handler,
        body={"messages": [_msg("user", "hello world")], "model": "gpt-4o-mini"},
    )
    ctx.resp_status = 200
    ctx.resp_headers = {"Content-Type": "application/json"}
    ctx.resp_body = b'{"ok":true}'
    ctx.proc_result = {"cost": 0.0}
    ok = proxy._phase_context(ctx)
    assert ok is True
    proxy._phase_send_response(ctx)
    assert handler.headers_sent.get("X-Orchesis-Priority") in {"high", "normal", "critical", "low", "bulk"}
