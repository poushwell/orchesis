from __future__ import annotations

import threading
import time

from orchesis.tool_policy import ApprovalQueue


def test_add_pending() -> None:
    queue = ApprovalQueue()
    approval_id = queue.add("req-1", "agent-a", "execute", {"cmd": "ls"}, "needs approval")
    pending = queue.get_pending()
    assert approval_id == "req-1"
    assert len(pending) == 1
    assert pending[0]["tool_name"] == "execute"


def test_approve_removes() -> None:
    queue = ApprovalQueue()
    queue.add("req-1", "agent-a", "execute", {}, "needs approval")
    assert queue.approve("req-1") is True
    assert queue.get_pending() == []


def test_deny_removes() -> None:
    queue = ApprovalQueue()
    queue.add("req-1", "agent-a", "execute", {}, "needs approval")
    assert queue.deny("req-1") is True
    assert queue.get_pending() == []


def test_get_pending_sorted() -> None:
    queue = ApprovalQueue()
    queue.add("req-2", "agent-a", "execute", {}, "needs approval")
    time.sleep(0.01)
    queue.add("req-1", "agent-a", "execute", {}, "needs approval")
    pending = queue.get_pending()
    assert [item["approval_id"] for item in pending] == ["req-2", "req-1"]


def test_max_pending_limit() -> None:
    queue = ApprovalQueue(max_pending=2)
    queue.add("req-1", "agent-a", "execute", {}, "1")
    queue.add("req-2", "agent-a", "execute", {}, "2")
    queue.add("req-3", "agent-a", "execute", {}, "3")
    ids = [row["approval_id"] for row in queue.get_pending()]
    assert "req-1" not in ids
    assert len(ids) == 2


def test_stats_counts() -> None:
    queue = ApprovalQueue()
    queue.add("req-1", "agent-a", "execute", {}, "needs approval")
    queue.add("req-2", "agent-a", "execute", {}, "needs approval")
    queue.approve("req-1")
    queue.deny("req-2")
    stats = queue.get_stats()
    assert stats["pending_count"] == 0
    assert stats["approved_count"] == 1
    assert stats["denied_count"] == 1


def test_approve_nonexistent() -> None:
    queue = ApprovalQueue()
    assert queue.approve("nope") is False


def test_deny_nonexistent() -> None:
    queue = ApprovalQueue()
    assert queue.deny("nope") is False


def test_consume_approved_success() -> None:
    queue = ApprovalQueue()
    queue.add("req-1", "agent-a", "execute", {}, "needs approval")
    queue.approve("req-1")
    assert queue.consume_approved("req-1") is True
    assert queue.consume_approved("req-1") is False


def test_add_generates_id_when_missing() -> None:
    queue = ApprovalQueue()
    approval_id = queue.add("", "agent-a", "execute", {}, "needs approval")
    assert approval_id
    assert len(queue.get_pending()) == 1


def test_stats_avg_wait_seconds_positive() -> None:
    queue = ApprovalQueue()
    queue.add("req-1", "agent-a", "execute", {}, "needs approval")
    time.sleep(0.01)
    queue.approve("req-1")
    assert queue.get_stats()["avg_wait_seconds"] >= 0.0


def test_pending_contains_reason_and_args() -> None:
    queue = ApprovalQueue()
    queue.add("req-1", "agent-a", "web_fetch", {"url": "https://a.b"}, "domain requires review")
    pending = queue.get_pending()[0]
    assert pending["reason"] == "domain requires review"
    assert pending["tool_args"]["url"] == "https://a.b"


def test_thread_safety() -> None:
    queue = ApprovalQueue(max_pending=500)

    def worker(idx: int) -> None:
        for i in range(50):
            queue.add(f"req-{idx}-{i}", f"agent-{idx}", "execute", {}, "x")

    threads = [threading.Thread(target=worker, args=(idx,)) for idx in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(queue.get_pending()) == 400


def test_approve_updates_stats() -> None:
    queue = ApprovalQueue()
    queue.add("req-1", "agent-a", "execute", {}, "needs approval")
    queue.approve("req-1")
    assert queue.get_stats()["approved_count"] == 1


def test_deny_updates_stats() -> None:
    queue = ApprovalQueue()
    queue.add("req-1", "agent-a", "execute", {}, "needs approval")
    queue.deny("req-1")
    assert queue.get_stats()["denied_count"] == 1

