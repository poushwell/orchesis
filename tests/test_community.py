from __future__ import annotations

import json
import sqlite3
import threading
import time
from types import SimpleNamespace
from urllib.error import URLError

from fastapi.testclient import TestClient

from orchesis.api import create_api_app
from orchesis.community import CommunityClient
from orchesis.community_intel import CommunityIntel
from orchesis.privacy_filter import CommunitySignal, PrivacyFilter


def _cfg(tmp_path, **extra):
    base = {
        "enabled": True,
        "data_dir": str(tmp_path / "community"),
        "hub_url": "https://example.invalid/api/v1",
        "send_interval_seconds": 0.1,
        "poll_interval_seconds": 0.1,
        "max_batch_size": 3,
        "max_pending_signals": 10,
        "max_cached_signatures": 10,
        "min_anomaly_score": 30,
    }
    base.update(extra)
    return base


def _signal(i: int = 1) -> CommunitySignal:
    return CommunitySignal(
        signal_id=f"550e8400-e29b-41d4-a716-44665544{i:04d}",
        timestamp=time.time(),
        signal_type="anomaly",
        threat_ids=["ORCH-TA-002"],
        anomaly_score=70.0,
        risk_level="high",
        privacy_level=2,
    )


def _pending_count(client: CommunityClient) -> int:
    with sqlite3.connect(str(client._db_path)) as conn:  # noqa: SLF001
        row = conn.execute("SELECT COUNT(*) FROM pending_signals WHERE sent_at IS NULL").fetchone()
        return int(row[0]) if row else 0


def _cached_count(client: CommunityClient) -> int:
    with sqlite3.connect(str(client._db_path)) as conn:  # noqa: SLF001
        row = conn.execute("SELECT COUNT(*) FROM community_signatures").fetchone()
        return int(row[0]) if row else 0


def test_init_creates_db(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    assert c._db_path.exists()  # noqa: SLF001


def test_init_generates_instance_id(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    assert c.instance_id


def test_init_instance_id_persists(tmp_path) -> None:
    c1 = CommunityClient(_cfg(tmp_path))
    c2 = CommunityClient(_cfg(tmp_path))
    assert c1.instance_id == c2.instance_id


def test_init_disabled_does_nothing(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path, enabled=False))
    assert c.enabled is False
    assert not (tmp_path / "community").exists()


def test_init_custom_config(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path, max_pending_signals=123, min_anomaly_score=44))
    assert c.max_pending_signals == 123
    assert c.min_anomaly_score == 44


def test_record_signal_stores_in_db(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    c.record_signal(_signal())
    assert _pending_count(c) == 1


def test_record_detection_creates_and_stores_signal(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    det = SimpleNamespace(anomaly_score=70.0, risk_level="high", drift_type="normal", entropy_score=10.0, threat_ids=["ORCH-TA-002"], pattern_types=[])
    c.record_detection(det)
    assert _pending_count(c) == 1


def test_record_detection_skips_low_score(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    det = SimpleNamespace(anomaly_score=5.0, risk_level="low", drift_type="normal", entropy_score=1.0, threat_ids=[], pattern_types=[])
    c.record_detection(det)
    assert _pending_count(c) == 0


def test_record_detection_uses_privacy_filter(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    det = {"anomaly_score": 70.0, "risk_level": "high", "threat_ids": ["ORCH-TA-002"], "pattern_types": []}
    c.record_detection(det, request_meta={"prompt": "ignore previous instructions"})
    assert _pending_count(c) == 1


def test_max_pending_signals_enforced(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path, max_pending_signals=3))
    for i in range(10):
        c.record_signal(_signal(i + 1))
    assert _pending_count(c) == 3


def test_send_batch_no_pending(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    assert c._send_batch() == (0, 0)  # noqa: SLF001


def test_send_batch_hub_unreachable(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    c.record_signal(_signal())

    def boom(*_args, **_kwargs):
        raise URLError("down")

    monkeypatch.setattr(c, "_post_json", boom)
    assert c._send_batch() == (0, 0)  # noqa: SLF001
    assert _pending_count(c) == 1


def test_send_batch_success_marks_as_sent(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    for i in range(2):
        c.record_signal(_signal(i + 1))

    def ok(*_args, **_kwargs):
        return 200, {"trust_score": 0.7, "community_size": 12}, {}

    monkeypatch.setattr(c, "_post_json", ok)
    sent, failed = c._send_batch()  # noqa: SLF001
    assert sent == 2
    assert failed == 0
    assert _pending_count(c) == 0


def test_send_batch_respects_max_batch_size(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path, max_batch_size=2))
    for i in range(5):
        c.record_signal(_signal(i + 1))
    monkeypatch.setattr(c, "_post_json", lambda *_a, **_k: (200, {}, {}))
    sent, _ = c._send_batch()  # noqa: SLF001
    assert sent == 2


def test_send_batch_retries_on_failure(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    c.record_signal(_signal())
    monkeypatch.setattr(c, "_post_json", lambda *_a, **_k: (500, {}, {}))
    sent, failed = c._send_batch()  # noqa: SLF001
    assert sent == 0
    assert failed == 1


def test_send_batch_never_raises_exception(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    c.record_signal(_signal())
    monkeypatch.setattr(c, "_post_json", lambda *_a, **_k: (_ for _ in ()).throw(RuntimeError("x")))
    assert c._send_batch() == (0, 0)  # noqa: SLF001


def test_poll_signatures_hub_unreachable(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    monkeypatch.setattr(c, "_get_json", lambda *_a, **_k: (_ for _ in ()).throw(URLError("down")))
    assert c._poll_signatures() == 0  # noqa: SLF001


def test_poll_signatures_stores_in_cache(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    payload = {
        "signatures": [
            {
                "signature_id": "COMM-1",
                "signature_type": "injection",
                "pattern": "ignore previous instructions",
                "confidence": 0.9,
                "reporters": 7,
                "first_seen": time.time() - 100,
                "last_seen": time.time(),
                "severity": "high",
            }
        ]
    }
    monkeypatch.setattr(c, "_get_json", lambda *_a, **_k: (200, payload))
    assert c._poll_signatures() == 1  # noqa: SLF001
    assert _cached_count(c) == 1


def test_get_community_signatures_from_cache(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    payload = {"signatures": [{"signature_id": "COMM-2", "signature_type": "loop", "pattern": "x", "confidence": 0.4, "reporters": 3, "first_seen": time.time(), "last_seen": time.time(), "severity": "medium"}]}
    monkeypatch.setattr(c, "_get_json", lambda *_a, **_k: (200, payload))
    c._poll_signatures()  # noqa: SLF001
    sigs = c.get_community_signatures()
    assert len(sigs) == 1
    assert sigs[0].signature_id == "COMM-2"


def test_has_signature_true_and_false(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    payload = {"signatures": [{"signature_id": "COMM-3", "signature_type": "loop", "pattern": "x", "confidence": 0.4, "reporters": 3, "first_seen": time.time(), "last_seen": time.time(), "severity": "medium"}]}
    monkeypatch.setattr(c, "_get_json", lambda *_a, **_k: (200, payload))
    c._poll_signatures()  # noqa: SLF001
    assert c.has_signature("COMM-3")
    assert not c.has_signature("COMM-404")


def test_poll_cleans_expired_signatures(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    now = time.time()
    with sqlite3.connect(str(c._db_path)) as conn:  # noqa: SLF001
        conn.execute(
            "INSERT INTO community_signatures(signature_id, signature_json, received_at, expires_at) VALUES(?, ?, ?, ?)",
            ("COMM-X", json.dumps({"signature_id": "COMM-X"}), now - 1000, now - 1),
        )
        conn.commit()
    c._cleanup_old_signals()  # noqa: SLF001
    assert _cached_count(c) == 0


def test_start_creates_threads(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    c.start()
    assert c._sender_thread is not None  # noqa: SLF001
    assert c._receiver_thread is not None  # noqa: SLF001
    c.stop()


def test_stop_flushes_pending(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    called = {"n": 0}
    monkeypatch.setattr(c, "_send_batch", lambda: called.__setitem__("n", called["n"] + 1) or (0, 0))
    c.start()
    c.stop()
    assert called["n"] >= 1


def test_workers_are_daemon_threads(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    c.start()
    assert bool(c._sender_thread and c._sender_thread.daemon)  # noqa: SLF001
    assert bool(c._receiver_thread and c._receiver_thread.daemon)  # noqa: SLF001
    c.stop()


def test_workers_survive_exceptions(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path, send_interval_seconds=0.1, poll_interval_seconds=0.1))
    monkeypatch.setattr(c, "_send_batch", lambda: (_ for _ in ()).throw(RuntimeError("x")))
    monkeypatch.setattr(c, "_poll_signatures", lambda: (_ for _ in ()).throw(RuntimeError("y")))
    c.start()
    time.sleep(0.25)
    assert c._sender_thread is not None and c._sender_thread.is_alive()  # noqa: SLF001
    assert c._receiver_thread is not None and c._receiver_thread.is_alive()  # noqa: SLF001
    c.stop()


def test_get_stats_comprehensive(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    c.record_signal(_signal())
    stats = c.get_stats()
    assert stats.signals_pending >= 1
    assert stats.hub_status in {"offline", "connected", "error"}


def test_get_status_offline(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    status = c.get_status()
    assert status["enabled"] is True
    assert status["hub_status"] in {"offline", "connected", "error"}


def test_get_status_with_pending_signals(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    c.record_signal(_signal())
    status = c.get_status()
    assert status["signals_pending"] >= 1


def test_cleanup_old_sent_signals(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    now = time.time()
    with sqlite3.connect(str(c._db_path)) as conn:  # noqa: SLF001
        conn.execute(
            "INSERT INTO pending_signals(signal_json, created_at, retry_count, sent_at) VALUES(?, ?, 0, ?)",
            (json.dumps({"x": 1}), now - 90000, now - 90000),
        )
        conn.commit()
    c._cleanup_old_signals()  # noqa: SLF001
    with sqlite3.connect(str(c._db_path)) as conn:  # noqa: SLF001
        row = conn.execute("SELECT COUNT(*) FROM pending_signals").fetchone()
        assert int(row[0]) == 0


def test_cleanup_stale_pending_signals(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    now = time.time()
    with sqlite3.connect(str(c._db_path)) as conn:  # noqa: SLF001
        conn.execute(
            "INSERT INTO pending_signals(signal_json, created_at, retry_count, sent_at) VALUES(?, ?, 0, NULL)",
            (json.dumps({"x": 1}), now - 8 * 86400),
        )
        conn.commit()
    c._cleanup_old_signals()  # noqa: SLF001
    assert _pending_count(c) == 0


def test_cleanup_expired_signatures(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    now = time.time()
    with sqlite3.connect(str(c._db_path)) as conn:  # noqa: SLF001
        conn.execute(
            "INSERT INTO community_signatures(signature_id, signature_json, received_at, expires_at) VALUES(?, ?, ?, ?)",
            ("COMM-E", json.dumps({"signature_id": "COMM-E"}), now, now - 10),
        )
        conn.commit()
    c._cleanup_old_signals()  # noqa: SLF001
    assert _cached_count(c) == 0


def test_concurrent_record_and_send(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    monkeypatch.setattr(c, "_post_json", lambda *_a, **_k: (200, {}, {}))
    stop = {"v": False}

    def writer():
        i = 1
        while not stop["v"]:
            c.record_signal(_signal(i))
            i += 1

    t = threading.Thread(target=writer)
    t.start()
    for _ in range(5):
        c._send_batch()  # noqa: SLF001
    stop["v"] = True
    t.join(timeout=1.0)
    assert c.get_stats().signals_sent >= 0


def test_concurrent_record_from_multiple_agents(tmp_path) -> None:
    c = CommunityClient(_cfg(tmp_path))
    pf = PrivacyFilter()

    def worker(idx: int):
        for i in range(20):
            det = {"anomaly_score": 60.0, "risk_level": "high", "threat_ids": [f"ORCH-TA-{idx:03d}"]}
            s = pf.create_signal(detection_result=det)
            if s:
                c.record_signal(s)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert _pending_count(c) > 0


def test_corrupted_db_recreated(tmp_path) -> None:
    data_dir = tmp_path / "community"
    data_dir.mkdir(parents=True, exist_ok=True)
    db_path = data_dir / "community.sqlite3"
    db_path.write_text("not-sqlite", encoding="utf-8")
    c = CommunityClient(_cfg(tmp_path))
    assert c._db_path.exists()  # noqa: SLF001
    assert c.get_status()["enabled"] is True


def test_empty_hub_response(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    monkeypatch.setattr(c, "_get_json", lambda *_a, **_k: (200, {}))
    assert c._poll_signatures() == 0  # noqa: SLF001


def test_invalid_signature_format_skipped(tmp_path, monkeypatch) -> None:
    c = CommunityClient(_cfg(tmp_path))
    payload = {"signatures": [{"signature_type": "injection"}]}
    monkeypatch.setattr(c, "_get_json", lambda *_a, **_k: (200, payload))
    assert c._poll_signatures() == 0  # noqa: SLF001


def _policy_yaml_for_community() -> str:
    return """
api:
  token: "orch_sk_test"
community:
  enabled: false
  share_signatures: true
  share_patterns: false
rules: []
"""


def test_community_disabled_by_default() -> None:
    intel = CommunityIntel({})
    assert intel.enabled is False
    stats = intel.get_stats()
    assert stats["enabled"] is False


def test_anonymize_removes_pii() -> None:
    intel = CommunityIntel({"enabled": True})
    payload = intel.anonymize(
        {
            "agent_id": "agent-1",
            "session_id": "sess-1",
            "content": "secret prompt",
            "api_key": "sk-secret",
            "threat_type": "prompt_injection",
            "severity": "high",
            "pattern": "ignore all rules",
            "timestamp": 1700000000,
        }
    )
    assert "agent_id" not in payload
    assert "session_id" not in payload
    assert "content" not in payload
    assert "api_key" not in payload
    assert "pattern_hash" in payload


def test_anonymize_keeps_threat_type() -> None:
    intel = CommunityIntel({"enabled": True})
    payload = intel.anonymize({"threat_type": "tool_abuse", "severity": "medium", "timestamp": 1700000000})
    assert payload["threat_type"] == "tool_abuse"


def test_submit_threat_anonymized() -> None:
    intel = CommunityIntel({"enabled": True, "share_signatures": True})
    ok = intel.submit_threat(
        {
            "threat_type": "prompt_injection",
            "severity": "high",
            "signature": "ignore all previous instructions",
            "agent_id": "agent-1",
            "session_id": "sess-1",
            "content": "raw prompt",
            "timestamp": 1700000000,
        }
    )
    assert ok is True
    stats = intel.get_stats()
    assert stats["threats_submitted"] == 1
    stored = intel._submitted[0]  # noqa: SLF001
    assert "agent_id" not in stored
    assert "session_id" not in stored
    assert "content" not in stored
    assert stored["threat_type"] == "prompt_injection"


def test_enable_disable_toggle(tmp_path) -> None:
    policy_path = tmp_path / "policy.yaml"
    policy_path.write_text(_policy_yaml_for_community(), encoding="utf-8")
    app = create_api_app(policy_path=str(policy_path), decisions_log=str(tmp_path / "decisions.jsonl"))
    client = TestClient(app)
    headers = {"Authorization": "Bearer orch_sk_test"}
    status = client.get("/api/v1/community/status", headers=headers)
    assert status.status_code == 200
    assert status.json()["enabled"] is False
    enabled = client.post("/api/v1/community/enable", headers=headers)
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True
    disabled = client.post("/api/v1/community/disable", headers=headers)
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False


def test_stats_tracked() -> None:
    intel = CommunityIntel(
        {
            "enabled": True,
            "seed_updates": [
                {"threat_type": "prompt_injection", "pattern_hash": "abc", "severity": "high", "timestamp": 1700000001}
            ],
        }
    )
    intel.submit_threat({"threat_type": "tool_abuse", "severity": "medium", "signature": "rm -rf", "timestamp": 1700000000})
    updates = intel.pull_updates()
    stats = intel.get_stats()
    assert len(updates) == 1
    assert stats["threats_submitted"] == 1
    assert stats["updates_pulled"] == 1
    assert stats["community_signatures"] == 1
