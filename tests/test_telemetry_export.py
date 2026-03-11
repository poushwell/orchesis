from __future__ import annotations

import json
import threading
from types import SimpleNamespace

from orchesis.telemetry_export import (
    TelemetryCollector,
    TelemetryRecord,
    _classify_failure_mode,
    build_record_from_context,
)


def _record() -> TelemetryRecord:
    return TelemetryRecord(
        request_id="r1",
        session_id="s1",
        agent_id="a1",
        model_requested="gpt-4o",
        model_used="gpt-4o-mini",
        total_ms=12.0,
        upstream_ms=10.0,
        proxy_overhead_ms=2.0,
        input_tokens=11,
        output_tokens=7,
        cost_usd=0.0012,
        threat_matches=["t1"],
        threat_categories=["prompt_injection"],
        blocked=False,
        cache_hit=False,
        status_code=200,
    )


def test_record_basic() -> None:
    c = TelemetryCollector(enabled=True)
    c.record(_record())
    assert c.stats["total_recorded"] == 1
    assert c.stats["buffered"] == 1


def test_record_with_all_fields() -> None:
    c = TelemetryCollector(enabled=True)
    rec = TelemetryRecord(
        request_id="full",
        session_id="s",
        agent_id="a",
        model_requested="m1",
        model_used="m2",
        total_ms=1.0,
        upstream_ms=0.6,
        proxy_overhead_ms=0.4,
        input_tokens=1,
        output_tokens=2,
        cost_usd=0.3,
        threat_matches=["x", "y"],
        threat_categories=["cat1", "cat2"],
        threat_max_severity="high",
        blocked=True,
        block_reason="reason",
        cache_hit=True,
        cache_type="semantic",
        loop_detected=True,
        loop_count=3,
        content_hash_blocked=True,
        heartbeat_detected=True,
        session_risk_score=55.2,
        session_risk_level="warn",
        turn_number=2,
        tool_calls_count=1,
        has_tool_results=True,
        is_streaming=True,
        failure_mode="FM-1.3-loop",
        budget_remaining_usd=4.2,
        spend_rate_5min_usd=1.1,
        budget_blocked=True,
        was_cascaded=True,
        cascade_reason="escalated",
        status_code=429,
        error_type="budget_exceeded",
    )
    c.record(rec)
    got = c.get_records()
    assert got and got[0]["failure_mode"] == "FM-1.3-loop"


def test_disabled_collector_ignores() -> None:
    c = TelemetryCollector(enabled=False)
    c.record(_record())
    assert c.stats["total_recorded"] == 0
    assert c.get_records() == []


def test_max_records_bounded() -> None:
    c = TelemetryCollector(max_records=1000, enabled=True)
    for i in range(1100):
        rec = _record()
        rec.request_id = f"r{i}"
        c.record(rec)
    assert c.stats["buffered"] == 1000
    assert c.stats["dropped"] >= 100


def test_export_jsonl_creates_file(tmp_path) -> None:  # noqa: ANN001
    c = TelemetryCollector(enabled=True)
    c.record(_record())
    out = tmp_path / "telemetry.jsonl"
    n = c.export_jsonl(str(out))
    assert n == 1
    assert out.exists()


def test_export_jsonl_valid_json_per_line(tmp_path) -> None:  # noqa: ANN001
    c = TelemetryCollector(enabled=True)
    c.record(_record())
    c.record(_record())
    out = tmp_path / "telemetry.jsonl"
    c.export_jsonl(str(out))
    lines = out.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == 2
    for line in lines:
        parsed = json.loads(line)
        assert isinstance(parsed, dict)
        assert "request_id" in parsed


def test_export_csv_creates_file(tmp_path) -> None:  # noqa: ANN001
    c = TelemetryCollector(enabled=True)
    c.record(_record())
    out = tmp_path / "telemetry.csv"
    n = c.export_csv(str(out))
    assert n == 1
    assert out.exists()


def test_export_csv_valid_headers(tmp_path) -> None:  # noqa: ANN001
    c = TelemetryCollector(enabled=True)
    c.record(_record())
    out = tmp_path / "telemetry.csv"
    c.export_csv(str(out))
    first = out.read_text(encoding="utf-8").splitlines()[0]
    assert "request_id" in first
    assert "status_code" in first


def test_export_csv_flattened_lists(tmp_path) -> None:  # noqa: ANN001
    c = TelemetryCollector(enabled=True)
    rec = _record()
    rec.threat_matches = ["a", "b"]
    c.record(rec)
    out = tmp_path / "telemetry.csv"
    c.export_csv(str(out))
    text = out.read_text(encoding="utf-8")
    assert "a;b" in text


def test_export_empty_records(tmp_path) -> None:  # noqa: ANN001
    c = TelemetryCollector(enabled=True)
    out = tmp_path / "empty.csv"
    assert c.export_csv(str(out)) == 0


def test_get_records_all() -> None:
    c = TelemetryCollector(enabled=True)
    c.record(_record())
    c.record(_record())
    assert len(c.get_records()) == 2


def test_get_records_last_n() -> None:
    c = TelemetryCollector(enabled=True)
    for i in range(5):
        rec = _record()
        rec.request_id = f"r{i}"
        c.record(rec)
    got = c.get_records(last_n=2)
    assert [item["request_id"] for item in got] == ["r3", "r4"]


def test_clear_records() -> None:
    c = TelemetryCollector(enabled=True)
    c.record(_record())
    assert c.clear() == 1
    assert c.get_records() == []


def test_build_record_from_empty_context() -> None:
    rec = build_record_from_context(SimpleNamespace(proc_result={}))
    assert isinstance(rec, TelemetryRecord)
    assert rec.cache_type == "miss"
    assert rec.session_risk_level == "observe"


def test_build_record_from_full_context() -> None:
    pr = {
        "request_id": "r",
        "session_id": "s",
        "agent_id": "a",
        "model": "m1",
        "model_used": "m2",
        "total_ms": 21.5,
        "upstream_ms": 12.0,
        "input_tokens": 123,
        "output_tokens": 7,
        "cost_usd": 0.004,
        "blocked": True,
        "block_reason": "policy",
        "cache_hit": True,
        "cache_type": "semantic",
        "loop_detected": True,
        "loop_count": 2,
        "content_hash_blocked": True,
        "heartbeat_detected": True,
        "session_risk_score": 77.0,
        "session_risk_level": "block",
        "turn_number": 4,
        "tool_calls_count": 3,
        "has_tool_results": True,
        "streaming": True,
        "budget_remaining_usd": 4.5,
        "spend_rate_5min": 1.2,
        "budget_blocked": True,
        "cascaded": True,
        "cascade_reason": "fallback",
        "status_code": 429,
        "error_type": "budget_exceeded",
    }
    rec = build_record_from_context(SimpleNamespace(proc_result=pr))
    assert rec.request_id == "r"
    assert rec.status_code == 429
    assert rec.cache_type == "semantic"
    assert rec.proxy_overhead_ms == 9.5


def test_build_record_extracts_threat_info() -> None:
    m1 = SimpleNamespace(name="threat-a", category="prompt_injection", severity="low")
    m2 = SimpleNamespace(name="threat-b", category="data_exfiltration", severity="high")
    rec = build_record_from_context(SimpleNamespace(proc_result={"threat_matches": [m1, m2]}))
    assert set(rec.threat_matches) == {"threat-a", "threat-b"}
    assert set(rec.threat_categories) == {"prompt_injection", "data_exfiltration"}
    assert rec.threat_max_severity == "high"


def test_build_record_extracts_cache_info() -> None:
    rec = build_record_from_context(SimpleNamespace(proc_result={"cache_hit": True, "cache_type": "exact"}))
    assert rec.cache_hit is True
    assert rec.cache_type == "exact"


def test_classify_loop_detected() -> None:
    assert _classify_failure_mode({"loop_detected": True}) == "FM-1.3-loop"


def test_classify_token_waste() -> None:
    assert _classify_failure_mode({"input_tokens": 1200, "output_tokens": 50}) == "OE-6-token-waste"


def test_classify_heartbeat() -> None:
    assert _classify_failure_mode({"heartbeat_detected": True}) == "OE-heartbeat-storm"


def test_classify_budget_blocked() -> None:
    assert _classify_failure_mode({"budget_blocked": True}) == "OE-budget-exceeded"


def test_classify_threat_blocked() -> None:
    assert _classify_failure_mode({"blocked": True, "threat_matches": ["x"]}) == "SEC-threat-blocked"


def test_classify_no_failure() -> None:
    assert _classify_failure_mode({}) == ""


def test_stats_tracking(tmp_path) -> None:  # noqa: ANN001
    c = TelemetryCollector(enabled=True)
    c.record(_record())
    c.record(_record())
    c.export_jsonl(str(tmp_path / "out.jsonl"))
    st = c.stats
    assert st["total_recorded"] == 2
    assert st["total_exported"] == 2


def test_concurrent_record() -> None:
    c = TelemetryCollector(enabled=True)

    def _worker(start: int) -> None:
        for i in range(100):
            rec = _record()
            rec.request_id = f"r{start+i}"
            c.record(rec)

    threads = [threading.Thread(target=_worker, args=(i * 100,)) for i in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert c.stats["total_recorded"] == 800
    assert c.stats["buffered"] == 800
