"""Structured telemetry export for research and analysis.

Captures every request through the proxy as a structured record.
Exports to JSONL (one JSON object per line) and CSV.
Designed for offline analysis - zero impact on request path.
"""

from __future__ import annotations

import csv
import json
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass
class TelemetryRecord:
    """Single request telemetry record."""

    timestamp: float = 0.0
    request_id: str = ""
    session_id: str = ""
    agent_id: str = ""
    model_requested: str = ""
    model_used: str = ""

    total_ms: float = 0.0
    upstream_ms: float = 0.0
    proxy_overhead_ms: float = 0.0

    input_tokens: int = 0
    output_tokens: int = 0
    cost_usd: float = 0.0

    threat_matches: list[str] = field(default_factory=list)
    threat_categories: list[str] = field(default_factory=list)
    threat_max_severity: str = ""
    blocked: bool = False
    block_reason: str = ""

    cache_hit: bool = False
    cache_type: str = "miss"

    loop_detected: bool = False
    loop_count: int = 0
    content_hash_blocked: bool = False
    heartbeat_detected: bool = False

    session_risk_score: float = 0.0
    session_risk_level: str = "observe"

    turn_number: int = 0
    tool_calls_count: int = 0
    has_tool_results: bool = False
    is_streaming: bool = False

    failure_mode: str = ""

    budget_remaining_usd: float = 0.0
    spend_rate_5min_usd: float = 0.0
    budget_blocked: bool = False

    was_cascaded: bool = False
    cascade_reason: str = ""

    status_code: int = 0
    error_type: str = ""


class TelemetryCollector:
    """Collect telemetry records in memory with bounded buffer."""

    def __init__(
        self,
        max_records: int = 100_000,
        auto_export_path: str | None = None,
        auto_export_interval: float = 300.0,
        enabled: bool = True,
    ) -> None:
        self._enabled = bool(enabled)
        self._max_records = max(1000, int(max_records))
        self._records: deque[TelemetryRecord] = deque(maxlen=self._max_records)
        self._lock = threading.Lock()
        self._stats = {"total_recorded": 0, "total_exported": 0, "dropped": 0}

        self._auto_export_path = auto_export_path
        self._auto_export_interval = float(max(1.0, auto_export_interval))
        self._export_thread: threading.Thread | None = None
        self._stop_event = threading.Event()

        if self._enabled and self._auto_export_path:
            self._start_auto_export()

    @property
    def enabled(self) -> bool:
        return self._enabled

    def record(self, rec: TelemetryRecord) -> None:
        if not self._enabled:
            return
        rec.timestamp = rec.timestamp or time.time()
        with self._lock:
            if len(self._records) >= self._max_records:
                self._stats["dropped"] += 1
            self._records.append(rec)
            self._stats["total_recorded"] += 1

    def export_jsonl(self, path: str) -> int:
        with self._lock:
            records = list(self._records)
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        count = 0
        with p.open("w", encoding="utf-8") as handle:
            for rec in records:
                handle.write(json.dumps(asdict(rec), default=str) + "\n")
                count += 1
        with self._lock:
            self._stats["total_exported"] += count
        return count

    def export_csv(self, path: str) -> int:
        with self._lock:
            records = list(self._records)
        if not records:
            return 0
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        fieldnames = list(asdict(records[0]).keys())
        count = 0
        with p.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for rec in records:
                row = asdict(rec)
                for key, value in row.items():
                    if isinstance(value, list):
                        row[key] = ";".join(str(item) for item in value)
                writer.writerow(row)
                count += 1
        with self._lock:
            self._stats["total_exported"] += count
        return count

    def get_records(self, last_n: int = 0) -> list[dict[str, Any]]:
        with self._lock:
            if last_n > 0:
                items = list(self._records)[-int(last_n) :]
            else:
                items = list(self._records)
        return [asdict(item) for item in items]

    def clear(self) -> int:
        with self._lock:
            count = len(self._records)
            self._records.clear()
            return count

    @property
    def stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                **self._stats,
                "buffered": len(self._records),
                "max_records": self._max_records,
                "enabled": self._enabled,
            }

    def _start_auto_export(self) -> None:
        def _loop() -> None:
            while not self._stop_event.wait(self._auto_export_interval):
                if self._auto_export_path and len(self._records) > 0:
                    try:
                        self.export_jsonl(self._auto_export_path)
                    except Exception:
                        pass

        self._export_thread = threading.Thread(target=_loop, daemon=True, name="telemetry-export")
        self._export_thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        if self._export_thread is not None:
            self._export_thread.join(timeout=5.0)
        if self._auto_export_path and len(self._records) > 0:
            try:
                self.export_jsonl(self._auto_export_path)
            except Exception:
                pass


def build_record_from_context(ctx: Any) -> TelemetryRecord:
    rec = TelemetryRecord()
    pr = getattr(ctx, "proc_result", {}) if ctx else {}
    if not isinstance(pr, dict):
        pr = {}

    rec.request_id = str(pr.get("request_id", ""))
    rec.session_id = str(pr.get("session_id", ""))
    rec.agent_id = str(pr.get("agent_id", ""))
    rec.model_requested = str(pr.get("model", ""))
    rec.model_used = str(pr.get("model_used", pr.get("model", "")))

    rec.total_ms = float(pr.get("total_ms", 0.0) or 0.0)
    rec.upstream_ms = float(pr.get("upstream_ms", 0.0) or 0.0)
    rec.proxy_overhead_ms = max(0.0, rec.total_ms - rec.upstream_ms)

    rec.input_tokens = int(pr.get("input_tokens", 0) or 0)
    rec.output_tokens = int(pr.get("output_tokens", 0) or 0)
    rec.cost_usd = float(pr.get("cost_usd", 0.0) or 0.0)

    threat_matches = pr.get("threat_matches", [])
    if isinstance(threat_matches, list) and threat_matches:
        rec.threat_matches = [str(getattr(m, "name", m)) for m in threat_matches]
        rec.threat_categories = sorted(
            {str(getattr(m, "category", "")).strip() for m in threat_matches if str(getattr(m, "category", "")).strip()}
        )
        sev = [str(getattr(m, "severity", "")).lower() for m in threat_matches]
        order = {"": 0, "info": 1, "low": 2, "medium": 3, "high": 4, "critical": 5}
        rec.threat_max_severity = max(sev, key=lambda item: order.get(item, 0), default="")

    rec.blocked = bool(pr.get("blocked", False))
    rec.block_reason = str(pr.get("block_reason", ""))

    rec.cache_hit = bool(pr.get("cache_hit", False))
    rec.cache_type = str(pr.get("cache_type", "miss"))

    rec.loop_detected = bool(pr.get("loop_detected", False))
    rec.loop_count = int(pr.get("loop_count", 0) or 0)
    rec.content_hash_blocked = bool(pr.get("content_hash_blocked", False))
    rec.heartbeat_detected = bool(pr.get("heartbeat_detected", False))

    rec.session_risk_score = float(pr.get("session_risk_score", 0.0) or 0.0)
    rec.session_risk_level = str(pr.get("session_risk_level", "observe"))

    rec.turn_number = int(pr.get("turn_number", 0) or 0)
    rec.tool_calls_count = int(pr.get("tool_calls_count", 0) or 0)
    rec.has_tool_results = bool(pr.get("has_tool_results", False))
    rec.is_streaming = bool(pr.get("streaming", False))

    rec.failure_mode = _classify_failure_mode(pr)

    rec.budget_remaining_usd = float(pr.get("budget_remaining_usd", 0.0) or 0.0)
    rec.spend_rate_5min_usd = float(pr.get("spend_rate_5min", 0.0) or 0.0)
    rec.budget_blocked = bool(pr.get("budget_blocked", False))

    rec.was_cascaded = bool(pr.get("cascaded", False))
    rec.cascade_reason = str(pr.get("cascade_reason", ""))

    rec.status_code = int(pr.get("status_code", 200) or 200)
    rec.error_type = str(pr.get("error_type", ""))
    return rec


def _classify_failure_mode(pr: dict[str, Any]) -> str:
    if pr.get("loop_detected") or pr.get("content_hash_blocked"):
        return "FM-1.3-loop"
    if pr.get("context_erosion_detected"):
        return "FM-1.4-context-erosion"
    if pr.get("unaware_termination"):
        return "FM-1.5-unaware-termination"
    if pr.get("task_derailment_detected"):
        return "FM-2.3-task-derailment"
    if pr.get("termination_confusion"):
        return "FM-3.1-termination-confusion"
    if pr.get("hallucination_risk"):
        return "OE-1-hallucination-risk"

    input_tokens = int(pr.get("input_tokens", 0) or 0)
    output_tokens = int(pr.get("output_tokens", 0) or 0)
    if input_tokens > 0 and output_tokens > 0 and input_tokens > output_tokens * 10:
        return "OE-6-token-waste"

    if pr.get("heartbeat_detected"):
        return "OE-heartbeat-storm"
    if pr.get("budget_blocked"):
        return "OE-budget-exceeded"
    if pr.get("blocked") and pr.get("threat_matches"):
        return "SEC-threat-blocked"
    return ""
