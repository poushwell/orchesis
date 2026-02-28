"""Prometheus-compatible metrics collector."""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any

from orchesis.telemetry import DecisionEvent, EventEmitter


class MetricsCollector(EventEmitter):
    """Collects metrics from decision events."""

    def __init__(self):
        self._counters: dict[str, int] = defaultdict(int)
        self._histograms: dict[str, list[float]] = defaultdict(list)
        self._lock = threading.Lock()

    def emit(self, event: DecisionEvent) -> None:
        with self._lock:
            self._counters[f'orchesis_decisions_total|decision={event.decision}'] += 1
            self._counters[
                f'orchesis_decisions_by_agent|agent={event.agent_id}|decision={event.decision}'
            ] += 1
            self._counters[
                f'orchesis_decisions_by_tool|tool={event.tool}|decision={event.decision}'
            ] += 1
            if any(reason.startswith("anomaly:") for reason in event.reasons):
                self._counters["orchesis_anomalies_total"] += 1
            self._histograms["orchesis_evaluation_duration_us"].append(
                float(event.evaluation_duration_us)
            )

    def _counter_value(self, key: str) -> int:
        return int(self._counters.get(key, 0))

    def prometheus_text(self) -> str:
        with self._lock:
            lines: list[str] = []
            lines.append("# HELP orchesis_decisions_total Total decisions")
            lines.append("# TYPE orchesis_decisions_total counter")
            for decision in ("ALLOW", "DENY"):
                value = self._counter_value(f"orchesis_decisions_total|decision={decision}")
                lines.append(f'orchesis_decisions_total{{decision="{decision}"}} {value}')

            lines.append("# HELP orchesis_decisions_by_agent Decisions by agent and decision")
            lines.append("# TYPE orchesis_decisions_by_agent counter")
            for key, value in sorted(self._counters.items()):
                if not key.startswith("orchesis_decisions_by_agent|"):
                    continue
                parts = key.split("|")
                agent = parts[1].split("=", 1)[1]
                decision = parts[2].split("=", 1)[1]
                lines.append(
                    f'orchesis_decisions_by_agent{{agent="{agent}",decision="{decision}"}} {value}'
                )

            lines.append("# HELP orchesis_decisions_by_tool Decisions by tool and decision")
            lines.append("# TYPE orchesis_decisions_by_tool counter")
            for key, value in sorted(self._counters.items()):
                if not key.startswith("orchesis_decisions_by_tool|"):
                    continue
                parts = key.split("|")
                tool = parts[1].split("=", 1)[1]
                decision = parts[2].split("=", 1)[1]
                lines.append(
                    f'orchesis_decisions_by_tool{{tool="{tool}",decision="{decision}"}} {value}'
                )

            lines.append("# HELP orchesis_anomalies_total Total detected anomalies")
            lines.append("# TYPE orchesis_anomalies_total counter")
            lines.append(f"orchesis_anomalies_total {self._counter_value('orchesis_anomalies_total')}")

            values = self._histograms.get("orchesis_evaluation_duration_us", [])
            total = sum(values)
            count = len(values)
            lines.append("# HELP orchesis_evaluation_duration_us Evaluation latency")
            lines.append("# TYPE orchesis_evaluation_duration_us histogram")
            lines.append(f"orchesis_evaluation_duration_us_sum {total}")
            lines.append(f"orchesis_evaluation_duration_us_count {count}")
            return "\n".join(lines) + "\n"

    def reset(self) -> None:
        with self._lock:
            self._counters = defaultdict(int)
            self._histograms = defaultdict(list)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return {
                "counters": dict(self._counters),
                "histograms": {key: list(values) for key, values in self._histograms.items()},
            }
