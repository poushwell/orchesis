"""Community-driven data flywheel primitives."""

from __future__ import annotations

import threading
from collections import defaultdict
from hashlib import sha256
from typing import Any


class DataFlywheel:
    """Community-driven data flywheel for continuous improvement.

    4-level flywheel:
    L1: Raw signal collection (opt-in)
    L2: Pattern extraction (local)
    L3: Signature calibration (aggregated)
    L4: Public leaderboard (anonymized)
    """

    LEVELS = {
        "L1": "Raw signal collection",
        "L2": "Pattern extraction",
        "L3": "Signature calibration",
        "L4": "Public leaderboard",
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        levels = cfg.get("levels", ["L1", "L2"])
        self.enabled_levels = (
            [str(item) for item in levels if str(item) in self.LEVELS]
            if isinstance(levels, list)
            else ["L1", "L2"]
        )
        if not self.enabled_levels:
            self.enabled_levels = ["L1", "L2"]
        self._signals: list[dict[str, Any]] = []
        self._patterns: dict[str, int] = {}
        self._lock = threading.Lock()

    @staticmethod
    def _anon_value(value: Any) -> str:
        raw = str(value or "")
        return sha256(raw.encode("utf-8")).hexdigest()[:12]

    def _anonymize(self, signal: dict[str, Any]) -> dict[str, Any]:
        row = dict(signal)
        for key in ("agent_id", "session_id", "request_id", "user_id"):
            if key in row:
                row[f"{key}_anon"] = self._anon_value(row.get(key))
                row.pop(key, None)
        return row

    def collect_signal(self, signal: dict) -> None:
        """L1: Collect anonymized signal from proxy."""
        if "L1" not in self.enabled_levels:
            return
        if not isinstance(signal, dict):
            return
        row = self._anonymize(signal)
        with self._lock:
            self._signals.append(row)
            if len(self._signals) > 10_000:
                del self._signals[:-10_000]

    def extract_patterns(self) -> dict:
        """L2: Extract patterns from collected signals."""
        if "L2" not in self.enabled_levels:
            return {"patterns": {}, "signals_used": 0}
        with self._lock:
            counts: dict[str, int] = defaultdict(int)
            for item in self._signals:
                model = str(item.get("model", "unknown") or "unknown").strip() or "unknown"
                task = str(item.get("task_type", "unknown") or "unknown").strip() or "unknown"
                counts[f"model:{model}"] += 1
                counts[f"task:{task}"] += 1
                if bool(item.get("blocked", False)):
                    counts["blocked:true"] += 1
            self._patterns = dict(counts)
            return {"patterns": dict(self._patterns), "signals_used": len(self._signals)}

    def calibrate_signatures(self, community_data: list[dict]) -> dict:
        """L3: Auto-calibrate detection thresholds."""
        if "L3" not in self.enabled_levels:
            return {
                "signatures_updated": 0,
                "thresholds_adjusted": 0,
                "false_positive_reduction": 0.0,
            }
        rows = [item for item in community_data if isinstance(item, dict)] if isinstance(community_data, list) else []
        fp_sum = 0.0
        for item in rows:
            value = item.get("false_positive_rate")
            if isinstance(value, int | float):
                fp_sum += float(value)
        fp_avg = (fp_sum / float(len(rows))) if rows else 0.0
        reduction = max(0.0, min(0.5, fp_avg * 0.4))
        return {
            "signatures_updated": int(len(rows)),
            "thresholds_adjusted": int(sum(1 for item in rows if "threshold" in item)),
            "false_positive_reduction": round(reduction, 4),
        }

    def get_leaderboard(self) -> list[dict]:
        """L4: Model × task performance leaderboard."""
        if "L4" not in self.enabled_levels:
            return []
        with self._lock:
            buckets: dict[tuple[str, str], dict[str, float]] = {}
            for item in self._signals:
                model = str(item.get("model", "unknown") or "unknown")
                task = str(item.get("task_type", "unknown") or "unknown")
                key = (model, task)
                row = buckets.setdefault(
                    key,
                    {"quality_sum": 0.0, "cost_sum": 0.0, "count": 0.0},
                )
                q = item.get("quality", item.get("avg_quality", 0.0))
                c = item.get("cost", item.get("avg_cost", 0.0))
                row["quality_sum"] += float(q) if isinstance(q, int | float) else 0.0
                row["cost_sum"] += float(c) if isinstance(c, int | float) else 0.0
                row["count"] += 1.0
            results: list[dict[str, Any]] = []
            for (model, task), item in buckets.items():
                count = max(1, int(item["count"]))
                results.append(
                    {
                        "model": model,
                        "task_type": task,
                        "avg_quality": round(float(item["quality_sum"]) / float(count), 4),
                        "avg_cost": round(float(item["cost_sum"]) / float(count), 6),
                        "sample_count": count,
                    }
                )
            results.sort(key=lambda row: (float(row["avg_quality"]), -float(row["avg_cost"])), reverse=True)
            return results

    def get_flywheel_stats(self) -> dict:
        with self._lock:
            signals_count = len(self._signals)
            patterns_count = len(self._patterns)
        leaderboard_count = len(self.get_leaderboard()) if "L4" in self.enabled_levels else 0
        return {
            "signals_collected": int(signals_count),
            "patterns_extracted": int(patterns_count),
            "enabled_levels": list(self.enabled_levels),
            "leaderboard_entries": int(leaderboard_count),
        }
