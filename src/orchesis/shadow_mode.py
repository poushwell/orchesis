"""Shadow policy execution without blocking traffic."""

from __future__ import annotations

import threading
from typing import Any, Callable


class ShadowModeRunner:
    """Runs requests against shadow policy without blocking traffic."""

    def __init__(self, shadow_policy: dict, engine: Callable[[dict, dict], dict]):
        self.shadow_policy = shadow_policy if isinstance(shadow_policy, dict) else {}
        self.engine = engine
        self._results: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def shadow_evaluate(self, request: dict, real_decision: dict) -> dict:
        """Evaluate against shadow policy, compare with real decision."""
        req = dict(request) if isinstance(request, dict) else {}
        real = dict(real_decision) if isinstance(real_decision, dict) else {}
        shadow = self.engine(req, self.shadow_policy)
        real_label = str(real.get("decision", "ALLOW" if bool(real.get("allowed", True)) else "DENY")).upper()
        shadow_label = str(
            shadow.get("decision", "ALLOW" if bool(shadow.get("allowed", True)) else "DENY")
        ).upper()
        match = real_label == shadow_label
        divergence_reason = None
        if not match:
            divergence_reason = f"real={real_label}, shadow={shadow_label}"
        row = {
            "request_id": str(req.get("request_id", real.get("request_id", ""))),
            "real_decision": real_label,
            "shadow_decision": shadow_label,
            "match": bool(match),
            "divergence_reason": divergence_reason,
        }
        with self._lock:
            self._results.append(row)
            if len(self._results) > 5000:
                del self._results[:-5000]
        return row

    def get_divergence_report(self) -> dict:
        with self._lock:
            rows = list(self._results)
        total = len(rows)
        matches = sum(1 for item in rows if bool(item.get("match", False)))
        divergences = total - matches
        false_positives = sum(
            1
            for item in rows
            if str(item.get("real_decision", "")).upper() == "ALLOW"
            and str(item.get("shadow_decision", "")).upper() == "DENY"
        )
        false_negatives = sum(
            1
            for item in rows
            if str(item.get("real_decision", "")).upper() == "DENY"
            and str(item.get("shadow_decision", "")).upper() == "ALLOW"
        )
        rate = (float(divergences) / float(total)) if total > 0 else 0.0
        return {
            "total_evaluated": int(total),
            "matches": int(matches),
            "divergences": int(divergences),
            "divergence_rate": round(rate, 6),
            "false_positives": int(false_positives),
            "false_negatives": int(false_negatives),
        }

    def get_divergences(self, limit: int = 100) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 1000))
        with self._lock:
            rows = [item for item in self._results if not bool(item.get("match", False))]
        return rows[-safe_limit:]

    def get_recommendation(self) -> str:
        """Should shadow policy replace real policy?"""
        report = self.get_divergence_report()
        total = int(report.get("total_evaluated", 0))
        rate = float(report.get("divergence_rate", 0.0))
        false_neg = int(report.get("false_negatives", 0))
        if total < 20:
            return "collect_more_data"
        if rate <= 0.05 and false_neg == 0:
            return "promote_shadow_policy"
        if rate <= 0.15:
            return "tune_shadow_policy"
        return "do_not_promote"
