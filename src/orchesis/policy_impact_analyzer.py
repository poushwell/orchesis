"""Policy Impact Analyzer - simulate policy change impact before applying."""

from __future__ import annotations

import threading


class PolicyImpactAnalyzer:
    """Simulate and analyze impact of policy changes."""

    def __init__(self):
        self._simulations: list[dict] = []
        self._lock = threading.Lock()

    def simulate(self, current_policy: dict, new_policy: dict, sample_requests: list[dict]) -> dict:
        """Simulate impact of policy change on sample requests."""
        changes = self._detect_changes(current_policy, new_policy)
        impacts: list[dict] = []

        for req in list(sample_requests)[:100]:
            current_result = self._evaluate_mock(req, current_policy)
            new_result = self._evaluate_mock(req, new_policy)
            if current_result != new_result:
                impacts.append(
                    {
                        "request_id": req.get("id", "unknown"),
                        "before": current_result,
                        "after": new_result,
                        "change_type": "block_to_allow" if new_result == "ALLOW" else "allow_to_block",
                    }
                )

        result = {
            "changes_detected": changes,
            "requests_simulated": len(list(sample_requests)[:100]),
            "impacted_requests": len(impacts),
            "impact_rate": round(len(impacts) / max(1, len(sample_requests)), 4),
            "new_blocks": sum(1 for item in impacts if item["change_type"] == "allow_to_block"),
            "new_allows": sum(1 for item in impacts if item["change_type"] == "block_to_allow"),
            "sample_impacts": impacts[:10],
            "safe_to_apply": len([item for item in impacts if item["change_type"] == "allow_to_block"]) < 5,
        }

        with self._lock:
            self._simulations.append(result)
        return result

    def _detect_changes(self, old: dict, new: dict) -> list[str]:
        changes = []
        for key in set(list(old.keys()) + list(new.keys())):
            if old.get(key) != new.get(key):
                changes.append(f"{key}: {old.get(key)} -> {new.get(key)}")
        return changes

    def _evaluate_mock(self, request: dict, policy: dict) -> str:
        budget = policy.get("budgets", {}).get("daily", float("inf"))
        cost = request.get("cost", 0.0)
        return "DENY" if float(cost) > float(budget) else "ALLOW"

    def get_stats(self) -> dict:
        with self._lock:
            return {"simulations": len(self._simulations)}

