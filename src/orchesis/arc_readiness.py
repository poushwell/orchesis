"""ARC readiness certification for production agents."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import uuid
from typing import Any


class AgentReadinessCertifier:
    """ARC — Agent Readiness Certification for production deployment.

    14 criteria, 4 categories.
    CI/CD gate: orchesis arc-check --min-score 75
    Badge: "Orchesis Verified: ARC 82/100"
    """

    CRITERIA = {
        "security": [
            "threat_detection_active",
            "credential_scanning_enabled",
            "loop_detection_configured",
            "rate_limiting_set",
        ],
        "reliability": [
            "circuit_breaker_configured",
            "auto_healing_enabled",
            "error_rate_below_threshold",
            "uptime_above_threshold",
        ],
        "compliance": [
            "recording_enabled",
            "audit_trail_available",
            "eu_ai_act_logging",
        ],
        "performance": [
            "latency_within_sla",
            "cost_within_budget",
            "cache_hit_rate_acceptable",
        ],
    }

    def __init__(self) -> None:
        self._certificates: list[dict[str, Any]] = []

    @staticmethod
    def _bool_metric(metrics: dict[str, Any], key: str, default: bool = False) -> bool:
        value = metrics.get(key, default)
        return bool(value)

    def check_criterion(self, criterion: str, metrics: dict, policy: dict) -> bool:
        """Check single criterion."""
        m = metrics if isinstance(metrics, dict) else {}
        p = policy if isinstance(policy, dict) else {}

        if criterion == "threat_detection_active":
            return bool(p.get("threat_intel", {}).get("enabled", False)) or self._bool_metric(m, criterion)
        if criterion == "credential_scanning_enabled":
            return self._bool_metric(m, criterion, True)
        if criterion == "loop_detection_configured":
            return bool(p.get("loop_detection", {}).get("enabled", False)) or self._bool_metric(m, criterion)
        if criterion == "rate_limiting_set":
            rules = p.get("rules", [])
            has_rule = any(
                isinstance(rule, dict) and str(rule.get("name", "")).strip().lower() == "rate_limit"
                for rule in (rules if isinstance(rules, list) else [])
            )
            api_limit = bool(p.get("api_rate_limit", {}).get("enabled", False))
            return has_rule or api_limit or self._bool_metric(m, criterion)

        if criterion == "circuit_breaker_configured":
            return self._bool_metric(m, criterion, True)
        if criterion == "auto_healing_enabled":
            return self._bool_metric(m, criterion, True)
        if criterion == "error_rate_below_threshold":
            rate = m.get("error_rate", 0.0)
            try:
                return float(rate) <= 0.05
            except (TypeError, ValueError):
                return self._bool_metric(m, criterion, True)
        if criterion == "uptime_above_threshold":
            uptime = m.get("uptime", 1.0)
            try:
                return float(uptime) >= 0.99
            except (TypeError, ValueError):
                return self._bool_metric(m, criterion, True)

        if criterion == "recording_enabled":
            return bool(p.get("recording", {}).get("enabled", False)) or self._bool_metric(m, criterion)
        if criterion == "audit_trail_available":
            return self._bool_metric(m, criterion, True) or bool(p.get("recording", {}).get("enabled", False))
        if criterion == "eu_ai_act_logging":
            return bool(p.get("recording", {}).get("enabled", False))

        if criterion == "latency_within_sla":
            latency = m.get("latency_ms", 0.0)
            sla = m.get("latency_sla_ms", 800.0)
            try:
                return float(latency) <= float(sla)
            except (TypeError, ValueError):
                return self._bool_metric(m, criterion, True)
        if criterion == "cost_within_budget":
            cost = m.get("cost", 0.0)
            budget = m.get("budget_limit", max(1.0, float(cost) + 1.0))
            try:
                return float(cost) <= float(budget)
            except (TypeError, ValueError):
                return self._bool_metric(m, criterion, True)
        if criterion == "cache_hit_rate_acceptable":
            ratio = m.get("cache_hit_rate", 0.0)
            try:
                return float(ratio) >= 0.2
            except (TypeError, ValueError):
                return self._bool_metric(m, criterion, True)

        return False

    def get_badge(self, score: float) -> str:
        """Generate badge text."""
        return f"Orchesis Verified: ARC {int(round(float(score))):d}/100"

    def certify(self, agent_id: str, metrics: dict, policy: dict) -> dict:
        all_criteria = [name for names in self.CRITERIA.values() for name in names]
        passed = 0
        failures: list[str] = []
        category_scores: dict[str, float] = {}

        for category, criteria in self.CRITERIA.items():
            cat_pass = 0
            for criterion in criteria:
                ok = self.check_criterion(criterion, metrics, policy)
                if ok:
                    passed += 1
                    cat_pass += 1
                else:
                    failures.append(criterion)
            category_scores[category] = round((cat_pass / len(criteria) * 100.0) if criteria else 0.0, 2)

        total = len(all_criteria)
        score = round((passed / total * 100.0) if total > 0 else 0.0, 2)
        certified = score >= 75.0
        if score >= 90.0:
            grade = "ARC-A"
        elif score >= 80.0:
            grade = "ARC-B"
        elif score >= 75.0:
            grade = "ARC-C"
        else:
            grade = "NOT_CERTIFIED"

        certificate_id: str | None = None
        valid_until: str | None = None
        if certified:
            certificate_id = f"arc-{uuid.uuid4().hex[:12]}"
            valid_until = (datetime.now(timezone.utc) + timedelta(days=90)).isoformat()
            self._certificates.append(
                {
                    "certificate_id": certificate_id,
                    "agent_id": str(agent_id),
                    "score": score,
                    "grade": grade,
                    "badge": self.get_badge(score),
                    "issued_at": datetime.now(timezone.utc).isoformat(),
                    "valid_until": valid_until,
                }
            )

        return {
            "agent_id": str(agent_id),
            "score": score,
            "certified": certified,
            "grade": grade,
            "badge": self.get_badge(score),
            "categories": category_scores,
            "failures": failures,
            "certificate_id": certificate_id,
            "valid_until": valid_until,
        }

    def list_certificates(self) -> list[dict]:
        """List all issued certificates."""
        return [dict(item) for item in self._certificates]

