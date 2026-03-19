"""Weekly Intelligence Report - automated weekly summary."""

from __future__ import annotations

from datetime import datetime, timezone


class WeeklyReportGenerator:
    """Generates weekly intelligence report across all subsystems."""

    def generate(self, data: dict) -> dict:
        return {
            "report_id": f"weekly-{datetime.now(timezone.utc).strftime('%Y-W%V')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "period": "weekly",
            "sections": {
                "security": self._security_summary(data.get("security", {})),
                "cost": self._cost_summary(data.get("cost", {})),
                "compliance": self._compliance_summary(data.get("compliance", {})),
                "competitive": self._competitive_summary(data.get("competitive", {})),
                "research": self._research_summary(data.get("research", {})),
            },
            "highlights": self._extract_highlights(data),
            "actions_required": self._get_actions(data),
        }

    def _security_summary(self, data: dict) -> dict:
        return {
            "threats_blocked": data.get("blocked", 0),
            "new_signatures": data.get("new_sigs", 0),
            "red_queen_ari": data.get("ari", 0.0),
        }

    def _cost_summary(self, data: dict) -> dict:
        return {
            "total_cost": data.get("cost", 0.0),
            "savings": data.get("savings", 0.0),
            "token_yield": data.get("yield", 0.0),
        }

    def _compliance_summary(self, data: dict) -> dict:
        return {
            "eu_ai_act_score": data.get("eu_score", 0.0),
            "arc_certified": data.get("arc_count", 0),
            "incidents": data.get("incidents", 0),
        }

    def _competitive_summary(self, data: dict) -> dict:
        return {
            "threats_detected": data.get("threats", 0),
            "opportunities": data.get("opportunities", 0),
        }

    def _research_summary(self, data: dict) -> dict:
        return {
            "experiments_run": data.get("experiments", 0),
            "hypotheses_confirmed": data.get("confirmed", 0),
        }

    def _extract_highlights(self, data: dict) -> list[str]:
        highlights: list[str] = []
        cost = data.get("cost", {})
        if cost.get("savings", 0) > 0:
            highlights.append(f"Saved ${cost['savings']:.2f} via cache/compression")
        security = data.get("security", {})
        if security.get("blocked", 0) > 0:
            highlights.append(f"Blocked {security['blocked']} threats")
        return highlights or ["No significant events this week"]

    def _get_actions(self, data: dict) -> list[str]:
        actions: list[str] = []
        compliance = data.get("compliance", {})
        if compliance.get("eu_score", 1.0) < 0.8:
            actions.append("Review EU AI Act compliance - score below 80%")
        return actions
