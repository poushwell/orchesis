"""Competitive intelligence monitoring helpers."""

from __future__ import annotations

from datetime import datetime, timezone


class CompetitiveMonitor:
    """Monitor competitors and ecosystem changes."""

    COMPETITORS = {
        "openguard": {"stars_trigger": 100, "current": 4},
        "dashclaw": {"stars_trigger": 500, "current": 0},
        "toran_sh": {"feature_trigger": "active_management"},
        "helicone": {"stars_trigger": 5000, "current": 0},
    }

    TRIGGER_EVENTS = [
        "competitor_stars_spike",
        "new_proxy_product_launched",
        "openai_agent_gateway",
        "eu_ai_act_safe_harbor",
        "major_ai_incident",
    ]

    def check_competitor(self, name: str, current_data: dict) -> dict:
        """Check if competitor has hit a trigger threshold."""
        key = str(name or "").strip().lower()
        baseline = self.COMPETITORS.get(key, {})
        data = dict(current_data) if isinstance(current_data, dict) else {}
        trigger_type: str | None = None
        action_required: str | None = None
        triggered = False

        stars_trigger = baseline.get("stars_trigger")
        if isinstance(stars_trigger, int | float):
            stars = int(data.get("stars", data.get("github_stars", 0)) or 0)
            if stars >= int(stars_trigger):
                triggered = True
                trigger_type = "competitor_stars_spike"
                action_required = "Run positioning update and publish comparison notes."

        feature_trigger = baseline.get("feature_trigger")
        if isinstance(feature_trigger, str):
            features = data.get("features", [])
            if isinstance(features, list) and feature_trigger in {str(item) for item in features}:
                triggered = True
                trigger_type = "new_proxy_product_launched"
                action_required = "Assess feature gap and prepare response roadmap."

        return {
            "name": key or str(name),
            "triggered": triggered,
            "trigger_type": trigger_type,
            "action_required": action_required,
            "data": data,
        }

    def detect_ecosystem_changes(self, feed: list[dict]) -> list[dict]:
        """Detect significant ecosystem changes from feed."""
        changes: list[dict] = []
        for item in feed if isinstance(feed, list) else []:
            if not isinstance(item, dict):
                continue
            text = f"{item.get('title', '')} {item.get('text', '')} {item.get('event', '')}".lower()
            event_type = None
            if "openai" in text and "gateway" in text:
                event_type = "openai_agent_gateway"
            elif "eu ai act" in text and ("safe harbor" in text or "safe-harbor" in text):
                event_type = "eu_ai_act_safe_harbor"
            elif "incident" in text and "ai" in text:
                event_type = "major_ai_incident"
            elif "launch" in text and ("proxy" in text or "agent" in text):
                event_type = "new_proxy_product_launched"
            if event_type is None:
                continue
            changes.append(
                {
                    "event": event_type,
                    "title": str(item.get("title", "")),
                    "source": str(item.get("source", "")),
                    "severity": "high" if event_type in {"major_ai_incident", "openai_agent_gateway"} else "medium",
                }
            )
        return changes

    def generate_weekly_report(self, data: dict) -> dict:
        """Generate weekly competitive intelligence report."""
        payload = data if isinstance(data, dict) else {}
        competitors = payload.get("competitors", {})
        feed = payload.get("feed", [])
        threats: list[dict] = []
        opportunities: list[dict] = []
        actions: list[str] = []
        highlights: list[str] = []

        if isinstance(competitors, dict):
            for name, row in competitors.items():
                check = self.check_competitor(str(name), row if isinstance(row, dict) else {})
                if check["triggered"]:
                    threats.append(check)
                    actions.append(str(check.get("action_required") or "Review competitor change."))
                    highlights.append(f"Trigger: {check['name']} -> {check['trigger_type']}")
                elif self.score_threat_level(str(name), row if isinstance(row, dict) else {}) < 0.35:
                    opportunities.append(
                        {
                            "name": str(name),
                            "angle": "Expand educational content while competitor pressure is low.",
                        }
                    )

        eco_changes = self.detect_ecosystem_changes(feed if isinstance(feed, list) else [])
        for change in eco_changes:
            threats.append(change)
            highlights.append(f"Ecosystem event: {change.get('event')}")
            if change.get("event") == "major_ai_incident":
                opportunities.append(
                    {
                        "name": "incident-response-content",
                        "angle": "Publish trust/safety guidance tied to incident lessons.",
                    }
                )

        if not actions:
            actions.append("Maintain weekly cadence and monitor trigger deltas.")

        return {
            "week": datetime.now(timezone.utc).strftime("%Y-W%W"),
            "highlights": highlights,
            "threats": threats,
            "opportunities": opportunities,
            "actions": actions,
        }

    def score_threat_level(self, competitor: str, data: dict) -> float:
        """Score competitive threat 0-1."""
        key = str(competitor or "").strip().lower()
        baseline = self.COMPETITORS.get(key, {})
        payload = data if isinstance(data, dict) else {}
        score = 0.1
        stars = int(payload.get("stars", payload.get("github_stars", 0)) or 0)
        stars_trigger = baseline.get("stars_trigger")
        if isinstance(stars_trigger, int | float) and stars_trigger > 0:
            score += min(0.6, stars / float(stars_trigger) * 0.6)
        velocity = float(payload.get("weekly_growth", 0.0) or 0.0)
        score += min(0.2, max(0.0, velocity) / 100.0)
        features = payload.get("features", [])
        if isinstance(features, list) and features:
            score += min(0.2, len(features) * 0.03)
        return max(0.0, min(1.0, round(score, 3)))
