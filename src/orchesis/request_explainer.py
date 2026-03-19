"""Request Explainer - human-readable explanation of proxy decisions.

EU AI Act Article 13: transparency and explainability.
"Why was this request blocked?"
"""

from __future__ import annotations

from collections import Counter


class RequestExplainer:
    """Generates human-readable explanations for proxy decisions."""

    REASON_TEMPLATES = {
        "budget_exceeded": "Request cost ${cost:.4f} exceeds daily budget of ${budget:.2f}.",
        "loop_detected": "This request appears to be part of a loop ({count} similar requests detected).",
        "rate_limited": "Rate limit exceeded: {count} requests in {window}s (limit: {limit}).",
        "prompt_injection": "Potential prompt injection detected in {field}.",
        "credential_leak": "Potential credential leak detected: {pattern}.",
        "content_blocked": "Content matched security rule: {rule}.",
        "context_budget": "Context budget exhausted at Level {level}.",
    }

    def explain(self, decision: dict) -> dict:
        action = str(decision.get("decision", "ALLOW"))
        reasons = list(decision.get("reasons", []) or [])

        explanations: list[str] = []
        for reason in reasons:
            template = self.REASON_TEMPLATES.get(str(reason), f"Rule triggered: {reason}")
            explanations.append(template)

        plain_english = self._to_plain_english(action, explanations)

        return {
            "decision": action,
            "plain_english": plain_english,
            "technical_reasons": reasons,
            "explanations": explanations,
            "eu_ai_act_article": "Article 13 - Transparency",
            "appeal_possible": action == "DENY",
        }

    def _to_plain_english(self, action: str, explanations: list[str]) -> str:
        if action == "ALLOW":
            return "This request was allowed. No policy violations detected."
        if action == "DENY":
            reason_text = " ".join(explanations) if explanations else "Policy violation detected."
            return f"This request was blocked. {reason_text}"
        return f"Decision: {action}."

    def explain_session(self, decisions: list[dict]) -> dict:
        """Explain a full session's decision pattern."""
        total = len(decisions)
        denies = [item for item in decisions if item.get("decision") == "DENY"]
        return {
            "total_requests": total,
            "denied": len(denies),
            "deny_rate": round(len(denies) / max(1, total), 4),
            "top_denial_reasons": self._top_reasons(denies),
            "session_verdict": "healthy" if len(denies) / max(1, total) < 0.1 else "problematic",
        }

    def _top_reasons(self, denies: list[dict]) -> list[str]:
        reasons = [r for item in denies for r in item.get("reasons", [])]
        return [reason for reason, _ in Counter(reasons).most_common(3)]

