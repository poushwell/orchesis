"""Lightweight intent classifier for user messages."""

from __future__ import annotations

from typing import Any


class IntentClassifier:
    """Classifies user intent from message content."""

    INTENTS = {
        "code_generation": ["write", "implement", "create function", "code"],
        "data_extraction": ["extract", "parse", "find all", "get list"],
        "web_browsing": ["search", "browse", "fetch url", "open website"],
        "file_operations": ["read file", "write file", "delete", "move"],
        "system_commands": ["run", "execute", "bash", "terminal", "shell"],
        "data_exfiltration": ["send to", "upload to", "post to", "exfiltrate"],
        "privilege_escalation": ["sudo", "admin", "root", "bypass", "override"],
        "reconnaissance": ["list all", "enumerate", "scan", "discover"],
    }

    RISK_LEVELS = {
        "code_generation": "low",
        "data_extraction": "low",
        "web_browsing": "medium",
        "file_operations": "medium",
        "system_commands": "high",
        "data_exfiltration": "critical",
        "privilege_escalation": "critical",
        "reconnaissance": "high",
    }

    _RISK_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

    def __init__(self) -> None:
        self._intent_counts: dict[str, int] = {}
        self._risk_counts: dict[str, int] = {}
        self._total = 0

    def classify(self, text: str) -> dict:
        normalized = (text or "").strip().lower()
        matches: list[dict[str, Any]] = []
        if normalized:
            for intent, keywords in self.INTENTS.items():
                hit_count = sum(1 for keyword in keywords if keyword in normalized)
                if hit_count <= 0:
                    continue
                confidence = min(1.0, 0.35 + 0.2 * hit_count)
                matches.append(
                    {
                        "intent": intent,
                        "confidence": round(confidence, 3),
                        "risk_level": self.RISK_LEVELS[intent],
                    }
                )
        matches.sort(key=lambda item: float(item.get("confidence", 0.0)), reverse=True)
        if not matches:
            result = {
                "primary_intent": "unknown",
                "confidence": 0.0,
                "all_intents": [],
                "risk_level": "low",
                "requires_approval": False,
            }
            self._track(result["primary_intent"], result["risk_level"])
            return result
        primary = matches[0]
        risk_level = str(primary["risk_level"])
        result = {
            "primary_intent": str(primary["intent"]),
            "confidence": float(primary["confidence"]),
            "all_intents": matches,
            "risk_level": risk_level,
            "requires_approval": risk_level in {"high", "critical"},
        }
        self._track(result["primary_intent"], risk_level)
        return result

    def batch_classify(self, messages: list[dict]) -> list[dict]:
        """Classify all messages in a conversation."""
        out: list[dict[str, Any]] = []
        for idx, message in enumerate(messages if isinstance(messages, list) else []):
            text = ""
            if isinstance(message, dict):
                content = message.get("content", message.get("text", ""))
                if isinstance(content, str):
                    text = content
            classification = self.classify(text)
            out.append({"index": idx, "text": text, **classification})
        return out

    def get_session_risk(self, classifications: list[dict]) -> dict:
        """Aggregate risk across session."""
        if not isinstance(classifications, list) or not classifications:
            return {
                "session_risk": "low",
                "requires_approval": False,
                "max_confidence": 0.0,
                "intent_counts": {},
            }
        max_risk = "low"
        requires_approval = False
        max_conf = 0.0
        intent_counts: dict[str, int] = {}
        for row in classifications:
            if not isinstance(row, dict):
                continue
            risk = str(row.get("risk_level", "low"))
            if self._RISK_ORDER.get(risk, 0) > self._RISK_ORDER.get(max_risk, 0):
                max_risk = risk
            requires_approval = requires_approval or bool(row.get("requires_approval", False))
            try:
                max_conf = max(max_conf, float(row.get("confidence", 0.0)))
            except (TypeError, ValueError):
                pass
            intent = str(row.get("primary_intent", "unknown"))
            intent_counts[intent] = intent_counts.get(intent, 0) + 1
        return {
            "session_risk": max_risk,
            "requires_approval": requires_approval,
            "max_confidence": round(max_conf, 3),
            "intent_counts": intent_counts,
        }

    def get_stats(self) -> dict:
        """Intent distribution stats."""
        return {
            "total_classified": int(self._total),
            "intent_counts": dict(self._intent_counts),
            "risk_counts": dict(self._risk_counts),
        }

    def _track(self, intent: str, risk: str) -> None:
        self._total += 1
        self._intent_counts[intent] = self._intent_counts.get(intent, 0) + 1
        self._risk_counts[risk] = self._risk_counts.get(risk, 0) + 1
