"""Session memory tracking and poisoning detection."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any


class MemoryTracker:
    """Tracks agent memory usage and detects memory poisoning."""

    _MODEL_WINDOWS = {
        "gpt-4o": 128000,
        "gpt-4o-mini": 128000,
        "claude-3-5-sonnet": 200000,
        "claude-sonnet-4-20250514": 200000,
        "claude-haiku-4-5-20251001": 200000,
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.max_memory_entries = int(cfg.get("max_entries", 1000))
        self._sessions: dict[str, dict[str, Any]] = {}

    @staticmethod
    def _as_dict(item: Any) -> dict[str, Any]:
        if isinstance(item, dict):
            return item
        if hasattr(item, "__dict__"):
            raw = getattr(item, "__dict__", {})
            if isinstance(raw, dict):
                return raw
        return {}

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _estimate_tokens(messages: list[dict]) -> int:
        total_chars = 0
        for message in messages:
            row = message if isinstance(message, dict) else {}
            for key in ("content", "text", "prompt", "message"):
                value = row.get(key)
                if isinstance(value, str):
                    total_chars += len(value)
                    break
            total_chars += 12
        return max(0, int(total_chars / 4))

    @staticmethod
    def _extract_text(messages: list[dict]) -> str:
        parts: list[str] = []
        for message in messages:
            row = message if isinstance(message, dict) else {}
            text = row.get("content", row.get("text", row.get("prompt", row.get("message", ""))))
            if isinstance(text, str) and text.strip():
                parts.append(text.strip())
        return " ".join(parts).lower()

    def record(self, session_id: str, messages: list[dict]) -> None:
        """Record message history for session."""
        sid = str(session_id or "")
        rows = [self._as_dict(item) for item in messages if isinstance(self._as_dict(item), dict)]
        entry = {
            "timestamp": self._now_iso(),
            "message_count": len(rows),
            "estimated_tokens": self._estimate_tokens(rows),
            "messages": rows,
        }
        session = self._sessions.setdefault(sid, {"entries": []})
        entries = session.setdefault("entries", [])
        entries.append(entry)
        if len(entries) > self.max_memory_entries:
            session["entries"] = entries[-self.max_memory_entries :]

    def get_memory_stats(self, session_id: str) -> dict:
        sid = str(session_id or "")
        session = self._sessions.get(sid, {})
        entries = session.get("entries", []) if isinstance(session, dict) else []
        if not entries:
            return {
                "session_id": sid,
                "message_count": 0,
                "estimated_tokens": 0,
                "oldest_message": "",
                "newest_message": "",
                "growth_rate": 0.0,
                "anomaly_detected": False,
            }

        first = entries[0]
        last = entries[-1]
        first_tokens = int(first.get("estimated_tokens", 0) or 0)
        last_tokens = int(last.get("estimated_tokens", 0) or 0)
        steps = max(1, len(entries) - 1)
        growth_rate = float(last_tokens - first_tokens) / float(steps)
        anomaly = growth_rate > 250.0 or last_tokens > 100000
        return {
            "session_id": sid,
            "message_count": int(last.get("message_count", 0) or 0),
            "estimated_tokens": last_tokens,
            "oldest_message": str(first.get("timestamp", "") or ""),
            "newest_message": str(last.get("timestamp", "") or ""),
            "growth_rate": round(growth_rate, 6),
            "anomaly_detected": bool(anomaly),
        }

    def detect_poisoning(self, session_id: str) -> dict:
        """Detect memory poisoning attempts."""
        sid = str(session_id or "")
        session = self._sessions.get(sid, {})
        entries = session.get("entries", []) if isinstance(session, dict) else []
        if not entries:
            return {"poisoned": False, "signals": [], "severity": "low"}
        latest = entries[-1]
        messages = latest.get("messages", [])
        text = self._extract_text(messages if isinstance(messages, list) else [])
        checks = {
            "instruction_override": ["ignore previous", "override instructions", "ignore system"],
            "policy_bypass": ["disable guardrails", "bypass safety", "bypass policy"],
            "secret_exfiltration": ["reveal api key", "exfiltrate", "print secrets"],
            "system_prompt_probe": ["show system prompt", "developer instructions"],
        }
        signals: list[str] = []
        for label, phrases in checks.items():
            if any(phrase in text for phrase in phrases):
                signals.append(label)
        severity = "low"
        if len(signals) >= 3:
            severity = "critical"
        elif len(signals) == 2:
            severity = "high"
        elif len(signals) == 1:
            severity = "medium"
        return {
            "poisoned": bool(signals),
            "signals": signals,
            "severity": severity,
        }

    def get_context_pressure(self, session_id: str, model: str) -> dict:
        """How close to context window limit."""
        stats = self.get_memory_stats(session_id)
        used_tokens = int(stats.get("estimated_tokens", 0) or 0)
        model_key = str(model or "gpt-4o-mini")
        max_tokens = int(self._MODEL_WINDOWS.get(model_key, 128000))
        pressure = (float(used_tokens) / float(max_tokens)) if max_tokens > 0 else 0.0
        level = "normal"
        if pressure >= 0.9:
            level = "critical"
        elif pressure >= 0.75:
            level = "warning"
        return {
            "used_tokens": used_tokens,
            "max_tokens": max_tokens,
            "pressure": round(max(0.0, min(1.0, pressure)), 6),
            "level": level,
        }

    def clear_session(self, session_id: str) -> None:
        self._sessions.pop(str(session_id or ""), None)
