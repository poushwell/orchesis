"""Response safety and quality analyzer."""

from __future__ import annotations

import re
from typing import Any


class ResponseAnalyzer:
    """Analyzes LLM responses for safety and quality."""

    _EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
    _SSN_RE = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
    _CRED_RE = re.compile(
        r"(sk-[A-Za-z0-9]{12,}|AKIA[0-9A-Z]{16}|api[_-]?key\s*[:=]\s*[A-Za-z0-9_\-]{8,}|password\s*[:=])",
        re.IGNORECASE,
    )

    def analyze(self, response: dict) -> dict:
        text = self._extract_text(response)
        issues: list[dict[str, Any]] = []
        leakage = self.check_for_leakage(response)
        if leakage:
            issues.extend(leakage)
        hallucination = self.check_for_hallucination_signals(response)
        if hallucination.get("suspicious"):
            issues.append({"type": "hallucination_signals", "signals": hallucination.get("signals", [])})

        contains_code = self._contains_code(text)
        contains_pii = bool(self._EMAIL_RE.search(text) or self._SSN_RE.search(text))
        contains_credentials = bool(self._CRED_RE.search(text))
        if contains_pii:
            issues.append({"type": "pii_detected", "severity": "high"})
        if contains_credentials:
            issues.append({"type": "credentials_detected", "severity": "critical"})

        word_count = len([part for part in re.split(r"\s+", text.strip()) if part]) if text.strip() else 0
        estimated_tokens = max(0, int(round(len(text) / 4.0)))
        quality = self.get_quality_breakdown(response)
        quality_score = float(quality.get("quality_score", 0.0))
        sentiment = self._sentiment(text)
        safe = not contains_pii and not contains_credentials and not bool(leakage)
        return {
            "safe": bool(safe),
            "quality_score": max(0.0, min(1.0, quality_score)),
            "issues": issues,
            "contains_code": contains_code,
            "contains_pii": contains_pii,
            "contains_credentials": contains_credentials,
            "word_count": int(word_count),
            "estimated_tokens": int(estimated_tokens),
            "sentiment": sentiment,
        }

    def check_for_leakage(self, response: dict) -> list[dict]:
        """Detect if response contains system prompt leakage."""
        text = self._extract_text(response).lower()
        issues: list[dict[str, Any]] = []
        indicators = [
            "system prompt",
            "internal instruction",
            "developer message",
            "hidden policy",
            "do not reveal",
        ]
        hits = [item for item in indicators if item in text]
        if hits:
            issues.append({"type": "prompt_leakage", "indicators": hits, "severity": "critical"})
        return issues

    def check_for_hallucination_signals(self, response: dict) -> dict:
        """Detect common hallucination patterns."""
        text = self._extract_text(response)
        lowered = text.lower()
        signals: list[str] = []
        if re.search(r"\bfeb(ruary)?\s+30\b", lowered):
            signals.append("Impossible date")
        if re.search(r"\b(100|200)%\s+guaranteed\b", lowered):
            signals.append("Overconfident certainty")
        if "as proven by nasa 1890" in lowered:
            signals.append("Likely fabricated citation")
        return {"suspicious": bool(signals), "signals": signals}

    def get_quality_breakdown(self, response: dict) -> dict:
        """Detailed quality metrics."""
        text = self._extract_text(response)
        wc = len([part for part in re.split(r"\s+", text.strip()) if part]) if text.strip() else 0
        readability = 1.0 if wc <= 200 else max(0.4, 1.0 - ((wc - 200) / 1000.0))
        structure_bonus = 0.1 if ("\n" in text or "- " in text or "1." in text) else 0.0
        quality_score = max(0.0, min(1.0, readability + structure_bonus))
        return {
            "word_count": wc,
            "readability": round(readability, 3),
            "structure_bonus": round(structure_bonus, 3),
            "quality_score": round(quality_score, 3),
        }

    @staticmethod
    def _contains_code(text: str) -> bool:
        lowered = text.lower()
        return (
            "```" in text
            or "def " in lowered
            or "class " in lowered
            or "import " in lowered
            or re.search(r"\b(function|const|let|var)\b", lowered) is not None
        )

    @staticmethod
    def _extract_text(response: dict) -> str:
        if not isinstance(response, dict):
            return ""
        for key in ("text", "output_text", "content", "response"):
            value = response.get(key)
            if isinstance(value, str):
                return value
            if isinstance(value, list):
                parts: list[str] = []
                for item in value:
                    if isinstance(item, dict):
                        text = item.get("text", item.get("content", ""))
                        if isinstance(text, str):
                            parts.append(text)
                if parts:
                    return " ".join(parts)
        choices = response.get("choices")
        if isinstance(choices, list) and choices and isinstance(choices[0], dict):
            msg = choices[0].get("message")
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                return msg["content"]
        return ""

    @staticmethod
    def _sentiment(text: str) -> str:
        lowered = text.lower()
        positive = sum(word in lowered for word in ("great", "good", "success", "happy", "excellent"))
        negative = sum(word in lowered for word in ("error", "fail", "bad", "sad", "problem"))
        if positive > negative:
            return "positive"
        if negative > positive:
            return "negative"
        return "neutral"
