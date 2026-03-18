"""Active context poisoning removal for non-user messages."""

from __future__ import annotations

import threading
from collections import defaultdict
from typing import Any


class ApoptosisEngine:
    """Active removal of harmful context elements.

    Removes: contradictions, outdated authoritative facts, causal poison.
    Never modifies user content - only assistant/system context.
    """

    POISON_TYPES = {
        "contradiction": "Contradicting statements in context",
        "outdated_fact": "Superseded authoritative information",
        "causal_poison": "False causal relationships injected",
        "role_confusion": "Mixed agent/user role assignments",
        "instruction_override": "Later instructions negating safety rules",
    }

    SAFETY_RULES = {
        "never_modify_user_content": True,
        "never_remove_last_n_turns": 3,
        "max_removals_per_session": 5,
        "require_confidence": 0.8,
    }

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", False))
        self.confidence_threshold = float(
            cfg.get("confidence", self.SAFETY_RULES["require_confidence"])
        )
        self._lock = threading.Lock()
        self._removal_log: list[dict[str, Any]] = []
        self._total_scans = 0
        self._total_removals = 0
        self._safety_blocks = 0
        self._by_type: dict[str, int] = defaultdict(int)

    @staticmethod
    def _content(msg: dict[str, Any]) -> str:
        content = msg.get("content", "")
        return content if isinstance(content, str) else ""

    def detect_contradiction(self, messages: list[dict]) -> list[dict]:
        """Find contradicting message pairs."""
        facts: dict[str, tuple[bool, int, str]] = {}
        findings: list[dict[str, Any]] = []
        for idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "")).lower()
            if role not in {"assistant", "system"}:
                continue
            text = self._content(msg).strip().lower()
            if " is " not in text:
                continue
            subject, rest = text.split(" is ", 1)
            subject = " ".join(subject.split())[:120]
            negative = rest.startswith("not ")
            if subject in facts:
                prev_negative, prev_idx, prev_text = facts[subject]
                if prev_negative != negative:
                    findings.append(
                        {
                            "index": idx,
                            "type": "contradiction",
                            "confidence": 0.9,
                            "description": f"Contradiction with message {prev_idx}: '{prev_text[:80]}'",
                            "safe_to_remove": True,
                        }
                    )
            facts[subject] = (negative, idx, text)
        return findings

    def detect_instruction_override(self, messages: list[dict]) -> list[dict]:
        """Find instructions that override safety rules."""
        findings: list[dict[str, Any]] = []
        for idx, msg in enumerate(messages):
            if not isinstance(msg, dict):
                continue
            role = str(msg.get("role", "")).lower()
            if role not in {"assistant", "system"}:
                continue
            text = self._content(msg).lower()
            if "ignore previous" in text and (
                "safety" in text or "guardrail" in text or "policy" in text
            ):
                findings.append(
                    {
                        "index": idx,
                        "type": "instruction_override",
                        "confidence": 0.95,
                        "description": "Instruction override of safety context detected",
                        "safe_to_remove": True,
                    }
                )
        return findings

    def scan(self, messages: list[dict]) -> list[dict]:
        """Scan for poison elements. Returns findings."""
        rows = messages if isinstance(messages, list) else []
        findings: list[dict[str, Any]] = []
        findings.extend(self.detect_contradiction(rows))
        findings.extend(self.detect_instruction_override(rows))
        with self._lock:
            self._total_scans += 1
            for item in findings:
                poison_type = str(item.get("type", "unknown"))
                self._by_type[poison_type] += 1
        return findings

    def remove(self, messages: list[dict], findings: list[dict]) -> dict:
        """Remove confirmed poison. Returns cleaned messages + report."""
        rows = [dict(item) for item in messages if isinstance(item, dict)]
        if not rows:
            return {
                "messages": [],
                "removed_count": 0,
                "removal_log": [],
                "safety_checks_passed": True,
            }
        max_removals = int(self.SAFETY_RULES["max_removals_per_session"])
        protected_start = max(0, len(rows) - int(self.SAFETY_RULES["never_remove_last_n_turns"]))

        indices: list[int] = []
        safety_checks_passed = True
        for raw in findings if isinstance(findings, list) else []:
            if not isinstance(raw, dict):
                continue
            idx = raw.get("index")
            if not isinstance(idx, int) or idx < 0 or idx >= len(rows):
                continue
            role = str(rows[idx].get("role", "")).lower()
            if role == "user":
                safety_checks_passed = False
                with self._lock:
                    self._safety_blocks += 1
                continue
            confidence = float(raw.get("confidence", 0.0) or 0.0)
            if confidence < self.confidence_threshold:
                continue
            if idx >= protected_start:
                safety_checks_passed = False
                with self._lock:
                    self._safety_blocks += 1
                continue
            if not bool(raw.get("safe_to_remove", False)):
                continue
            indices.append(idx)

        unique_sorted = sorted(set(indices))
        unique_sorted = unique_sorted[:max_removals]
        removal_log: list[dict[str, Any]] = []
        cleaned: list[dict[str, Any]] = []
        removed = 0
        index_set = set(unique_sorted)
        for idx, msg in enumerate(rows):
            if idx in index_set:
                removed += 1
                removal_log.append(
                    {
                        "index": idx,
                        "role": str(msg.get("role", "")),
                        "content_preview": self._content(msg)[:120],
                    }
                )
                continue
            cleaned.append(msg)

        with self._lock:
            self._total_removals += removed
            self._removal_log.extend(removal_log)
            if len(self._removal_log) > 5000:
                del self._removal_log[:-5000]

        return {
            "messages": cleaned,
            "removed_count": removed,
            "removal_log": removal_log,
            "safety_checks_passed": bool(safety_checks_passed),
        }

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "total_scans": int(self._total_scans),
                "total_removals": int(self._total_removals),
                "by_type": dict(self._by_type),
                "safety_blocks": int(self._safety_blocks),
            }
