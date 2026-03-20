"""Orchestration Patterns - common agent design patterns with Orchesis."""

from __future__ import annotations

PATTERNS = {
    "sequential_chain": {
        "name": "Sequential Chain",
        "description": "Agents run in sequence, each consuming previous output",
        "orchesis_value": "Context compression between steps prevents token explosion",
        "recommended_policy": "cost_optimized",
        "risks": ["context_collapse", "budget_exhaustion"],
    },
    "parallel_fan_out": {
        "name": "Parallel Fan-Out",
        "description": "One task split across N agents simultaneously",
        "orchesis_value": "Fleet coordination via Quorum Sensing (N*=16)",
        "recommended_policy": "openclaw_secure",
        "risks": ["byzantine_agents", "context_inconsistency"],
    },
    "hierarchical": {
        "name": "Hierarchical / Manager-Worker",
        "description": "Manager agent delegates to specialized workers",
        "orchesis_value": "Raft Context Protocol ensures consistent beliefs",
        "recommended_policy": "openclaw_secure",
        "risks": ["manager_compromise", "privilege_escalation"],
    },
    "reflection_loop": {
        "name": "Reflection Loop",
        "description": "Agent reviews and improves its own output iteratively",
        "orchesis_value": "Loop detection prevents infinite reflection",
        "recommended_policy": "research_permissive",
        "risks": ["loop_detected", "context_collapse"],
    },
    "tool_use_heavy": {
        "name": "Tool-Use Heavy",
        "description": "Agent makes many tool calls per request",
        "orchesis_value": "Tool Call Analyzer detects dangerous chains",
        "recommended_policy": "openclaw_secure",
        "risks": ["tool_abuse", "command_injection"],
    },
}


class OrchestrationPatternAdvisor:
    def list_patterns(self) -> list[dict]:
        return [{"id": k, **{f: v[f] for f in ["name", "description"]}} for k, v in PATTERNS.items()]

    def get_pattern(self, pattern_id: str) -> dict | None:
        return PATTERNS.get(pattern_id)

    def recommend_policy(self, pattern_id: str) -> str | None:
        pattern = PATTERNS.get(pattern_id)
        return pattern["recommended_policy"] if pattern else None

    def get_risks(self, pattern_id: str) -> list[str]:
        pattern = PATTERNS.get(pattern_id)
        return pattern["risks"] if pattern else []

    def analyze_fleet(self, agent_count: int, pattern_id: str) -> dict:
        pattern = PATTERNS.get(pattern_id, {})
        return {
            "pattern": pattern_id,
            "agent_count": agent_count,
            "quorum_ready": int(agent_count) >= 16,
            "byzantine_safe": int(agent_count) >= 5,
            "recommended_policy": pattern.get("recommended_policy", "openclaw_secure"),
            "risks": pattern.get("risks", []),
            "orchesis_features_needed": self._needed_features(pattern_id, int(agent_count)),
        }

    def _needed_features(self, pattern_id: str, n: int) -> list[str]:
        base = ["loop_detection", "semantic_cache"]
        if n >= 16:
            base.append("quorum_sensing")
        if n >= 5:
            base.append("byzantine_detector")
        if pattern_id in ("reflection_loop", "sequential_chain"):
            base.append("uci_compression")
        return base

