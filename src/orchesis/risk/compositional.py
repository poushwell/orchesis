"""Compositional Risk Tracker — detects dangerous tool combinations."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from orchesis.utils.log import get_logger

logger = get_logger(__name__)


@dataclass
class ToolCall:
    tool_name: str
    args: dict[str, Any] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)
    agent_id: str = ""


@dataclass
class DangerousChain:
    """A known dangerous tool combination."""

    chain_id: str
    pattern: list[str]
    category: str
    severity: str
    description: str


@dataclass
class CompositionRisk:
    """Result of compositional risk assessment."""

    score: float = 0.0
    detected_chains: list[dict[str, Any]] = field(default_factory=list)
    tool_count: int = 0
    unique_tools: int = 0
    window_seconds: float = 0.0
    recommendation: str = ""


KNOWN_DANGEROUS_CHAINS = [
    DangerousChain(
        chain_id="DC-001",
        pattern=["read_file", "send_email"],
        category="data_exfiltration",
        severity="HIGH",
        description="File read followed by email send - potential data exfiltration.",
    ),
    DangerousChain(
        chain_id="DC-002",
        pattern=["read_file", "write_file", "execute"],
        category="code_injection",
        severity="HIGH",
        description="Read-modify-execute chain - potential code injection.",
    ),
    DangerousChain(
        chain_id="DC-003",
        pattern=["list_directory", "read_file", "send_email"],
        category="reconnaissance_exfil",
        severity="HIGH",
        description="Directory listing to file read to email - reconnaissance plus exfiltration.",
    ),
    DangerousChain(
        chain_id="DC-004",
        pattern=["execute", "execute"],
        category="command_chaining",
        severity="MEDIUM",
        description="Multiple sequential executions - potential command chaining.",
    ),
    DangerousChain(
        chain_id="DC-005",
        pattern=["search", "read_file", "write_file"],
        category="data_tampering",
        severity="MEDIUM",
        description="Search to read to write - potential data tampering.",
    ),
    DangerousChain(
        chain_id="DC-006",
        pattern=["get_credentials", "execute"],
        category="privilege_escalation",
        severity="HIGH",
        description="Credential access followed by execution - privilege escalation.",
    ),
    DangerousChain(
        chain_id="DC-007",
        pattern=["read_file", "create_file", "upload"],
        category="data_staging",
        severity="MEDIUM",
        description="Read to create to upload - data staging for exfiltration.",
    ),
    DangerousChain(
        chain_id="DC-008",
        pattern=["delete_file", "delete_file", "delete_file"],
        category="destructive",
        severity="HIGH",
        description="Multiple file deletions - potential destructive attack.",
    ),
]


class CompositionalRiskTracker:
    """Track tool call sequences and detect compositional risks."""

    def __init__(
        self,
        window_seconds: float = 300.0,
        chains: list[DangerousChain] | None = None,
        score_threshold: float = 0.7,
    ):
        self.window_seconds = float(window_seconds)
        self.chains = list(chains) if chains is not None else list(KNOWN_DANGEROUS_CHAINS)
        self.score_threshold = float(score_threshold)
        self._history: list[ToolCall] = []

    def _trim_history(self) -> None:
        cutoff = time.time() - self.window_seconds
        self._history = [tc for tc in self._history if tc.timestamp >= cutoff]

    def record_tool_call(
        self,
        tool_name: str,
        args: dict[str, Any] | None = None,
        agent_id: str = "",
    ) -> None:
        """Record a tool call for sequence analysis."""
        self._history.append(
            ToolCall(
                tool_name=str(tool_name or ""),
                args=dict(args) if isinstance(args, dict) else {},
                timestamp=time.time(),
                agent_id=str(agent_id or ""),
            )
        )
        self._trim_history()

    def _get_tool_sequence(self) -> list[str]:
        """Get current tool name sequence within window."""
        return [tc.tool_name for tc in self._history]

    def _check_chain(self, sequence: list[str], pattern: list[str]) -> list[int]:
        """Return start indices where a pattern matches as a contiguous subsequence."""
        matches: list[int] = []
        pat_len = len(pattern)
        for idx in range(len(sequence) - pat_len + 1):
            if sequence[idx : idx + pat_len] == pattern:
                matches.append(idx)
        return matches

    def check_compositional_risk(self) -> CompositionRisk:
        """Analyze current tool sequence for compositional risks."""
        self._trim_history()
        sequence = self._get_tool_sequence()
        if not sequence:
            return CompositionRisk(score=0.0, tool_count=0, unique_tools=0, window_seconds=self.window_seconds)

        detected: list[dict[str, Any]] = []
        max_severity_score = 0.0
        severity_scores = {"HIGH": 0.9, "MEDIUM": 0.6, "LOW": 0.3}

        for chain in self.chains:
            matches = self._check_chain(sequence, chain.pattern)
            if not matches:
                continue
            for idx in matches:
                detected.append(
                    {
                        "chain_id": chain.chain_id,
                        "pattern": "->".join(chain.pattern),
                        "category": chain.category,
                        "severity": chain.severity,
                        "position": idx,
                        "description": chain.description,
                    }
                )
                max_severity_score = max(max_severity_score, severity_scores.get(chain.severity, 0.3))

        unique_tools = len(set(sequence))
        diversity_bonus = min(0.1, unique_tools * 0.02) if detected else 0.0
        score = min(1.0, max_severity_score + diversity_bonus)

        recommendation = ""
        if score >= self.score_threshold:
            recommendation = (
                f"BLOCK: Detected {len(detected)} dangerous tool chain(s). "
                f"Risk score {score:.2f} exceeds threshold {self.score_threshold:.2f}."
            )
        elif detected:
            recommendation = (
                f"WARN: Detected {len(detected)} tool chain(s) with moderate risk. "
                "Monitor closely."
            )

        risk = CompositionRisk(
            score=score,
            detected_chains=detected,
            tool_count=len(sequence),
            unique_tools=unique_tools,
            window_seconds=self.window_seconds,
            recommendation=recommendation,
        )

        if detected:
            logger.warning(
                "Compositional risk detected",
                extra={
                    "component": "compositional_risk",
                    "agent_id": self._history[-1].agent_id if self._history else "",
                    "chain_count": len(detected),
                },
            )

        return risk

    def clear(self) -> None:
        """Clear tool call history."""
        self._history.clear()

    def get_history(self) -> list[ToolCall]:
        return list(self._history)


def check_compositional_risk(
    tool_calls: list[dict[str, Any]],
    window_seconds: float = 300.0,
) -> CompositionRisk:
    """Standalone function for checking compositional risk."""
    tracker = CompositionalRiskTracker(window_seconds=window_seconds)
    for tc in tool_calls:
        if not isinstance(tc, dict):
            continue
        tracker._history.append(
            ToolCall(
                tool_name=str(tc.get("tool", tc.get("tool_name", "")) or ""),
                args=dict(tc.get("args", {})) if isinstance(tc.get("args"), dict) else {},
                timestamp=float(tc.get("timestamp", time.time()) or time.time()),
                agent_id=str(tc.get("agent_id", "") or ""),
            )
        )
    return tracker.check_compositional_risk()
