"""Tool call pattern analysis for abuse detection."""

from __future__ import annotations

from typing import Any


class ToolCallAnalyzer:
    """Analyzes tool call patterns for abuse detection."""

    HIGH_RISK_TOOLS = {
        "bash": "critical",
        "shell": "critical",
        "execute_code": "high",
        "write_file": "high",
        "delete_file": "critical",
        "web_search": "medium",
        "read_file": "low",
        "web_fetch": "medium",
    }

    _RANK = {"low": 1, "medium": 2, "high": 3, "critical": 4}
    _CHAINS = [
        ("web_search", "read_file", "bash"),
        ("web_fetch", "read_file", "execute_code"),
        ("read_file", "write_file", "bash"),
        ("read_file", "delete_file"),
    ]

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
    def _tool_name(row: dict[str, Any]) -> str:
        candidate = row.get("tool_name", row.get("tool", row.get("name", "")))
        return str(candidate or "").strip().lower()

    def get_tool_risk(self, tool_name: str) -> str:
        """Returns risk level for tool."""
        key = str(tool_name or "").strip().lower()
        return self.HIGH_RISK_TOOLS.get(key, "low")

    def detect_chaining(self, tool_calls: list[dict]) -> list[dict]:
        """Detect dangerous tool call chains."""
        names = [self._tool_name(self._as_dict(item)) for item in tool_calls]
        names = [name for name in names if name]
        hits: list[dict[str, Any]] = []
        if not names:
            return hits
        for chain in self._CHAINS:
            chain_len = len(chain)
            if chain_len == 0 or len(names) < chain_len:
                continue
            for start in range(0, len(names) - chain_len + 1):
                segment = tuple(names[start : start + chain_len])
                if segment == chain:
                    hits.append(
                        {
                            "type": "dangerous_chain",
                            "sequence": list(chain),
                            "start_index": start,
                            "severity": "critical" if "bash" in chain or "delete_file" in chain else "high",
                        }
                    )
        return hits

    def analyze(self, tool_calls: list[dict]) -> dict:
        rows = [self._as_dict(item) for item in tool_calls]
        names = [self._tool_name(row) for row in rows]
        names = [name for name in names if name]

        tool_frequency: dict[str, int] = {}
        for name in names:
            tool_frequency[name] = int(tool_frequency.get(name, 0)) + 1

        unique_tools = sorted(tool_frequency.keys())
        high_risk_tools_used = sorted(
            {
                name
                for name in unique_tools
                if self.get_tool_risk(name) in {"high", "critical"}
            }
        )
        suspicious_patterns = self.detect_chaining(rows)
        if any(item.get("severity") == "critical" for item in suspicious_patterns):
            risk_level = "critical"
        else:
            top_rank = 1
            for name in unique_tools:
                top_rank = max(top_rank, self._RANK.get(self.get_tool_risk(name), 1))
            if suspicious_patterns and top_rank < self._RANK["high"]:
                top_rank = self._RANK["high"]
            reverse = {v: k for k, v in self._RANK.items()}
            risk_level = reverse.get(top_rank, "low")

        return {
            "total_calls": len(names),
            "unique_tools": unique_tools,
            "risk_level": risk_level,
            "suspicious_patterns": suspicious_patterns,
            "tool_frequency": tool_frequency,
            "high_risk_tools_used": high_risk_tools_used,
            "chaining_detected": bool(suspicious_patterns),
        }

    def get_session_tool_stats(self, session_id: str, decisions_log: list) -> dict:
        """Tool usage stats for entire session."""
        target = str(session_id or "")
        calls: list[dict[str, Any]] = []
        for item in decisions_log:
            row = self._as_dict(item)
            snapshot = row.get("state_snapshot")
            if not isinstance(snapshot, dict):
                snapshot = {}
            row_session = str(snapshot.get("session_id", row.get("session_id", "")) or "")
            if row_session != target:
                continue

            tool_name = self._tool_name(row)
            if tool_name:
                calls.append({"tool": tool_name})

            embedded = snapshot.get("tool_calls")
            if isinstance(embedded, list):
                for tool_call in embedded:
                    tool_row = self._as_dict(tool_call)
                    embedded_name = self._tool_name(tool_row)
                    if embedded_name:
                        calls.append({"tool": embedded_name})

        analysis = self.analyze(calls)
        return {
            "session_id": target,
            "tool_stats": analysis,
        }
