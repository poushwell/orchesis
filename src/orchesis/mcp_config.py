"""Configuration helpers for the MCP stdio interceptor."""

from __future__ import annotations

import os
import shlex
from dataclasses import dataclass, field
from pathlib import Path


def _default_policy_path() -> str:
    project_root = Path(__file__).resolve().parents[2]
    return str(project_root / "examples" / "policy.yaml")


def _parse_downstream_args(raw: str | None) -> list[str]:
    if not raw:
        return []
    return shlex.split(raw)


@dataclass(frozen=True)
class McpProxySettings:
    """Runtime settings for Orchesis MCP proxy."""

    policy_path: str = field(default_factory=_default_policy_path)
    downstream_command: str = "python"
    downstream_args: list[str] = field(default_factory=list)
    default_tool_cost: float = 0.0
    downstream_timeout_seconds: float | None = None
    control_url: str | None = None
    api_token: str | None = None
    node_id: str | None = None
    sync_poll_interval_seconds: int = 30

    @classmethod
    def from_env(cls) -> "McpProxySettings":
        """Create settings from environment variables."""
        return cls(
            policy_path=os.getenv("POLICY_PATH", _default_policy_path()),
            downstream_command=os.getenv("DOWNSTREAM_COMMAND", "python"),
            downstream_args=_parse_downstream_args(os.getenv("DOWNSTREAM_ARGS")),
            default_tool_cost=float(os.getenv("DEFAULT_TOOL_COST", "0")),
            downstream_timeout_seconds=(
                float(os.getenv("DOWNSTREAM_TIMEOUT_SECONDS"))
                if os.getenv("DOWNSTREAM_TIMEOUT_SECONDS")
                else None
            ),
            control_url=os.getenv("CONTROL_URL"),
            api_token=os.getenv("API_TOKEN"),
            node_id=os.getenv("NODE_ID"),
            sync_poll_interval_seconds=int(os.getenv("SYNC_POLL_INTERVAL_SECONDS", "30")),
        )
