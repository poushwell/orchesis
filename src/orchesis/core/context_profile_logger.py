"""Context profile JSONL logger for per-request metrics."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Iterable


DEFAULT_LOG_PATH = Path(".orchesis/context_profile.jsonl")


def infer_task_type(tool_calls: Iterable[str]) -> str:
    """Infer task type from tool names."""
    names = [str(name).strip().lower() for name in tool_calls if isinstance(name, str)]
    if not names:
        return "unknown"

    coding_tokens = (
        "code",
        "python",
        "js",
        "typescript",
        "compile",
        "test",
        "build",
        "git",
        "patch",
        "refactor",
    )
    research_tokens = (
        "search",
        "web",
        "browse",
        "fetch",
        "read",
        "query",
        "lookup",
        "wikipedia",
    )
    planning_tokens = (
        "plan",
        "roadmap",
        "todo",
        "task",
        "strategy",
        "design",
        "spec",
    )

    for name in names:
        if any(token in name for token in coding_tokens):
            return "coding"
    for name in names:
        if any(token in name for token in research_tokens):
            return "research"
    for name in names:
        if any(token in name for token in planning_tokens):
            return "planning"
    return "unknown"


def log_context_profile(
    *,
    session_id: str,
    agent_id: str,
    prompt_length: int,
    tool_calls: list[str] | tuple[str, ...] | None,
    model: str,
    latency_ms: float,
    retry_count: int,
    compression_ratio: float = 1.0,
    log_path: str | Path = DEFAULT_LOG_PATH,
) -> None:
    """
    Append one request profile to JSONL.

    Safe and non-blocking: all I/O errors are swallowed intentionally.
    """
    tools = [str(item) for item in (tool_calls or []) if isinstance(item, str)]
    payload = {
        "timestamp": float(time.time()),
        "session_id": str(session_id or "unknown"),
        "agent_id": str(agent_id or "unknown"),
        "prompt_length": max(0, int(prompt_length or 0)),
        "tool_calls": tools,
        "model": str(model or ""),
        "latency_ms": float(latency_ms or 0.0),
        "retry_count": max(0, int(retry_count or 0)),
        "task_type": infer_task_type(tools),
        "compression_ratio": float(compression_ratio or 1.0),
    }

    try:
        out_path = Path(log_path)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        with out_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")
    except Exception:
        # Must never block or fail the main request path.
        return
