"""Shared runner for horror story attack scenarios."""

from __future__ import annotations

import json
import sys
from dataclasses import asdict, dataclass
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent.parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))
sys.path.insert(0, str(Path(__file__).parent.parent))

from orchesis_guard import OrchesisToolGuard  # type: ignore
from tools.mock_tools import log as tool_log


@dataclass
class StoryResult:
    story_id: str
    title: str
    category: str
    description: str
    attack_narrative: str
    without_orchesis: dict
    with_orchesis: dict
    policy_that_blocks: str
    real_world_impact: str
    mitre_atlas_id: str = ""
    owasp_asi_id: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def run_without_orchesis(attack_func) -> dict:
    """Run attack without protection, record what happens."""
    tool_log.calls.clear()
    try:
        result = attack_func()
        return {
            "vulnerable": True,
            "details": result if isinstance(result, str) else str(result),
            "tool_calls": json.loads(tool_log.to_json()),
            "summary": tool_log.summary(),
        }
    except Exception as error:  # pragma: no cover - defensive path
        return {
            "vulnerable": False,
            "details": f"Error: {error}",
            "tool_calls": [],
            "summary": {},
        }


def run_with_orchesis(attack_func, policy_path: str | None = None) -> dict:
    """Run attack with Orchesis protection, record what gets blocked."""
    tool_log.calls.clear()
    if policy_path is None:
        policy_path = str(Path(__file__).parent.parent / "policies" / "protective_policy.yaml")

    guard = OrchesisToolGuard(Path(policy_path))
    original_tools: dict[str, object] = {}
    import tools.mock_tools as mt

    arg_map = {
        "shell_execute": ["command"],
        "read_file": ["path"],
        "write_file": ["path", "content"],
        "web_search": ["query"],
        "send_email": ["to", "subject", "body"],
        "run_command": ["command"],
        "send_payment": ["amount", "to", "currency"],
        "buy_crypto": ["amount", "token"],
        "check_balance": [],
        "format_code": ["code"],
        "search_docs": ["query"],
    }
    tool_names = list(arg_map.keys())
    for tool_name in tool_names:
        if not hasattr(mt, tool_name):
            continue
        original_func = getattr(mt, tool_name)
        original_tools[tool_name] = original_func

        def make_guarded(name: str, func):
            def guarded(*args, **kwargs):
                params: dict[str, object] = {}
                for index, arg in enumerate(args):
                    names = arg_map.get(name, [])
                    if index < len(names):
                        params[names[index]] = arg
                params.update(kwargs)
                allowed, reason = guard.evaluate(name, params)
                if not allowed:
                    tool_log.record(name, params, f"BLOCKED: {reason}", blocked=True)
                    return f"[BLOCKED BY ORCHESIS] {reason}"
                return func(*args, **kwargs)

            return guarded

        setattr(mt, tool_name, make_guarded(tool_name, original_func))

    try:
        result = attack_func()
        summary = tool_log.summary()
        blocked = summary.get("blocked", 0) > 0
        return {
            "blocked": blocked,
            "details": result if isinstance(result, str) else str(result),
            "tool_calls": json.loads(tool_log.to_json()),
            "summary": summary,
        }
    except Exception as error:  # pragma: no cover - defensive path
        return {
            "blocked": True,
            "details": f"Blocked/Error: {error}",
            "tool_calls": [],
            "summary": {},
        }
    finally:
        for name, func in original_tools.items():
            setattr(mt, name, func)

