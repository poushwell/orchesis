"""Pre-request budget check.

Historically lived at `src/orchesis/pipeline.py` as a top-level helper. Moved
into the pipeline package alongside the plugin architecture so the public
import path `from orchesis.pipeline import check_budget` stays intact.
"""

from __future__ import annotations

from typing import Any

from orchesis.agent_store import AgentPolicyStore


def check_budget(
    agent_id: str,
    *,
    policy_store: AgentPolicyStore,
    decisions_log_path: str,
) -> tuple[bool, dict[str, Any]]:
    """Block the request when today's spend already meets the daily limit.

    Returns (allowed, info). When allowed is False, info contains a structured
    block reason suitable for the response payload.
    """
    policy = policy_store.get_policy(agent_id)
    limit = policy.get("budget_daily")
    if not isinstance(limit, int | float):
        return True, {}
    spent = policy_store.get_cost_today(agent_id, decisions_log_path)
    safe_limit = float(limit)
    if spent >= safe_limit:
        return (
            False,
            {
                "blocked": True,
                "reason": "budget_exceeded",
                "spent": spent,
                "limit": safe_limit,
                "message": f"Daily budget ${safe_limit:.2f} reached (spent: ${spent:.2f})",
            },
        )
    return True, {}
