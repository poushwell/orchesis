"""Shared request-pipeline helpers."""

from __future__ import annotations

from typing import Any

from orchesis.agent_store import AgentPolicyStore


def check_budget(
    agent_id: str,
    *,
    policy_store: AgentPolicyStore,
    decisions_log_path: str,
) -> tuple[bool, dict[str, Any]]:
    """
    Pre-request check.
    Blocks if spent today is already at/above agent budget.
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
