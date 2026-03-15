"""Per-agent policy storage and overwatch aggregation helpers."""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from orchesis.replay import read_events_from_jsonl


def _parse_ts(value: str) -> float | None:
    if not isinstance(value, str) or not value:
        return None
    normalized = value.replace("Z", "+00:00")
    try:
        dt = datetime.fromisoformat(normalized)
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def infer_agent_status(last_seen_ts: float | None, now_ts: float | None = None) -> str:
    if last_seen_ts is None:
        return "unknown"
    now = float(now_ts if isinstance(now_ts, int | float) else time.time())
    elapsed = max(0.0, now - float(last_seen_ts))
    if elapsed < 30.0:
        return "working"
    if elapsed < 300.0:
        return "idle"
    return "offline"


class AgentPolicyStore:
    """Simple JSON-backed policy store for per-agent overrides."""

    def __init__(self, path: str | Path = ".orchesis/agent_policies.json") -> None:
        self._path = Path(path)

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self._path.exists():
            return {}
        try:
            payload = json.loads(self._path.read_text(encoding="utf-8"))
        except Exception:
            return {}
        if not isinstance(payload, dict):
            return {}
        out: dict[str, dict[str, Any]] = {}
        for key, value in payload.items():
            if isinstance(key, str) and key.strip() and isinstance(value, dict):
                out[key.strip()] = dict(value)
        return out

    def _save(self, payload: dict[str, dict[str, Any]]) -> None:
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    def get_policy(self, agent_id: str) -> dict[str, Any]:
        data = self._load()
        return dict(data.get(str(agent_id), {}))

    def set_daily_limit(self, agent_id: str, daily_limit: float) -> dict[str, Any]:
        data = self._load()
        policy = dict(data.get(str(agent_id), {}))
        policy["budget_daily"] = float(daily_limit)
        data[str(agent_id)] = policy
        self._save(data)
        return policy

    def update_policy(self, agent_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        data = self._load()
        policy = dict(data.get(str(agent_id), {}))
        for key in ("budget_daily", "block_patterns", "require_approval", "mode"):
            if key in patch:
                policy[key] = patch[key]
        data[str(agent_id)] = policy
        self._save(data)
        return policy

    def get_cost_today(self, agent_id: str, decisions_log_path: str | Path) -> float:
        target = Path(decisions_log_path)
        if not target.exists():
            return 0.0
        today = datetime.now(timezone.utc).date()
        total = 0.0
        for event in read_events_from_jsonl(target):
            if event.agent_id != agent_id:
                continue
            ts = _parse_ts(event.timestamp)
            if ts is None:
                continue
            if datetime.fromtimestamp(ts, tz=timezone.utc).date() != today:
                continue
            total += float(event.cost or 0.0)
        return round(total, 6)


def build_agent_overwatch_snapshot(
    *,
    decisions_log_path: str | Path,
    policy_store: AgentPolicyStore,
    now_ts: float | None = None,
) -> dict[str, Any]:
    now = float(now_ts if isinstance(now_ts, int | float) else time.time())
    target = Path(decisions_log_path)
    events = read_events_from_jsonl(target) if target.exists() else []
    today = datetime.fromtimestamp(now, tz=timezone.utc).date()
    ten_min_ago = now - 600.0

    by_agent: dict[str, dict[str, Any]] = {}
    for event in events:
        agent_id = str(event.agent_id or "__global__")
        item = by_agent.setdefault(
            agent_id,
            {
                "id": agent_id,
                "last_seen_ts": None,
                "last_model": None,
                "cost_today": 0.0,
                "cost_10m": 0.0,
                "requests_today": 0,
                "threats_today": 0,
                "last_threat_at": None,
                "deny_count_today": 0,
            },
        )
        ts = _parse_ts(event.timestamp)
        if ts is None:
            continue
        if item["last_seen_ts"] is None or ts > float(item["last_seen_ts"]):
            item["last_seen_ts"] = ts
        state = event.state_snapshot if isinstance(event.state_snapshot, dict) else {}
        model = state.get("model") if isinstance(state.get("model"), str) else None
        if model:
            item["last_model"] = model
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).date()
        if dt == today:
            cost = float(event.cost or 0.0)
            item["cost_today"] += cost
            item["requests_today"] += 1
            if event.decision == "DENY":
                item["threats_today"] += 1
                item["deny_count_today"] += 1
                previous_threat_ts = _parse_ts(str(item["last_threat_at"])) if item["last_threat_at"] else None
                if previous_threat_ts is None or ts > previous_threat_ts:
                    item["last_threat_at"] = event.timestamp
            if ts >= ten_min_ago:
                item["cost_10m"] += cost

    agents: list[dict[str, Any]] = []
    for item in by_agent.values():
        agent_id = str(item["id"])
        policy = policy_store.get_policy(agent_id)
        limit = policy.get("budget_daily")
        budget_limit = float(limit) if isinstance(limit, int | float) else None
        spent = round(float(item["cost_today"]), 6)
        budget_remaining = round(budget_limit - spent, 6) if isinstance(budget_limit, float) else None
        status = infer_agent_status(item.get("last_seen_ts"), now)
        deny_count = int(item.get("deny_count_today", 0))
        req_count = max(1, int(item.get("requests_today", 0)))
        deny_rate = deny_count / float(req_count)
        security_score = "A+"
        if deny_rate >= 0.4:
            security_score = "C"
        elif deny_rate >= 0.2:
            security_score = "B"
        agents.append(
            {
                "id": agent_id,
                "status": status,
                "model": item.get("last_model") or "unknown",
                "cost_today": spent,
                "cost_velocity": round(float(item.get("cost_10m", 0.0)) * 6.0, 6),
                "budget_limit": budget_limit,
                "budget_remaining": budget_remaining,
                "security_score": security_score,
                "threats_today": int(item.get("threats_today", 0)),
                "last_threat_at": item.get("last_threat_at"),
                "requests_today": int(item.get("requests_today", 0)),
                "pending_approvals": 0,
            }
        )

    agents.sort(key=lambda row: row["id"])
    summary = {
        "total_cost_today": round(sum(float(a["cost_today"]) for a in agents), 6),
        "threats_blocked": int(sum(int(a["threats_today"]) for a in agents)),
        "active_agents": int(sum(1 for a in agents if a["status"] == "working")),
        "pending_approvals": int(sum(int(a["pending_approvals"]) for a in agents)),
    }
    return {"agents": agents, "overwatch_summary": summary}
