from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import httpx
import pytest
import yaml

from orchesis.api import create_api_app
from orchesis.context_budget import ContextBudget
from orchesis.dashboard import get_dashboard_html


def _msg(role: str, content: str) -> dict[str, str]:
    return {"role": role, "content": content}


def test_l0_triggered_at_80_percent() -> None:
    budget = ContextBudget()
    assert budget.check_level(used_tokens=80, max_tokens=100) == "L0"


def test_l1_trims_old_turns() -> None:
    budget = ContextBudget()
    messages = [_msg("system", "You are helpful")] + [
        _msg("user" if i % 2 == 0 else "assistant", f"turn-{i}") for i in range(10)
    ]
    out = budget.apply(messages=messages, level="L1", max_tokens=100)
    assert out[0]["role"] == "system"
    assert len(out) <= 5
    contents = [item.get("content") for item in out if isinstance(item, dict)]
    assert "turn-9" in contents


def test_l2_keeps_only_system_prompt() -> None:
    budget = ContextBudget()
    messages = [
        _msg("system", "You are concise"),
        _msg("user", "question"),
        _msg("assistant", "answer"),
    ]
    out = budget.apply(messages=messages, level="L2", max_tokens=100)
    assert len(out) == 1
    assert out[0]["role"] == "system"
    assert out[0]["content"] == "You are concise"


def test_normal_below_threshold() -> None:
    budget = ContextBudget()
    assert budget.check_level(used_tokens=79, max_tokens=100) == "normal"


def test_degradation_stats_tracked() -> None:
    budget = ContextBudget()
    _ = budget.check_level(used_tokens=79, max_tokens=100)  # normal
    _ = budget.check_level(used_tokens=80, max_tokens=100)  # L0
    _ = budget.check_level(used_tokens=90, max_tokens=100)  # L1
    _ = budget.check_level(used_tokens=100, max_tokens=100)  # L2
    stats = budget.get_stats()
    assert stats["events"]["normal"] == 1
    assert stats["events"]["L0"] == 1
    assert stats["events"]["L1"] == 1
    assert stats["events"]["L2"] == 1


def test_config_from_yaml() -> None:
    raw = yaml.safe_load(
        """
context_budget:
  enabled: true
  model_context_windows:
    gpt-4o: 128000
    gpt-4o-mini: 128000
    claude-3-5-sonnet: 200000
  l0_threshold: 0.80
  l1_threshold: 0.90
  l2_threshold: 1.00
"""
    )
    cfg = raw["context_budget"]
    budget = ContextBudget(cfg)
    stats = budget.get_stats()
    assert budget.enabled is True
    assert budget.model_context_windows["gpt-4o"] == 128000
    assert stats["thresholds"]["L0"] == 0.80
    assert stats["thresholds"]["L1"] == 0.90
    assert stats["thresholds"]["L2"] == 1.00


def _policy_yaml() -> str:
    return """
api:
  token: "orch_sk_test"
rules: []
"""


def _auth() -> dict[str, str]:
    return {"Authorization": "Bearer orch_sk_test"}


async def _client(app):
    transport = httpx.ASGITransport(app=app)
    return httpx.AsyncClient(transport=transport, base_url="http://test")


def _write_event(
    decisions_log: Path,
    *,
    session_id: str,
    level: str,
    tokens_saved: int,
    model: str = "gpt-4o-mini",
    agent_id: str = "agent_ctx",
) -> None:
    row = {
        "event_id": f"evt-{session_id}-{level}",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "agent_id": agent_id,
        "tool": "shell.exec",
        "params_hash": "abc123",
        "cost": 0.1,
        "decision": "ALLOW",
        "reasons": [],
        "rules_checked": [],
        "rules_triggered": [],
        "evaluation_order": [],
        "evaluation_duration_us": 120,
        "policy_version": "v1",
        "state_snapshot": {
            "session_id": session_id,
            "context_budget_level": level,
            "context_tokens_saved": tokens_saved,
            "model": model,
        },
        "decision_reason": None,
        "credentials_injected": [],
        "signature": None,
    }
    decisions_log.parent.mkdir(parents=True, exist_ok=True)
    with decisions_log.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row) + "\n")


def _make_app(tmp_path: Path):
    policy_path = tmp_path / "policy.yaml"
    decisions_log = tmp_path / "decisions.jsonl"
    policy_path.write_text(_policy_yaml(), encoding="utf-8")
    app = create_api_app(
        policy_path=str(policy_path),
        state_persist=str(tmp_path / "state.jsonl"),
        decisions_log=str(decisions_log),
        history_path=str(tmp_path / "policy_versions.jsonl"),
    )
    return app, decisions_log

@pytest.mark.asyncio
async def test_api_stats_endpoint(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, session_id="s1", level="L0", tokens_saved=1200)
    _write_event(decisions_log, session_id="s2", level="L1", tokens_saved=800)
    _write_event(decisions_log, session_id="s2", level="L2", tokens_saved=600)
    async with await _client(app) as client:
        res = await client.get("/api/v1/context-budget/stats", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["session_id"] == "global"
    assert payload["current_level"] in {"normal", "L0", "L1", "L2"}
    assert payload["degradation_events"]["L0"] >= 1
    assert payload["degradation_events"]["L1"] >= 1
    assert payload["degradation_events"]["L2"] >= 1
    assert payload["tokens_saved_by_degradation"] >= 2600
    assert payload["model"] == "gpt-4o-mini"
    assert payload["context_window"] == 128000


@pytest.mark.asyncio
async def test_api_session_endpoint(tmp_path: Path) -> None:
    app, decisions_log = _make_app(tmp_path)
    _write_event(decisions_log, session_id="sess_target", level="L2", tokens_saved=5000)
    _write_event(decisions_log, session_id="other_session", level="L0", tokens_saved=100)
    async with await _client(app) as client:
        res = await client.get("/api/v1/context-budget/sess_target", headers=_auth())
    assert res.status_code == 200
    payload = res.json()
    assert payload["session_id"] == "sess_target"
    assert payload["current_level"] == "L2"
    assert payload["degradation_events"]["L2"] == 1
    assert payload["tokens_saved_by_degradation"] == 5000


def test_dashboard_widget_renders() -> None:
    html = get_dashboard_html(demo_mode=False)
    assert "Context Budget" in html
    assert "Context window pressure" in html
    assert "cbg-level" in html
    assert "cbg-used-bar" in html
