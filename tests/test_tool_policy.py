from __future__ import annotations

import threading

from orchesis.tool_policy import ToolPolicyEngine


def _cfg():
    return {
        "default_action": "deny",
        "rules": {
            "read": "allow",
            "delete": "block",
            "execute": {"action": "approve", "max_per_session": 2},
            "web_search": {"action": "allow", "max_per_session": 3},
            "web_fetch": {"action": "allow", "blocked_domains": ["internal.corp.com", "*.local"]},
            "system_run": {"action": "warn"},
        },
    }


# Basic rules
def test_explicit_allow() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("read", "a1")
    assert d.action == "allow"


def test_explicit_block() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("delete", "a1")
    assert d.action == "block"


def test_explicit_approve() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("execute", "a1", session_id="s1")
    assert d.action == "approve"


def test_default_action_deny() -> None:
    e = ToolPolicyEngine({"default_action": "deny"})
    d = e.evaluate("unknown", "a1")
    assert d.action == "block"


def test_default_action_allow() -> None:
    e = ToolPolicyEngine({"default_action": "allow"})
    d = e.evaluate("unknown", "a1")
    assert d.action == "allow"


def test_unknown_tool_uses_default() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("unknown", "a1")
    assert d.rule_source == "default_action"


def test_legacy_allowed_backward_compat() -> None:
    e = ToolPolicyEngine({"default_action": "deny", "allowed": ["read", "write"]})
    assert e.evaluate("read", "a1").action == "allow"
    assert e.evaluate("delete", "a1").action == "block"


# Rate limiting
def test_rate_limit_under_threshold_allow() -> None:
    e = ToolPolicyEngine(_cfg())
    assert e.evaluate("web_search", "a1", session_id="s1").action == "allow"
    e.record_usage("web_search", "a1", "s1")
    assert e.evaluate("web_search", "a1", session_id="s1").action == "allow"


def test_rate_limit_over_threshold_block() -> None:
    e = ToolPolicyEngine(_cfg())
    for _ in range(3):
        e.record_usage("web_search", "a1", "s1")
    d = e.evaluate("web_search", "a1", session_id="s1")
    assert d.action == "block"
    assert d.rule_source == "rate_limit"


def test_rate_limit_per_session_independent() -> None:
    e = ToolPolicyEngine(_cfg())
    for _ in range(3):
        e.record_usage("web_search", "a1", "s1")
    assert e.evaluate("web_search", "a1", session_id="s1").action == "block"
    assert e.evaluate("web_search", "a1", session_id="s2").action == "allow"


def test_rate_limit_per_agent_independent() -> None:
    e = ToolPolicyEngine(_cfg())
    for _ in range(3):
        e.record_usage("web_search", "a1", "s1")
    assert e.evaluate("web_search", "a1", session_id="s1").action == "block"
    assert e.evaluate("web_search", "a2", session_id="s2").action == "allow"


# Domain blocking
def test_domain_block_exact_match() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("web_fetch", "a1", tool_args={"url": "https://internal.corp.com/path"}, session_id="s1")
    assert d.action == "block"
    assert d.rule_source == "domain_block"


def test_domain_block_wildcard() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("web_fetch", "a1", tool_args={"url": "https://svc.local/api"}, session_id="s1")
    assert d.action == "block"


def test_domain_allow_not_blocked() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("web_fetch", "a1", tool_args={"url": "https://example.com"}, session_id="s1")
    assert d.action == "allow"


def test_domain_block_no_url_in_args() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("web_fetch", "a1", tool_args={"q": "x"}, session_id="s1")
    assert d.action == "allow"


def test_domain_block_json_args_string() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("web_fetch", "a1", tool_args='{"url":"https://a.local/x"}', session_id="s1")
    assert d.action == "block"


# Tool stats
def test_tool_stats_counts() -> None:
    e = ToolPolicyEngine(_cfg())
    e.evaluate("read", "a1")
    e.record_usage("read", "a1", "s1")
    stats = e.get_tool_stats()
    assert stats["tools"]["read"]["usage_count"] == 1


def test_blocked_attempts_recorded() -> None:
    e = ToolPolicyEngine(_cfg())
    e.evaluate("delete", "a1", session_id="s1")
    attempts = e.get_blocked_attempts()
    assert len(attempts) == 1
    assert attempts[0]["tool_name"] == "delete"


def test_record_usage_increments() -> None:
    e = ToolPolicyEngine(_cfg())
    e.record_usage("read", "a1", "s1")
    e.record_usage("read", "a1", "s1")
    stats = e.get_tool_stats()
    assert stats["tools"]["read"]["usage_count"] == 2


def test_warn_action_supported() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("system_run", "a1")
    assert d.action == "warn"


# Integration-like
def test_evaluate_multiple_tools_mixed_decisions() -> None:
    e = ToolPolicyEngine(_cfg())
    a = e.evaluate("read", "a1")
    b = e.evaluate("delete", "a1")
    c = e.evaluate("execute", "a1", session_id="s1")
    assert {a.action, b.action, c.action} == {"allow", "block", "approve"}


def test_evaluate_no_rules_default_only() -> None:
    e = ToolPolicyEngine({"default_action": "allow"})
    d = e.evaluate("tool_x", "a1")
    assert d.action == "allow"


def test_evaluate_thread_safety() -> None:
    e = ToolPolicyEngine(_cfg())
    errs = []

    def worker(idx: int) -> None:
        try:
            for _ in range(100):
                t = "web_search" if idx % 2 == 0 else "read"
                dec = e.evaluate(t, f"a{idx}", session_id=f"s{idx}")
                if dec.action != "block":
                    e.record_usage(t, f"a{idx}", f"s{idx}")
        except Exception as exc:  # noqa: BLE001
            errs.append(exc)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(6)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errs == []


def test_rule_source_explicit_rule() -> None:
    e = ToolPolicyEngine(_cfg())
    d = e.evaluate("read", "a1")
    assert d.rule_source == "explicit_rule"


def test_rule_source_default_action() -> None:
    e = ToolPolicyEngine({"default_action": "allow"})
    d = e.evaluate("x", "a1")
    assert d.rule_source == "default_action"


def test_blocked_attempts_bounded() -> None:
    e = ToolPolicyEngine({"default_action": "deny"})
    for i in range(550):
        e.evaluate(f"x{i}", "a1", session_id="s1")
    assert len(e.get_blocked_attempts()) <= 500


def test_top_users_tracked() -> None:
    e = ToolPolicyEngine(_cfg())
    for _ in range(3):
        e.record_usage("read", "a1", "s1")
    for _ in range(2):
        e.record_usage("read", "a2", "s2")
    stats = e.get_tool_stats()
    assert stats["tools"]["read"]["top_users"]["a1"] == 3

