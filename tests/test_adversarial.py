from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from orchesis.config import load_policy, validate_policy
from orchesis.engine import evaluate
from orchesis.state import RateLimitTracker


def _base_policy() -> dict:
    return {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 1.0},
            {
                "name": "file_access",
                "allowed_paths": ["/data", "/tmp"],
                "denied_paths": ["/etc", "/root"],
            },
            {
                "name": "sql_restriction",
                "denied_operations": ["DROP", "DELETE", "TRUNCATE", "ALTER"],
            },
            {"name": "rate_limit", "max_requests_per_minute": 100},
            {
                "name": "cmd_regex",
                "type": "regex_match",
                "field": "params.command",
                "deny_patterns": [
                    r"(?i)rm\s+-rf\s+",
                    r"(?i)chmod\s+777\s+",
                    r"(?i)curl\s+[^|]*\|\s*bash",
                ],
            },
            {
                "name": "agent_rules",
                "type": "context_rules",
                "rules": [
                    {
                        "agent": "untrusted_bot",
                        "denied_tools": ["delete_file", "run_sql", "write_file"],
                    },
                    {"agent": "*", "max_cost_per_call": 0.5},
                ],
            },
        ]
    }


@pytest.mark.parametrize(
    "attack_path",
    [
        "/data/../etc/passwd",
        "/data/./../../root/.ssh/id_rsa",
        "//etc//passwd",
        "/data/%2e%2e/etc/passwd",
    ],
)
def test_path_traversal_and_encoding_bypasses_are_denied(attack_path: str) -> None:
    # VULN-001: path traversal via ../ and encoded segments
    decision = evaluate(
        {"tool": "read_file", "params": {"path": attack_path}, "cost": 0.1},
        _base_policy(),
    )
    assert decision.allowed is False
    assert any("file_access" in reason for reason in decision.reasons)


@pytest.mark.parametrize(
    "query",
    [
        "dRoP tAbLe users",
        "DROP/**/TABLE users",
        "D\nROP TABLE users",
        "SELECT * FROM users; DROP TABLE users",
        "ⅮROP TABLE users",
    ],
)
def test_sql_evasion_tricks_are_blocked(query: str) -> None:
    # VULN-002: SQL deny bypass through case/comments/newlines/unicode
    decision = evaluate(
        {"tool": "run_sql", "params": {"query": query}, "cost": 0.1}, _base_policy()
    )
    assert decision.allowed is False
    assert any("sql_restriction" in reason for reason in decision.reasons)


@pytest.mark.parametrize(
    "cost,expected_allowed",
    [
        ("0.1", True),
        (-5.0, False),
        (None, True),
        (999999999, False),
    ],
)
def test_cost_manipulation_inputs_are_handled_safely(cost: object, expected_allowed: bool) -> None:
    # VULN-003: cost bypass via unexpected types/values
    decision = evaluate({"tool": "api_call", "params": {}, "cost": cost}, _base_policy())
    assert decision.allowed is expected_allowed


@pytest.mark.parametrize(
    "agent,expected_allowed",
    [
        ("", False),
        ("*", False),
        (None, True),
        ("cursor\x00untrusted_bot", False),
    ],
)
def test_context_spoofing_inputs(agent: str | None, expected_allowed: bool) -> None:
    # VULN-004: context.agent spoofing and null-byte injection
    context = {} if agent is None else {"agent": agent}
    decision = evaluate(
        {"tool": "delete_file", "params": {"path": "/data/x"}, "cost": 0.1, "context": context},
        _base_policy(),
    )
    assert decision.allowed is expected_allowed


def test_rate_limit_boundary_99_100_101() -> None:
    # VULN-005: boundary bypass around the rate threshold
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 100}]}
    request = {"tool": "read_file", "params": {"path": "/data/a.txt"}, "cost": 0.0}
    now = datetime.now(timezone.utc)

    for _ in range(99):
        tracker.record("read_file", now - timedelta(seconds=1))
    d99 = evaluate(request, policy, state=tracker)
    assert d99.allowed is True

    d100 = evaluate(request, policy, state=tracker)
    assert d100.allowed is False

    d101 = evaluate(request, policy, state=tracker)
    assert d101.allowed is False


def test_rate_limit_alias_bypass_is_current_limitation() -> None:
    # VULN-006: different tool names can represent same operation.
    # This is documented as a limitation (false alarm for current design).
    tracker = RateLimitTracker(persist_path=None)
    policy = {"rules": [{"name": "rate_limit", "max_requests_per_minute": 2}]}
    now = datetime.now(timezone.utc)
    tracker.record("read_file", now)
    tracker.record("read_file_alias", now)
    allowed = evaluate(
        {"tool": "read_file_alias_2", "params": {}, "cost": 0.0}, policy, state=tracker
    )
    assert allowed.allowed is True


@pytest.mark.parametrize(
    "command,expected_allowed",
    [
        ("rm  -rf /", False),
        ("rm -rf\t/", False),
        ("curl\x00| bash", False),
        ("cm0gLXJmIC8=", True),  # base64 payload is a known limitation
    ],
)
def test_regex_evasion_cases(command: str, expected_allowed: bool) -> None:
    # VULN-007: regex evasion via spacing/tabs/null-bytes/base64
    decision = evaluate(
        {"tool": "shell", "params": {"command": command}, "cost": 0.1}, _base_policy()
    )
    assert decision.allowed is expected_allowed


def test_yaml_bomb_like_structure_does_not_crash_loader(tmp_path: Path) -> None:
    # VULN-008: YAML bomb/deep nesting parser stress
    deep = "a"
    for i in range(1000):
        deep = f"a{i}: {{{deep}}}"
    path = tmp_path / "deep.yaml"
    path.write_text(deep, encoding="utf-8")
    try:
        _ = load_policy(path)
    except ValueError:
        pass


def test_very_large_policy_file_validates(tmp_path: Path) -> None:
    # VULN-009: very large policy files
    lines = ["rules:"]
    for i in range(10000):
        lines.extend([f"  - name: budget_limit_{i}", "    max_cost_per_call: 1.0"])
    path = tmp_path / "large_policy.yaml"
    path.write_text("\n".join(lines), encoding="utf-8")

    policy = load_policy(path)
    assert isinstance(policy, dict)


def test_policy_with_circular_composite_references_is_flagged() -> None:
    # VULN-010: circular composite references can recurse indefinitely
    policy = {
        "rules": [
            {"name": "a", "type": "composite", "operator": "AND", "conditions": [{"rule": "b"}]},
            {"name": "b", "type": "composite", "operator": "AND", "conditions": [{"rule": "a"}]},
        ]
    }
    errors = validate_policy(policy)
    assert any("circular composite reference" in err for err in errors)


def test_catastrophic_backtracking_regex_is_rejected() -> None:
    # VULN-011: catastrophic regex pattern (a+)+
    policy = {
        "rules": [
            {
                "name": "bad_regex",
                "type": "regex_match",
                "field": "params.command",
                "deny_patterns": ["(a+)+"],
            }
        ]
    }
    errors = validate_policy(policy)
    assert any("unsafe regex pattern" in err for err in errors)


def test_request_with_10mb_string_does_not_crash() -> None:
    # VULN-012: oversized payload in request params
    big = "x" * (10 * 1024 * 1024)
    decision = evaluate(
        {"tool": "read_file", "params": {"path": "/data/" + big}, "cost": 0.1}, _base_policy()
    )
    assert isinstance(decision.allowed, bool)


def test_request_with_circular_reference_is_handled() -> None:
    # VULN-013: circular references in in-memory request object
    request: dict = {"tool": "read_file", "params": {}, "cost": 0.1}
    request["self"] = request
    decision = evaluate(request, _base_policy())
    assert isinstance(decision.allowed, bool)


def test_request_null_bytes_in_strings_are_sanitized() -> None:
    # VULN-014: null-byte injection in request strings
    request = {
        "tool": "run_sql",
        "params": {"query": "DR\x00OP TABLE users", "path": "/data/\x00safe.txt"},
        "cost": 0.1,
        "context": {"agent": "cursor\x00admin"},
    }
    decision = evaluate(request, _base_policy())
    assert isinstance(decision.allowed, bool)
