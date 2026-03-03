from __future__ import annotations

from pathlib import Path

import pytest

from orchesis.config import PolicyError, load_policy
from orchesis.engine import evaluate


def _decision(policy: dict, tool: str, params: dict | None = None):
    return evaluate({"tool": tool, "params": params or {}}, policy)


def test_default_action_deny_blocks_unlisted_tool() -> None:
    policy = {"default_action": "deny", "capabilities": [], "rules": []}
    decision = _decision(policy, "read_file", {"path": "/workspace/a.txt"})
    assert decision.allowed is False
    assert any("default_action=deny" in reason for reason in decision.reasons)


def test_default_action_deny_allows_matching_capability() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/workspace/*"]}}],
        "rules": [],
    }
    decision = _decision(policy, "read_file", {"path": "/workspace/a.txt"})
    assert decision.allowed is True


def test_path_glob_matching_workspace_csv() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/workspace/*.csv"]}}],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/workspace/report.csv"}).allowed is True
    assert _decision(policy, "read_file", {"path": "/workspace/report.json"}).allowed is False


def test_domain_glob_matching() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "web_search", "allow": {"domains": ["*.github.com"]}}],
        "rules": [],
    }
    assert _decision(policy, "web_search", {"url": "https://api.github.com/repos/x"}).allowed is True
    assert _decision(policy, "web_search", {"url": "https://example.com"}).allowed is False


def test_command_allowlist_exact_match() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "shell_execute", "allow": {"commands": ["git status", "git log", "ls"]}}],
        "rules": [],
    }
    assert _decision(policy, "shell_execute", {"command": "git status"}).allowed is True
    assert _decision(policy, "shell_execute", {"command": "git push"}).allowed is False


def test_wildcard_tool_applies_to_all_tools() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "*", "allow": {"paths": ["/workspace/*"]}}],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/workspace/a.txt"}).allowed is True
    assert _decision(policy, "write_file", {"path": "/workspace/b.txt"}).allowed is True


def test_capability_deny_blocks_specific_path() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [
            {"tool": "read_file", "allow": {"paths": ["/workspace/*"]}},
            {"tool": "*", "deny": {"paths": ["/workspace/secret/*"]}},
        ],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/workspace/public/a.txt"}).allowed is True
    denied = _decision(policy, "read_file", {"path": "/workspace/secret/token.txt"})
    assert denied.allowed is False
    assert any("denied by path constraint" in reason for reason in denied.reasons)


def test_backward_compat_no_capabilities_uses_existing_behavior() -> None:
    policy = {
        "rules": [],
        "tool_access": {"mode": "denylist", "denied": ["shell_execute"]},
    }
    assert _decision(policy, "read_file", {"path": "/tmp/a"}).allowed is True
    assert _decision(policy, "shell_execute", {"command": "id"}).allowed is False


def test_backward_compat_default_action_allow_uses_existing_denylist() -> None:
    policy = {
        "default_action": "allow",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/workspace/*"]}}],
        "tool_access": {"mode": "denylist", "denied": ["shell_execute"]},
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/etc/passwd"}).allowed is True
    assert _decision(policy, "shell_execute", {"command": "id"}).allowed is False


def test_mixed_mode_capabilities_and_denied_tools_coexist() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "shell_execute", "allow": {"commands": ["git status"]}}],
        "tool_access": {"mode": "denylist", "denied": ["shell_execute"]},
        "rules": [],
    }
    decision = _decision(policy, "shell_execute", {"command": "git status"})
    assert decision.allowed is False
    assert any("denylist" in reason for reason in decision.reasons)


def test_empty_capabilities_with_deny_blocks_everything() -> None:
    policy = {"default_action": "deny", "capabilities": [], "rules": []}
    assert _decision(policy, "web_search", {"url": "https://example.com"}).allowed is False
    assert _decision(policy, "read_file", {"path": "/tmp/a"}).allowed is False


def test_multiple_capabilities_for_same_tool_union_permissions() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [
            {"tool": "read_file", "allow": {"paths": ["/workspace/*"]}},
            {"tool": "read_file", "allow": {"paths": ["/tmp/*"]}},
        ],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/workspace/a.txt"}).allowed is True
    assert _decision(policy, "read_file", {"path": "/tmp/b.txt"}).allowed is True
    assert _decision(policy, "read_file", {"path": "/etc/passwd"}).allowed is False


def test_nested_path_glob_matches_data_json() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/workspace/data/**/*.json"]}}],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/workspace/data/x/y/z.json"}).allowed is True


def test_tool_names_are_case_insensitive() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/workspace/*"]}}],
        "rules": [],
    }
    assert _decision(policy, "READ_FILE", {"path": "/workspace/a.txt"}).allowed is True


def test_missing_path_param_does_not_fail_path_allow_constraint() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/workspace/*"]}}],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"mode": "metadata_only"}).allowed is True


def test_missing_domain_param_does_not_fail_domain_allow_constraint() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "web_search", "allow": {"domains": ["*.github.com"]}}],
        "rules": [],
    }
    assert _decision(policy, "web_search", {"query": "release notes"}).allowed is True


def test_missing_command_param_does_not_fail_command_allow_constraint() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "shell_execute", "allow": {"commands": ["git status"]}}],
        "rules": [],
    }
    assert _decision(policy, "shell_execute", {"cwd": "/workspace"}).allowed is True


def test_capability_deny_domain_blocks_even_when_allow_exists() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [
            {"tool": "web_search", "allow": {"domains": ["*.github.com", "*.google.com"]}},
            {"tool": "web_search", "deny": {"domains": ["*.google.com"]}},
        ],
        "rules": [],
    }
    assert _decision(policy, "web_search", {"url": "https://api.github.com"}).allowed is True
    assert _decision(policy, "web_search", {"url": "https://mail.google.com"}).allowed is False


def test_capability_deny_command_blocks() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [
            {"tool": "shell_execute", "allow": {"commands": ["git *"]}},
            {"tool": "shell_execute", "deny": {"commands": ["git push*"]}},
        ],
        "rules": [],
    }
    assert _decision(policy, "shell_execute", {"command": "git status"}).allowed is True
    assert _decision(policy, "shell_execute", {"command": "git push origin main"}).allowed is False


def test_capability_wildcard_allows_by_domain_for_any_tool() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "*", "allow": {"domains": ["*.github.com"]}}],
        "rules": [],
    }
    assert _decision(policy, "web_fetch", {"url": "https://api.github.com/repos"}).allowed is True
    assert _decision(policy, "web_fetch", {"url": "https://example.com"}).allowed is False


def test_capability_path_matching_uses_normalized_path() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/workspace/*"]}}],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/workspace/../workspace/a.txt"}).allowed is True


def test_capability_supports_filepath_key() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/tmp/*"]}}],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"filePath": "/tmp/a.txt"}).allowed is True


def test_default_action_allow_with_capability_deny_only_still_denies() -> None:
    policy = {
        "default_action": "allow",
        "capabilities": [{"tool": "*", "deny": {"paths": ["/etc/*"]}}],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/etc/passwd"}).allowed is False
    assert _decision(policy, "read_file", {"path": "/tmp/a"}).allowed is True


def test_capability_reason_when_constraints_not_met() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/workspace/*"]}}],
        "rules": [],
    }
    decision = _decision(policy, "read_file", {"path": "/root/id_rsa"})
    assert decision.allowed is False
    assert any("does not satisfy allow constraints" in reason for reason in decision.reasons)


def test_capability_and_rule_based_denied_paths_both_apply() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "read_file", "allow": {"paths": ["/workspace/*", "/etc/*"]}}],
        "rules": [{"name": "file_access", "denied_paths": ["/etc"]}],
    }
    assert _decision(policy, "read_file", {"path": "/workspace/a.txt"}).allowed is True
    assert _decision(policy, "read_file", {"path": "/etc/passwd"}).allowed is False


def test_capability_can_allow_all_tool_params_when_allow_empty_mapping() -> None:
    policy = {"default_action": "deny", "capabilities": [{"tool": "web_search", "allow": {}}], "rules": []}
    assert _decision(policy, "web_search", {"query": "x", "url": "https://example.com"}).allowed is True


def test_capability_tool_wildcard_with_only_deny_blocks_all_tools() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [
            {"tool": "*", "allow": {"paths": ["/workspace/*"]}},
            {"tool": "*", "deny": {"paths": ["/workspace/secret/*"]}},
        ],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/workspace/secret/a.txt"}).allowed is False
    assert _decision(policy, "write_file", {"path": "/workspace/secret/b.txt"}).allowed is False


def test_capability_tool_mismatch_deny_default_blocks() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "web_search", "allow": {"domains": ["*.github.com"]}}],
        "rules": [],
    }
    assert _decision(policy, "read_file", {"path": "/workspace/a.txt"}).allowed is False


def test_capability_domain_can_be_plain_host() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "web_search", "allow": {"domains": ["api.github.com"]}}],
        "rules": [],
    }
    assert _decision(policy, "web_search", {"domain": "api.github.com"}).allowed is True


def test_capability_command_glob_supported() -> None:
    policy = {
        "default_action": "deny",
        "capabilities": [{"tool": "shell_execute", "allow": {"commands": ["git *", "ls*"]}}],
        "rules": [],
    }
    assert _decision(policy, "shell_execute", {"command": "git log --oneline"}).allowed is True
    assert _decision(policy, "shell_execute", {"command": "python -V"}).allowed is False


def test_load_policy_invalid_capability_structure_graceful(tmp_path: Path) -> None:
    path = tmp_path / "bad.yaml"
    path.write_text(
        """
default_action: deny
capabilities:
  - tool: read_file
    allow:
      paths: "/workspace/*"
rules: []
""".strip(),
        encoding="utf-8",
    )
    with pytest.raises(PolicyError):
        load_policy(path)


def test_load_policy_empty_capabilities_with_deny_is_valid(tmp_path: Path) -> None:
    path = tmp_path / "deny-all.yaml"
    path.write_text("default_action: deny\ncapabilities: []\nrules: []\n", encoding="utf-8")
    policy = load_policy(path)
    decision = _decision(policy, "read_file", {"path": "/workspace/a"})
    assert decision.allowed is False

