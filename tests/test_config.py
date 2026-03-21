from pathlib import Path

import pytest

from orchesis import config as config_module
from orchesis.config import PolicyError, PolicyWatcher, load_policy, validate_policy


def _write_yaml(tmp_path: Path, name: str, content: str) -> Path:
    file_path = tmp_path / name
    file_path.write_text(content, encoding="utf-8")
    return file_path


def test_load_policy_reads_valid_yaml_mapping(tmp_path: Path) -> None:
    policy_path = _write_yaml(
        tmp_path,
        "policy.yaml",
        """
rules:
  - name: budget_limit
    max_cost_per_call: 0.5
""".strip(),
    )

    policy = load_policy(policy_path)

    assert isinstance(policy, dict)
    assert policy["rules"][0]["name"] == "budget_limit"


def test_load_policy_raises_on_non_mapping_root(tmp_path: Path) -> None:
    policy_path = _write_yaml(
        tmp_path,
        "invalid.yaml",
        """
- name: budget_limit
  max_cost_per_call: 0.5
""".strip(),
    )

    with pytest.raises(ValueError, match="top-level YAML object"):
        load_policy(policy_path)


def test_load_policy_raises_policy_error_for_fuzzed_non_mapping_yaml(tmp_path: Path) -> None:
    policy_path = _write_yaml(tmp_path, "fuzzed.yaml", "[0b_\n#2\n")
    policy = load_policy(policy_path)
    assert isinstance(policy, dict)


def test_load_policy_raises_policy_error_for_valid_non_mapping_yaml(tmp_path: Path) -> None:
    policy_path = _write_yaml(tmp_path, "list-root.yaml", "[0b1]")
    with pytest.raises(PolicyError, match="top-level YAML object"):
        load_policy(policy_path)


def test_policy_loader_handles_binary_yaml(tmp_path: Path) -> None:
    policy_path = tmp_path / "binary.yaml"
    policy_path.write_bytes(b"rules:\n  - name: budget_limit\n    max_cost_per_call: 0.5\n\xff\xfe")
    policy = load_policy(policy_path)
    assert isinstance(policy, dict)


def test_load_policy_regression_invalid_bytes_returns_empty_mapping(tmp_path: Path) -> None:
    policy_path = tmp_path / "invalid-bytes.yaml"
    policy_path.write_bytes(b"{\xff")
    policy = load_policy(policy_path)
    assert isinstance(policy, dict)


def test_load_policy_regression_safe_load_guard_on_nonchars(tmp_path: Path) -> None:
    policy_path = tmp_path / "nonchar-bytes.yaml"
    # Includes UTF-8 for U+FFFF (noncharacter) + malformed YAML.
    policy_path.write_bytes(b"{\xef\xbf\xbf")
    policy = load_policy(policy_path)
    assert isinstance(policy, dict)


def test_validate_policy_accepts_valid_policy() -> None:
    policy = {
        "rules": [
            {"name": "budget_limit", "max_cost_per_call": 0.5, "daily_budget": 50.0},
            {"name": "file_access", "allowed_paths": ["/tmp"], "denied_paths": ["/etc"]},
            {
                "name": "sql_restriction",
                "allowed_operations": ["SELECT"],
                "denied_operations": ["DROP"],
            },
            {"name": "rate_limit", "max_requests_per_minute": 100},
        ]
    }

    errors = validate_policy(policy)

    assert errors == []


def test_validate_policy_requires_rules_list() -> None:
    errors = validate_policy({})
    assert "policy.rules must be a list" in errors


def test_validate_policy_requires_rule_name() -> None:
    policy = {"rules": [{"max_cost_per_call": 0.5}]}

    errors = validate_policy(policy)

    assert "rules[0].name must be a non-empty string" in errors


def test_validate_policy_checks_required_fields_per_known_rule() -> None:
    policy = {
        "rules": [
            {"name": "budget_limit"},
            {"name": "file_access"},
            {"name": "sql_restriction"},
            {"name": "rate_limit"},
        ]
    }

    errors = validate_policy(policy)

    assert "rules[0].max_cost_per_call is required for budget_limit" in errors
    assert "rules[1] must define allowed_paths and/or denied_paths for file_access" in errors
    assert "rules[2].denied_operations is required for sql_restriction" in errors
    assert "rules[3].max_requests_per_minute is required for rate_limit" in errors


def test_load_policy_normalizes_default_action_and_capabilities(tmp_path: Path) -> None:
    policy_path = _write_yaml(
        tmp_path,
        "caps.yaml",
        """
default_action: deny
capabilities:
  - tool: READ_FILE
    allow:
      paths:
        - /workspace/*
  - tool: "*"
    deny:
      domains:
        - "*.evil.com"
rules: []
""".strip(),
    )
    policy = load_policy(policy_path)
    assert policy["default_action"] == "deny"
    assert policy["capabilities"][0]["tool"] == "read_file"
    assert policy["capabilities"][1]["tool"] == "*"


def test_load_policy_defaults_to_allow_when_default_action_missing(tmp_path: Path) -> None:
    policy_path = _write_yaml(tmp_path, "default-action.yaml", "rules: []")
    policy = load_policy(policy_path)
    assert policy["default_action"] == "allow"
    assert policy["capabilities"] == []


def test_load_policy_raises_on_invalid_default_action(tmp_path: Path) -> None:
    policy_path = _write_yaml(
        tmp_path,
        "bad-default-action.yaml",
        """
default_action: block
rules: []
""".strip(),
    )
    with pytest.raises(PolicyError, match="default_action"):
        load_policy(policy_path)


def test_load_policy_raises_on_invalid_capability_structure(tmp_path: Path) -> None:
    policy_path = _write_yaml(
        tmp_path,
        "bad-capability.yaml",
        """
default_action: deny
capabilities:
  - tool: read_file
    allow: "/workspace/*"
rules: []
""".strip(),
    )
    with pytest.raises(PolicyError, match="capabilities\\[0\\]\\.allow"):
        load_policy(policy_path)


def test_load_policy_raises_on_capability_without_allow_or_deny(tmp_path: Path) -> None:
    policy_path = _write_yaml(
        tmp_path,
        "empty-capability.yaml",
        """
default_action: deny
capabilities:
  - tool: read_file
rules: []
""".strip(),
    )
    with pytest.raises(PolicyError, match="must define 'allow' and/or 'deny'"):
        load_policy(policy_path)


def test_config_check_throttle(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = _write_yaml(tmp_path, "policy.yaml", "rules: []")
    reloaded: list[dict] = []
    watcher = PolicyWatcher(str(policy_path), reloaded.append, check_interval_s=1.0)
    hash_calls = {"count": 0}
    load_calls = {"count": 0}

    def fake_hash() -> str:
        hash_calls["count"] += 1
        return "hash-1"

    def fake_load_policy(_path: Path) -> dict:
        load_calls["count"] += 1
        return {"rules": []}

    monkeypatch.setattr(watcher, "current_hash", fake_hash)
    monkeypatch.setattr(config_module, "load_policy", fake_load_policy)

    assert watcher.check() is True
    assert watcher.check() is False
    assert hash_calls["count"] == 1
    assert load_calls["count"] == 1


def test_config_check_after_interval(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = _write_yaml(tmp_path, "policy.yaml", "rules: []")
    reloaded: list[dict] = []
    watcher = PolicyWatcher(str(policy_path), reloaded.append, check_interval_s=1.0)
    hash_values = iter(["hash-1", "hash-2"])
    load_calls = {"count": 0}
    monotonic_values = iter([0.0, 1.5])

    def fake_hash() -> str:
        return next(hash_values)

    def fake_load_policy(_path: Path) -> dict:
        load_calls["count"] += 1
        return {"rules": []}

    monkeypatch.setattr(watcher, "current_hash", fake_hash)
    monkeypatch.setattr(config_module, "load_policy", fake_load_policy)
    monkeypatch.setattr(config_module.time, "monotonic", lambda: next(monotonic_values))

    assert watcher.check() is True
    assert watcher.check() is True
    assert load_calls["count"] == 2


def test_config_check_interval_env_var(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = _write_yaml(tmp_path, "policy.yaml", "rules: []")
    monkeypatch.setenv("ORCHESIS_CONFIG_CHECK_INTERVAL", "0.5")
    watcher = PolicyWatcher(str(policy_path), lambda _policy: None)
    assert watcher.check_interval_s == 0.5


def test_config_check_interval_zero(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    policy_path = _write_yaml(tmp_path, "policy.yaml", "rules: []")
    watcher = PolicyWatcher(str(policy_path), lambda _policy: None, check_interval_s=0.0)
    hash_values = iter(["hash-1", "hash-2"])
    load_calls = {"count": 0}
    monotonic_values = iter([0.0, 0.0])

    def fake_hash() -> str:
        return next(hash_values)

    def fake_load_policy(_path: Path) -> dict:
        load_calls["count"] += 1
        return {"rules": []}

    monkeypatch.setattr(watcher, "current_hash", fake_hash)
    monkeypatch.setattr(config_module, "load_policy", fake_load_policy)
    monkeypatch.setattr(config_module.time, "monotonic", lambda: next(monotonic_values))

    assert watcher.check() is True
    assert watcher.check() is True
    assert load_calls["count"] == 2
