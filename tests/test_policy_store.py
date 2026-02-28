from __future__ import annotations

import hashlib
from pathlib import Path

from orchesis.identity import TrustTier
from orchesis.policy_store import PolicyStore


def _write_policy(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def test_load_creates_version(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    _write_policy(path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0")
    store = PolicyStore(history_path=tmp_path / "policy_versions.jsonl")
    version = store.load(str(path))
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    assert version.version_id == expected
    assert store.current is not None
    assert store.current.version_id == expected


def test_multiple_loads_create_history(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    store = PolicyStore(history_path=tmp_path / "policy_versions.jsonl")
    _write_policy(path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0")
    v1 = store.load(str(path))
    _write_policy(path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 2.0")
    v2 = store.load(str(path))
    _write_policy(path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 3.0")
    v3 = store.load(str(path))
    history = store.history()
    assert len(history) == 3
    assert history[0].version_id == v3.version_id
    assert history[1].version_id == v2.version_id
    assert history[2].version_id == v1.version_id


def test_rollback_to_previous(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    store = PolicyStore(history_path=tmp_path / "policy_versions.jsonl")
    _write_policy(path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0")
    a = store.load(str(path))
    _write_policy(path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 2.0")
    b = store.load(str(path))
    assert store.current is not None
    assert store.current.version_id == b.version_id
    rolled = store.rollback()
    assert rolled is not None
    assert rolled.version_id == a.version_id
    assert store.current is not None
    assert store.current.version_id == a.version_id


def test_rollback_at_first_version_returns_none(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    store = PolicyStore(history_path=tmp_path / "policy_versions.jsonl")
    _write_policy(path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0")
    _ = store.load(str(path))
    assert store.rollback() is None


def test_max_versions_limit(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    store = PolicyStore(max_versions=3, history_path=tmp_path / "policy_versions.jsonl")
    for idx in range(5):
        _write_policy(path, f"rules:\n  - name: budget_limit\n    max_cost_per_call: {idx + 1}.0")
        store.load(str(path))
    history = store.history()
    assert len(history) == 3


def test_get_version_by_hash(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    store = PolicyStore(history_path=tmp_path / "policy_versions.jsonl")
    _write_policy(path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0")
    version = store.load(str(path))
    found = store.get_version(version.version_id)
    assert found is not None
    assert found.version_id == version.version_id


def test_version_includes_registry(tmp_path: Path) -> None:
    path = tmp_path / "policy.yaml"
    _write_policy(
        path,
        """
default_trust_tier: intern
agents:
  - id: "cursor"
    name: "Cursor IDE Agent"
    trust_tier: operator
rules: []
""",
    )
    store = PolicyStore(history_path=tmp_path / "policy_versions.jsonl")
    version = store.load(str(path))
    identity = version.registry.get("cursor")
    assert identity.agent_id == "cursor"
    assert identity.trust_tier == TrustTier.OPERATOR
