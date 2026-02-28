from __future__ import annotations

from pathlib import Path

from orchesis.policy_store import PolicyStore


def _write_policy(path: Path, content: str) -> None:
    path.write_text(content.strip() + "\n", encoding="utf-8")


def test_history_persists_across_instances(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    history_path = tmp_path / ".orchesis" / "policy_versions.jsonl"
    _write_policy(policy_path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0")
    store_a = PolicyStore(history_path=history_path)
    v1 = store_a.load(str(policy_path))
    _write_policy(policy_path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 2.0")
    v2 = store_a.load(str(policy_path))
    assert v1.version_id != v2.version_id

    store_b = PolicyStore(history_path=history_path)
    history = store_b.history()
    assert len(history) >= 2
    assert history[0].version_id == v2.version_id
    assert history[1].version_id == v1.version_id


def test_rollback_persists_across_instances(tmp_path: Path) -> None:
    policy_path = tmp_path / "policy.yaml"
    history_path = tmp_path / ".orchesis" / "policy_versions.jsonl"
    _write_policy(policy_path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 1.0")
    store_a = PolicyStore(history_path=history_path)
    v1 = store_a.load(str(policy_path))
    _write_policy(policy_path, "rules:\n  - name: budget_limit\n    max_cost_per_call: 2.0")
    v2 = store_a.load(str(policy_path))
    assert store_a.current is not None
    assert store_a.current.version_id == v2.version_id
    rolled = store_a.rollback()
    assert rolled is not None
    assert rolled.version_id == v1.version_id

    store_b = PolicyStore(history_path=history_path)
    assert store_b.current is not None
    assert store_b.current.version_id == v1.version_id


def test_corrupt_history_file_handled_gracefully(tmp_path: Path) -> None:
    history_path = tmp_path / ".orchesis" / "policy_versions.jsonl"
    history_path.parent.mkdir(parents=True, exist_ok=True)
    history_path.write_text('{"broken": true}\nnot-json\n{"version_id": 1}\n', encoding="utf-8")
    store = PolicyStore(history_path=history_path)
    assert store.history() == []
    assert store.current is None
