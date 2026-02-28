"""Deterministic planner: task name/description -> static tool sequence."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


def load_task_catalog(path: str | Path) -> dict[str, Any]:
    """Load agent task definitions from YAML."""
    loaded = yaml.safe_load(Path(path).read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ValueError("Task catalog must be a mapping")
    tasks = loaded.get("tasks")
    if not isinstance(tasks, list):
        raise ValueError("Task catalog must contain a 'tasks' list")
    return loaded


def resolve_task_steps(task: str, catalog: dict[str, Any]) -> list[dict[str, Any]]:
    """Resolve a task string into deterministic step sequence."""
    tasks = catalog.get("tasks")
    if not isinstance(tasks, list):
        raise ValueError("Task catalog must contain a 'tasks' list")

    normalized = task.strip().lower()
    for item in tasks:
        if not isinstance(item, dict):
            continue
        name = item.get("name")
        description = item.get("description")
        steps = item.get("steps")
        if not isinstance(steps, list):
            continue

        if isinstance(name, str) and name.strip().lower() == normalized:
            return steps
        if isinstance(description, str) and description.strip().lower() == normalized:
            return steps

    raise ValueError(f"Unknown task: {task}")
