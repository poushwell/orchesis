"""Decision logging utilities."""

import json
from pathlib import Path
from typing import Any

from orchesis.models import Decision


def append_decision(
    decision: Decision,
    request: dict[str, Any],
    log_path: str | Path,
    *,
    signature: str | None = None,
) -> None:
    """Append one decision line to a JSONL file."""
    path = Path(log_path)
    payload = {
        "timestamp": decision.timestamp,
        "tool": request.get("tool"),
        "decision": "ALLOW" if decision.allowed else "DENY",
        "reasons": decision.reasons,
        "rules_checked": decision.rules_checked,
        "cost": request.get("cost"),
    }
    if signature is not None:
        payload["signature"] = signature
    with path.open("a", encoding="utf-8") as file:
        file.write(json.dumps(payload, ensure_ascii=False) + "\n")


def read_decisions(log_path: str | Path) -> list[dict[str, Any]]:
    """Read all decisions from a JSONL file."""
    path = Path(log_path)
    if not path.exists():
        return []

    entries: list[dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as file:
        for line in file:
            stripped = line.strip()
            if not stripped:
                continue
            entries.append(json.loads(stripped))
    return entries
