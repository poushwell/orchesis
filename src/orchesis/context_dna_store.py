"""Persistent storage for Context DNA profiles."""

from __future__ import annotations

import json
from pathlib import Path

from orchesis.context_dna import ContextDNA


class ContextDNAStore:
    """Persistent storage for agent DNA profiles."""

    def __init__(self, storage_path: str = ".orchesis/dna"):
        self.storage_path = Path(storage_path)
        self.storage_path.mkdir(parents=True, exist_ok=True)

    def _agent_path(self, agent_id: str) -> Path:
        safe = "".join(ch if ch.isalnum() or ch in {"-", "_", "."} else "_" for ch in str(agent_id))
        return self.storage_path / f"{safe}.json"

    def get(self, agent_id: str) -> ContextDNA | None:
        path = self._agent_path(agent_id)
        if not path.exists():
            return None
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            return None
        dna = ContextDNA(agent_id=agent_id)
        dna.load(payload if isinstance(payload, dict) else {})
        return dna

    def save(self, dna: ContextDNA) -> None:
        payload = dna.export()
        path = self._agent_path(dna.agent_id)
        path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")

    def list_agents(self) -> list[str]:
        agents: list[str] = []
        for file_path in sorted(self.storage_path.glob("*.json")):
            agents.append(file_path.stem)
        return agents

