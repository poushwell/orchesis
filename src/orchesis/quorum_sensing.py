"""Fleet quorum sensing for emergent context sharing."""

from __future__ import annotations

from datetime import datetime, timezone
from difflib import SequenceMatcher
import hashlib
import threading
from typing import Any


class QuorumSensor:
    """When N agents share similar tasks — auto context sharing.

    Confirmed: N*=16 from bootstrap experiment (Exp 13, RG Universality).
    Emergent coordination without orchestrator.
    """

    QUORUM_THRESHOLD = 16  # N* from experiment
    SIMILARITY_THRESHOLD = 0.75

    def __init__(self, config: dict | None = None):
        cfg = config if isinstance(config, dict) else {}
        self.n_star = int(cfg.get("n_star", self.QUORUM_THRESHOLD))
        self.similarity = float(cfg.get("similarity", self.SIMILARITY_THRESHOLD))
        self._agent_tasks: dict[str, dict[str, Any]] = {}
        self._quorums: list[dict[str, Any]] = []
        self._quorum_contexts: dict[str, dict[str, Any]] = {}
        self._lock = threading.RLock()

    @staticmethod
    def _now_iso() -> str:
        return datetime.now(timezone.utc).isoformat()

    def register_task(self, agent_id: str, task_fingerprint: str) -> None:
        """Register agent's current task fingerprint."""
        aid = str(agent_id or "").strip()
        fp = str(task_fingerprint or "").strip()
        if not aid or not fp:
            return
        with self._lock:
            self._agent_tasks[aid] = {
                "task_fingerprint": fp,
                "updated_at": self._now_iso(),
            }

    def _similarity(self, a: str, b: str) -> float:
        return float(SequenceMatcher(None, a, b).ratio())

    def _build_components(self, items: list[tuple[str, str]]) -> list[list[str]]:
        # Build graph of similar tasks, then extract connected components.
        graph: dict[str, set[str]] = {agent_id: set() for agent_id, _ in items}
        for i, (agent_i, fp_i) in enumerate(items):
            for agent_j, fp_j in items[i + 1 :]:
                if self._similarity(fp_i, fp_j) >= self.similarity:
                    graph[agent_i].add(agent_j)
                    graph[agent_j].add(agent_i)

        seen: set[str] = set()
        groups: list[list[str]] = []
        for node in graph:
            if node in seen:
                continue
            stack = [node]
            comp: list[str] = []
            while stack:
                cur = stack.pop()
                if cur in seen:
                    continue
                seen.add(cur)
                comp.append(cur)
                stack.extend(n for n in graph[cur] if n not in seen)
            groups.append(sorted(comp))
        return groups

    def detect_quorum(self) -> list[dict]:
        """Detect groups of agents with similar tasks."""
        with self._lock:
            items = [
                (agent_id, str(payload.get("task_fingerprint", "")))
                for agent_id, payload in self._agent_tasks.items()
                if isinstance(payload, dict) and str(payload.get("task_fingerprint", "")).strip()
            ]
            components = self._build_components(items)
            by_agent = {agent_id: fp for agent_id, fp in items}
            new_quorums: list[dict[str, Any]] = []
            for agents in components:
                if len(agents) < max(1, int(self.n_star)):
                    continue
                fps = [by_agent[a] for a in agents]
                if len(fps) <= 1:
                    avg_score = 1.0
                else:
                    sims: list[float] = []
                    for i, left in enumerate(fps):
                        for right in fps[i + 1 :]:
                            sims.append(self._similarity(left, right))
                    avg_score = sum(sims) / len(sims) if sims else 1.0
                key_src = "|".join(sorted(fps))
                key = hashlib.sha1(key_src.encode("utf-8")).hexdigest()[:16]
                quorum_id = f"qrm-{hashlib.md5(','.join(agents).encode('utf-8')).hexdigest()[:12]}"
                formed_at = self._quorum_contexts.get(quorum_id, {}).get("formed_at", self._now_iso())
                shared_context_key = f"ctx-{key}"
                new_quorums.append(
                    {
                        "quorum_id": quorum_id,
                        "agents": agents,
                        "similarity_score": round(float(avg_score), 6),
                        "shared_context_key": shared_context_key,
                        "formed_at": formed_at,
                    }
                )
                if quorum_id not in self._quorum_contexts:
                    self._quorum_contexts[quorum_id] = {
                        "quorum_id": quorum_id,
                        "shared_context_key": shared_context_key,
                        "formed_at": formed_at,
                        "contributors": {},
                    }
            self._quorums = new_quorums
            active_ids = {row["quorum_id"] for row in new_quorums}
            self._quorum_contexts = {qid: payload for qid, payload in self._quorum_contexts.items() if qid in active_ids}
            return [dict(row) for row in self._quorums]

    def get_shared_context(self, quorum_id: str) -> dict | None:
        """Get shared context for a quorum."""
        with self._lock:
            self.detect_quorum()
            row = self._quorum_contexts.get(str(quorum_id))
            if not isinstance(row, dict):
                return None
            merged: dict[str, Any] = {}
            contributors = row.get("contributors", {})
            if isinstance(contributors, dict):
                for ctx in contributors.values():
                    if isinstance(ctx, dict):
                        merged.update(ctx)
            return {
                "quorum_id": row.get("quorum_id"),
                "shared_context_key": row.get("shared_context_key"),
                "formed_at": row.get("formed_at"),
                "contributors": sorted(list(contributors.keys())) if isinstance(contributors, dict) else [],
                "context": merged,
            }

    def contribute_context(self, quorum_id: str, agent_id: str, context: dict) -> bool:
        """Agent contributes context to quorum pool."""
        qid = str(quorum_id or "").strip()
        aid = str(agent_id or "").strip()
        if not qid or not aid or not isinstance(context, dict):
            return False
        with self._lock:
            self.detect_quorum()
            row = self._quorum_contexts.get(qid)
            if not isinstance(row, dict):
                return False
            contributors = row.setdefault("contributors", {})
            if not isinstance(contributors, dict):
                contributors = {}
                row["contributors"] = contributors
            contributors[aid] = dict(context)
            row["updated_at"] = self._now_iso()
            return True

    def get_stats(self) -> dict:
        quorums = self.detect_quorum()
        total_agents = len(self._agent_tasks)
        in_quorum = len({agent for row in quorums for agent in row.get("agents", [])})
        rate = (float(in_quorum) / float(total_agents) * 100.0) if total_agents > 0 else 0.0
        return {
            "active_quorums": len(quorums),
            "total_agents": total_agents,
            "agents_in_quorum": in_quorum,
            "n_star": int(self.n_star),
            "quorum_rate": round(rate, 2),
        }

