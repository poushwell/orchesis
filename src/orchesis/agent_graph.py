"""Agent collaboration graph primitives."""

from __future__ import annotations

from collections import defaultdict
from typing import Any


class AgentCollaborationGraph:
    """Tracks and visualizes agent-to-agent interactions."""

    def __init__(self):
        self._edges: dict[tuple[str, str, str], int] = {}
        self._node_stats: dict[str, dict[str, Any]] = {}

    def record_agent(self, agent_id: str, requests: int = 0, cost: float = 0.0) -> None:
        """Register or update a node without adding an edge."""
        aid = str(agent_id or "").strip()
        if not aid:
            return
        node = self._node_stats.setdefault(aid, {"requests": 0, "cost": 0.0})
        node["requests"] = int(node.get("requests", 0)) + max(0, int(requests))
        node["cost"] = float(node.get("cost", 0.0)) + max(0.0, float(cost or 0.0))

    def record_interaction(
        self,
        from_agent: str,
        to_agent: str,
        interaction_type: str = "context_share",
    ) -> None:
        """Record an interaction between agents."""
        src = str(from_agent or "").strip()
        dst = str(to_agent or "").strip()
        if not src or not dst:
            return
        itype = str(interaction_type or "context_share").strip() or "context_share"
        self.record_agent(src, requests=1, cost=0.0)
        self.record_agent(dst, requests=0, cost=0.0)
        key = (src, dst, itype)
        self._edges[key] = int(self._edges.get(key, 0)) + 1

    def get_graph(self) -> dict:
        nodes = [
            {"id": agent_id, "requests": int(stats["requests"]), "cost": round(float(stats["cost"]), 6)}
            for agent_id, stats in sorted(self._node_stats.items())
        ]
        edges = [
            {"from": src, "to": dst, "weight": int(weight), "type": itype}
            for (src, dst, itype), weight in sorted(self._edges.items())
        ]
        degree = defaultdict(int)
        for edge in edges:
            degree[str(edge["from"])] += 1
            degree[str(edge["to"])] += 1
        central_agent = ""
        if degree:
            central_agent = max(sorted(degree.keys()), key=lambda agent_id: degree[agent_id])
        isolated_agents = [node["id"] for node in nodes if degree.get(str(node["id"]), 0) == 0]
        return {
            "nodes": nodes,
            "edges": edges,
            "central_agent": central_agent,
            "isolated_agents": isolated_agents,
        }

    def get_clusters(self) -> list[list[str]]:
        """Group agents by interaction patterns."""
        adjacency: dict[str, set[str]] = {agent: set() for agent in self._node_stats}
        for (src, dst, _itype), _weight in self._edges.items():
            adjacency.setdefault(src, set()).add(dst)
            adjacency.setdefault(dst, set()).add(src)
        visited: set[str] = set()
        clusters: list[list[str]] = []
        for agent in sorted(adjacency.keys()):
            if agent in visited:
                continue
            stack = [agent]
            component: list[str] = []
            while stack:
                cur = stack.pop()
                if cur in visited:
                    continue
                visited.add(cur)
                component.append(cur)
                for nxt in sorted(adjacency.get(cur, set())):
                    if nxt not in visited:
                        stack.append(nxt)
            clusters.append(sorted(component))
        return clusters

    def get_stats(self) -> dict:
        """Graph statistics: density, avg degree, etc."""
        node_count = len(self._node_stats)
        edge_count = len(self._edges)
        if node_count <= 1:
            density = 0.0
        else:
            density = edge_count / float(node_count * (node_count - 1))
        degree = defaultdict(int)
        for (src, dst, _itype), _weight in self._edges.items():
            degree[src] += 1
            degree[dst] += 1
        avg_degree = (sum(degree.values()) / float(node_count)) if node_count else 0.0
        return {
            "nodes": node_count,
            "edges": edge_count,
            "density": round(density, 6),
            "avg_degree": round(avg_degree, 6),
            "clusters": len(self.get_clusters()),
        }
