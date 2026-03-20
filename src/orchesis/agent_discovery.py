"""Agent discovery and inventory for Orchesis."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import threading
import time
from typing import Any, Optional


@dataclass
class AgentProfile:
    """Complete profile of a discovered agent."""

    agent_id: str
    first_seen: float
    last_seen: float
    total_requests: int
    total_tokens: int
    total_cost_usd: float
    models_used: list[str]
    primary_model: str
    tools_used: list[str]
    tool_call_count: int
    ars_grade: str
    ars_score: float
    anomaly_count: int
    mast_findings_count: int
    risk_level: str
    avg_tokens_per_request: float
    avg_latency_ms: float
    avg_cost_per_request: float
    session_count: int
    is_cron: bool
    status: str
    health: str


class AgentDiscovery:
    """Centralized agent inventory and status."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", True))
        self.retention_hours = max(1, int(cfg.get("retention_hours", 168)))
        thresholds = cfg.get("health_thresholds") if isinstance(cfg.get("health_thresholds"), dict) else {}
        self.warning_anomaly_rate = float(thresholds.get("warning_anomaly_rate", 0.1))
        self.critical_anomaly_rate = float(thresholds.get("critical_anomaly_rate", 0.3))
        self._lock = threading.Lock()
        self._agents: dict[str, dict[str, Any]] = {}
        self._stats = {
            "requests_recorded": 0,
            "detections_recorded": 0,
            "cleanup_runs": 0,
            "agents_removed": 0,
        }

    @staticmethod
    def _now() -> float:
        return time.time()

    def _get_or_create(self, agent_id: str) -> dict[str, Any]:
        key = str(agent_id or "unknown")
        now = self._now()
        item = self._agents.get(key)
        if item is None:
            item = {
                "agent_id": key,
                "first_seen": now,
                "last_seen": now,
                "total_requests": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "total_latency_ms": 0.0,
                "models_counter": {},
                "tools_counter": {},
                "tool_call_count": 0,
                "ars_grade": "",
                "ars_score": 0.0,
                "anomaly_count": 0,
                "mast_findings_count": 0,
                "risk_level": "low",
                "sessions": set(),
                "is_cron": False,
                "blocked": False,
                "rate_limited": False,
            }
            self._agents[key] = item
        return item

    def record_request(
        self,
        agent_id: str,
        request_data: dict,
        model: str | None = None,
        tokens: int = 0,
        cost: float = 0.0,
        latency_ms: float = 0.0,
        tools: list | None = None,
    ) -> None:
        if not self.enabled:
            return
        req = request_data if isinstance(request_data, dict) else {}
        with self._lock:
            item = self._get_or_create(agent_id)
            now = self._now()
            item["last_seen"] = now
            item["total_requests"] += 1
            item["total_tokens"] += max(0, int(tokens or 0))
            item["total_cost_usd"] += max(0.0, float(cost or 0.0))
            item["total_latency_ms"] += max(0.0, float(latency_ms or 0.0))
            model_name = str(model or req.get("model", "") or "")
            if model_name:
                models_counter = item["models_counter"]
                models_counter[model_name] = int(models_counter.get(model_name, 0)) + 1
            session_id = req.get("session_id")
            if isinstance(session_id, str) and session_id:
                item["sessions"].add(session_id)
            parsed_tools: list[str] = []
            if isinstance(tools, list):
                for tool in tools:
                    if isinstance(tool, str) and tool:
                        parsed_tools.append(tool)
                    elif isinstance(tool, dict):
                        name = tool.get("name") or (tool.get("function") or {}).get("name")
                        if isinstance(name, str) and name:
                            parsed_tools.append(name)
            for name in parsed_tools:
                tools_counter = item["tools_counter"]
                tools_counter[name] = int(tools_counter.get(name, 0)) + 1
                item["tool_call_count"] += 1
            self._stats["requests_recorded"] += 1

    def record_detection(
        self,
        agent_id: str,
        anomaly_score: float = 0.0,
        mast_findings: int = 0,
        risk_level: str = "low",
        ars_grade: str | None = None,
        ars_score: float | None = None,
        is_cron: bool = False,
        status: str | None = None,
    ) -> None:
        if not self.enabled:
            return
        with self._lock:
            item = self._get_or_create(agent_id)
            item["last_seen"] = self._now()
            if float(anomaly_score or 0.0) > 0.0:
                item["anomaly_count"] += 1
            item["mast_findings_count"] += max(0, int(mast_findings or 0))
            safe_risk = str(risk_level or "low").lower()
            if safe_risk in {"low", "medium", "high", "critical"}:
                item["risk_level"] = safe_risk
            if isinstance(ars_grade, str):
                item["ars_grade"] = ars_grade
            if isinstance(ars_score, int | float):
                item["ars_score"] = float(ars_score)
            if is_cron:
                item["is_cron"] = True
            if isinstance(status, str) and status in {"active", "idle", "rate_limited", "blocked"}:
                item["blocked"] = status == "blocked"
                item["rate_limited"] = status == "rate_limited"
            elif safe_risk == "critical":
                item["blocked"] = True
            self._stats["detections_recorded"] += 1

    def _derive_status(self, item: dict[str, Any], now: float) -> str:
        if bool(item.get("blocked", False)):
            return "blocked"
        if bool(item.get("rate_limited", False)):
            return "rate_limited"
        idle_for = now - float(item.get("last_seen", now))
        if idle_for > 3600.0:
            return "idle"
        return "active"

    def _derive_health(self, item: dict[str, Any]) -> str:
        total_requests = max(1, int(item.get("total_requests", 0)))
        anomaly_rate = float(item.get("anomaly_count", 0)) / float(total_requests)
        risk_level = str(item.get("risk_level", "low")).lower()
        if risk_level == "critical" or anomaly_rate >= self.critical_anomaly_rate:
            return "critical"
        if risk_level == "high" or anomaly_rate >= self.warning_anomaly_rate:
            return "warning"
        return "healthy"

    @staticmethod
    def _top_key(counter: dict[str, int]) -> str:
        if not counter:
            return ""
        return max(counter.items(), key=lambda item: item[1])[0]

    def _to_profile(self, item: dict[str, Any]) -> AgentProfile:
        now = self._now()
        total_requests = int(item.get("total_requests", 0))
        total_tokens = int(item.get("total_tokens", 0))
        total_cost = float(item.get("total_cost_usd", 0.0))
        total_latency = float(item.get("total_latency_ms", 0.0))
        models_counter = dict(item.get("models_counter", {}))
        tools_counter = dict(item.get("tools_counter", {}))
        status = self._derive_status(item, now)
        health = self._derive_health(item)
        denom = float(total_requests) if total_requests > 0 else 1.0
        return AgentProfile(
            agent_id=str(item.get("agent_id", "unknown")),
            first_seen=float(item.get("first_seen", now)),
            last_seen=float(item.get("last_seen", now)),
            total_requests=total_requests,
            total_tokens=total_tokens,
            total_cost_usd=round(total_cost, 8),
            models_used=sorted(models_counter.keys()),
            primary_model=self._top_key(models_counter),
            tools_used=sorted(tools_counter.keys()),
            tool_call_count=int(item.get("tool_call_count", 0)),
            ars_grade=str(item.get("ars_grade", "") or ""),
            ars_score=float(item.get("ars_score", 0.0) or 0.0),
            anomaly_count=int(item.get("anomaly_count", 0)),
            mast_findings_count=int(item.get("mast_findings_count", 0)),
            risk_level=str(item.get("risk_level", "low") or "low"),
            avg_tokens_per_request=round(total_tokens / denom, 3),
            avg_latency_ms=round(total_latency / denom, 3),
            avg_cost_per_request=round(total_cost / denom, 8),
            session_count=len(item.get("sessions", set())),
            is_cron=bool(item.get("is_cron", False)),
            status=status,
            health=health,
        )

    def get_agent(self, agent_id: str) -> Optional[AgentProfile]:
        with self._lock:
            raw = self._agents.get(str(agent_id or "unknown"))
            if raw is None:
                return None
            snapshot = dict(raw)
            snapshot["models_counter"] = dict(raw.get("models_counter", {}))
            snapshot["tools_counter"] = dict(raw.get("tools_counter", {}))
            snapshot["sessions"] = set(raw.get("sessions", set()))
        return self._to_profile(snapshot)

    def get_all_agents(self) -> list[AgentProfile]:
        with self._lock:
            snapshots: list[dict[str, Any]] = []
            for raw in self._agents.values():
                snap = dict(raw)
                snap["models_counter"] = dict(raw.get("models_counter", {}))
                snap["tools_counter"] = dict(raw.get("tools_counter", {}))
                snap["sessions"] = set(raw.get("sessions", set()))
                snapshots.append(snap)
        profiles = [self._to_profile(item) for item in snapshots]
        profiles.sort(key=lambda item: item.last_seen, reverse=True)
        return profiles

    def get_summary(self) -> dict:
        profiles = self.get_all_agents()
        now = self._now()
        active_cutoff = now - 3600.0
        health = {"healthy": 0, "warning": 0, "critical": 0}
        models: set[str] = set()
        total_cost_24h = 0.0
        total_requests_24h = 0
        for item in profiles:
            health[item.health] = int(health.get(item.health, 0)) + 1
            for model in item.models_used:
                models.add(model)
            if item.last_seen >= (now - 86400.0):
                total_cost_24h += float(item.total_cost_usd)
                total_requests_24h += int(item.total_requests)
        top_by_cost = sorted(profiles, key=lambda item: item.total_cost_usd, reverse=True)[:5]
        top_by_risk = sorted(
            profiles,
            key=lambda item: (float(item.anomaly_count) / float(max(1, item.total_requests))),
            reverse=True,
        )[:5]
        return {
            "total_agents": len(profiles),
            "active_agents": sum(1 for item in profiles if item.last_seen >= active_cutoff and item.status == "active"),
            "idle_agents": sum(1 for item in profiles if item.status == "idle"),
            "blocked_agents": sum(1 for item in profiles if item.status == "blocked"),
            "health": health,
            "total_cost_24h_usd": round(total_cost_24h, 6),
            "total_requests_24h": int(total_requests_24h),
            "models_in_use": sorted(models),
            "top_agents_by_cost": [asdict(item) for item in top_by_cost],
            "top_agents_by_risk": [asdict(item) for item in top_by_risk],
        }

    def cleanup(self) -> int:
        cutoff = self._now() - (self.retention_hours * 3600.0)
        removed = 0
        with self._lock:
            for key in list(self._agents.keys()):
                if float(self._agents[key].get("last_seen", 0.0)) < cutoff:
                    self._agents.pop(key, None)
                    removed += 1
            self._stats["cleanup_runs"] += 1
            self._stats["agents_removed"] += removed
        return removed

    def get_stats(self) -> dict:
        with self._lock:
            return {
                "enabled": self.enabled,
                "agents_tracked": len(self._agents),
                **self._stats,
            }

    def reset(self) -> None:
        with self._lock:
            self._agents = {}
            self._stats = {
                "requests_recorded": 0,
                "detections_recorded": 0,
                "cleanup_runs": 0,
                "agents_removed": 0,
            }

