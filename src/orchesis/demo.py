"""Demo mode server for dashboard-only experience."""

from __future__ import annotations

import json
import random
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlsplit

from orchesis.dashboard import get_dashboard_html


DEMO_STATS: dict[str, Any] = {
    "requests_total": 14847,
    "requests_blocked": 23,
    "requests_allowed": 14824,
    "tokens_saved": 2891443,
    "money_saved_usd": 43.37,
    "cache_hits": 1204,
    "cache_hit_rate": 0.081,
    "active_sessions": 7,
    "agents_discovered": 12,
    "overwatch_health": "B+",
    "cost_velocity": {"current_rate_per_hour": 1.24, "projection_24h": 29.76, "is_anomalous": False},
    "threat_intel": {
        "signatures_loaded": 25,
        "blocked_by_category": {
            "prompt_injection": 8,
            "credential_leak": 5,
            "tool_abuse": 4,
            "privilege_escalation": 3,
            "data_exfiltration": 2,
            "loop_attack": 1,
        },
    },
    "top_models": [
        {"model": "gpt-4o", "requests": 8421, "cost": 12.63},
        {"model": "claude-sonnet-4-20250514", "requests": 3891, "cost": 7.78},
        {"model": "gpt-4o-mini", "requests": 2535, "cost": 0.51},
    ],
    "mast_compliance": {
        "covered": 11,
        "total": 14,
        "score": 78.6,
        "gaps": ["M12: Cascading Failure", "M13: Resource Exhaustion", "M14: Emergent Behavior"],
    },
    "owasp_coverage": {"covered": 8, "total": 10, "score": 80.0},
    "approvals_pending": 2,
    "uptime_seconds": 86400,
}


class DemoServer:
    """Serves dashboard with deterministic, realistic mock data."""

    def __init__(self) -> None:
        self._start = time.time()
        self._lock = threading.Lock()
        self._pending_approvals: dict[str, dict[str, Any]] = {
            "demo-approval-1": {
                "approval_id": "demo-approval-1",
                "timestamp": time.time() - 180,
                "agent_id": "deploy-bot",
                "tool_name": "system.run",
                "tool_args": {"action": "rm -rf /tmp/cache"},
                "reason": "Destructive command detected",
                "risk": "high",
            },
            "demo-approval-2": {
                "approval_id": "demo-approval-2",
                "timestamp": time.time() - 720,
                "agent_id": "data-sync",
                "tool_name": "api.call",
                "tool_args": {"domain": "internal.corp.com"},
                "reason": "Blocked domain match",
                "risk": "medium",
            },
        }
        self._approval_history: list[dict[str, Any]] = [
            {"status": "approved", "agent_id": "api-monitor", "tool_name": "api.call", "timestamp": time.time() - 7200},
            {"status": "denied", "agent_id": "refactor-agent", "tool_name": "system.run", "timestamp": time.time() - 18000},
        ]

    def _handle_stats(self) -> dict[str, Any]:
        jitter = random.Random(int(time.time() // 2))
        base_rate = float(DEMO_STATS["cost_velocity"]["current_rate_per_hour"])
        rate = max(0.1, base_rate + jitter.uniform(-0.08, 0.08))
        projection = rate * 24.0
        with self._lock:
            pending = list(self._pending_approvals.values())
            history = list(self._approval_history)
        return {
            "requests": int(DEMO_STATS["requests_total"] + jitter.randint(-4, 4)),
            "blocked": int(DEMO_STATS["requests_blocked"]),
            "cost_today": round(20.14 + jitter.uniform(-0.15, 0.15), 4),
            "cache_hit_rate_percent": round(float(DEMO_STATS["cache_hit_rate"]) * 100.0, 2),
            "semantic_cache": {
                "enabled": True,
                "hit_rate_percent": round(float(DEMO_STATS["cache_hit_rate"]) * 100.0, 2),
                "exact_hits": 889,
                "semantic_hits": 315,
                "misses": 13542,
                "entries": 202,
                "max_entries": 1000,
                "total_tokens_saved": int(DEMO_STATS["tokens_saved"]),
                "total_cost_saved_usd": float(DEMO_STATS["money_saved_usd"]),
            },
            "threat_intel": {
                "enabled": True,
                "total_signatures": int(DEMO_STATS["threat_intel"]["signatures_loaded"]),
                "total_scans": int(DEMO_STATS["requests_total"]),
                "total_matches": int(DEMO_STATS["requests_blocked"]),
                "blocks": int(DEMO_STATS["requests_blocked"]),
                "matches_by_category": dict(DEMO_STATS["threat_intel"]["blocked_by_category"]),
                "matches_by_severity": {"critical": 2, "high": 7, "medium": 11, "low": 3},
                "top_threats": [["Prompt Injection", 8], ["Credential Leak", 5], ["Tool Abuse", 4]],
            },
            "experiments": {"active": 2, "total_assignments": 643},
            "task_tracking": {"overall_success_rate": 0.94, "tracked_sessions": 123, "outcomes": {"success": 114, "failure": 5, "loop": 1, "abandoned": 2, "timeout": 1, "escalated": 0}},
            "context_engine": {"enabled": True, "total_tokens_saved": int(DEMO_STATS["tokens_saved"]), "strategy_hits": {"dedup_system_prompt": 321, "remove_stale_messages": 198}},
            "context_optimizer": {
                "enabled": True,
                "total_original_tokens": 5400000,
                "total_optimized_tokens": 2508557,
            },
            "cost_velocity": {
                "current_rate_per_hour": round(rate, 4),
                "projection_24h": round(projection, 4),
                "avg_7d_rate": 1.02,
                "is_anomalous": False,
            },
            "agent_discovery": {
                "enabled": True,
                "agents_tracked": int(DEMO_STATS["agents_discovered"]),
            },
            "tool_policy": {
                "approvals": {"pending_count": len(pending), "approved_count": 12, "denied_count": 3, "avg_wait_seconds": 211.0}
            },
            "compliance": {
                "frameworks": {
                    "owasp_llm_top10_2025": {"percent": 80.0},
                    "nist_ai_rmf_1_0": {"percent": 50.0},
                }
            },
            "demo_approvals_history": history,
        }

    def _overview(self) -> dict[str, Any]:
        stats = self._handle_stats()
        now = time.time()
        return {
            "status": "monitoring",
            "uptime_seconds": max(1.0, now - self._start),
            "total_requests": stats["requests"],
            "blocked_requests": stats["blocked"],
            "total_cost_usd": stats["cost_today"],
            "active_agents": int(DEMO_STATS["agents_discovered"]),
            "overwatch_health": str(DEMO_STATS["overwatch_health"]),
            "money_saved_usd": float(DEMO_STATS["money_saved_usd"]),
            "cost_velocity": dict(stats["cost_velocity"]),
            "compliance_overview": {
                "mast": {"score": 78.6, "covered": 11, "total": 14, "gaps": ["M12 Cascading Failure", "M13 Resource Exhaustion", "M14 Emergent Behavior"]},
                "owasp_agentic_ai": {"score": 80.0, "covered": 8, "total": 10, "gaps": ["ASI-09 Insufficient Logging", "ASI-10 Unsafe Plugin Design"]},
                "eu_ai_act": {"score": 60.0, "audit_trail": True, "incident_reporting": True, "risk_assessment": "partial", "human_oversight": "partial", "documentation": False},
                "nist_ai_rmf": {"score": 50.0, "govern": "full", "map": "partial", "measure": "full", "manage": "partial"},
            },
            "circuit_breakers": {"default": {"state": "closed", "failures": 0}},
            "budget": {"limit_usd": 10.0, "spent_usd": stats["cost_today"], "remaining_usd": max(0.0, 10.0 - float(stats["cost_today"]))},
            "recent_events": [
                {"timestamp": now - 50, "type": "blocked", "severity": "high", "description": "Blocked prompt injection attempt"},
                {"timestamp": now - 180, "type": "warn", "severity": "medium", "description": "Tool approval required for system.run"},
            ],
            "cost_timeline": [{"timestamp": now - 3600 + i * 300, "cumulative_cost": round(0.8 + i * 0.13, 4)} for i in range(12)],
            "flow_xray": {"enabled": True},
            "connection_pool": {"active": 4, "total_connections": 12, "hits": 1204, "misses": 275, "pools": {"api.openai.com": 7}},
            "savings": {"cache_savings": 20.5, "cascade_savings": 11.2, "loop_savings": 2.1, "total_savings": 33.8},
        }

    def _json(self, handler: BaseHTTPRequestHandler, status: int, payload: dict[str, Any]) -> None:
        raw = json.dumps(payload).encode("utf-8")
        handler.send_response(status)
        handler.send_header("Content-Type", "application/json")
        handler.send_header("Content-Length", str(len(raw)))
        handler.end_headers()
        handler.wfile.write(raw)

    def start(self, port: int = 8080) -> None:
        server = self

        class _Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:  # noqa: N802
                parsed = urlsplit(self.path)
                path = parsed.path
                if path in {"/", "/dashboard", "/dashboard/"}:
                    html = get_dashboard_html(demo_mode=True).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html)))
                    self.end_headers()
                    self.wfile.write(html)
                    return
                if path == "/health":
                    server._json(self, 200, {"status": "ok", "mode": "demo"})
                    return
                if path in {"/stats", "/api/v1/stats"}:
                    server._json(self, 200, server._handle_stats())
                    return
                if path == "/api/dashboard/overview":
                    server._json(self, 200, server._overview())
                    return
                if path == "/api/dashboard/agents":
                    server._json(
                        self,
                        200,
                        {"agents": [{"agent_id": "deploy-bot", "state": "active", "total_requests": 382, "avg_tokens": 914, "anomaly_score": 0.08, "tools_used": ["system.run", "web_fetch"], "last_seen": "just now"}]},
                    )
                    return
                if path in {"/api/sessions", "/sessions"}:
                    server._json(self, 200, {"sessions": []})
                    return
                if path == "/api/flow/sessions":
                    server._json(self, 200, {"sessions": [{"id": "demo-session-1"}]})
                    return
                if path.startswith("/api/flow/analyze/"):
                    server._json(self, 200, {"topology": {"depth": 3, "width": 2, "density": 0.44, "total_cost_usd": 1.83, "critical_path": ["node-a", "node-b"]}, "summary": {"health_score": 0.82}, "patterns": []})
                    return
                if path.startswith("/api/flow/graph/"):
                    server._json(self, 200, {"nodes": [{"node_id": "node-a", "node_type": "llm", "model": "gpt-4o", "cost_usd": 0.12}], "edges": []})
                    return
                if path == "/api/experiments":
                    server._json(self, 200, {"experiments": [{"experiment_id": "exp-1", "name": "Routing AB", "status": "running"}]})
                    return
                if path == "/api/tasks/outcomes":
                    server._json(self, 200, {"ok": True})
                    return
                if path == "/api/tasks/correlations":
                    server._json(self, 200, {"insights": ["Tool-approved flows have lower failure rate in demo data."]})
                    return
                if path == "/api/threats":
                    server._json(self, 200, {"threats": [{"threat_id": "ORCH-TA-001", "name": "Prompt Injection", "category": "prompt_injection", "severity": "high"}]})
                    return
                if path == "/api/threats/stats":
                    stats = server._handle_stats()["threat_intel"]
                    server._json(self, 200, stats)
                    return
                if path == "/api/compliance/summary":
                    server._json(self, 200, {"frameworks": {"owasp_llm_top10_2025": {"percent": 80.0}, "nist_ai_rmf_1_0": {"percent": 50.0}}})
                    return
                if path == "/api/compliance/coverage":
                    server._json(self, 200, {"frameworks": {"owasp_llm_top10_2025": {"items": [{"id": "ASI-01", "name": "Authorization", "status": "covered", "modules": ["policy_engine"]}]}}})
                    return
                if path.startswith("/api/compliance/findings"):
                    server._json(self, 200, {"findings": [{"timestamp": "now", "severity": "medium", "description": "Demo gap: ASI-10 unsafe plugin design", "framework_mappings": [["owasp_llm_top10_2025", "ASI-10"]]}]})
                    return
                if path.startswith("/api/compliance/report"):
                    server._json(self, 200, {"report": "demo"})
                    return
                if path == "/api/v1/savings":
                    server._json(self, 200, {"cache_savings": 20.5, "cascade_savings": 11.2, "loop_savings": 2.1, "total_savings": 33.8})
                    return
                if path == "/api/v1/approvals":
                    with server._lock:
                        pending = list(server._pending_approvals.values())
                        history = list(server._approval_history)
                    server._json(self, 200, {"pending": pending, "history": history, "stats": {"pending_count": len(pending)}})
                    return
                server._json(self, 404, {"error": "not_found"})

            def do_POST(self) -> None:  # noqa: N802
                parsed = urlsplit(self.path)
                path = parsed.path
                if path.startswith("/api/v1/approvals/") and path.endswith("/approve"):
                    request_id = path.split("/api/v1/approvals/", 1)[1].rsplit("/approve", 1)[0].strip("/")
                    with server._lock:
                        item = server._pending_approvals.pop(request_id, None)
                        ok = item is not None
                        if ok:
                            server._approval_history.insert(0, {"status": "approved", "agent_id": item["agent_id"], "tool_name": item["tool_name"], "timestamp": time.time()})
                    server._json(self, 200 if ok else 404, {"approved": ok, "approval_id": request_id})
                    return
                if path.startswith("/api/v1/approvals/") and path.endswith("/deny"):
                    request_id = path.split("/api/v1/approvals/", 1)[1].rsplit("/deny", 1)[0].strip("/")
                    with server._lock:
                        item = server._pending_approvals.pop(request_id, None)
                        ok = item is not None
                        if ok:
                            server._approval_history.insert(0, {"status": "denied", "agent_id": item["agent_id"], "tool_name": item["tool_name"], "timestamp": time.time()})
                    server._json(self, 200 if ok else 404, {"denied": ok, "approval_id": request_id})
                    return
                server._json(self, 404, {"error": "not_found"})

            def log_message(self, fmt: str, *args: Any) -> None:
                _ = (fmt, args)

        httpd = ThreadingHTTPServer(("0.0.0.0", max(1, int(port))), _Handler)
        print(f"Orchesis demo dashboard running at http://127.0.0.1:{int(port)}/dashboard")
        httpd.serve_forever()

