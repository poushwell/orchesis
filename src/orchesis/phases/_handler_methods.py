"""Handler method bodies for LLMHTTPProxy, extracted from proxy.py.

Mixed into LLMHTTPProxy as HandlerMethodsMixin. Method bodies kept
byte-identical to original form. Module-level helpers from proxy.py
are runtime-injected from proxy_async via proxy.py at the bottom of
proxy.py module load.
"""

from __future__ import annotations

from typing import Any, TYPE_CHECKING


class HandlerMethodsMixin:
    """HTTP handler methods (request dispatch + reload endpoints)."""

    def _handle_thresholds_reload(self, handler: BaseHTTPRequestHandler) -> None:
        """Hot-reload the threshold table from the current `policy["thresholds"]`.

        Atomic replacement: parses and validates the full new spec before
        swapping. On failure, the existing table is preserved unchanged.
        """
        thresholds_cfg = self._policy.get("thresholds")
        thresholds_lookups = self._policy.get("threshold_lookups") or {}
        if not isinstance(thresholds_cfg, dict):
            thresholds_cfg = DEFAULT_THRESHOLDS
        try:
            self._threshold_resolver.reload(thresholds_cfg, lookups=thresholds_lookups)
        except DslError as e:
            self._send_json(
                handler,
                400,
                {"status": "error", "message": "threshold_reload_failed", "detail": str(e)},
            )
            return
        self._send_json(
            handler,
            200,
            {
                "status": "reloaded",
                "thresholds_count": len(thresholds_cfg),
                "timestamp": time.time(),
            },
        )

    def _handle_pipeline_reload(self, handler: BaseHTTPRequestHandler) -> None:
        """Rebuild the plugin pipeline graph from current registered phases.

        In Checkpoint 1 this swap is functionally a no-op (only one phase is
        registered), but it exercises the registry refcount / snapshot machinery
        end-to-end so later checkpoints can rely on the same code path.
        """
        try:
            new_version = self._phase_registry.reload()
        except Exception as e:
            self._send_json(
                handler,
                500,
                {"status": "error", "message": "pipeline_reload_failed", "detail": str(e)},
            )
            return
        self._send_json(
            handler,
            200,
            {
                "status": "reloaded",
                "version": new_version,
                "in_flight": self._phase_registry.in_flight_count,
                "phase_count": len(self._phase_registry.current_graph),
                "timestamp": time.time(),
            },
        )

    def _handle_policy_reload(self, handler: BaseHTTPRequestHandler) -> None:
        policy_path = str(self._policy_path or "policy.yaml")
        try:
            loaded = load_policy(policy_path)
        except ValueError as error:
            self._send_json(handler, 400, {"status": "invalid", "errors": [str(error)]})
            return
        errors = validate_policy(loaded)
        if errors:
            self._send_json(handler, 400, {"status": "invalid", "errors": errors})
            return
        if not self.reload_policy(loaded):
            self._send_json(handler, 500, {"status": "error", "message": "policy_reload_failed"})
            return
        self._send_json(
            handler,
            200,
            {
                "status": "reloaded",
                "version": self._policy_hash(loaded),
                "timestamp": time.time(),
            },
        )
        self._state_tracker.flush()
        self._connection_pool.close_all()
        _evidence_ledger.flush()
        if self._recorder is not None:
            self._recorder.close_all()
        if self._otlp_exporter is not None:
            self._otlp_exporter.stop()
        if self._alert_manager is not None:
            self._alert_manager.stop()
        if self._telemetry_collector is not None:
            self._telemetry_collector.stop()
        if self._community is not None:
            self._community.stop()
        if self._thompson is not None:
            self._thompson.stop()

    def _inc(self, field: str) -> None:
        with self._stats_lock:
            self._stats[field] = int(self._stats.get(field, 0)) + 1
        if field == "blocked":
            self._add_dashboard_event("blocked", "medium", "Request blocked by runtime guardrail.")
            if self._compliance_enabled:
                self._compliance_engine.map_finding(
                    source_module="engine",
                    source_detail="tool_allowlist",
                    description="Runtime guardrail blocked a request.",
                    severity=Severity.MEDIUM,
                    evidence={"counter": "blocked"},
                )
        elif field == "errors":
            self._add_dashboard_event("error", "high", "Runtime error while processing request.")
            if self._compliance_enabled:
                self._compliance_engine.map_finding(
                    source_module="circuit_breaker",
                    source_detail="automated_response",
                    description="Runtime error recorded by proxy.",
                    severity=Severity.HIGH,
                    evidence={"counter": "errors"},
                )

    def _add_dashboard_event(
        self,
        event_type: str,
        severity: str,
        description: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        self._dashboard_events.append(
            {
                "timestamp": time.time(),
                "type": str(event_type),
                "severity": str(severity),
                "description": str(description),
                "metadata": metadata if isinstance(metadata, dict) else {},
            }
        )

    def _build_dashboard_overview(self) -> dict[str, Any]:
        stats = self.stats
        now = time.time()
        recent_events = sorted(
            self._dashboard_events, key=lambda e: float(e.get("timestamp", 0.0)), reverse=True
        )
        critical_recent = [
            e
            for e in recent_events
            if (now - float(e.get("timestamp", 0.0))) <= 60.0
            and str(e.get("severity", "")).lower() == "critical"
        ]
        blocked_recent = [
            e
            for e in recent_events
            if (now - float(e.get("timestamp", 0.0))) <= _DASHBOARD_RECENT_BLOCKED_WINDOW_SECONDS
            and e.get("type") == "blocked"
        ]
        circuit_state = str(stats.get("circuit_breaker", {}).get("state", "CLOSED")).upper()
        if circuit_state == "OPEN" or critical_recent:
            status = "alert"
        elif blocked_recent:
            status = "monitoring"
        else:
            status = "clear"
        flow_stats = stats.get("flow_xray", {}) if isinstance(stats.get("flow_xray"), dict) else {}
        behavioral_stats = (
            stats.get("behavioral_detector", {})
            if isinstance(stats.get("behavioral_detector"), dict)
            else {}
        )
        active_agents = int(behavioral_stats.get("agents_monitored", 0)) + int(
            behavioral_stats.get("agents_learning", 0)
        )
        circuit_breakers = {
            "default": {
                "state": str(stats.get("circuit_breaker", {}).get("state", "closed")).lower(),
                "failures": int(stats.get("circuit_breaker", {}).get("error_count", 0)),
            }
        }
        daily_limit = self._budget_cfg.get("daily")
        limit_usd = float(daily_limit) if isinstance(daily_limit, int | float) else 0.0
        spent_usd = float(stats.get("cost_today", 0.0))
        budget = {
            "limit_usd": limit_usd,
            "spent_usd": spent_usd,
            "remaining_usd": max(0.0, limit_usd - spent_usd) if limit_usd > 0 else 0.0,
        }
        return {
            "status": status,
            "uptime_seconds": max(0.0, now - self._start_time),
            "total_requests": int(stats.get("requests", 0)),
            "blocked_requests": int(stats.get("blocked", 0)),
            "total_cost_usd": float(stats.get("cost_today", 0.0)),
            "active_agents": active_agents,
            "cost_velocity": self._cost_velocity.get_stats(),
            "overwatch_health": self._overwatch_health_grade(),
            "money_saved_usd": self._estimate_money_saved(),
            "compliance_overview": self._build_compliance_overview(stats),
            "approvals_pending": (
                int(self._tool_policy.approval_queue.get_stats().get("pending_count", 0))
                if self._tool_policy is not None
                else 0
            ),
            "circuit_breakers": circuit_breakers,
            "budget": budget,
            "recent_events": recent_events[:20],
            "cost_timeline": list(self._dashboard_cost_timeline),
            "flow_xray": flow_stats,
            "connection_pool": stats.get("proxy_engine", {}).get("connection_pool", {}),
            "savings": self._build_savings_payload(),
        }

    def _overwatch_health_grade(self) -> str:
        if self._agent_discovery is None or not self._agent_discovery.enabled:
            return "A"
        profiles = self._agent_discovery.get_all_agents()
        if not profiles:
            return "A"
        rank = {"A": 0, "B": 1, "C": 2, "D": 3, "F": 4}
        worst = "A"
        for item in profiles:
            grade = str(item.ars_grade or "").upper()
            if grade not in rank:
                continue
            if rank[grade] > rank[worst]:
                worst = grade
        return worst

    def _estimate_money_saved(self) -> float:
        stats = self.stats
        cache_tokens = 0.0
        context_tokens = 0.0
        sem = stats.get("semantic_cache", {})
        if isinstance(sem, dict):
            cache_tokens = float(sem.get("total_tokens_saved", 0.0) or 0.0)
        context_opt = stats.get("context_optimizer", {})
        if isinstance(context_opt, dict):
            original = float(context_opt.get("total_original_tokens", 0.0) or 0.0)
            optimized = float(context_opt.get("total_optimized_tokens", 0.0) or 0.0)
            context_tokens = max(0.0, original - optimized)
        return round((cache_tokens + context_tokens) * 0.000003, 6)

    @staticmethod
    def _build_compliance_overview(stats: dict[str, Any]) -> dict[str, Any]:
        comp = stats.get("compliance", {}) if isinstance(stats.get("compliance"), dict) else {}
        frameworks = comp.get("frameworks", {}) if isinstance(comp.get("frameworks"), dict) else {}
        owasp = (
            frameworks.get("owasp_llm_top10_2025", {})
            if isinstance(frameworks.get("owasp_llm_top10_2025"), dict)
            else {}
        )
        nist = (
            frameworks.get("nist_ai_rmf_1_0", {})
            if isinstance(frameworks.get("nist_ai_rmf_1_0"), dict)
            else {}
        )
        return {
            "mast": {
                "score": 78.6,
                "covered": 11,
                "total": 14,
                "gaps": [
                    "M12 Cascading Failure",
                    "M13 Resource Exhaustion",
                    "M14 Emergent Behavior",
                ],
            },
            "owasp_agentic_ai": {
                "score": float(owasp.get("percent", 0.0) or 0.0),
                "covered": 8,
                "total": 10,
                "gaps": ["ASI-09 Insufficient Logging", "ASI-10 Unsafe Plugin Design"],
            },
            "eu_ai_act": {
                "score": 60.0,
                "audit_trail": True,
                "incident_reporting": True,
                "risk_assessment": "partial",
                "human_oversight": "partial",
                "documentation": False,
            },
            "nist_ai_rmf": {
                "score": float(nist.get("percent", 0.0) or 0.0),
                "govern": "full",
                "map": "partial",
                "measure": "full",
                "manage": "partial",
            },
        }

    def _build_savings_payload(self) -> dict[str, Any]:
        stats = self.stats
        semantic_stats = (
            stats.get("semantic_cache", {}) if isinstance(stats.get("semantic_cache"), dict) else {}
        )
        cache_savings = float(semantic_stats.get("total_cost_saved_usd", 0.0))
        cache_hits = int(semantic_stats.get("exact_hits", 0)) + int(
            semantic_stats.get("semantic_hits", 0)
        )
        cascade_savings = float(self._cost_tracker.get_cascade_savings_today())
        cascade_stats = stats.get("cascade_requests_by_level", {})
        cascaded_requests = 0
        if isinstance(cascade_stats, dict):
            cascaded_requests = int(
                cascade_stats.get("trivial", 0)
                + cascade_stats.get("simple", 0)
                + cascade_stats.get("medium", 0)
                + cascade_stats.get("complex", 0)
            )
        loop_blocked = 0
        if self._content_loop_detector is not None:
            loop_blocked = int(self._content_loop_detector.stats.get("blocked", 0))
        loop_savings = float(loop_blocked * self._estimated_avg_request_cost_usd)
        total_savings = cache_savings + cascade_savings + loop_savings
        return {
            "cache_savings": round(cache_savings, 6),
            "cascade_savings": round(cascade_savings, 6),
            "loop_savings": round(loop_savings, 6),
            "total_savings": round(total_savings, 6),
            "details": {
                "cache_hits": cache_hits,
                "cascaded_requests": cascaded_requests,
                "loops_blocked": loop_blocked,
            },
        }

    def _build_dashboard_agents(self) -> dict[str, Any]:
        if not self._behavioral_detector.enabled:
            return {"agents": []}
        agents_payload: list[dict[str, Any]] = []
        with self._behavioral_detector._lock:  # noqa: SLF001 - internal read for dashboard endpoint
            agent_ids = list(self._behavioral_detector._agents.keys())  # noqa: SLF001
        for agent_id in agent_ids:
            profile = self._behavioral_detector.get_agent_profile(agent_id)
            if not isinstance(profile, dict):
                continue
            dims = (
                profile.get("dimensions", {}) if isinstance(profile.get("dimensions"), dict) else {}
            )
            prompt_mean = (
                float(dims.get("prompt_tokens", {}).get("mean", 0.0))
                if isinstance(dims.get("prompt_tokens"), dict)
                else 0.0
            )
            completion_mean = (
                float(dims.get("completion_tokens", {}).get("mean", 0.0))
                if isinstance(dims.get("completion_tokens"), dict)
                else 0.0
            )
            anomaly_score = min(
                1.0,
                max(
                    0.0,
                    float(dims.get("error_rate", {}).get("mean", 0.0))
                    if isinstance(dims.get("error_rate"), dict)
                    else 0.0,
                ),
            )
            agents_payload.append(
                {
                    "agent_id": agent_id,
                    "state": str(profile.get("state", "monitoring")),
                    "total_requests": int(profile.get("total_requests", 0)),
                    "avg_tokens": round(prompt_mean + completion_mean, 4),
                    "anomaly_score": round(anomaly_score, 6),
                    "tools_used": sorted(list((profile.get("tool_distribution") or {}).keys()))
                    if isinstance(profile.get("tool_distribution"), dict)
                    else [],
                    "last_seen": str(profile.get("last_seen", "")),
                    "request_frequency": float(dims.get("request_frequency", {}).get("mean", 0.0))
                    if isinstance(dims.get("request_frequency"), dict)
                    else 0.0,
                    "anomaly_scores": {"error_rate": anomaly_score},
                }
            )
        agents_payload.sort(key=lambda item: float(item.get("total_requests", 0)), reverse=True)
        return {"agents": agents_payload}

    def _handle_session_export(
        self,
        handler: BaseHTTPRequestHandler,
        session_id: str,
        query_params: dict[str, list[str]],
    ) -> None:
        if self._recorder is None:
            self._send_json(handler, 404, {"error": "recording_not_enabled"})
            return
        if not session_id:
            self._send_json(handler, 400, {"error": "session_id_required"})
            return
        content_level = (
            str((query_params.get("content_level") or ["structure"])[0]).strip().lower()
            or "structure"
        )
        format_name = str((query_params.get("format") or ["air"])[0]).strip().lower() or "air"
        download = str((query_params.get("download") or ["false"])[0]).strip().lower() == "true"
        if format_name != "air":
            self._send_json(handler, 400, {"error": "unsupported_format", "format": format_name})
            return
        try:
            doc = export_session_to_air(
                session_id=session_id,
                recorder=self._recorder,
                flow_analyzer=self._flow_analyzer,
                behavioral_detector=self._behavioral_detector
                if self._behavioral_detector.enabled
                else None,
                compliance_engine=self._compliance_engine if self._compliance_enabled else None,
                content_level=content_level,
                version=ORCHESIS_VERSION,
            )
        except ValueError as exc:
            self._send_json(handler, 400, {"error": "invalid_content_level", "message": str(exc)})
            return
        if "error" in doc:
            self._send_json(handler, 404, doc)
            return
        if download:
            self._send_json(
                handler,
                200,
                doc,
                extra_headers={
                    "Content-Disposition": f'attachment; filename="session_{session_id}.air"'
                },
            )
            return
        self._send_json(handler, 200, doc)

    def _handle_get(self, handler: BaseHTTPRequestHandler) -> None:
        parsed = urlsplit(handler.path)
        path = parsed.path
        query_params = parse_qs(parsed.query, keep_blank_values=True)
        if path in {"/dashboard", "/dashboard/"}:
            payload = get_dashboard_html().encode("utf-8")
            handler.send_response(200)
            handler.send_header("Content-Type", "text/html; charset=utf-8")
            handler.send_header("Content-Length", str(len(payload)))
            handler.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
            handler.send_header("Pragma", "no-cache")
            handler.send_header("Expires", "0")
            if self._config.cors:
                handler.send_header("Access-Control-Allow-Origin", "*")
            handler.end_headers()
            handler.wfile.write(payload)
            return
        if path == "/favicon.ico":
            handler.send_response(204)
            handler.send_header("Content-Length", "0")
            if self._config.cors:
                handler.send_header("Access-Control-Allow-Origin", "*")
            handler.end_headers()
            return
        if path in {"/", "/health"}:
            self._send_json(
                handler,
                200,
                {
                    "status": "ok",
                    "proxy": f"{self._config.host}:{self._config.port}",
                    "policy": self._policy_path or "none",
                    "stats": self.stats,
                    "model_routing": self._router is not None,
                    "loop_detection": self._loop_detector is not None,
                    "killed": self._killed,
                    "kill_reason": self._kill_reason,
                    "killed_at": self._kill_time,
                },
            )
            return
        if path in {"/stats", "/api/v1/stats"}:
            self._send_json(handler, 200, self.stats)
            return
        if path == "/api/v1/telemetry/stats":
            if self._telemetry_collector is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._telemetry_collector.stats)
            return
        if path == "/api/v1/telemetry/export":
            if self._telemetry_collector is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            last_raw = (query_params.get("last") or ["0"])[0]
            try:
                last_n = max(0, int(last_raw))
            except Exception:
                last_n = 0
            fmt = str((query_params.get("format") or ["json"])[0]).strip().lower()
            records = self._telemetry_collector.get_records(last_n=last_n)
            if fmt == "jsonl":
                lines = "\n".join(json.dumps(item, default=str) for item in records)
                payload = lines.encode("utf-8")
                handler.send_response(200)
                handler.send_header("Content-Type", "application/x-ndjson")
                handler.send_header("Content-Length", str(len(payload)))
                if self._config.cors:
                    handler.send_header("Access-Control-Allow-Origin", "*")
                handler.end_headers()
                handler.wfile.write(payload)
                return
            self._send_json(handler, 200, {"records": records, "count": len(records)})
            return
        if path == "/api/v1/alerts":
            payload = (
                {"enabled": self._alert_manager.enabled, "stats": self._alert_manager.stats}
                if self._alert_manager is not None
                else {
                    "enabled": False,
                    "stats": {
                        "sent": 0,
                        "dropped_rate_limit": 0,
                        "dropped_severity": 0,
                        "errors": 0,
                    },
                }
            )
            self._send_json(handler, 200, payload)
            return
        if path == "/api/v1/detection":
            if self._adaptive_detector is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._adaptive_detector.get_all_agents())
            return
        if path.startswith("/api/v1/detection/"):
            agent_id = path.split("/api/v1/detection/", 1)[1].strip("/")
            if self._adaptive_detector is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._adaptive_detector.get_agent_status(agent_id))
            return
        if path == "/api/v1/community":
            if self._community is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, asdict(self._community.get_stats()))
            return
        if path.startswith("/api/v1/mast/"):
            agent_id = path.split("/api/v1/mast/", 1)[1].strip("/")
            if self._mast is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._mast.get_agent_compliance(agent_id))
            return
        if path.startswith("/api/v1/healing/"):
            agent_id = path.split("/api/v1/healing/", 1)[1].strip("/")
            if self._auto_healer is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._auto_healer.get_agent_healing_history(agent_id))
            return
        if path == "/api/v1/agents":
            if self._agent_discovery is None or not self._agent_discovery.enabled:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(
                handler, 200, [asdict(item) for item in self._agent_discovery.get_all_agents()]
            )
            return
        if path == "/api/v1/agents/summary":
            if self._agent_discovery is None or not self._agent_discovery.enabled:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._agent_discovery.get_summary())
            return
        if path.startswith("/api/v1/agents/"):
            agent_id = path.split("/api/v1/agents/", 1)[1].strip("/")
            if self._agent_discovery is None or not self._agent_discovery.enabled:
                self._send_json(handler, 200, {"enabled": False})
                return
            profile = self._agent_discovery.get_agent(agent_id)
            if profile is None:
                self._send_json(handler, 200, {"found": False, "agent_id": agent_id})
                return
            self._send_json(handler, 200, asdict(profile))
            return
        if path == "/api/v1/tools":
            if self._tool_policy is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._tool_policy.get_tool_stats())
            return
        if path == "/api/v1/tools/blocked":
            if self._tool_policy is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._tool_policy.get_blocked_attempts())
            return
        if path == "/api/v1/approvals":
            if self._tool_policy is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(
                handler,
                200,
                {
                    "pending": self._tool_policy.approval_queue.get_pending(),
                    "history": self._tool_policy.approval_queue.get_history(),
                    "stats": self._tool_policy.approval_queue.get_stats(),
                },
            )
            return
        if path == "/api/v1/router":
            if self._thompson is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(
                handler,
                200,
                {
                    "enabled": True,
                    "model_stats": self._thompson.get_model_stats(),
                    "report": self._thompson.get_routing_report(),
                },
            )
            return
        if path == "/api/v1/router/recommend":
            if self._thompson is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._thompson.get_recommendation())
            return
        if path.startswith("/api/v1/session-risk/"):
            session_id = path.split("/api/v1/session-risk/", 1)[1].strip("/")
            if self._session_risk is None:
                self._send_json(handler, 200, {"error": "session_risk not enabled"})
                return
            state = self._session_risk.get_session_state(session_id)
            self._send_json(handler, 200, state or {"error": "session not found"})
            return
        if path == "/api/v1/ars":
            if self._ars is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            results = self._ars.compute_all()
            self._send_json(
                handler,
                200,
                {
                    "agents": [
                        {
                            "agent_id": item.agent_id,
                            "score": item.score,
                            "grade": item.grade,
                            "components": item.components,
                            "sample_size": item.sample_size,
                            "confidence": item.confidence,
                        }
                        for item in results
                    ]
                },
            )
            return
        if path.startswith("/api/v1/ars/"):
            agent_id = path.split("/api/v1/ars/", 1)[1].strip("/")
            if self._ars is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            result = self._ars.compute(agent_id)
            if result is None:
                self._send_json(handler, 200, {"error": "agent not found"})
                return
            self._send_json(
                handler,
                200,
                {
                    "agent_id": result.agent_id,
                    "score": result.score,
                    "grade": result.grade,
                    "components": result.components,
                    "sample_size": result.sample_size,
                    "confidence": result.confidence,
                },
            )
            return
        if path == "/api/v1/savings":
            self._send_json(handler, 200, self._build_savings_payload())
            return
        if path == "/api/threats" or path == "/api/threats/":
            if self._threat_matcher is None:
                self._send_json(handler, 200, {"threats": []})
                return
            category = (query_params.get("category") or [""])[0]
            severity = (query_params.get("severity") or [""])[0]
            threats = self._threat_matcher.list_threats(
                category=str(category) if category else "",
                severity=str(severity) if severity else "",
            )
            self._send_json(handler, 200, {"threats": threats})
            return
        if path.startswith("/api/threats/") and path != "/api/threats/stats":
            threat_id = path.split("/api/threats/", 1)[1].strip("/")
            if self._threat_matcher is None:
                self._send_json(handler, 404, {"error": "threat_intel_not_enabled"})
                return
            sig = self._threat_matcher.get_threat(threat_id)
            if sig is None:
                self._send_json(handler, 404, {"error": "threat_not_found", "threat_id": threat_id})
                return
            self._send_json(
                handler,
                200,
                {
                    "threat_id": sig.threat_id,
                    "name": sig.name,
                    "category": sig.category.value,
                    "severity": sig.severity.value,
                    "description": sig.description,
                    "detection": sig.detection,
                    "mitigation": sig.mitigation,
                    "owasp_ref": sig.owasp_ref,
                    "mitre_ref": sig.mitre_ref,
                    "references": list(sig.references),
                },
            )
            return
        if path == "/api/threats/stats":
            if self._threat_matcher is None:
                self._send_json(handler, 200, {"enabled": False})
                return
            self._send_json(handler, 200, self._threat_matcher.get_stats())
            return
        if path == "/api/dashboard/overview":
            self._send_json(handler, 200, self._build_dashboard_overview())
            return
        if path == "/api/dashboard/agents":
            self._send_json(handler, 200, self._build_dashboard_agents())
            return
        if path in {"/api/sessions", "/sessions"} and self._recorder is not None:
            sessions = [asdict(item) for item in self._recorder.list_sessions()]
            self._send_json(handler, 200, {"sessions": sessions})
            return
        if path.startswith("/api/sessions/") and path.endswith("/export"):
            session_id = path[len("/api/sessions/") : -len("/export")].strip("/")
            self._handle_session_export(handler, session_id, query_params)
            return
        if (
            path.startswith("/sessions/") or path.startswith("/api/sessions/")
        ) and self._recorder is not None:
            session_id = (
                path.split("/api/sessions/", 1)[1].strip()
                if path.startswith("/api/sessions/")
                else path.split("/sessions/", 1)[1].strip()
            )
            if not session_id:
                self._send_json(handler, 400, {"error": "session_id_required"})
                return
            try:
                summary = self._recorder.get_session_summary(session_id)
            except FileNotFoundError:
                self._send_json(handler, 404, {"error": "session_not_found"})
                return
            self._send_json(handler, 200, {"session": asdict(summary)})
            return
        if path == "/api/flow/sessions":
            if self._flow_analyzer is None:
                self._send_json(handler, 200, {"sessions": []})
                return
            self._send_json(handler, 200, {"sessions": self._flow_analyzer.list_sessions()})
            return
        if path.startswith("/api/flow/analyze/"):
            if self._flow_analyzer is None:
                self._send_json(handler, 404, {"error": "Session not found"})
                return
            session_id = path.split("/api/flow/analyze/", 1)[1].strip()
            analysis = self._flow_analyzer.analyze_session(session_id)
            if analysis is None:
                self._send_json(handler, 404, {"error": "Session not found"})
                return
            self._send_json(handler, 200, analysis.to_dict())
            return
        if path.startswith("/api/flow/graph/"):
            if self._flow_analyzer is None:
                self._send_json(handler, 404, {"error": "Session not found"})
                return
            session_id = path.split("/api/flow/graph/", 1)[1].strip()
            graph_json = self._flow_analyzer.export_graph_json(session_id)
            if not graph_json:
                self._send_json(handler, 404, {"error": "Session not found"})
                return
            self._send_json(handler, 200, json.loads(graph_json))
            return
        if path == "/api/flow/patterns":
            if self._flow_analyzer is None:
                self._send_json(handler, 200, {"sessions_tracked": 0, "pattern_counts": {}})
                return
            self._send_json(handler, 200, self._flow_analyzer.get_stats())
            return
        if path == "/api/compliance/summary":
            self._send_json(handler, 200, self._compliance_engine.get_summary())
            return
        if path == "/api/compliance/coverage":
            reports: dict[str, Any] = {}
            for framework in self._compliance_engine._frameworks:  # noqa: SLF001
                reports[framework.value] = self._compliance_engine.get_coverage_report(framework)
            self._send_json(handler, 200, {"frameworks": reports})
            return
        if path.startswith("/api/compliance/coverage/"):
            framework_token = path.split("/api/compliance/coverage/", 1)[1].strip().lower()
            framework = ComplianceEngine._framework_from_alias(framework_token)
            if framework is None:
                self._send_json(handler, 404, {"error": "framework_not_found"})
                return
            self._send_json(handler, 200, self._compliance_engine.get_coverage_report(framework))
            return
        if path == "/api/compliance/findings":
            framework = ComplianceEngine._framework_from_alias(
                (query_params.get("framework") or [None])[0]
            )
            severity_token = (query_params.get("severity") or [None])[0]
            sev = None
            if isinstance(severity_token, str) and severity_token.strip():
                try:
                    sev = Severity(severity_token.strip().lower())
                except Exception:
                    sev = None
            limit_raw = (query_params.get("limit") or ["100"])[0]
            try:
                limit = int(limit_raw)
            except Exception:
                limit = 100
            findings = self._compliance_engine.get_findings(
                framework=framework, severity=sev, limit=limit
            )
            self._send_json(
                handler,
                200,
                {
                    "findings": [
                        {
                            **asdict(item),
                            "severity": item.severity.value,
                        }
                        for item in findings
                    ]
                },
            )
            return
        if path == "/api/experiments" and self._experiment_manager is not None:
            self._send_json(
                handler, 200, {"experiments": self._experiment_manager.list_experiments()}
            )
            return
        if (
            path.startswith("/api/experiments/")
            and path.endswith("/results")
            and self._experiment_manager is not None
        ):
            parts = path.split("/")
            exp_id = parts[3] if len(parts) > 3 else ""
            if exp_id:
                try:
                    result = self._experiment_manager.get_results(exp_id)
                    self._send_json(handler, 200, result.to_dict())
                except ValueError:
                    self._send_json(handler, 404, {"error": "experiment_not_found"})
            else:
                self._send_json(handler, 404, {"error": "experiment_id_required"})
            return
        if (
            path.startswith("/api/experiments/")
            and path.endswith("/live")
            and self._experiment_manager is not None
        ):
            parts = path.split("/")
            exp_id = parts[3] if len(parts) > 3 else ""
            if exp_id:
                stats = self._experiment_manager.get_live_stats(exp_id)
                self._send_json(handler, 200, stats)
            else:
                self._send_json(handler, 404, {"error": "experiment_id_required"})
            return
        if path == "/api/tasks/outcomes" and self._experiment_manager is not None:
            outcomes = self._experiment_manager._task_tracker.get_outcome_distribution()
            self._send_json(handler, 200, outcomes)
            return
        if path == "/api/tasks/correlations" and self._experiment_manager is not None:
            correlations = self._experiment_manager._task_tracker.get_correlations()
            self._send_json(handler, 200, correlations)
            return
        if path.startswith("/api/tasks/sessions/") and self._experiment_manager is not None:
            session_id = path.split("/api/tasks/sessions/", 1)[1].strip()
            if session_id:
                state = self._experiment_manager._task_tracker.get_session_state(session_id)
                if state:
                    sess_dict = asdict(state)
                    if hasattr(state.outcome, "value"):
                        sess_dict["outcome"] = state.outcome.value
                    self._send_json(handler, 200, {"session": sess_dict})
                else:
                    self._send_json(handler, 404, {"error": "session_not_found"})
            else:
                self._send_json(handler, 400, {"error": "session_id_required"})
            return
        if path == "/api/compliance/report":
            fmt = str((query_params.get("format") or ["json"])[0]).strip().lower()
            report = self._compliance_engine.export_report(format=fmt)
            if isinstance(report, str):
                payload = report.encode("utf-8")
                handler.send_response(200)
                handler.send_header("Content-Type", "text/markdown; charset=utf-8")
                handler.send_header("Content-Length", str(len(payload)))
                if self._config.cors:
                    handler.send_header("Access-Control-Allow-Origin", "*")
                handler.end_headers()
                handler.wfile.write(payload)
                return
            self._send_json(handler, 200, report)
            return
        self._send_json(handler, 404, {"error": "Not found"})

    def _run_phase_span(
        self,
        ctx: _RequestContext,
        phase_name: str,
        phase_fn: Any,
        extra_attrs: dict[str, str | int | float | bool] | None = None,
    ) -> bool:
        """Run a phase and optionally emit a span. Returns phase result."""
        if phase_name in getattr(ctx, "skip_phases", set()):
            return True
        if self._span_emitter is None or ctx.trace_ctx is None:
            return phase_fn(ctx)
        parent_id = ctx.root_span.span_id if ctx.root_span else None
        span = self._span_emitter.create_phase_span(phase_name, ctx.trace_ctx, parent_id or "")
        try:
            ok = phase_fn(ctx)
            attrs = dict(extra_attrs or {})
            if phase_name == "cascade":
                attrs["orchesis.cascade_level"] = getattr(ctx, "cascade_level_name", "") or ""
                attrs["orchesis.cache_hit"] = getattr(ctx, "cascade_cache_state", "") == "hit"
            elif phase_name == "threat_intel":
                attrs["orchesis.threat_detected"] = bool(getattr(ctx, "threat_matches", []))
                matches = getattr(ctx, "threat_matches", []) or []
                attrs["orchesis.threat_ids"] = ",".join(
                    getattr(m, "threat_id", str(m)) for m in matches[:5]
                )[:200]
            elif phase_name == "loop_detection":
                attrs["orchesis.loop_detected"] = getattr(ctx, "was_loop_detected", False)
            elif phase_name == "context":
                attrs["orchesis.context_tokens_saved"] = getattr(ctx, "context_tokens_saved", 0)
            elif phase_name == "post_upstream" and getattr(ctx, "from_semantic_cache", False):
                attrs["orchesis.cache_hit"] = True
                attrs["orchesis.cache_type"] = "semantic"
            self._span_emitter.end_span(span, status="OK" if ok else "ERROR", attributes=attrs)
            return ok
        except Exception:
            self._span_emitter.end_span(span, status="ERROR")
            raise

    def _run_migrated_phase(self, ctx: "_RequestContext", phase_name: str) -> bool:
        """Dispatch a Checkpoint-2 migrated phase through the plugin engine.

        Lazily builds the new RequestContext on first call per request and
        caches it on the legacy ctx so subsequent migrated phases reuse it.
        Phase logic still lives in the proxy's `_phase_<name>` method; the
        wrapper plugin reads `_legacy_ctx` from `params` to call back into it.
        """
        if phase_name in getattr(ctx, "skip_phases", set()):
            return True
        pl_ctx = getattr(ctx, "_pipeline_ctx", None)
        if pl_ctx is None:
            pl_ctx = self._build_pipeline_ctx(ctx)
            pl_ctx.processed.params["_legacy_ctx"] = ctx
            ctx._pipeline_ctx = pl_ctx  # type: ignore[attr-defined]
        span = None
        if self._span_emitter is not None and ctx.trace_ctx is not None:
            parent_id = ctx.root_span.span_id if ctx.root_span else ""
            span = self._span_emitter.create_phase_span(
                phase_name, ctx.trace_ctx, parent_id or ""
            )
        try:
            try:
                result = asyncio.run(
                    self._pipeline_engine.process_one(phase_name, pl_ctx)
                )
            except RuntimeError:
                # Already inside a running event loop (defensive — proxy is
                # sync but tests can run inside asyncio.run).
                loop = asyncio.new_event_loop()
                try:
                    result = loop.run_until_complete(
                        self._pipeline_engine.process_one(phase_name, pl_ctx)
                    )
                finally:
                    loop.close()
        except Exception:
            if span is not None:
                self._span_emitter.end_span(span, status="ERROR")
            raise
        ok = result.status in ("pass", "skip")
        if span is not None:
            self._span_emitter.end_span(
                span, status="OK" if ok else "ERROR"
            )
        return ok

    def _handle_post(self, handler: BaseHTTPRequestHandler) -> None:
        self._inc("requests")
        parsed_path = urlsplit(handler.path)
        request_path = parsed_path.path
        query_params = parse_qs(parsed_path.query, keep_blank_values=True)
        ctx = _RequestContext(
            handler=handler,
            request_started=time.perf_counter(),
            circuit_state_header=self._circuit_breaker.get_state().lower().replace("_", "-"),
            session_id=self._resolve_session_id(handler.headers),
            request_id=uuid.uuid4().hex if self._recorder is not None else "",
        )
        ctx.session_headers = (
            {"X-Orchesis-Session-Id": ctx.session_id, "X-Orchesis-Request-Id": ctx.request_id}
            if self._recorder is not None
            else {}
        )
        if self._span_emitter:
            headers_dict = {k: v for k, v in handler.headers.items()}
            ctx.trace_ctx = TraceContext.from_headers(headers_dict)
        try:
            if request_path == "/api/v1/telemetry/export-file":
                if self._telemetry_collector is None:
                    self._send_json(handler, 200, {"enabled": False})
                    return
                fmt = str((query_params.get("format") or ["jsonl"])[0]).strip().lower()
                if fmt == "csv":
                    export_path = "telemetry_export.csv"
                    count = self._telemetry_collector.export_csv(export_path)
                else:
                    export_path = "telemetry_export.jsonl"
                    count = self._telemetry_collector.export_jsonl(export_path)
                self._send_json(handler, 200, {"exported": count, "path": export_path})
                return
            if request_path.startswith("/api/v1/approvals/") and request_path.endswith("/approve"):
                if self._tool_policy is None:
                    self._send_json(handler, 200, {"enabled": False})
                    return
                approval_id = (
                    request_path.split("/api/v1/approvals/", 1)[1]
                    .rsplit("/approve", 1)[0]
                    .strip("/")
                )
                ok = self._tool_policy.approval_queue.approve(approval_id)
                self._send_json(
                    handler, 200 if ok else 404, {"approved": ok, "approval_id": approval_id}
                )
                return
            if request_path.startswith("/api/v1/approvals/") and request_path.endswith("/deny"):
                if self._tool_policy is None:
                    self._send_json(handler, 200, {"enabled": False})
                    return
                approval_id = (
                    request_path.split("/api/v1/approvals/", 1)[1].rsplit("/deny", 1)[0].strip("/")
                )
                ok = self._tool_policy.approval_queue.deny(approval_id)
                self._send_json(
                    handler, 200 if ok else 404, {"denied": ok, "approval_id": approval_id}
                )
                return
            if request_path == "/kill":
                self._handle_kill(handler)
                return
            if request_path == "/resume":
                self._handle_resume(handler)
                return
            if request_path == "/api/v1/policy/reload":
                self._handle_policy_reload(handler)
                return
            if request_path == "/api/v1/pipeline/reload":
                self._handle_pipeline_reload(handler)
                return
            if request_path == "/api/v1/thresholds/reload":
                self._handle_thresholds_reload(handler)
                return
            if self._experiment_manager is not None and request_path == "/api/experiments":
                body = self._read_json_body(handler)
                if bool(getattr(handler, "_orchesis_body_too_large", False)):
                    return
                if isinstance(body, dict) and body.get("name") and body.get("variants"):
                    try:
                        exp = self._experiment_manager.create_experiment(**body)
                        self._send_json(handler, 201, exp.to_dict())
                    except ValueError as e:
                        self._send_json(handler, 400, {"error": str(e)})
                else:
                    self._send_json(handler, 400, {"error": "name and variants required"})
                return
            if self._experiment_manager is not None and "/api/experiments/" in handler.path:
                parts = handler.path.split("/")
                if len(parts) >= 4:
                    exp_id = parts[3]
                    if handler.path.endswith("/start"):
                        ok = self._experiment_manager.start_experiment(exp_id)
                        self._send_json(handler, 200 if ok else 409, {"started": ok})
                        return
                    if handler.path.endswith("/stop"):
                        try:
                            result = self._experiment_manager.stop_experiment(exp_id)
                            self._send_json(handler, 200, result.to_dict())
                        except ValueError:
                            self._send_json(handler, 404, {"error": "experiment_not_found"})
                        return
                    if handler.path.endswith("/pause"):
                        ok = self._experiment_manager.pause_experiment(exp_id)
                        self._send_json(handler, 200 if ok else 409, {"paused": ok})
                        return
                    if handler.path.endswith("/resume"):
                        ok = self._experiment_manager.resume_experiment(exp_id)
                        self._send_json(handler, 200 if ok else 409, {"resumed": ok})
                        return
            if self._killed:
                self._inc("blocked")
                self._send_json(
                    handler,
                    503,
                    {
                        "error": {
                            "type": "kill_switch",
                            "message": self._kill_reason or "Emergency kill switch is active",
                            "killed_at": self._kill_time,
                        }
                    },
                )
                return
            self._compute_fast_path_skip_phases(ctx)
            if not self._run_migrated_phase(ctx, "parse"):
                return
            # CompressionDecodePhase: no-op when no Content-Encoding header
            # set; otherwise decompresses + reparses the body. Failure blocks.
            if not self._run_migrated_phase(ctx, "compression_decode"):
                return
            if self._span_emitter and ctx.trace_ctx:
                agent_id = (
                    ctx.handler.headers.get("X-Orchesis-Agent")
                    or ctx.handler.headers.get("x-orchesis-agent")
                    or ctx.behavior_agent_id
                    or ""
                )
                ctx.root_span = self._span_emitter.create_request_span(
                    ctx.trace_ctx,
                    model=str(ctx.body.get("model", ctx.parsed_req.model or "")),
                    provider=ctx.parsed_req.provider or "",
                    session_id=ctx.session_id or "",
                    agent_id=agent_id,
                )
            if not self._run_migrated_phase(ctx, "experiment"):
                return
            if not self._run_migrated_phase(ctx, "flow_xray_record"):
                return
            if not self._run_migrated_phase(ctx, "cascade"):
                if ctx.root_span:
                    self._span_emitter.end_span(
                        ctx.root_span,
                        attributes={
                            "orchesis.cascade_level": str(getattr(ctx, "cascade_level_name", "")),
                            "orchesis.cache_hit": bool(
                                getattr(ctx, "cascade_cache_state", "") == "hit"
                            ),
                        },
                    )
                return

            def _end_root_early() -> None:
                if ctx.root_span and self._span_emitter:
                    self._span_emitter.end_span(
                        ctx.root_span,
                        status="OK",
                        attributes={"orchesis.decision": "block"},
                    )

            if not self._run_migrated_phase(ctx, "circuit_breaker"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "loop_detection"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "behavioral"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "adaptive_detection"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "mast_request"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "auto_healing"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "budget"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "policy"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "threat_intel"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "model_router"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "secrets"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "context"):
                _end_root_early()
                return
            # CanonicalizePhase: byte-deterministic canonical form for cache
            # keys + provider adapter dispatch. Skipped when already
            # canonicalized; blocks only when the amplification guard fires.
            if not self._run_migrated_phase(ctx, "canonicalize"):
                return
            if not self._run_migrated_phase(ctx, "upstream"):
                _end_root_early()
                return
            if not self._run_migrated_phase(ctx, "post_upstream"):
                _end_root_early()
                return
            if ctx.root_span:
                cost = (
                    (ctx.proc_result or {}).get("cost", 0.0)
                    if isinstance(ctx.proc_result, dict)
                    else 0.0
                )
                parsed = ctx.parsed_resp_obj
                self._span_emitter.end_span(
                    ctx.root_span,
                    attributes={
                        "gen_ai.response.model": str(ctx.body.get("model", "")),
                        "gen_ai.usage.input_tokens": getattr(parsed, "input_tokens", 0)
                        if parsed
                        else 0,
                        "gen_ai.usage.output_tokens": getattr(parsed, "output_tokens", 0)
                        if parsed
                        else 0,
                        "gen_ai.response.finish_reasons": getattr(parsed, "stop_reason", "")
                        if parsed
                        else "",
                        "orchesis.cost_usd": float(cost)
                        if isinstance(ctx.proc_result, dict)
                        else 0.0,
                        "orchesis.decision": "allow",
                        "orchesis.experiment_id": getattr(ctx, "experiment_id", "") or "",
                        "orchesis.variant_name": getattr(ctx, "variant_name", "") or "",
                    },
                )
            self._run_migrated_phase(ctx, "send_response")
        except Exception as error:  # noqa: BLE001
            _HTTP_PROXY_LOGGER.exception("proxy runtime error")
            self._inc("errors")
            self._send_json(
                handler,
                500,
                {"error": {"type": "proxy_error", "message": str(error)}},
                extra_headers=ctx.session_headers,
            )
        finally:
            self._record_telemetry_for_ctx(ctx)

    def _record_telemetry_for_ctx(self, ctx: _RequestContext) -> None:
        try:
            proc = ctx.proc_result if isinstance(ctx.proc_result, dict) else {}
            if not isinstance(proc, dict):
                proc = {}
            elapsed_ms = (time.perf_counter() - float(ctx.request_started or 0.0)) * 1000.0
            if elapsed_ms > 0:
                proc["total_ms"] = float(proc.get("total_ms", 0.0) or elapsed_ms)
            if "upstream_ms" not in proc:
                proc["upstream_ms"] = float(proc.get("upstream_ms", 0.0) or 0.0)
            if "request_id" not in proc or not proc.get("request_id"):
                proc["request_id"] = str(ctx.request_id or "")
            if "session_id" not in proc or not proc.get("session_id"):
                proc["session_id"] = str(ctx.session_id or "unknown")
            if "agent_id" not in proc or not proc.get("agent_id"):
                proc["agent_id"] = str(ctx.behavior_agent_id or "")
            if "model" not in proc or not proc.get("model"):
                proc["model"] = str(ctx.original_model or ctx.body.get("model", ""))
            if "model_used" not in proc or not proc.get("model_used"):
                proc["model_used"] = str(ctx.body.get("model", ctx.original_model))
            if "cost_usd" not in proc:
                proc["cost_usd"] = float(proc.get("cost", 0.0) or 0.0)
            if "input_tokens" not in proc:
                proc["input_tokens"] = int(getattr(ctx.parsed_resp_obj, "input_tokens", 0) or 0)
            if "output_tokens" not in proc:
                proc["output_tokens"] = int(getattr(ctx.parsed_resp_obj, "output_tokens", 0) or 0)
            if "tool_calls_count" not in proc:
                proc["tool_calls_count"] = len(getattr(ctx.parsed_req, "tool_calls", []) or [])
            if "has_tool_results" not in proc:
                proc["has_tool_results"] = bool(
                    getattr(ctx.parsed_resp_obj, "tool_calls", []) or []
                )
            if "streaming" not in proc:
                proc["streaming"] = bool(ctx.is_streaming)
            if "cache_hit" not in proc:
                proc["cache_hit"] = bool(ctx.from_semantic_cache)
            if "cache_type" not in proc:
                proc["cache_type"] = (
                    str(ctx.semantic_cache_type or "semantic")
                    if ctx.from_semantic_cache
                    else str("miss" if ctx.cascade_cache_state == "miss" else "exact")
                )
            if "loop_detected" not in proc:
                proc["loop_detected"] = bool(ctx.was_loop_detected)
            if "loop_count" not in proc:
                proc["loop_count"] = int(ctx.content_loop_count)
            if "content_hash_blocked" not in proc:
                proc["content_hash_blocked"] = bool(
                    getattr(ctx.handler, "_orchesis_last_error_type", "") == "content_loop_detected"
                )
            if "heartbeat_detected" not in proc:
                proc["heartbeat_detected"] = bool(ctx.heartbeat_detected)
            if "spend_rate_5min" not in proc:
                proc["spend_rate_5min"] = float(ctx.spend_rate_per_min)
            if "cascaded" not in proc:
                proc["cascaded"] = bool(ctx.was_escalated)
            if "cascade_reason" not in proc:
                proc["cascade_reason"] = "escalated" if ctx.was_escalated else ""
            if "threat_matches" not in proc and ctx.threat_matches:
                proc["threat_matches"] = list(ctx.threat_matches)
            status_hint = int(getattr(ctx.handler, "_orchesis_last_status", 0) or 0)
            if "status_code" not in proc or int(proc.get("status_code", 0) or 0) <= 0:
                proc["status_code"] = int(
                    ctx.resp_status if ctx.resp_status > 0 else status_hint or 200
                )
            if "error_type" not in proc or not proc.get("error_type"):
                proc["error_type"] = str(getattr(ctx.handler, "_orchesis_last_error_type", ""))[
                    :120
                ]
            if "blocked" not in proc:
                proc["blocked"] = bool(int(proc.get("status_code", 0) or 0) >= 400)
            if "block_reason" not in proc or not proc.get("block_reason"):
                proc["block_reason"] = str(proc.get("error_type", ""))
            ctx.proc_result = proc
            if self._ars is not None:
                agent_id = str(proc.get("agent_id", "") or "")
                if agent_id:
                    status_code = int(proc.get("status_code", 200) or 200)
                    error_type = str(proc.get("error_type", "") or "").lower()
                    session_success = bool(status_code < 400 and not proc.get("blocked", False))
                    clean_termination = bool(
                        status_code < 500
                        and "timeout" not in error_type
                        and "circuit" not in error_type
                        and "budget_exceeded" not in error_type
                    )
                    self._ars.update(
                        agent_id,
                        is_session_end=True,
                        session_success=session_success,
                        loop_flagged=bool(proc.get("loop_detected", False)),
                        cost_usd=float(proc.get("cost_usd", 0.0) or 0.0),
                        latency_ms=float(proc.get("total_ms", 0.0) or 0.0),
                        token_count=int(proc.get("input_tokens", 0) or 0)
                        + int(proc.get("output_tokens", 0) or 0),
                        clean_termination=clean_termination,
                        has_threat=bool(proc.get("threat_matches")),
                    )
            if self._telemetry_collector is not None:
                from orchesis.telemetry_export import build_record_from_context

                rec = build_record_from_context(ctx)
                self._telemetry_collector.record(rec)
        except Exception as error:  # noqa: BLE001
            _HTTP_PROXY_LOGGER.warning("telemetry/ars finalize hook failed: %s", error)
            return

    def _handle_kill(self, handler: BaseHTTPRequestHandler) -> None:
        payload = self._read_json_body(handler)
        if bool(getattr(handler, "_orchesis_body_too_large", False)):
            return
        reason = "manual emergency shutdown"
        if isinstance(payload, dict):
            raw_reason = payload.get("reason")
            if isinstance(raw_reason, str) and raw_reason.strip():
                reason = raw_reason.strip()
        self._activate_kill_switch(reason)
        self._send_json(
            handler,
            200,
            {"status": "killed", "reason": self._kill_reason, "killed_at": self._kill_time},
        )

    def _handle_delete(self, handler: BaseHTTPRequestHandler) -> None:
        if self._experiment_manager is not None and handler.path.startswith("/api/experiments/"):
            parts = handler.path.split("/")
            if len(parts) >= 4 and parts[3]:
                exp_id = parts[3]
                ok = self._experiment_manager.delete_experiment(exp_id)
                self._send_json(handler, 200 if ok else 404, {"deleted": ok})
                return
        if handler.path.startswith("/sessions/") and self._recorder is not None:
            session_id = handler.path.split("/sessions/", 1)[1].strip()
            if not session_id:
                self._send_json(handler, 400, {"error": "session_id_required"})
                return
            deleted = self._recorder.delete_session(session_id)
            if deleted:
                self._send_json(handler, 200, {"deleted": True, "session_id": session_id})
                return
            self._send_json(handler, 404, {"deleted": False, "error": "session_not_found"})
            return
        self._send_json(handler, 404, {"error": "Not found"})

    def _handle_resume(self, handler: BaseHTTPRequestHandler) -> None:
        payload = self._read_json_body(handler)
        if bool(getattr(handler, "_orchesis_body_too_large", False)):
            return
        token = ""
        if isinstance(payload, dict):
            raw_token = payload.get("token")
            if isinstance(raw_token, str):
                token = raw_token
        if token != self._resume_token:
            self._send_json(
                handler,
                403,
                {"error": {"type": "invalid_resume_token", "message": "Resume token is invalid"}},
            )
            return
        self._killed = False
        self._kill_reason = ""
        self._kill_time = ""
        self._secret_trigger_hits = 0
        self._loop_trigger_hits = 0
        self._send_json(handler, 200, {"status": "resumed"})

