"""Auto-healing response engine for anomaly mitigation."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import copy
import json
import threading
import time
from typing import Any, Optional
from urllib import request as urlrequest

from orchesis.message_chain import validate_tool_chain

_SUSPICIOUS_TEXT_MARKERS = (
    "ignore previous instructions",
    "override system",
    "disable security",
    "enter your password",
    "sk-",
    "-----begin private key-----",
)

DIAGNOSIS_RULES: dict[str, list[str]] = {
    "anomaly_high": ["strip_content", "rate_limit"],
    "anomaly_critical": ["strip_content", "rate_limit", "escalate"],
    "entropy_drop": ["reset_context"],
    "entropy_spike": ["strip_content"],
    "entropy_zero": ["reset_context", "rate_limit"],
    "tool_chain_loop": ["reset_context"],
    "escalation_chain": ["reset_context"],
    "ping_pong": ["reset_context", "rate_limit"],
    "request_template_repeat": ["rate_limit"],
    "drift_injection": ["strip_content", "inject_guardrail"],
    "drift_model_switch": ["inject_guardrail"],
    "drift_persona": ["inject_guardrail", "escalate"],
    "FM-1.3": ["inject_guardrail", "escalate"],
    "FM-1.4": ["rate_limit", "strip_content"],
    "FM-1.5": ["strip_content"],
    "FM-2.3": ["reset_context", "retry_model"],
    "FM-2.6": ["rate_limit", "escalate"],
    "FM-3.1": ["strip_content", "escalate"],
    "OE-1": ["inject_guardrail"],
    "OE-6": ["inject_guardrail", "escalate"],
    "upstream_429": ["retry_model"],
    "upstream_500": ["retry_model"],
    "upstream_context_length": ["reset_context", "retry_model"],
    "budget_exceeded": ["retry_model"],
    "context_overflow": ["reset_context", "retry_model"],
    "loop_detected": ["reset_context"],
    "cron_accumulation": ["reset_context"],
    "retry_storm": ["rate_limit"],
    "heartbeat_storm": ["rate_limit"],
    "injection_detected": ["strip_content"],
    "credential_leakage": ["strip_content"],
    "output_manipulation": ["strip_content", "escalate"],
    "privilege_escalation": ["inject_guardrail", "escalate"],
    "compliance_drift": ["inject_guardrail", "escalate"],
    "tool_abuse": ["rate_limit", "strip_content"],
    "cascading_failure": ["rate_limit", "escalate"],
}

_DEFAULT_ACTION_ORDER = (
    "log_only",
    "warn_header",
    "compress_context",
    "model_downgrade",
    "circuit_break",
    "strip_content",
    "reset_context",
    "retry_model",
    "inject_guardrail",
    "rate_limit",
    "escalate",
)


class HealingLevel:
    L1 = "log_only"
    L2 = "warn_header"
    L3 = "compress_context"
    L4 = "rate_limit"
    L5 = "model_downgrade"
    L6 = "circuit_break"


SAFETY_GUARDS = {
    "never_modify_user_content": True,
    "max_interventions_per_session": 3,
    "min_interval_between_actions": 3,
    "l6_max_duration_seconds": 300,
}


@dataclass
class HealingAction:
    """A single healing action to apply."""

    action_type: str
    reason: str
    parameters: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.5
    source_detection: str = ""


@dataclass
class HealingResult:
    """Result of applying healing actions."""

    actions_taken: list[HealingAction] = field(default_factory=list)
    original_issue: str = ""
    resolution: str = "failed"
    messages_modified: bool = False
    model_switched: bool = False
    context_reset: bool = False
    latency_added_ms: float = 0.0


class AgentRateLimiter:
    """Per-agent rate limiting."""

    def __init__(self) -> None:
        self._limits: dict[str, dict[str, float]] = {}
        self._lock = threading.Lock()

    def set_limit(self, agent_id: str, max_requests: int, window_seconds: int) -> None:
        key = str(agent_id or "unknown")
        with self._lock:
            self._limits[key] = {
                "window_start": time.monotonic(),
                "count": 0.0,
                "max_requests": float(max(1, int(max_requests))),
                "window_seconds": float(max(1, int(window_seconds))),
            }

    def check(self, agent_id: str) -> bool:
        key = str(agent_id or "unknown")
        now = time.monotonic()
        with self._lock:
            item = self._limits.get(key)
            if item is None:
                return True
            if (now - float(item["window_start"])) >= float(item["window_seconds"]):
                item["window_start"] = now
                item["count"] = 0.0
            item["count"] = float(item["count"]) + 1.0
            return item["count"] <= float(item["max_requests"])

    def remove_limit(self, agent_id: str) -> None:
        key = str(agent_id or "unknown")
        with self._lock:
            self._limits.pop(key, None)

    def get_limited_agents(self) -> list[str]:
        with self._lock:
            return sorted(self._limits.keys())

    def reset(self) -> None:
        with self._lock:
            self._limits = {}


class AutoHealer:
    """Automated response engine for detected anomalies."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", True))
        self.mode = str(cfg.get("mode", "active") or "active").strip().lower()
        if self.mode not in {"active", "monitor"}:
            self.mode = "active"
        self.max_retries = max(1, int(cfg.get("max_retries", 2)))
        self.max_healing_time_ms = max(1, int(cfg.get("max_healing_time_ms", 3000)))
        actions_cfg = cfg.get("actions") if isinstance(cfg.get("actions"), dict) else {}
        self._actions_cfg = actions_cfg
        self._action_confidence: dict[str, float] = {name: 0.7 for name in _DEFAULT_ACTION_ORDER}
        self._action_confidence["pass"] = 1.0
        self.rate_limiter = AgentRateLimiter()
        self._lock = threading.Lock()
        self._agent_history: dict[str, list[dict[str, Any]]] = {}
        self._session_interventions: dict[str, list[dict[str, Any]]] = {}
        self._session_request_counter: dict[str, int] = {}
        self._session_last_action_index: dict[str, int] = {}
        self._session_circuit_until: dict[str, float] = {}
        self._safety_guards = dict(SAFETY_GUARDS)
        guards_cfg = cfg.get("safety_guards")
        if isinstance(guards_cfg, dict):
            self._safety_guards.update(guards_cfg)
        self._stats = {
            "total_diagnoses": 0,
            "total_actions_taken": 0,
            "actions_by_type": {},
            "healed_or_mitigated": 0,
            "total_healing_time_ms": 0.0,
            "healing_attempts": 0,
            "escalations": 0,
        }

    def _action_enabled(self, action_type: str) -> bool:
        section = self._actions_cfg.get(action_type)
        if isinstance(section, dict):
            return bool(section.get("enabled", True))
        return True

    def _action_cfg(self, action_type: str) -> dict[str, Any]:
        section = self._actions_cfg.get(action_type)
        return section if isinstance(section, dict) else {}

    @staticmethod
    def _session_key(session_id: str | None) -> str:
        return str(session_id or "unknown")

    def can_intervene(self, session_id: str, level: str) -> bool:
        """Check safety guards before intervening."""
        sid = self._session_key(session_id)
        _ = level
        with self._lock:
            used = len(self._session_interventions.get(sid, []))
            max_int = int(self._safety_guards.get("max_interventions_per_session", 3) or 3)
            if used >= max(0, max_int):
                return False
            min_interval = int(self._safety_guards.get("min_interval_between_actions", 3) or 3)
            if min_interval > 0:
                current_idx = int(self._session_request_counter.get(sid, 0))
                last_idx = int(self._session_last_action_index.get(sid, -10_000))
                if (current_idx - last_idx) < min_interval:
                    return False
            return True

    def record_intervention(self, session_id: str, level: str, reason: str) -> None:
        """Record intervention for budget tracking."""
        sid = self._session_key(session_id)
        now = time.time()
        with self._lock:
            current_idx = int(self._session_request_counter.get(sid, 0))
            self._session_interventions.setdefault(sid, []).append(
                {
                    "timestamp": now,
                    "level": str(level),
                    "reason": str(reason),
                    "request_index": current_idx,
                }
            )
            self._session_last_action_index[sid] = current_idx
            if len(self._session_interventions[sid]) > 100:
                self._session_interventions[sid] = self._session_interventions[sid][-100:]

    def get_session_budget(self, session_id: str) -> dict:
        """Returns: interventions_used, interventions_remaining, last_action."""
        sid = self._session_key(session_id)
        with self._lock:
            used = len(self._session_interventions.get(sid, []))
            max_int = int(self._safety_guards.get("max_interventions_per_session", 3) or 3)
            remaining = max(0, max_int - used)
            last = self._session_interventions.get(sid, [])[-1] if self._session_interventions.get(sid) else None
            return {
                "interventions_used": used,
                "interventions_remaining": remaining,
                "last_action": copy.deepcopy(last),
            }

    def _collect_signals(self, detection_result: Any, mast_findings: Any, request_data: dict[str, Any]) -> list[str]:
        signals: list[str] = []
        det = detection_result
        if det is not None:
            try:
                if bool(getattr(det, "is_anomalous", False)):
                    level = str(getattr(det, "risk_level", "low"))
                    if level in {"high", "critical"}:
                        signals.append(f"anomaly_{level}")
                drift = str(getattr(det, "drift_type", "") or "")
                if drift and drift != "normal":
                    signals.append(f"drift_{drift}")
                if bool(getattr(det, "entropy_anomalous", False)):
                    score = float(getattr(det, "entropy_score", 0.0) or 0.0)
                    if score <= 0.01:
                        signals.append("entropy_zero")
                    elif score < 25.0:
                        signals.append("entropy_drop")
                    elif score >= 80.0:
                        signals.append("entropy_spike")
                patterns = getattr(det, "patterns_found", []) or []
                for pat in patterns:
                    ptype = str(getattr(pat, "pattern_type", "") or "")
                    if ptype == "request_template":
                        signals.append("request_template_repeat")
                    elif ptype:
                        signals.append(ptype)
            except Exception:
                pass
        if isinstance(mast_findings, list):
            for finding in mast_findings:
                mode = str(getattr(finding, "failure_mode", "") or "")
                if mode:
                    signals.append(mode)
        if isinstance(request_data, dict):
            issue = str(request_data.get("healing_issue", "") or "")
            if issue:
                signals.append(issue)
            status_code = int(request_data.get("upstream_status", 0) or 0)
            if status_code == 429:
                signals.append("upstream_429")
            elif status_code >= 500:
                signals.append("upstream_500")
            if bool(request_data.get("context_overflow")):
                signals.append("context_overflow")
        return list(dict.fromkeys(signals))

    def _candidate_actions_for_signal(self, signal: str) -> list[str]:
        return list(DIAGNOSIS_RULES.get(signal, []))

    def diagnose(
        self,
        detection_result: Any = None,
        mast_findings: Any = None,
        request_data: Any = None,
        context: Any = None,
    ) -> list[HealingAction]:
        req = request_data if isinstance(request_data, dict) else {}
        _ = context
        signals = self._collect_signals(detection_result, mast_findings, req)
        with self._lock:
            self._stats["total_diagnoses"] += 1
        if not signals:
            return []
        actions: list[HealingAction] = []
        seen: set[str] = set()
        for signal in signals:
            for action_type in self._candidate_actions_for_signal(signal):
                if action_type in seen:
                    continue
                if not self._action_enabled(action_type):
                    continue
                if action_type == "retry_model":
                    fallback_models = self._action_cfg("retry_model").get("fallback_models", [])
                    if not isinstance(fallback_models, list) or not fallback_models:
                        continue
                conf = float(self._action_confidence.get(action_type, 0.6))
                reason = f"trigger={signal}"
                params: dict[str, Any] = {}
                if action_type == "retry_model":
                    params["fallback_models"] = list(
                        self._action_cfg("retry_model").get("fallback_models", [])
                    )
                elif action_type == "reset_context":
                    cfg = self._action_cfg("reset_context")
                    params = {
                        "preserve_system": bool(cfg.get("preserve_system", True)),
                        "preserve_last_n": int(cfg.get("preserve_last_n", 3)),
                    }
                elif action_type == "rate_limit":
                    cfg = self._action_cfg("rate_limit")
                    params = {
                        "window_seconds": int(cfg.get("window_seconds", 60)),
                        "max_requests": int(cfg.get("max_requests", 10)),
                    }
                elif action_type == "inject_guardrail":
                    cfg = self._action_cfg("inject_guardrail")
                    params = {
                        "guardrail_prefix": str(
                            cfg.get(
                                "guardrail_prefix",
                                "IMPORTANT: Do not attempt to access tools or resources outside your approved scope.",
                            )
                        )
                    }
                elif action_type == "escalate":
                    cfg = self._action_cfg("escalate")
                    params = {"webhook_url": cfg.get("webhook_url")}
                actions.append(
                    HealingAction(
                        action_type=action_type,
                        reason=reason,
                        parameters=params,
                        confidence=max(0.0, min(1.0, conf)),
                        source_detection=signal,
                    )
                )
                seen.add(action_type)
        if not actions:
            return []
        order_idx = {name: idx for idx, name in enumerate(_DEFAULT_ACTION_ORDER)}
        actions.sort(
            key=lambda item: (
                -float(item.confidence),
                order_idx.get(item.action_type, 99),
            )
        )
        return actions[:3]

    @staticmethod
    def _copy_request(request_data: dict[str, Any]) -> dict[str, Any]:
        return copy.deepcopy(request_data if isinstance(request_data, dict) else {})

    @staticmethod
    def _sanitize_text(text: str) -> str:
        value = str(text or "")
        lowered = value.lower()
        if any(marker in lowered for marker in _SUSPICIOUS_TEXT_MARKERS):
            return "[stripped suspicious content]"
        return value

    def _apply_retry_model(self, data: dict[str, Any], action: HealingAction, result: HealingResult) -> None:
        current_model = str(data.get("model", "") or "")
        fallbacks = action.parameters.get("fallback_models", [])
        if not isinstance(fallbacks, list):
            return
        for candidate in fallbacks:
            model = str(candidate or "")
            if model and model != current_model:
                data["model"] = model
                result.model_switched = True
                return

    def _apply_reset_context(self, data: dict[str, Any], action: HealingAction, result: HealingResult) -> None:
        messages = data.get("messages")
        if not isinstance(messages, list):
            return
        preserve_system = bool(action.parameters.get("preserve_system", True))
        preserve_last_n = max(0, int(action.parameters.get("preserve_last_n", 3)))
        tail = messages[-preserve_last_n:] if preserve_last_n > 0 else []
        kept: list[dict[str, Any]] = []
        if preserve_system:
            for msg in messages:
                if isinstance(msg, dict) and str(msg.get("role", "")).lower() == "system":
                    kept.append(dict(msg))
        for msg in tail:
            if isinstance(msg, dict):
                kept.append(dict(msg))
        data["messages"] = validate_tool_chain(kept)
        result.messages_modified = True
        result.context_reset = True

    def _apply_strip_content(self, data: dict[str, Any], result: HealingResult) -> None:
        messages = data.get("messages")
        if not isinstance(messages, list):
            return
        new_messages: list[dict[str, Any]] = []
        changed = False
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            copied = dict(msg)
            content = copied.get("content")
            if isinstance(content, str):
                safe = self._sanitize_text(content)
                if safe != content:
                    changed = True
                copied["content"] = safe
            new_messages.append(copied)
        if changed:
            result.messages_modified = True
            data["messages"] = validate_tool_chain(new_messages)

    def _apply_rate_limit(self, agent_id: str, action: HealingAction) -> None:
        max_requests = int(action.parameters.get("max_requests", 10))
        window_seconds = int(action.parameters.get("window_seconds", 60))
        self.rate_limiter.set_limit(agent_id, max_requests=max_requests, window_seconds=window_seconds)

    @staticmethod
    def _apply_warn_header(data: dict[str, Any], reason: str) -> None:
        headers = data.get("headers")
        if not isinstance(headers, dict):
            headers = {}
            data["headers"] = headers
        headers["X-Orchesis-Warning"] = str(reason or "auto-healing warning")

    @staticmethod
    def _apply_compress_context(data: dict[str, Any], result: HealingResult) -> None:
        messages = data.get("messages")
        if not isinstance(messages, list):
            return
        out: list[dict[str, Any]] = []
        changed = False
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            copied = dict(msg)
            content = copied.get("content")
            role = str(copied.get("role", "")).lower()
            if isinstance(content, str) and len(content) > 240:
                if role == "user":
                    # Safety guard: never alter user-authored content.
                    pass
                else:
                    copied["content"] = f"{content[:220]} ...[compressed]"
                    changed = True
            out.append(copied)
        if changed:
            data["messages"] = validate_tool_chain(out)
            result.messages_modified = True

    def _apply_model_downgrade(self, data: dict[str, Any], action: HealingAction, result: HealingResult) -> None:
        current_model = str(data.get("model", "") or "")
        target = str(action.parameters.get("downgrade_model", "gpt-4o-mini") or "gpt-4o-mini")
        if target and target != current_model:
            data["model"] = target
            result.model_switched = True

    def _apply_circuit_break(self, session_id: str, action: HealingAction) -> None:
        sid = self._session_key(session_id)
        requested = int(action.parameters.get("duration_seconds", 60) or 60)
        hard_cap = int(self._safety_guards.get("l6_max_duration_seconds", 300) or 300)
        duration = max(1, min(requested, max(1, hard_cap)))
        with self._lock:
            self._session_circuit_until[sid] = time.time() + float(duration)

    def _apply_inject_guardrail(self, data: dict[str, Any], action: HealingAction, result: HealingResult) -> None:
        messages = data.get("messages")
        if not isinstance(messages, list):
            return
        guardrail = str(action.parameters.get("guardrail_prefix", "") or "").strip()
        if not guardrail:
            return
        out: list[dict[str, Any]] = []
        injected = False
        for msg in messages:
            if not isinstance(msg, dict):
                continue
            copied = dict(msg)
            role = str(copied.get("role", "")).lower()
            if not injected and role == "system":
                original = str(copied.get("content", "") or "")
                if not original.startswith(guardrail):
                    copied["content"] = f"{guardrail}\n\n{original}".strip()
                    result.messages_modified = True
                injected = True
            out.append(copied)
        if not injected:
            out.insert(0, {"role": "system", "content": guardrail})
            result.messages_modified = True
        data["messages"] = validate_tool_chain(out)

    @staticmethod
    def _async_webhook(url: str, payload: dict[str, Any]) -> None:
        def _worker() -> None:
            try:
                req = urlrequest.Request(
                    url=url,
                    data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                with urlrequest.urlopen(req, timeout=2.0):  # noqa: S310
                    pass
            except Exception:
                return

        t = threading.Thread(target=_worker, daemon=True)
        t.start()

    def apply(self, actions: list[HealingAction], request_data: dict, agent_id: str) -> tuple[dict, HealingResult]:
        started = time.perf_counter()
        data = self._copy_request(request_data)
        session_id = self._session_key(data.get("session_id") if isinstance(data, dict) else None)
        with self._lock:
            self._session_request_counter[session_id] = int(self._session_request_counter.get(session_id, 0)) + 1
        result = HealingResult(
            actions_taken=[],
            original_issue=",".join([a.source_detection for a in actions]) if actions else "",
            resolution="failed",
        )
        if not actions:
            result.resolution = "failed"
            return data, result
        attempts = 0
        for action in actions:
            if attempts >= self.max_retries:
                break
            elapsed_ms = (time.perf_counter() - started) * 1000.0
            if elapsed_ms > float(self.max_healing_time_ms):
                break
            attempts += 1
            a_type = action.action_type
            level_action = {
                HealingLevel.L1,
                HealingLevel.L2,
                HealingLevel.L3,
                HealingLevel.L4,
                HealingLevel.L5,
                HealingLevel.L6,
            }
            if a_type in level_action:
                if not self.can_intervene(session_id=session_id, level=a_type):
                    continue
            if a_type == "pass":
                result.actions_taken.append(action)
                continue
            if a_type == HealingLevel.L1:
                self.record_intervention(session_id, HealingLevel.L1, action.reason)
                result.actions_taken.append(action)
            elif a_type == HealingLevel.L2:
                self._apply_warn_header(data, action.reason)
                self.record_intervention(session_id, HealingLevel.L2, action.reason)
                result.actions_taken.append(action)
            elif a_type == HealingLevel.L3:
                self._apply_compress_context(data, result)
                self.record_intervention(session_id, HealingLevel.L3, action.reason)
                result.actions_taken.append(action)
            elif a_type == HealingLevel.L4:
                self._apply_rate_limit(str(agent_id or "unknown"), HealingAction("rate_limit", action.reason, {"window_seconds": 60, "max_requests": 10}, action.confidence, action.source_detection))
                self.record_intervention(session_id, HealingLevel.L4, action.reason)
                result.actions_taken.append(action)
            elif a_type == HealingLevel.L5:
                self._apply_model_downgrade(data, action, result)
                self.record_intervention(session_id, HealingLevel.L5, action.reason)
                result.actions_taken.append(action)
            elif a_type == HealingLevel.L6:
                self._apply_circuit_break(session_id, action)
                self.record_intervention(session_id, HealingLevel.L6, action.reason)
                result.actions_taken.append(action)
            if a_type == "retry_model":
                self._apply_retry_model(data, action, result)
                result.actions_taken.append(action)
            elif a_type == "reset_context":
                self._apply_reset_context(data, action, result)
                result.actions_taken.append(action)
            elif a_type == "strip_content":
                self._apply_strip_content(data, result)
                result.actions_taken.append(action)
            elif a_type == "rate_limit":
                self._apply_rate_limit(str(agent_id or "unknown"), action)
                result.actions_taken.append(action)
            elif a_type == "inject_guardrail":
                self._apply_inject_guardrail(data, action, result)
                result.actions_taken.append(action)
            elif a_type == "escalate":
                url = str(action.parameters.get("webhook_url", "") or "")
                payload = {
                    "agent_id": str(agent_id or "unknown"),
                    "reason": action.reason,
                    "source_detection": action.source_detection,
                    "timestamp": time.time(),
                }
                if url:
                    self._async_webhook(url, payload)
                with self._lock:
                    self._stats["escalations"] += 1
                result.actions_taken.append(action)
            with self._lock:
                self._stats["total_actions_taken"] += 1
                actions_map = self._stats["actions_by_type"]
                actions_map[a_type] = int(actions_map.get(a_type, 0)) + 1
        if result.messages_modified and isinstance(data.get("messages"), list):
            data["messages"] = validate_tool_chain(data["messages"])
        result.resolution = "healed" if (result.messages_modified or result.model_switched or result.context_reset) else "mitigated"
        result.latency_added_ms = round((time.perf_counter() - started) * 1000.0, 3)
        with self._lock:
            self._stats["healing_attempts"] += 1
            self._stats["total_healing_time_ms"] += result.latency_added_ms
            if result.resolution in {"healed", "mitigated"}:
                self._stats["healed_or_mitigated"] += 1
            self._agent_history.setdefault(str(agent_id or "unknown"), []).append(
                {
                    "timestamp": time.time(),
                    "result": asdict(result),
                    "actions": [asdict(a) for a in result.actions_taken],
                }
            )
            if len(self._agent_history[str(agent_id or "unknown")]) > 100:
                self._agent_history[str(agent_id or "unknown")] = self._agent_history[str(agent_id or "unknown")][-100:]
        return data, result

    def heal(
        self,
        detection_result: Any = None,
        mast_findings: Any = None,
        request_data: Any = None,
        agent_id: str | None = None,
        context: Any = None,
    ) -> tuple[dict, HealingResult]:
        req = self._copy_request(request_data if isinstance(request_data, dict) else {})
        session_id = self._session_key(req.get("session_id") if isinstance(req, dict) else None)
        with self._lock:
            until = float(self._session_circuit_until.get(session_id, 0.0) or 0.0)
        if until > time.time():
            blocked = HealingResult(
                actions_taken=[HealingAction(HealingLevel.L6, "circuit open", {"until": until}, 1.0, "circuit_break")],
                original_issue="circuit_break",
                resolution="mitigated",
                latency_added_ms=0.0,
            )
            req["blocked_by_circuit"] = True
            req["circuit_until"] = until
            return req, blocked
        actions = self.diagnose(
            detection_result=detection_result,
            mast_findings=mast_findings,
            request_data=req,
            context=context,
        )
        if self.mode == "monitor":
            monitor_action = HealingAction(
                action_type="pass",
                reason="monitor mode",
                parameters={},
                confidence=1.0,
                source_detection="monitor",
            )
            res = HealingResult(
                actions_taken=[monitor_action] if actions else [],
                original_issue=",".join([a.source_detection for a in actions]) if actions else "",
                resolution="mitigated" if actions else "failed",
                messages_modified=False,
                model_switched=False,
                context_reset=False,
                latency_added_ms=0.0,
            )
            with self._lock:
                self._agent_history.setdefault(str(agent_id or "unknown"), []).append(
                    {
                        "timestamp": time.time(),
                        "result": asdict(res),
                        "actions": [asdict(a) for a in res.actions_taken],
                    }
                )
            return req, res
        if not actions:
            return req, HealingResult(actions_taken=[], original_issue="", resolution="failed", latency_added_ms=0.0)
        return self.apply(actions=actions, request_data=req, agent_id=str(agent_id or "unknown"))

    def verify_healing(self, agent_id: str, pre_healing_score: float, post_healing_score: float) -> bool:
        improved = float(post_healing_score) <= float(pre_healing_score)
        key = str(agent_id or "unknown")
        with self._lock:
            history = self._agent_history.get(key, [])
            if history:
                last = history[-1]
                actions = last.get("actions", [])
                for item in actions:
                    action_type = str(item.get("action_type", ""))
                    if not action_type or action_type == "pass":
                        continue
                    current = float(self._action_confidence.get(action_type, 0.6))
                    if improved:
                        current = min(0.98, current + 0.03)
                    else:
                        current = max(0.10, current - 0.05)
                    self._action_confidence[action_type] = current
                last["verified"] = True
                last["improved"] = improved
                last["pre_score"] = float(pre_healing_score)
                last["post_score"] = float(post_healing_score)
        return improved

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            attempts = int(self._stats["healing_attempts"])
            avg_ms = (float(self._stats["total_healing_time_ms"]) / float(attempts)) if attempts > 0 else 0.0
            success_rate = (float(self._stats["healed_or_mitigated"]) / float(attempts)) if attempts > 0 else 0.0
            return {
                "enabled": self.enabled,
                "mode": self.mode,
                "total_diagnoses": int(self._stats["total_diagnoses"]),
                "total_actions_taken": int(self._stats["total_actions_taken"]),
                "actions_by_type": dict(self._stats["actions_by_type"]),
                "success_rate": round(success_rate, 4),
                "avg_healing_time_ms": round(avg_ms, 3),
                "escalations": int(self._stats["escalations"]),
                "currently_rate_limited": self.rate_limiter.get_limited_agents(),
                "confidence_by_action": dict(self._action_confidence),
            }

    def get_agent_healing_history(self, agent_id: str) -> list[dict]:
        key = str(agent_id or "unknown")
        with self._lock:
            return copy.deepcopy(self._agent_history.get(key, []))

    def reset(self, agent_id: str | None = None) -> None:
        if agent_id:
            key = str(agent_id or "unknown")
            with self._lock:
                self._agent_history.pop(key, None)
                self._session_interventions.pop(key, None)
                self._session_request_counter.pop(key, None)
                self._session_last_action_index.pop(key, None)
                self._session_circuit_until.pop(key, None)
            self.rate_limiter.remove_limit(key)
            return
        with self._lock:
            self._agent_history = {}
            self._session_interventions = {}
            self._session_request_counter = {}
            self._session_last_action_index = {}
            self._session_circuit_until = {}
            self._stats = {
                "total_diagnoses": 0,
                "total_actions_taken": 0,
                "actions_by_type": {},
                "healed_or_mitigated": 0,
                "total_healing_time_ms": 0.0,
                "healing_attempts": 0,
                "escalations": 0,
            }
            self._action_confidence = {name: 0.7 for name in _DEFAULT_ACTION_ORDER}
            self._action_confidence["pass"] = 1.0
        self.rate_limiter.reset()
