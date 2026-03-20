"""Dedicated MAST failure mode detectors (H2.3)."""

from __future__ import annotations

from collections import Counter, defaultdict, deque
from dataclasses import dataclass
import json
import math
import re
import threading
import time
from typing import Any, Optional

MODEL_CONTEXT_WINDOWS = {
    "gpt-4o": 128_000,
    "gpt-4o-mini": 128_000,
    "gpt-4-turbo": 128_000,
    "gpt-4": 8_192,
    "gpt-3.5-turbo": 16_385,
    "o1": 200_000,
    "o1-mini": 128_000,
    "o3": 200_000,
    "o3-mini": 200_000,
    "claude-sonnet-4-20250514": 200_000,
    "claude-opus-4-20250514": 200_000,
    "claude-3-5-sonnet-20241022": 200_000,
    "claude-3-5-haiku-20241022": 200_000,
    "gemini-2.0-flash": 1_000_000,
    "gemini-2.0-pro": 2_000_000,
    "gemini-1.5-pro": 2_000_000,
    "gemini-1.5-flash": 1_000_000,
    "_default": 128_000,
}

_SEVERITY_SCORE = {"low": 5, "medium": 12, "high": 25, "critical": 40}
_GRADE_VALUE = {"A": 5, "B": 4, "C": 3, "D": 2, "F": 1}
_SHELL_RE = re.compile(r"(?:\brm\s+-rf\b|\bcurl\b.+\|\s*(?:bash|sh)|\bwget\b.+\|\s*(?:bash|sh)|&&|;)")
_SQLI_RE = re.compile(r"(?:\bunion\s+select\b|\bdrop\s+table\b|'\s*or\s*1=1)", re.IGNORECASE)
_PATH_RE = re.compile(r"(?:\.\./|\.\.\\|/etc/passwd|\\windows\\system32)", re.IGNORECASE)
_SSRF_RE = re.compile(
    r"https?://(?:127\.0\.0\.1|localhost|169\.254\.169\.254|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)",
    re.IGNORECASE,
)
_API_KEY_RE = re.compile(r"\b(?:sk-[A-Za-z0-9_\-]{10,}|ghp_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16})\b")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b")
_CONN_RE = re.compile(r"\b(?:postgres(?:ql)?|mongodb|redis)://[^\s]+", re.IGNORECASE)
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")
_SOCIAL_RE = re.compile(
    r"(?:click here|enter your password|run this command|download this file|disable security)",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s)>\]]+", re.IGNORECASE)
_HIDDEN_UNICODE_RE = re.compile(r"[\u200b-\u200f\u2060\ufeff]")
_B64_RE = re.compile(r"(?:[A-Za-z0-9+/]{200,}={0,2})")


@dataclass
class MASTFinding:
    """A single MAST failure mode detection."""

    failure_mode: str
    name: str
    severity: str
    confidence: float
    description: str
    evidence: dict[str, Any]
    recommendation: str
    timestamp: float


class MASTDetectors:
    """Dedicated detectors for selected MAST failure modes."""

    def __init__(self, config: Optional[dict] = None):
        cfg = config if isinstance(config, dict) else {}
        self.enabled = bool(cfg.get("enabled", True))
        det_cfg = cfg.get("detectors") if isinstance(cfg.get("detectors"), dict) else {}
        self._enabled = {
            "privilege_escalation": bool(det_cfg.get("privilege_escalation", True)),
            "tool_abuse": bool(det_cfg.get("tool_abuse", True)),
            "credential_leakage": bool(det_cfg.get("credential_leakage", True)),
            "context_overflow": bool(det_cfg.get("context_overflow", True)),
            "cascading_failure": bool(det_cfg.get("cascading_failure", True)),
            "output_manipulation": bool(det_cfg.get("output_manipulation", True)),
            "observability_gap": bool(det_cfg.get("observability_gap", True)),
            "compliance_drift": bool(det_cfg.get("compliance_drift", True)),
        }
        self._lock = threading.Lock()
        self._agent_findings: dict[str, list[MASTFinding]] = defaultdict(list)
        self._agent_last_seen: dict[str, float] = {}
        self._tool_history: dict[str, deque[tuple[float, str, str]]] = defaultdict(lambda: deque(maxlen=500))
        self._error_events: deque[tuple[float, str, str]] = deque(maxlen=2000)
        self._stats = {
            "checks_request": 0,
            "checks_response": 0,
            "findings_total": 0,
            "findings_by_mode": defaultdict(int),
            "findings_by_severity": defaultdict(int),
        }

    @staticmethod
    def _tokens(text: str) -> int:
        return len((text or "").split())

    @staticmethod
    def _extract_messages(request_data: dict[str, Any]) -> list[dict[str, Any]]:
        messages = request_data.get("messages")
        return messages if isinstance(messages, list) else []

    @staticmethod
    def _extract_tool_calls(request_data: dict[str, Any]) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for msg in MASTDetectors._extract_messages(request_data):
            if not isinstance(msg, dict):
                continue
            calls = msg.get("tool_calls")
            if isinstance(calls, list):
                for call in calls:
                    if isinstance(call, dict):
                        name = (
                            call.get("name")
                            or (call.get("function") or {}).get("name")
                            or call.get("tool_name")
                            or ""
                        )
                        args = (
                            call.get("arguments")
                            or call.get("params")
                            or call.get("input")
                            or (call.get("function") or {}).get("arguments")
                            or ""
                        )
                        out.append({"name": str(name), "args": args})
        req_calls = request_data.get("tool_calls")
        if isinstance(req_calls, list):
            for call in req_calls:
                if isinstance(call, dict):
                    out.append({"name": str(call.get("name", "")), "args": call.get("args", call.get("params", {}))})
        return out

    @staticmethod
    def _context_window(model_name: str) -> int:
        return int(MODEL_CONTEXT_WINDOWS.get(model_name, MODEL_CONTEXT_WINDOWS["_default"]))

    @staticmethod
    def _char_entropy(text: str) -> float:
        if not text:
            return 0.0
        freq = Counter(text)
        total = float(len(text))
        score = 0.0
        for count in freq.values():
            p = count / total
            if p > 0.0:
                score -= p * math.log2(p)
        return score

    @staticmethod
    def _mk(
        mode: str,
        name: str,
        severity: str,
        confidence: float,
        desc: str,
        evidence: dict[str, Any],
        recommendation: str,
    ) -> MASTFinding:
        return MASTFinding(
            failure_mode=mode,
            name=name,
            severity=severity,
            confidence=max(0.0, min(1.0, float(confidence))),
            description=desc,
            evidence=evidence,
            recommendation=recommendation,
            timestamp=time.time(),
        )

    def _record(self, agent_id: str, finding: MASTFinding) -> None:
        with self._lock:
            self._agent_findings[agent_id].append(finding)
            self._agent_last_seen[agent_id] = finding.timestamp
            self._stats["findings_total"] += 1
            self._stats["findings_by_mode"][finding.failure_mode] += 1
            self._stats["findings_by_severity"][finding.severity] += 1

    def _check_privilege_escalation(self, agent_id: str, request_data: dict[str, Any], context: dict[str, Any]) -> Optional[MASTFinding]:
        _ = agent_id
        approved_tools = context.get("approved_tools")
        approved_tools_set = set(approved_tools) if isinstance(approved_tools, list) else set()
        approved_models = context.get("approved_models")
        approved_models_set = set(approved_models) if isinstance(approved_models, list) else set()
        messages = self._extract_messages(request_data)
        model = str(request_data.get("model", "") or "")
        calls = self._extract_tool_calls(request_data)
        for msg in messages:
            if isinstance(msg, dict) and str(msg.get("role", "")).lower() == "system":
                return self._mk(
                    "FM-1.3",
                    "Privilege Escalation",
                    "critical",
                    0.98,
                    "Agent attempted role escalation to system.",
                    {"role": "system"},
                    "Reject system-role injection and isolate session.",
                )
        for msg in messages:
            text = str(msg.get("content", "") if isinstance(msg, dict) else "")
            if "ignore previous instructions" in text.lower() or "override system" in text.lower():
                return self._mk(
                    "FM-1.3",
                    "Privilege Escalation",
                    "high",
                    0.9,
                    "Potential system prompt modification attempt detected.",
                    {"snippet": text[:120]},
                    "Block instruction override and enforce immutable system policy.",
                )
        if approved_models_set and model and model not in approved_models_set:
            return self._mk(
                "FM-1.3",
                "Privilege Escalation",
                "medium",
                0.8,
                "Agent requested unapproved model.",
                {"model": model},
                "Restrict model routing to approved model set.",
            )
        if approved_tools_set:
            for call in calls:
                name = str(call.get("name", ""))
                if name and name not in approved_tools_set:
                    return self._mk(
                        "FM-1.3",
                        "Privilege Escalation",
                        "medium",
                        0.78,
                        "Agent requested unapproved tool.",
                        {"tool": name},
                        "Enforce capabilities.allowlist and reject unapproved tool.",
                    )
        budget = context.get("token_budget", {})
        if isinstance(budget, dict):
            max_allowed = int(budget.get("max_tokens", 0) or 0)
            requested = int(request_data.get("max_completion_tokens", request_data.get("max_tokens", 0)) or 0)
            if max_allowed > 0 and requested > max_allowed:
                return self._mk(
                    "FM-1.3",
                    "Privilege Escalation",
                    "high",
                    0.85,
                    "Agent attempted token limit override beyond policy budget.",
                    {"requested": requested, "allowed": max_allowed},
                    "Clamp max tokens to policy budget and alert operator.",
                )
        return None

    def _check_tool_abuse(self, agent_id: str, request_data: dict[str, Any], context: dict[str, Any]) -> Optional[MASTFinding]:
        _ = context
        calls = self._extract_tool_calls(request_data)
        now = time.time()
        if not calls:
            return None
        history = self._tool_history[agent_id]
        burst_count = 0
        identical_counter: Counter[tuple[str, str]] = Counter()
        for call in calls:
            name = str(call.get("name", "") or "")
            raw_args = call.get("args", {})
            args_str = jsonable(raw_args)
            history.append((now, name, args_str))
            if now - history[-1][0] <= 60.0:
                burst_count += 1
            identical_counter[(name, args_str)] += 1
            if not args_str or args_str in {"{}", "[]", '""'}:
                return self._mk(
                    "FM-1.4",
                    "Tool Abuse",
                    "low",
                    0.6,
                    "Tool call has empty or malformed arguments.",
                    {"tool": name},
                    "Validate required tool arguments before execution.",
                )
            lowered = args_str.lower()
            if _SHELL_RE.search(lowered):
                return self._mk(
                    "FM-1.4",
                    "Tool Abuse",
                    "critical",
                    0.95,
                    "Shell injection-like pattern in tool arguments.",
                    {"tool": name, "args": args_str[:120]},
                    "Block execution and quarantine request for review.",
                )
            if _SQLI_RE.search(lowered):
                return self._mk(
                    "FM-1.4",
                    "Tool Abuse",
                    "critical",
                    0.95,
                    "SQL injection-like pattern in tool arguments.",
                    {"tool": name},
                    "Deny request and sanitize SQL inputs with parameterization.",
                )
            if _SSRF_RE.search(lowered):
                return self._mk(
                    "FM-1.4",
                    "Tool Abuse",
                    "critical",
                    0.92,
                    "Potential SSRF/internal-network target in tool arguments.",
                    {"tool": name},
                    "Block internal URL access and enforce allowlisted domains.",
                )
            if _PATH_RE.search(lowered):
                return self._mk(
                    "FM-1.4",
                    "Tool Abuse",
                    "high",
                    0.88,
                    "Path traversal/sensitive path pattern detected.",
                    {"tool": name},
                    "Restrict filesystem scope and sanitize path arguments.",
                )
        if any(v >= 3 for v in identical_counter.values()):
            tool, _args = max(identical_counter.items(), key=lambda kv: kv[1])[0]
            return self._mk(
                "FM-1.4",
                "Tool Abuse",
                "medium",
                0.8,
                "Repeated identical tool calls detected (stuck agent pattern).",
                {"tool": tool},
                "Add de-duplication/backoff for repeated tool invocations.",
            )
        recent = [item for item in history if now - item[0] <= 60.0]
        if len(recent) >= 10:
            baseline = max(1, len(history) - len(recent))
            if len(recent) >= baseline * 10:
                return self._mk(
                    "FM-1.4",
                    "Tool Abuse",
                    "medium",
                    0.75,
                    "Tool call frequency spike detected for this agent.",
                    {"recent_calls_60s": len(recent), "baseline_calls": baseline},
                    "Throttle tool calls and apply per-tool rate limits.",
                )
        return None

    def _check_credential_leakage(self, agent_id: str, response_data: dict[str, Any], original_request: dict[str, Any]) -> Optional[MASTFinding]:
        _ = (agent_id, original_request)
        content = response_text(response_data)
        if not content:
            return None
        if _PRIVATE_KEY_RE.search(content) or _JWT_RE.search(content):
            return self._mk(
                "FM-1.5",
                "Credential Leakage",
                "critical",
                0.98,
                "High-confidence credential material detected in response.",
                {"kind": "private_key_or_jwt"},
                "Redact response content and rotate potentially leaked credentials.",
            )
        if _API_KEY_RE.search(content) or _CONN_RE.search(content):
            return self._mk(
                "FM-1.5",
                "Credential Leakage",
                "high",
                0.9,
                "Potential API key or credential string found in response output.",
                {"kind": "api_key_or_connection_string"},
                "Block response and scrub sensitive data before returning to user.",
            )
        for token in re.findall(r"[A-Za-z0-9_\-+/=]{20,}", content):
            if self._char_entropy(token) > 4.5 and len(token) > 20:
                return self._mk(
                    "FM-1.5",
                    "Credential Leakage",
                    "high",
                    0.75,
                    "High-entropy token-like value found in response output.",
                    {"sample_len": len(token)},
                    "Inspect output and redact suspicious secret-like values.",
                )
        return None

    def _check_context_overflow(self, agent_id: str, request_data: dict[str, Any], context: dict[str, Any]) -> Optional[MASTFinding]:
        _ = agent_id
        model = str(request_data.get("model", "") or "")
        window = self._context_window(model)
        messages = self._extract_messages(request_data)
        lengths = [self._tokens(str(msg.get("content", "") if isinstance(msg, dict) else "")) for msg in messages]
        total = sum(lengths)
        if lengths and max(lengths) > int(window * 0.5):
            return self._mk(
                "FM-2.3",
                "Context Window Overflow",
                "critical",
                0.95,
                "Single message consumes >50% of model context window.",
                {"max_message_tokens": max(lengths), "context_window": window},
                "Reject oversized message and require chunking/summarization.",
            )
        usage_ratio = total / float(max(1, window))
        if usage_ratio > 0.8:
            return self._mk(
                "FM-2.3",
                "Context Window Overflow",
                "high",
                0.85,
                "Total prompt size exceeds 80% of context window.",
                {"total_tokens": total, "context_window": window},
                "Apply context compression and preserve core instructions.",
            )
        if usage_ratio > 0.6:
            return self._mk(
                "FM-2.3",
                "Context Window Overflow",
                "medium",
                0.65,
                "Prompt is approaching context limit.",
                {"ratio": round(usage_ratio, 3)},
                "Enable proactive trimming/summarization before overflow.",
            )
        for msg in messages:
            text = str(msg.get("content", "") if isinstance(msg, dict) else "")
            if _B64_RE.search(text):
                return self._mk(
                    "FM-2.3",
                    "Context Window Overflow",
                    "high",
                    0.8,
                    "Large encoded blob detected (possible context-filling attack).",
                    {"model": model or "_default"},
                    "Reject large encoded payloads and request structured input.",
                )
        if len(lengths) >= 4:
            grows = sum(1 for i in range(1, len(lengths)) if lengths[i] > lengths[i - 1] * 1.5 and lengths[i] > 200)
            if grows >= 3:
                return self._mk(
                    "FM-2.3",
                    "Context Window Overflow",
                    "high",
                    0.78,
                    "Rapid message growth trend indicates potential overflow strategy.",
                    {"growth_events": grows},
                    "Rate-limit large turns and enforce progressive size caps.",
                )
        return None

    def _check_cascading_failure(self, agent_id: str, request_data: dict[str, Any], context: dict[str, Any]) -> Optional[MASTFinding]:
        now = time.time()
        failed = bool(context.get("request_failed", False))
        status_code = int(request_data.get("status_code", 0) or 0)
        if status_code >= 500:
            failed = True
        if failed:
            self._error_events.append((now, agent_id, "error"))
        retry_count = int(context.get("retry_count", 0) or 0)
        if retry_count > 2:
            self._error_events.append((now, agent_id, "retry"))
        recent = [item for item in self._error_events if now - item[0] <= 60.0]
        failed_agents = {a for ts, a, kind in recent if kind == "error" and now - ts <= 60.0}
        if len(failed_agents) >= 3:
            return self._mk(
                "FM-2.6",
                "Cascading Failure",
                "high" if len(failed_agents) < 4 else "critical",
                0.9 if len(failed_agents) >= 4 else 0.82,
                "Multiple agents failing concurrently indicates cascading behavior.",
                {"failed_agents_60s": len(failed_agents)},
                "Open circuit for shared dependencies and isolate failing workloads.",
            )
        if len(failed_agents) == 2:
            return self._mk(
                "FM-2.6",
                "Cascading Failure",
                "medium",
                0.7,
                "Two agents failed within the same short time window.",
                {"failed_agents_60s": 2},
                "Monitor shared dependencies and apply backpressure.",
            )
        retries = [item for item in recent if item[2] == "retry"]
        if len(retries) >= 5:
            return self._mk(
                "FM-2.6",
                "Cascading Failure",
                "high",
                0.8,
                "Retry storm detected across agents.",
                {"retries_60s": len(retries)},
                "Enable exponential backoff and enforce retry budgets.",
            )
        return None

    def _check_output_manipulation(self, agent_id: str, response_data: dict[str, Any], original_request: dict[str, Any]) -> Optional[MASTFinding]:
        _ = agent_id
        role = str(response_data.get("role", "") or "")
        if role and role.lower() != "assistant":
            return self._mk(
                "FM-3.1",
                "Output Manipulation",
                "critical",
                0.95,
                "Response role mismatch detected.",
                {"role": role},
                "Reject response and verify upstream response integrity.",
            )
        text = response_text(response_data)
        if not text:
            return None
        if _HIDDEN_UNICODE_RE.search(text):
            return self._mk(
                "FM-3.1",
                "Output Manipulation",
                "critical",
                0.95,
                "Hidden/invisible Unicode content detected in output.",
                {"contains_hidden_unicode": True},
                "Strip invisible characters and alert operator.",
            )
        if _SOCIAL_RE.search(text):
            return self._mk(
                "FM-3.1",
                "Output Manipulation",
                "high",
                0.86,
                "Potential social-engineering instructions found in output.",
                {"snippet": text[:120]},
                "Warn user and require explicit confirmation before actions.",
            )
        urls = _URL_RE.findall(text)
        if urls:
            req_text = response_text(original_request or {})
            if not any(url in req_text for url in urls):
                return self._mk(
                    "FM-3.1",
                    "Output Manipulation",
                    "medium",
                    0.7,
                    "Response contains URLs not present in original request context.",
                    {"urls": urls[:3]},
                    "Flag suspicious links and enforce URL allowlist policy.",
                )
        return None

    def _check_observability_gap(self, agent_id: str, request_data: dict[str, Any], context: dict[str, Any]) -> Optional[MASTFinding]:
        now = time.time()
        session_id = str(request_data.get("session_id", context.get("session_id", "")) or "")
        model = str(request_data.get("model", "") or "")
        if not session_id and not str(request_data.get("request_id", "") or ""):
            return self._mk(
                "OE-1",
                "Observability Gap",
                "critical",
                0.92,
                "Request is completely untracked (missing session and request identifiers).",
                {},
                "Inject mandatory IDs at ingress and reject untracked traffic.",
            )
        if not session_id:
            return self._mk(
                "OE-1",
                "Observability Gap",
                "medium",
                0.7,
                "Missing session identifier reduces traceability.",
                {},
                "Ensure session id is propagated across all agent requests.",
            )
        if not model:
            return self._mk(
                "OE-1",
                "Observability Gap",
                "low",
                0.55,
                "Model field missing; cost and attribution may be incomplete.",
                {},
                "Populate model metadata before routing.",
            )
        with self._lock:
            last = self._agent_last_seen.get(agent_id)
            self._agent_last_seen[agent_id] = now
        if isinstance(last, float) and (now - last) > float(context.get("max_gap_seconds", 600.0)):
            return self._mk(
                "OE-1",
                "Observability Gap",
                "high",
                0.8,
                "Large unexplained activity gap detected for tracked agent.",
                {"gap_seconds": round(now - last, 3)},
                "Audit ingestion path for dropped telemetry events.",
            )
        calls = self._extract_tool_calls(request_data)
        if calls and not bool(context.get("tool_metadata_present", True)):
            return self._mk(
                "OE-1",
                "Observability Gap",
                "medium",
                0.68,
                "Tool calls present but tool metadata missing from observability context.",
                {"tool_calls": len(calls)},
                "Attach tool usage metadata in telemetry pipeline.",
            )
        return None

    def _check_compliance_drift(self, agent_id: str, request_data: dict[str, Any], context: dict[str, Any]) -> Optional[MASTFinding]:
        _ = agent_id
        model = str(request_data.get("model", "") or "")
        approved_models = context.get("approved_models")
        approved_models_set = set(approved_models) if isinstance(approved_models, list) else set()
        findings: list[tuple[str, float, str, dict[str, Any], str]] = []
        if approved_models_set and model and model not in approved_models_set:
            findings.append(
                (
                    "high",
                    0.85,
                    "Model outside approved compliance boundary.",
                    {"model": model},
                    "Route to approved model set only.",
                )
            )
        ars_hist = context.get("ars_history")
        if isinstance(ars_hist, list) and len(ars_hist) >= 2:
            try:
                first = _GRADE_VALUE.get(str(ars_hist[0]).upper(), 0)
                last = _GRADE_VALUE.get(str(ars_hist[-1]).upper(), 0)
                if first - last >= 2:
                    findings.append(
                        (
                            "high",
                            0.82,
                            "ARS grade declined by 2+ levels.",
                            {"from": str(ars_hist[0]), "to": str(ars_hist[-1])},
                            "Investigate regression and apply stricter runtime controls.",
                        )
                    )
            except Exception:
                pass
        risk_hist = context.get("risk_history")
        if isinstance(risk_hist, list) and len(risk_hist) >= 3:
            try:
                last3 = [float(x) for x in risk_hist[-3:]]
                if last3[0] < last3[1] < last3[2]:
                    sev = "critical" if last3[-1] >= 80 else "medium"
                    findings.append(
                        (
                            sev,
                            0.9 if sev == "critical" else 0.7,
                            "Session risk trending upward over time.",
                            {"recent_risk": last3},
                            "Trigger adaptive throttling and review policy drift.",
                        )
                    )
            except Exception:
                pass
        token_hist = context.get("token_usage_history")
        token_budget = context.get("token_budget")
        if isinstance(token_hist, list) and isinstance(token_budget, dict) and token_hist:
            budget_limit = float(token_budget.get("daily", token_budget.get("max_tokens", 0)) or 0.0)
            if budget_limit > 0:
                avg_recent = sum(float(x) for x in token_hist[-5:]) / float(min(5, len(token_hist)))
                if avg_recent > budget_limit * 0.5:
                    findings.append(
                        (
                            "medium",
                            0.66,
                            "Token usage trend is approaching budget ceiling.",
                            {"avg_recent": avg_recent, "budget_limit": budget_limit},
                            "Enable stronger context compression and budget controls.",
                        )
                    )
        if not findings:
            return None
        order = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        severity, conf, desc, evidence, rec = max(findings, key=lambda item: order[item[0]])
        return self._mk("OE-6", "Compliance Drift", severity, conf, desc, evidence, rec)

    def check_request(self, agent_id: str, request_data: dict[str, Any], context: dict | None = None) -> list[MASTFinding]:
        if not self.enabled:
            return []
        ctx = context if isinstance(context, dict) else {}
        req = request_data if isinstance(request_data, dict) else {}
        findings: list[MASTFinding] = []
        with self._lock:
            self._stats["checks_request"] += 1
        checks = [
            ("privilege_escalation", self._check_privilege_escalation),
            ("tool_abuse", self._check_tool_abuse),
            ("context_overflow", self._check_context_overflow),
            ("cascading_failure", self._check_cascading_failure),
            ("observability_gap", self._check_observability_gap),
            ("compliance_drift", self._check_compliance_drift),
        ]
        for key, fn in checks:
            if not self._enabled.get(key, False):
                continue
            try:
                finding = fn(agent_id, req, ctx)
                if isinstance(finding, MASTFinding):
                    findings.append(finding)
                    self._record(agent_id, finding)
            except Exception:
                continue
        return findings

    def check_response(
        self,
        agent_id: str,
        response_data: dict[str, Any],
        original_request: dict | None = None,
    ) -> list[MASTFinding]:
        if not self.enabled:
            return []
        findings: list[MASTFinding] = []
        with self._lock:
            self._stats["checks_response"] += 1
        checks = [
            ("credential_leakage", self._check_credential_leakage),
            ("output_manipulation", self._check_output_manipulation),
        ]
        for key, fn in checks:
            if not self._enabled.get(key, False):
                continue
            try:
                finding = fn(agent_id, response_data if isinstance(response_data, dict) else {}, original_request or {})
                if isinstance(finding, MASTFinding):
                    findings.append(finding)
                    self._record(agent_id, finding)
            except Exception:
                continue
        return findings

    def get_agent_compliance(self, agent_id: str) -> dict[str, Any]:
        with self._lock:
            findings = list(self._agent_findings.get(agent_id, []))
            last_check = float(self._agent_last_seen.get(agent_id, 0.0))
        by_sev = {"low": 0, "medium": 0, "high": 0, "critical": 0}
        modes: set[str] = set()
        penalty = 0
        for item in findings:
            by_sev[item.severity] = by_sev.get(item.severity, 0) + 1
            modes.add(item.failure_mode)
            penalty += _SEVERITY_SCORE.get(item.severity, 5)
        score = max(0, 100 - penalty)
        return {
            "agent_id": agent_id,
            "findings_total": len(findings),
            "findings_by_severity": by_sev,
            "failure_modes_triggered": sorted(modes),
            "compliance_score": score,
            "last_check": last_check,
        }

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            return {
                "enabled": self.enabled,
                "checks_request": int(self._stats["checks_request"]),
                "checks_response": int(self._stats["checks_response"]),
                "findings_total": int(self._stats["findings_total"]),
                "findings_by_mode": dict(self._stats["findings_by_mode"]),
                "findings_by_severity": dict(self._stats["findings_by_severity"]),
                "agents_tracked": len(self._agent_findings),
            }

    def reset(self, agent_id: str) -> None:
        with self._lock:
            self._agent_findings.pop(agent_id, None)
            self._agent_last_seen.pop(agent_id, None)
            self._tool_history.pop(agent_id, None)


def jsonable(value: Any) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    except Exception:
        return str(value)


def response_text(payload: dict[str, Any]) -> str:
    if not isinstance(payload, dict):
        return ""
    if isinstance(payload.get("content"), str):
        return str(payload.get("content", ""))
    choices = payload.get("choices")
    if isinstance(choices, list) and choices:
        first = choices[0]
        if isinstance(first, dict):
            msg = first.get("message")
            if isinstance(msg, dict) and isinstance(msg.get("content"), str):
                return str(msg.get("content", ""))
    output = payload.get("output_text")
    if isinstance(output, str):
        return output
    return ""
