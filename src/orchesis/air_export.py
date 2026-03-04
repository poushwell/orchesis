"""AIR (AI Interaction Record) export helpers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
import gzip
import json
import platform
from typing import Any

from orchesis import __version__ as _ORCHESIS_VERSION


_ALLOWED_CONTENT_LEVELS = {"metadata", "structure", "full"}


@dataclass
class AIRDocument:
    """Root of an AIR file."""

    air: str = "1.0"
    id: str = ""
    created: str = ""
    content_level: str = "structure"
    creator: dict[str, Any] = field(default_factory=dict)
    agent: dict[str, Any] = field(default_factory=dict)
    environment: dict[str, Any] = field(default_factory=dict)
    models: dict[str, Any] = field(default_factory=dict)
    summary: dict[str, Any] = field(default_factory=dict)
    turns: list[dict[str, Any]] = field(default_factory=list)
    annotations: list[dict[str, Any]] = field(default_factory=list)
    extensions: dict[str, Any] = field(default_factory=dict)


@dataclass
class AIRTurn:
    """One interaction unit in AIR."""

    turn_id: str
    sequence: int
    timestamp: str
    type: str
    request: dict[str, Any]
    response: dict[str, Any]
    timing: dict[str, Any]
    tool_results: list[dict[str, Any]]
    metadata: dict[str, Any]


def _iso_from_ts(timestamp: float) -> str:
    return datetime.fromtimestamp(float(timestamp), tz=timezone.utc).isoformat()


def _safe_jsonable(value: Any) -> Any:
    try:
        json.dumps(value, ensure_ascii=False)
        return value
    except Exception:
        return repr(value)


def _extract_tool_results(response_body: dict[str, Any] | None, content_level: str) -> list[dict[str, Any]]:
    if not isinstance(response_body, dict):
        return []
    content = response_body.get("content")
    if not isinstance(content, list):
        return []
    tool_results: list[dict[str, Any]] = []
    for item in content:
        if not isinstance(item, dict):
            continue
        if str(item.get("type")) not in {"tool_use", "tool_result"}:
            continue
        entry: dict[str, Any] = {
            "name": item.get("name", ""),
            "status": item.get("status", "ok"),
            "latency_ms": item.get("latency_ms"),
        }
        if content_level == "full":
            entry["input"] = _safe_jsonable(item.get("input"))
            entry["output"] = _safe_jsonable(item.get("output"))
        tool_results.append(entry)
    return tool_results


def _strip_messages_for_structure(messages: Any) -> list[dict[str, Any]]:
    if not isinstance(messages, list):
        return []
    result: list[dict[str, Any]] = []
    for msg in messages:
        if isinstance(msg, dict):
            role = msg.get("role")
            entry: dict[str, Any] = {"role": role if isinstance(role, str) else "unknown"}
            if "type" in msg:
                entry["type"] = msg.get("type")
            if "name" in msg:
                entry["name"] = msg.get("name")
            result.append(entry)
        else:
            result.append({"role": "unknown"})
    return result


def _build_turns_from_recording(entries: list[Any], content_level: str) -> list[dict[str, Any]]:
    turns: list[dict[str, Any]] = []
    if content_level not in _ALLOWED_CONTENT_LEVELS:
        raise ValueError(f"Invalid content_level: {content_level}")
    for index, raw_entry in enumerate(entries, start=1):
        entry = raw_entry if hasattr(raw_entry, "request_id") else None
        if entry is None:
            continue
        request_body = entry.request if isinstance(entry.request, dict) else {}
        response_body = entry.response if isinstance(entry.response, dict) else {}
        usage = response_body.get("usage", {}) if isinstance(response_body, dict) else {}
        input_tokens = int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0)
        output_tokens = int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0)

        base_request: dict[str, Any] = {
            "model": str(entry.model or request_body.get("model", "")),
            "parameters": {},
        }
        for key in ("temperature", "top_p", "max_tokens", "stop"):
            if key in request_body:
                base_request["parameters"][key] = _safe_jsonable(request_body.get(key))

        if content_level == "full":
            base_request["messages"] = _safe_jsonable(request_body.get("messages", []))
            base_request["tools"] = _safe_jsonable(request_body.get("tools", []))
        elif content_level == "structure":
            base_request["messages"] = _strip_messages_for_structure(request_body.get("messages", []))
            tools = request_body.get("tools", [])
            if isinstance(tools, list):
                base_request["tools"] = [
                    {"name": item.get("name", "")} if isinstance(item, dict) else {"name": str(item)}
                    for item in tools
                ]

        finish_reason = None
        if isinstance(response_body.get("choices"), list) and response_body["choices"]:
            first_choice = response_body["choices"][0]
            if isinstance(first_choice, dict):
                finish_reason = first_choice.get("finish_reason")

        turn = AIRTurn(
            turn_id=f"t_{index:03d}",
            sequence=index,
            timestamp=_iso_from_ts(float(entry.timestamp)),
            type="error" if entry.error or int(entry.status_code) >= 400 else "llm_call",
            request=base_request if content_level != "metadata" else {"model": base_request["model"]},
            response={
                "status": int(entry.status_code),
                "finish_reason": finish_reason,
                "usage": {
                    "input_tokens": input_tokens,
                    "output_tokens": output_tokens,
                },
                "cost_usd": round(float(entry.cost), 8),
            },
            timing={
                "latency_ms": round(float(entry.latency_ms), 4),
                "time_to_first_token_ms": None,
            },
            tool_results=[] if content_level == "metadata" else _extract_tool_results(response_body, content_level),
            metadata={
                "provider": entry.provider,
                "error": entry.error,
                "orchesis": _safe_jsonable(entry.metadata if isinstance(entry.metadata, dict) else {}),
            },
        )
        turns.append(asdict(turn))
    return turns


def air_summary_from_turns(turns: list[dict[str, Any]]) -> dict[str, Any]:
    if not turns:
        return {
            "duration_ms": 0.0,
            "total_turns": 0,
            "total_tokens": {"input": 0, "output": 0},
            "total_cost_usd": 0.0,
            "models_used": [],
            "tools_used": [],
            "outcome": "empty",
            "error_count": 0,
        }
    input_tokens = 0
    output_tokens = 0
    total_cost = 0.0
    models: set[str] = set()
    tools: set[str] = set()
    error_count = 0
    first_ts = turns[0].get("timestamp")
    last_ts = turns[-1].get("timestamp")
    for turn in turns:
        req = turn.get("request", {})
        if isinstance(req, dict):
            model = req.get("model")
            if isinstance(model, str) and model:
                models.add(model)
        resp = turn.get("response", {})
        if isinstance(resp, dict):
            usage = resp.get("usage", {})
            if isinstance(usage, dict):
                input_tokens += int(usage.get("input_tokens", 0) or 0)
                output_tokens += int(usage.get("output_tokens", 0) or 0)
            total_cost += float(resp.get("cost_usd", 0.0) or 0.0)
            if int(resp.get("status", 0) or 0) >= 400:
                error_count += 1
        for tool in turn.get("tool_results", []) if isinstance(turn.get("tool_results"), list) else []:
            if isinstance(tool, dict):
                name = tool.get("name")
                if isinstance(name, str) and name:
                    tools.add(name)
        if turn.get("type") == "error":
            error_count += 1

    duration_ms = 0.0
    try:
        start_dt = datetime.fromisoformat(str(first_ts))
        end_dt = datetime.fromisoformat(str(last_ts))
        duration_ms = max(0.0, (end_dt - start_dt).total_seconds() * 1000.0)
    except Exception:
        duration_ms = 0.0

    outcome = "error" if error_count > 0 else "ok"
    return {
        "duration_ms": round(duration_ms, 4),
        "total_turns": len(turns),
        "total_tokens": {"input": input_tokens, "output": output_tokens},
        "total_cost_usd": round(total_cost, 8),
        "models_used": sorted(models),
        "tools_used": sorted(tools),
        "outcome": outcome,
        "error_count": int(error_count),
    }


def _flow_extension(flow_analyzer: Any, session_id: str) -> dict[str, Any] | None:
    if flow_analyzer is None:
        return None
    try:
        analysis = flow_analyzer.analyze_session(session_id)
    except Exception:
        return None
    if analysis is None:
        return None
    payload = analysis.to_dict() if hasattr(analysis, "to_dict") else None
    if not isinstance(payload, dict):
        return None
    summary = payload.get("summary", {}) if isinstance(payload.get("summary"), dict) else {}
    topology = payload.get("topology", {}) if isinstance(payload.get("topology"), dict) else {}
    patterns = payload.get("patterns", []) if isinstance(payload.get("patterns"), list) else []
    return {
        "health_score": float(summary.get("health_score", 0.0)),
        "total_patterns": int(summary.get("total_patterns", 0)),
        "critical_patterns": int(summary.get("critical_patterns", 0)),
        "estimated_waste_usd": float(summary.get("estimated_waste_usd", 0.0)),
        "estimated_waste_ms": float(summary.get("estimated_waste_ms", 0.0)),
        "top_issue": str(summary.get("top_issue", "")),
        "topology": {
            "depth": int(topology.get("depth", 0)),
            "width": int(topology.get("width", 0)),
            "density": float(topology.get("density", 0.0)),
            "tool_diversity": float(topology.get("tool_diversity", 0.0)),
        },
        "patterns": patterns,
    }


def _agent_dna_extension(behavioral_detector: Any, session_records: list[Any]) -> dict[str, Any] | None:
    if behavioral_detector is None:
        return None
    agent_id = "default"
    for item in session_records:
        meta = item.metadata if hasattr(item, "metadata") and isinstance(item.metadata, dict) else {}
        candidate = meta.get("agent_id")
        if isinstance(candidate, str) and candidate:
            agent_id = candidate
            break
    try:
        profile = behavioral_detector.get_agent_profile(agent_id)
    except Exception:
        return None
    if not isinstance(profile, dict):
        return None
    dims = profile.get("dimensions", {}) if isinstance(profile.get("dimensions"), dict) else {}
    tool_dist = profile.get("tool_distribution", {}) if isinstance(profile.get("tool_distribution"), dict) else {}
    total_tools = sum(int(v) for v in tool_dist.values() if isinstance(v, int | float))
    tool_diversity = (len(tool_dist) / total_tools) if total_tools > 0 else 0.0
    return {
        "request_frequency": float(dims.get("request_frequency", {}).get("mean", 0.0))
        if isinstance(dims.get("request_frequency"), dict)
        else 0.0,
        "avg_input_tokens": float(dims.get("prompt_tokens", {}).get("mean", 0.0))
        if isinstance(dims.get("prompt_tokens"), dict)
        else 0.0,
        "avg_output_tokens": float(dims.get("completion_tokens", {}).get("mean", 0.0))
        if isinstance(dims.get("completion_tokens"), dict)
        else 0.0,
        "tool_diversity": round(float(tool_diversity), 6),
        "anomaly_scores": {
            "error_rate": float(dims.get("error_rate", {}).get("mean", 0.0))
            if isinstance(dims.get("error_rate"), dict)
            else 0.0
        },
        "total_requests": int(profile.get("total_requests", 0)),
    }


def export_session_to_air(
    session_id: str,
    recorder: Any,
    flow_analyzer: Any = None,
    behavioral_detector: Any = None,
    compliance_engine: Any = None,
    content_level: str = "structure",
    version: str | None = None,
) -> dict[str, Any]:
    """Export a recorded session to AIR document."""
    if content_level not in _ALLOWED_CONTENT_LEVELS:
        raise ValueError(f"Invalid content_level: {content_level}")
    if recorder is None:
        return {"error": "recorder_not_available", "session_id": session_id}
    try:
        records = recorder.load_session(session_id)
    except Exception:
        records = []
    if not records:
        return {"error": "session_not_found", "session_id": session_id}

    turns = _build_turns_from_recording(records, content_level)
    created = datetime.now(timezone.utc).isoformat()
    extensions: dict[str, Any] = {"orchesis": {}}

    flow_payload = _flow_extension(flow_analyzer, session_id)
    if flow_payload is not None:
        extensions["orchesis"]["flow_xray"] = flow_payload

    dna_payload = _agent_dna_extension(behavioral_detector, records)
    if dna_payload is not None:
        extensions["orchesis"]["agent_dna"] = dna_payload
    if compliance_engine is not None:
        try:
            findings = compliance_engine.get_findings(limit=500)
        except Exception:
            findings = []
        session_findings: list[dict[str, Any]] = []
        for item in findings:
            evidence = item.evidence if isinstance(item.evidence, dict) else {}
            sid = evidence.get("session_id")
            if sid is not None and str(sid) != session_id:
                continue
            if hasattr(item, "severity"):
                sev = getattr(item, "severity")
                severity_value = sev.value if hasattr(sev, "value") else str(sev)
            else:
                severity_value = "info"
            session_findings.append(
                {
                    "finding_id": str(getattr(item, "finding_id", "")),
                    "timestamp": str(getattr(item, "timestamp", "")),
                    "source_module": str(getattr(item, "source_module", "")),
                    "source_detail": str(getattr(item, "source_detail", "")),
                    "description": str(getattr(item, "description", "")),
                    "severity": severity_value,
                    "framework_mappings": list(getattr(item, "framework_mappings", [])),
                }
            )
        try:
            summary = compliance_engine.get_summary()
        except Exception:
            summary = {}
        frameworks = []
        if isinstance(summary, dict):
            fw_map = summary.get("frameworks", {})
            if isinstance(fw_map, dict):
                frameworks = list(fw_map.keys())
        owasp_percent = 0.0
        if isinstance(summary, dict):
            fw_map = summary.get("frameworks", {})
            if isinstance(fw_map, dict):
                owasp = fw_map.get("owasp_llm_top10_2025", {})
                if isinstance(owasp, dict):
                    owasp_percent = float(owasp.get("percent", 0.0))
        extensions["orchesis"]["compliance"] = {
            "frameworks_evaluated": frameworks,
            "owasp_coverage_percent": owasp_percent,
            "session_findings": session_findings,
        }

    models: dict[str, Any] = {}
    for turn in turns:
        req = turn.get("request", {})
        model = req.get("model") if isinstance(req, dict) else None
        if isinstance(model, str) and model:
            models.setdefault(model, {"pricing": {}, "provider": "unknown"})

    doc = AIRDocument(
        air="1.0",
        id=session_id,
        created=created,
        content_level=content_level,
        creator={"name": "orchesis", "version": str(version or _ORCHESIS_VERSION)},
        agent={"id": session_id},
        environment={
            "os": platform.platform(),
            "python": platform.python_version(),
            "timezone": datetime.now().astimezone().tzname(),
        },
        models=models,
        summary=air_summary_from_turns(turns),
        turns=turns,
        annotations=[],
        extensions=extensions,
    )
    return asdict(doc)


def export_session_to_air_file(
    session_id: str,
    output_path: str,
    recorder: Any,
    flow_analyzer: Any = None,
    behavioral_detector: Any = None,
    compliance_engine: Any = None,
    content_level: str = "structure",
    version: str | None = None,
    compress: bool = False,
) -> str:
    """Export session to .air or .air.gz file on disk."""
    doc = export_session_to_air(
        session_id=session_id,
        recorder=recorder,
        flow_analyzer=flow_analyzer,
        behavioral_detector=behavioral_detector,
        compliance_engine=compliance_engine,
        content_level=content_level,
        version=version,
    )
    if not isinstance(doc, dict) or "error" in doc:
        raise FileNotFoundError(f"Session not found: {session_id}")
    base_path = output_path
    if compress:
        if not base_path.endswith(".air.gz"):
            if base_path.endswith(".air"):
                base_path = f"{base_path}.gz"
            else:
                base_path = f"{base_path}.air.gz"
        with gzip.open(base_path, "wt", encoding="utf-8") as fh:
            json.dump(doc, fh, ensure_ascii=False, indent=2)
        return base_path
    if not base_path.endswith(".air"):
        base_path = f"{base_path}.air"
    with open(base_path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, ensure_ascii=False, indent=2)
    return base_path


def validate_air(data: dict[str, Any]) -> list[str]:
    """Validate AIR document and return errors list."""
    errors: list[str] = []
    if not isinstance(data, dict):
        return ["document must be an object"]
    required_root = ("air", "id", "created", "creator", "summary", "turns")
    for key in required_root:
        if key not in data:
            errors.append(f"missing required field: {key}")
    if "air" in data and str(data.get("air")) != "1.0":
        errors.append(f"unknown AIR version: {data.get('air')}")
    turns = data.get("turns")
    if not isinstance(turns, list):
        errors.append("turns must be a list")
        return errors
    required_turn = ("turn_id", "sequence", "timestamp", "type", "request", "response", "timing")
    for idx, turn in enumerate(turns):
        if not isinstance(turn, dict):
            errors.append(f"turn {idx} must be object")
            continue
        for key in required_turn:
            if key not in turn:
                errors.append(f"turn {idx} missing field: {key}")
    return errors

