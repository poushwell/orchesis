from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request

try:
    from orchesis.vibe_audit import VibeCodeAuditor
except ModuleNotFoundError:
    class VibeCodeAuditor:  # type: ignore[no-redef]
        def __init__(self, _config: dict[str, Any] | None = None):
            _ = _config

        def audit_code(self, code: str, language: str) -> dict[str, Any]:
            _ = (code, language)
            return {"score": 0.0, "findings": [], "summary": "vibe_audit module unavailable"}

        def audit_directory_summary(self, dir_path: str, extensions: list[str] | None = None) -> dict[str, Any]:
            _ = (dir_path, extensions)
            return {"files_audited": 0, "avg_score": 100.0, "grade": "A", "worst_files": []}

        def audit_directory(self, dir_path: str, extensions: list[str] | None = None) -> dict[str, Any]:
            _ = (dir_path, extensions)
            return {"files": []}


router = APIRouter(prefix="/api/v1", tags=["ecosystem"])


@dataclass
class PaginatedResponse:
    items: list[Any]
    total: int
    limit: int
    offset: int
    has_more: bool


def paginate(items: list[Any], limit: int = 100, offset: int = 0, max_limit: int = 1000) -> PaginatedResponse:
    safe_limit = max(1, min(int(limit), int(max_limit)))
    safe_offset = max(0, int(offset))
    total = len(items)
    page = items[safe_offset : safe_offset + safe_limit]
    return PaginatedResponse(
        items=page,
        total=total,
        limit=safe_limit,
        offset=safe_offset,
        has_more=(safe_offset + safe_limit) < total,
    )


def _require_auth(request: Request, authorization: str | None) -> None:
    auth = getattr(request.app.state, "require_auth", None)
    if callable(auth):
        auth(authorization)
        return
    raise HTTPException(status_code=401, detail={"error": "unauthorized"})


@router.get("/casura/incidents/stats")
def casura_incident_stats(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    return request.app.state.casura_db.get_stats()


@router.post("/casura/incidents/search")
def casura_incident_search(
    request: Request,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    query = str(payload.get("query", "") or "")
    filters = payload.get("filters", {})
    rows = request.app.state.casura_db.search(query=query, filters=filters if isinstance(filters, dict) else None)
    return {"incidents": rows, "total": len(rows)}


@router.get("/casura/incidents")
def casura_incidents(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    paginated: bool = Query(False),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    rows = request.app.state.casura_db.search(query="")
    if not paginated:
        return {"incidents": rows, "total": len(rows)}
    page = paginate(rows, limit=limit, offset=offset, max_limit=1000)
    return asdict(page)


@router.post("/casura/incidents")
def casura_create_incident(
    request: Request,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    return request.app.state.casura_db.create_incident(payload)


@router.get("/casura/incidents/{incident_id}")
def casura_get_incident(
    request: Request,
    incident_id: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    item = request.app.state.casura_db._incidents.get(incident_id)
    if not isinstance(item, dict):
        raise HTTPException(status_code=404, detail={"error": "incident not found"})
    return dict(item)


@router.get("/casura/intelligence/patterns")
def casura_intel_patterns(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    incidents = request.app.state.casura_db.search(query="")
    return request.app.state.casura_intel.analyze_patterns(incidents)


@router.get("/casura/intelligence/mitre-coverage")
def casura_mitre_coverage(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    incidents = request.app.state.casura_db.search(query="")
    return request.app.state.casura_intel.get_mitre_coverage(incidents)


@router.get("/aabb/leaderboard")
def aabb_leaderboard(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    paginated: bool = Query(False),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    rows = request.app.state.aabb_benchmark.get_leaderboard()
    if not paginated:
        return {"leaderboard": rows, "total": len(rows)}
    page = paginate(rows, limit=limit, offset=offset, max_limit=1000)
    return asdict(page)


@router.post("/aabb/run/{agent_id}")
def aabb_run(
    request: Request,
    agent_id: str,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    proxy_url = str(payload.get("proxy_url", "http://localhost:8080") or "http://localhost:8080")
    return request.app.state.aabb_benchmark.run_suite(agent_id=agent_id, proxy_url=proxy_url)


@router.get("/aabb/stats")
def aabb_stats(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    return request.app.state.aabb_benchmark.get_benchmark_stats()


@router.get("/aabb/compare/{agent_a}/{agent_b}")
def aabb_compare(
    request: Request,
    agent_a: str,
    agent_b: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    return request.app.state.aabb_benchmark.compare_agents(agent_a, agent_b)


@router.post("/are/slo")
def are_define_slo(
    request: Request,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    name = str(body.get("name", "")).strip()
    sli = str(body.get("sli", "")).strip()
    target = body.get("target")
    window_days = body.get("window_days", 30)
    if not name or not sli or target is None:
        raise HTTPException(status_code=400, detail={"error": "name, sli, target are required"})
    try:
        row = request.app.state.are.define_slo(
            name=name,
            sli=sli,
            target=float(target),
            window_days=int(window_days),
        )
    except (ValueError, TypeError) as error:
        raise HTTPException(status_code=400, detail={"error": str(error)}) from error
    return {"slo": row}


@router.post("/are/sli/{slo_name}")
def are_record_sli(
    request: Request,
    slo_name: str,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    if "value" not in body:
        raise HTTPException(status_code=400, detail={"error": "value is required"})
    try:
        request.app.state.are.record_sli(slo_name, float(body.get("value")))
    except KeyError as error:
        raise HTTPException(status_code=404, detail={"error": str(error)}) from error
    except (TypeError, ValueError) as error:
        raise HTTPException(status_code=400, detail={"error": str(error)}) from error
    return {"ok": True, "slo_name": slo_name}


@router.get("/are/budget/{slo_name}")
def are_budget(
    request: Request,
    slo_name: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    try:
        return request.app.state.are.get_error_budget(slo_name)
    except KeyError as error:
        raise HTTPException(status_code=404, detail={"error": str(error)}) from error


@router.get("/are/report")
def are_report(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    return request.app.state.are.get_reliability_report()


@router.get("/are/alerts")
def are_alerts(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    paginated: bool = Query(False),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    report = request.app.state.are.get_reliability_report()
    alerts: list[dict[str, Any]] = []
    for row in report.get("slos", []):
        if not isinstance(row, dict):
            continue
        slo_name = str(row.get("slo_name", "")).strip()
        if not slo_name:
            continue
        alert = request.app.state.are.get_burn_rate_alert(slo_name)
        if isinstance(alert, dict):
            alerts.append(alert)
    if not paginated:
        return {"alerts": alerts, "count": len(alerts)}
    return asdict(paginate(alerts, limit=limit, offset=offset, max_limit=1000))


@router.get("/competitive/latest")
def competitive_latest(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    incidents = request.app.state.casura_db.search(query="")
    changes = request.app.state.competitive_monitor.detect_ecosystem_changes(
        incidents if isinstance(incidents, list) else []
    )
    leaderboard = request.app.state.aabb_benchmark.get_leaderboard()
    competitor_alerts: list[dict[str, Any]] = []
    if isinstance(leaderboard, list):
        for row in leaderboard[:5]:
            if not isinstance(row, dict):
                continue
            agent_name = str(row.get("agent_id", "") or "")
            score = float(row.get("score", 0.0) or 0.0)
            if score >= 0.8:
                competitor_alerts.append(
                    {
                        "event": "competitor_stars_spike",
                        "title": f"High-performing competitor signal: {agent_name}",
                        "severity": "medium",
                        "score": score,
                    }
                )
    alerts = changes + competitor_alerts
    return {"alerts": alerts, "count": len(alerts)}


@router.get("/monitoring/parse-hn")
async def monitoring_parse_hn(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = await request.json() if request is not None else {}
    if not isinstance(payload, dict):
        payload = {}
    item = payload.get("item", {})
    if not isinstance(item, dict):
        raise HTTPException(status_code=400, detail={"error": "item must be an object"})
    parsed = request.app.state.social_parsers.parse_hn_item(item)
    request.app.state.monitoring_items.append(parsed)
    if len(request.app.state.monitoring_items) > 1000:
        request.app.state.monitoring_items = request.app.state.monitoring_items[-1000:]
    request.app.state.monitoring_opportunities = request.app.state.social_parsers.extract_opportunities(
        request.app.state.monitoring_items[-200:]
    )
    return {"parsed": parsed}


@router.get("/monitoring/opportunities")
def monitoring_opportunities(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    paginated: bool = Query(False),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    rows = request.app.state.monitoring_opportunities
    if not paginated:
        legacy = rows[-20:]
        return {"opportunities": legacy, "count": len(legacy)}
    return asdict(paginate(rows, limit=limit, offset=offset, max_limit=1000))


@router.get("/monitoring/weekly-report")
def monitoring_weekly_report(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    feed_items = request.app.state.monitoring_items[-200:]
    report = request.app.state.competitive_monitor.generate_weekly_report(
        {
            "competitors": {},
            "feed": feed_items,
        }
    )
    return report


@router.post("/monitoring/score-relevance")
def monitoring_score_relevance(
    request: Request,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    text = str(payload.get("text", "") or "")
    score = request.app.state.social_parsers.score_relevance(text)
    return {"text": text, "relevance_score": score}


@router.get("/ecosystem/summary")
def ecosystem_summary(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    casura_stats = request.app.state.casura_db.get_stats()
    leaderboard = request.app.state.aabb_benchmark.get_leaderboard()
    are_payload = request.app.state.are.get_reliability_report()
    competitive_payload = competitive_latest(request, authorization)
    return {
        "casura": casura_stats,
        "aabb": {
            "leaderboard": leaderboard[:5] if isinstance(leaderboard, list) else [],
            "total": len(leaderboard) if isinstance(leaderboard, list) else 0,
        },
        "are": are_payload,
        "competitive": competitive_payload,
    }


@router.post("/channels/{channel}/event")
def channels_record_event(
    request: Request,
    channel: str,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    event_type = str(payload.get("event_type", "") or "").strip().lower()
    if event_type not in {"inbound", "outbound"}:
        raise HTTPException(status_code=400, detail={"error": "event_type must be inbound or outbound"})
    metadata = payload.get("metadata", {})
    request.app.state.channel_monitor.record_event(
        channel=str(channel or "").strip().lower(),
        event_type=event_type,
        metadata=metadata if isinstance(metadata, dict) else {},
    )
    return {"ok": True, "channel": channel, "event_type": event_type}


@router.get("/channels/health")
def channels_health(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    return request.app.state.channel_monitor.check_health()


@router.get("/channels/stats")
def channels_stats(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    return request.app.state.channel_monitor.get_stats()


@router.get("/channels/{channel}/status")
def channels_status(
    request: Request,
    channel: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = request.app.state.channel_monitor.get_channel_status(str(channel or "").strip().lower())
    if not payload:
        raise HTTPException(status_code=404, detail={"error": "unknown channel"})
    return payload


@router.post("/vibe-audit/code")
def vibe_audit_code_endpoint(
    request: Request,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    code = str(body.get("code", "") or "")
    language = str(body.get("language", "python") or "python")
    severity = str(body.get("severity", "low") or "low")
    auditor = VibeCodeAuditor({"severity_threshold": severity.lower()})
    return auditor.audit_code(code=code, language=language)


@router.post("/vibe-audit/analyze")
def vibe_audit_analyze_endpoint(
    request: Request,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    code = str(body.get("code", "") or "")
    language = str(body.get("language", "python") or "python")
    severity = str(body.get("severity", "low") or "low")
    auditor = VibeCodeAuditor({"severity_threshold": severity.lower()})
    report = auditor.audit_code(code=code, language=language)
    checks = body.get("checks")
    if isinstance(checks, list) and checks:
        allow = {str(item).strip() for item in checks if str(item).strip()}
        report["findings"] = [item for item in report.get("findings", []) if str(item.get("check", "")) in allow]
        report["critical_count"] = sum(1 for item in report["findings"] if str(item.get("severity", "")) == "critical")
        report["high_count"] = sum(1 for item in report["findings"] if str(item.get("severity", "")) == "high")
    return report


@router.post("/vibe-audit/directory")
def vibe_audit_directory_endpoint(
    request: Request,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    dir_path = str(body.get("dir", ".") or ".")
    summary = bool(body.get("summary", True))
    severity = str(body.get("severity", "low") or "low")
    ext_raw = body.get("extensions")
    extensions = [str(item) for item in ext_raw if str(item).strip()] if isinstance(ext_raw, list) else None
    auditor = VibeCodeAuditor({"severity_threshold": severity.lower()})
    if summary:
        return auditor.audit_directory_summary(dir_path=dir_path, extensions=extensions)
    return auditor.audit_directory(dir_path=dir_path, extensions=extensions)
