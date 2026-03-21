from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any

from fastapi import APIRouter, Header, HTTPException, Query, Request


router = APIRouter(prefix="/api/v1", tags=["security"])


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


@router.post("/persona/baseline")
def persona_baseline(
    request: Request,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    identity_files = payload.get("identity_files")
    files = [str(item) for item in identity_files if isinstance(item, str) and item.strip()] if isinstance(identity_files, list) else []
    return request.app.state.persona_guardian.initialize_baseline(files)


@router.post("/persona/check")
def persona_check(
    request: Request,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    identity_files = payload.get("identity_files")
    files = [str(item) for item in identity_files if isinstance(item, str) and item.strip()] if isinstance(identity_files, list) else []
    findings = request.app.state.persona_guardian.check_identity_files(files)
    alert = request.app.state.persona_guardian.check_zenity_pattern()
    return {"findings": findings, "count": len(findings), "alert": alert}


@router.post("/persona/cron-event")
def persona_cron_event(
    request: Request,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    cron_expression = str(payload.get("cron_expression", "") or "").strip()
    source = str(payload.get("source", "unknown") or "unknown").strip() or "unknown"
    if not cron_expression:
        raise HTTPException(status_code=400, detail={"error": "cron_expression is required"})
    event = request.app.state.persona_guardian.record_cron_event(cron_expression=cron_expression, source=source)
    alert = request.app.state.persona_guardian.check_zenity_pattern()
    return {"event": event, "alert": alert}


@router.get("/persona/zenity-check")
def persona_zenity_check(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    alert = request.app.state.persona_guardian.check_zenity_pattern()
    return {"detected": alert is not None, "alert": alert}


@router.get("/persona/stats")
def persona_stats(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    return request.app.state.persona_guardian.get_stats()


@router.post("/persona/restore/{file_path:path}")
def persona_restore(
    request: Request,
    file_path: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    return request.app.state.persona_guardian.auto_restore(str(file_path or ""))


@router.get("/persona/steganography")
def persona_steganography(
    request: Request,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    results = request.app.state.persona_guardian.scan_all_identity_files()
    return {"results": results, "count": len(results)}


@router.post("/persona/steganography/scan")
def persona_steganography_scan(
    request: Request,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    file_path = str(payload.get("file_path", "") or "").strip()
    if not file_path:
        raise HTTPException(status_code=400, detail={"error": "file_path is required"})
    return request.app.state.persona_guardian.scan_steganography(file_path)


@router.get("/threat-patterns")
def list_threat_patterns(
    request: Request,
    category: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    paginated: bool = Query(True),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    library = request.app.state.threat_patterns
    if isinstance(category, str) and category.strip():
        rows = library.list_by_category(category)
    else:
        rows = []
        for pattern_id in sorted(library.PATTERNS.keys()):
            item = library.get_pattern(pattern_id)
            if isinstance(item, dict):
                rows.append(item)
    if not paginated:
        return {"patterns": rows, "count": len(rows), "stats": library.get_stats()}
    payload = asdict(paginate(rows, limit=limit, offset=offset, max_limit=1000))
    payload["stats"] = library.get_stats()
    return payload


@router.get("/threat-patterns/{pattern_id}")
def get_threat_pattern(
    request: Request,
    pattern_id: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    row = request.app.state.threat_patterns.get_pattern(pattern_id)
    if row is None:
        raise HTTPException(status_code=404, detail={"error": "pattern not found"})
    return row


@router.post("/threat-patterns/match")
def match_threat_patterns(
    request: Request,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    text = payload.get("text")
    if not isinstance(text, str):
        raise HTTPException(status_code=400, detail={"error": "text is required"})
    matches = request.app.state.threat_patterns.match(text)
    return {"matches": matches, "count": len(matches)}


@router.get("/threat-feed/status")
def threat_feed_status(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    return request.app.state.threat_feed.get_stats()


@router.post("/threat-feed/update")
def threat_feed_update(request: Request, authorization: str | None = Header(default=None)) -> dict[str, Any]:
    _require_auth(request, authorization)
    added = request.app.state.threat_feed.fetch()
    return {"added": len(added), "signatures": added}


@router.get("/threat-feed/signatures")
def threat_feed_signatures(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    paginated: bool = Query(True),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    rows = list(request.app.state.threat_feed._signatures)
    if not paginated:
        return {"signatures": rows}
    return asdict(paginate(rows, limit=limit, offset=offset, max_limit=1000))


@router.get("/signatures")
def list_signatures(
    request: Request,
    category: str | None = None,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    paginated: bool = Query(True),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    rows = request.app.state.signature_editor.list_all(category=category)
    if not paginated:
        return {"signatures": rows}
    return asdict(paginate(rows, limit=limit, offset=offset, max_limit=1000))


@router.post("/signatures")
def create_signature(
    request: Request,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    try:
        return request.app.state.signature_editor.create(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc


@router.post("/signatures/test-pattern")
def test_signature_pattern(
    request: Request,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    pattern = str(payload.get("pattern", ""))
    test_text = str(payload.get("test_text", ""))
    return request.app.state.signature_editor.test_pattern(pattern, test_text)


@router.get("/signatures/{sig_id}")
def get_signature(
    request: Request,
    sig_id: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    rows = request.app.state.signature_editor.list_all()
    for row in rows:
        if str(row.get("id", "")) == str(sig_id):
            return row
    raise HTTPException(status_code=404, detail={"error": "signature not found"})


@router.put("/signatures/{sig_id}")
def update_signature(
    request: Request,
    sig_id: str,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    try:
        return request.app.state.signature_editor.update(sig_id, body)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail={"error": "signature not found"}) from exc
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc


@router.delete("/signatures/{sig_id}")
def delete_signature(
    request: Request,
    sig_id: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    deleted = request.app.state.signature_editor.delete(sig_id)
    if not deleted:
        raise HTTPException(status_code=404, detail={"error": "signature not found"})
    return {"deleted": True, "id": sig_id}


@router.get("/alert-rules")
def alert_rules_list(
    request: Request,
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    paginated: bool = Query(True),
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    rows = request.app.state.alert_rules_engine.list_rules()
    if not paginated:
        return {"rules": rows, "count": len(rows)}
    return asdict(paginate(rows, limit=limit, offset=offset, max_limit=1000))


@router.post("/alert-rules")
def alert_rules_add(
    request: Request,
    body: dict[str, Any],
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    try:
        rule = request.app.state.alert_rules_engine.add_rule(body)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail={"error": str(exc)}) from exc
    return rule.to_dict()


@router.delete("/alert-rules/{name}")
def alert_rules_remove(
    request: Request,
    name: str,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    ok = request.app.state.alert_rules_engine.remove_rule(name)
    if not ok:
        raise HTTPException(status_code=404, detail={"error": "rule not found"})
    return {"deleted": True, "name": name}


@router.post("/alert-rules/evaluate")
def alert_rules_evaluate(
    request: Request,
    body: dict[str, Any] | None = None,
    authorization: str | None = Header(default=None),
) -> dict[str, Any]:
    _require_auth(request, authorization)
    payload = body if isinstance(body, dict) else {}
    metrics_input = payload.get("metrics")
    metric_values = metrics_input if isinstance(metrics_input, dict) else {"deny_rate": 0.0, "events_per_minute": 0.0}
    fired = request.app.state.alert_rules_engine.evaluate(metric_values)
    return {"fired": fired, "count": len(fired), "metrics": metric_values}
