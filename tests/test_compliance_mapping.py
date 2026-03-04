from __future__ import annotations

import json
from pathlib import Path
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.error import HTTPError
from urllib.request import Request as UrlRequest, urlopen

import pytest

from orchesis.air_export import export_session_to_air
from orchesis.compliance import (
    Framework,
    Severity,
    ComplianceEngine,
    NIST_AI_RMF_FUNCTIONS,
    ORCHESIS_NIST_MAPPINGS,
    ORCHESIS_OWASP_MAPPINGS,
    OWASP_LLM_TOP_10,
)
from orchesis.dashboard import get_dashboard_html
from orchesis.proxy import HTTPProxyConfig, LLMHTTPProxy
from orchesis.recorder import SessionRecord, SessionRecorder


def test_owasp_top10_has_exactly_10_items() -> None:
    assert len(OWASP_LLM_TOP_10) == 10


def test_owasp_items_have_required_fields() -> None:
    for item in OWASP_LLM_TOP_10:
        assert item.item_id and item.name and item.description and item.url


def test_nist_functions_defined() -> None:
    ids = {item.item_id for item in NIST_AI_RMF_FUNCTIONS}
    assert ids == {"GOVERN", "MAP", "MEASURE", "MANAGE"}


def test_no_duplicate_item_ids_in_frameworks() -> None:
    assert len({i.item_id for i in OWASP_LLM_TOP_10}) == len(OWASP_LLM_TOP_10)
    assert len({i.item_id for i in NIST_AI_RMF_FUNCTIONS}) == len(NIST_AI_RMF_FUNCTIONS)


def test_all_severities_are_valid_enum_values() -> None:
    allowed = {s for s in Severity}
    for item in OWASP_LLM_TOP_10 + NIST_AI_RMF_FUNCTIONS:
        assert item.severity in allowed


def test_every_owasp_item_except_llm08_has_mapping() -> None:
    mapped = {m.framework_item.item_id for m in ORCHESIS_OWASP_MAPPINGS}
    for item in OWASP_LLM_TOP_10:
        if item.item_id == "LLM08":
            continue
        assert item.item_id in mapped


def test_mappings_reference_non_empty_modules() -> None:
    for mapping in ORCHESIS_OWASP_MAPPINGS + ORCHESIS_NIST_MAPPINGS:
        assert mapping.orchesis_module
        assert mapping.orchesis_feature


def test_mapping_coverage_values_are_valid() -> None:
    allowed = {"full", "partial", "detect_only"}
    for mapping in ORCHESIS_OWASP_MAPPINGS + ORCHESIS_NIST_MAPPINGS:
        assert mapping.coverage in allowed


def test_llm01_has_full_coverage() -> None:
    assert any(m.framework_item.item_id == "LLM01" and m.coverage == "full" for m in ORCHESIS_OWASP_MAPPINGS)


def test_llm02_has_full_coverage() -> None:
    assert any(m.framework_item.item_id == "LLM02" and m.coverage == "full" for m in ORCHESIS_OWASP_MAPPINGS)


def test_llm10_has_multiple_mappings() -> None:
    assert sum(1 for m in ORCHESIS_OWASP_MAPPINGS if m.framework_item.item_id == "LLM10") >= 3


def test_nist_mappings_cover_all_4_functions() -> None:
    covered = {m.framework_item.item_id for m in ORCHESIS_NIST_MAPPINGS}
    assert covered == {"GOVERN", "MAP", "MEASURE", "MANAGE"}


def test_no_duplicate_mapping_module_feature_to_same_item() -> None:
    seen: set[tuple[str, str, str]] = set()
    for mapping in ORCHESIS_OWASP_MAPPINGS + ORCHESIS_NIST_MAPPINGS:
        key = (mapping.framework_item.item_id, mapping.orchesis_module, mapping.orchesis_feature)
        assert key not in seen
        seen.add(key)


def test_engine_initializes_with_default_frameworks() -> None:
    engine = ComplianceEngine()
    assert Framework.OWASP_LLM_TOP_10 in engine._frameworks  # noqa: SLF001
    assert Framework.NIST_AI_RMF in engine._frameworks  # noqa: SLF001


def test_map_finding_creates_valid_compliance_finding() -> None:
    engine = ComplianceEngine()
    finding = engine.map_finding("engine", "prompt_injection_scanner", "found injection", Severity.CRITICAL)
    assert finding.finding_id.startswith("cmp_")
    assert finding.framework_mappings


def test_map_finding_auto_populates_framework_mappings_by_module_name() -> None:
    engine = ComplianceEngine()
    finding = engine.map_finding("loop_detector", "loop_detection", "loop", Severity.HIGH)
    assert any(item_id == "LLM10" for _, item_id in finding.framework_mappings)


def test_get_coverage_report_returns_correct_structure() -> None:
    engine = ComplianceEngine()
    report = engine.get_coverage_report(Framework.OWASP_LLM_TOP_10)
    assert {"framework", "total_items", "covered_items", "coverage_percent", "items"} <= set(report.keys())


def test_get_coverage_report_shows_correct_covered_count() -> None:
    engine = ComplianceEngine()
    report = engine.get_coverage_report(Framework.OWASP_LLM_TOP_10)
    assert report["covered_items"] == 9


def test_get_findings_filters_by_framework() -> None:
    engine = ComplianceEngine()
    engine.map_finding("engine", "prompt_injection_scanner", "a", Severity.HIGH)
    engine.map_finding("config", "policy_as_code", "b", Severity.LOW)
    findings = engine.get_findings(framework=Framework.OWASP_LLM_TOP_10)
    assert findings
    assert all(any(fw == Framework.OWASP_LLM_TOP_10.value for fw, _ in f.framework_mappings) for f in findings)


def test_get_findings_filters_by_severity() -> None:
    engine = ComplianceEngine()
    engine.map_finding("engine", "prompt_injection_scanner", "a", Severity.HIGH)
    engine.map_finding("engine", "prompt_injection_scanner", "b", Severity.LOW)
    findings = engine.get_findings(severity=Severity.HIGH)
    assert len(findings) == 1
    assert findings[0].severity == Severity.HIGH


def test_get_summary_aggregates_across_frameworks() -> None:
    engine = ComplianceEngine()
    engine.map_finding("engine", "secret_scanner", "secret", Severity.HIGH)
    summary = engine.get_summary()
    assert "frameworks" in summary and "total_findings" in summary
    assert summary["total_findings"] >= 1


def test_findings_bounded_by_max_findings() -> None:
    engine = ComplianceEngine(max_findings=3)
    for idx in range(6):
        engine.map_finding("engine", "prompt_injection_scanner", f"f{idx}", Severity.MEDIUM)
    assert len(engine.get_findings(limit=100)) == 3


def test_export_report_json_returns_valid_dict() -> None:
    engine = ComplianceEngine()
    report = engine.export_report(format="json")
    assert isinstance(report, dict)
    assert "summary" in report


def test_owasp_coverage_percentage_is_accurate() -> None:
    engine = ComplianceEngine()
    report = engine.get_coverage_report(Framework.OWASP_LLM_TOP_10)
    assert report["coverage_percent"] == 90.0


def test_items_with_full_coverage_show_covered() -> None:
    engine = ComplianceEngine()
    report = engine.get_coverage_report(Framework.OWASP_LLM_TOP_10)
    llm01 = next(i for i in report["items"] if i["id"] == "LLM01")
    assert llm01["status"] == "covered"


def test_items_with_no_mapping_show_not_covered() -> None:
    engine = ComplianceEngine()
    report = engine.get_coverage_report(Framework.OWASP_LLM_TOP_10)
    llm08 = next(i for i in report["items"] if i["id"] == "LLM08")
    assert llm08["status"] == "not_covered"


def test_llm08_is_not_covered() -> None:
    engine = ComplianceEngine()
    report = engine.get_coverage_report(Framework.OWASP_LLM_TOP_10)
    assert any(i["id"] == "LLM08" and i["status"] == "not_covered" for i in report["items"])


def test_coverage_percent_calculation_is_correct() -> None:
    engine = ComplianceEngine()
    report = engine.get_coverage_report(Framework.NIST_AI_RMF)
    assert report["coverage_percent"] == 100.0


class _ComplianceUpstreamHandler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length", "0") or "0")
        _ = self.rfile.read(length)
        payload = {"usage": {"prompt_tokens": 2, "completion_tokens": 1}, "choices": [{"finish_reason": "stop"}]}
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def log_message(self, fmt: str, *args) -> None:
        _ = (fmt, args)


def _start_http_server(handler_cls: type[BaseHTTPRequestHandler]) -> tuple[HTTPServer, threading.Thread]:
    server = HTTPServer(("127.0.0.1", 0), handler_cls)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, thread


def _pick_port() -> int:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    p = int(sock.getsockname()[1])
    sock.close()
    return p


def _make_proxy(tmp_path: Path, policy_text: str) -> tuple[LLMHTTPProxy, HTTPServer]:
    upstream, _ = _start_http_server(_ComplianceUpstreamHandler)
    policy = tmp_path / "policy.yaml"
    policy.write_text(policy_text, encoding="utf-8")
    port = _pick_port()
    proxy = LLMHTTPProxy(
        policy_path=str(policy),
        config=HTTPProxyConfig(
            host="127.0.0.1",
            port=port,
            upstream={
                "openai": f"http://127.0.0.1:{upstream.server_address[1]}",
                "anthropic": f"http://127.0.0.1:{upstream.server_address[1]}",
            },
        ),
    )
    proxy.start(blocking=False)
    return proxy, upstream


def _get_json(port: int, path: str) -> tuple[int, dict]:
    with urlopen(f"http://127.0.0.1:{port}{path}", timeout=5) as resp:
        return int(resp.status), json.loads(resp.read().decode("utf-8"))


def test_proxy_compliance_summary_endpoint(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        code, payload = _get_json(proxy._config.port, "/api/compliance/summary")
        assert code == 200 and "frameworks" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_compliance_coverage_endpoint(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        code, payload = _get_json(proxy._config.port, "/api/compliance/coverage")
        assert code == 200 and "frameworks" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_compliance_framework_coverage_endpoint(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        code, payload = _get_json(proxy._config.port, "/api/compliance/coverage/owasp_llm_top10")
        assert code == 200 and payload["framework"] == "owasp_llm_top10_2025"
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_proxy_compliance_findings_endpoint(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        proxy._compliance_engine.map_finding("engine", "prompt_injection_scanner", "x", Severity.HIGH)  # noqa: SLF001
        code, payload = _get_json(proxy._config.port, "/api/compliance/findings")
        assert code == 200 and "findings" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_compliance_stats_appear_in_stats_response(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\n")
    try:
        code, payload = _get_json(proxy._config.port, "/stats")
        assert code == 200 and "compliance" in payload
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_compliance_disabled_when_config_says_disabled(tmp_path: Path) -> None:
    proxy, upstream = _make_proxy(tmp_path, "rules: []\ncompliance:\n  enabled: false\n")
    try:
        _, payload = _get_json(proxy._config.port, "/stats")
        assert payload["compliance"]["enabled"] is False
    finally:
        proxy.stop()
        upstream.shutdown()
        upstream.server_close()


def test_dashboard_html_contains_compliance_tab() -> None:
    html = get_dashboard_html()
    assert "Compliance" in html
    assert 'data-tab="compliance"' in html


def test_dashboard_html_contains_compliance_elements() -> None:
    html = get_dashboard_html()
    assert "cmp-owasp-percent" in html
    assert "/api/compliance/report?format=json" in html


def test_air_export_includes_compliance_extensions_when_engine_available(tmp_path: Path) -> None:
    recorder = SessionRecorder(storage_path=str(tmp_path / "sessions"), compress=False)
    recorder.record(
        SessionRecord(
            request_id="a1",
            session_id="s1",
            timestamp=time.time(),
            request={"model": "gpt-4o", "messages": []},
            response={"usage": {"prompt_tokens": 1, "completion_tokens": 1}},
            status_code=200,
            provider="openai",
            model="gpt-4o",
            latency_ms=10.0,
            cost=0.01,
            error=None,
            metadata={"agent_id": "a"},
        )
    )
    engine = ComplianceEngine()
    engine.map_finding(
        "engine",
        "prompt_injection_scanner",
        "session finding",
        Severity.HIGH,
        evidence={"session_id": "s1"},
    )
    doc = export_session_to_air("s1", recorder, compliance_engine=engine)
    assert "compliance" in doc["extensions"]["orchesis"]


def test_air_compliance_coverage_percent_matches_engine_report(tmp_path: Path) -> None:
    recorder = SessionRecorder(storage_path=str(tmp_path / "sessions"), compress=False)
    recorder.record(
        SessionRecord(
            request_id="a2",
            session_id="s2",
            timestamp=time.time(),
            request={"model": "gpt-4o", "messages": []},
            response={"usage": {"prompt_tokens": 1, "completion_tokens": 1}},
            status_code=200,
            provider="openai",
            model="gpt-4o",
            latency_ms=10.0,
            cost=0.01,
            error=None,
            metadata={"agent_id": "a"},
        )
    )
    engine = ComplianceEngine()
    doc = export_session_to_air("s2", recorder, compliance_engine=engine)
    assert doc["extensions"]["orchesis"]["compliance"]["owasp_coverage_percent"] == 90.0
