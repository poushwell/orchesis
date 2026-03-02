"""Stdlib HTTP server for scanner APIs."""

from __future__ import annotations

import json
import logging
import signal
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from orchesis import __version__
from orchesis.compliance import FRAMEWORK_CHECKS
from orchesis.contrib.ioc_database import IoCMatcher
from orchesis.scanner import McpConfigScanner, PolicyScanner, ScanFinding, SkillScanner

LOGGER = logging.getLogger("orchesis.scanner_server")
MAX_BODY_BYTES = 10 * 1024 * 1024


def _risk_level(score: int) -> str:
    if score >= 80:
        return "HIGH"
    if score >= 50:
        return "MEDIUM"
    if score >= 20:
        return "LOW"
    return "INFO"


def _finding_to_payload(finding: ScanFinding) -> dict[str, str]:
    return {
        "severity": str(finding.severity).upper(),
        "check": str(finding.category),
        "message": str(finding.description),
    }


def _scan_content_with(scanner: Any, suffix: str, content: str) -> list[ScanFinding]:
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=suffix, delete=False) as handle:
        temp_path = Path(handle.name)
        handle.write(content)
    try:
        report = scanner.scan(str(temp_path))
        return report.findings
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except Exception:
            pass


def create_scanner_http_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8081,
    policy_path: str | None = None,
    allow_file_access: bool = False,
) -> ThreadingHTTPServer:
    started_at = time.monotonic()
    skill_scanner = SkillScanner()
    mcp_scanner = McpConfigScanner()
    policy_scanner = PolicyScanner()
    ioc_matcher = IoCMatcher()
    _ = policy_path

    class ScannerHandler(BaseHTTPRequestHandler):
        server_version = "OrchesisScannerAPI/1.0"

        def _send_json(self, status: int, payload: dict[str, Any]) -> None:
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def _error(self, status: int, message: str) -> None:
            self._send_json(status, {"status": "error", "message": message})

        def _read_json_body(self) -> dict[str, Any] | None:
            content_type = str(self.headers.get("Content-Type", ""))
            if "application/json" not in content_type.lower():
                self._error(415, "Content-Type must be application/json")
                return None
            length_header = self.headers.get("Content-Length")
            if length_header is None:
                self._error(400, "Missing Content-Length header")
                return None
            try:
                content_length = int(length_header)
            except ValueError:
                self._error(400, "Invalid Content-Length header")
                return None
            if content_length < 0:
                self._error(400, "Invalid Content-Length header")
                return None
            if content_length > MAX_BODY_BYTES:
                self._error(413, "Request body too large")
                return None
            body = self.rfile.read(content_length)
            if len(body) > MAX_BODY_BYTES:
                self._error(413, "Request body too large")
                return None
            try:
                payload = json.loads(body.decode("utf-8"))
            except Exception:
                self._error(400, "Invalid JSON body")
                return None
            if not isinstance(payload, dict):
                self._error(400, "JSON body must be an object")
                return None
            return payload

        def do_GET(self) -> None:  # noqa: N802
            started = time.perf_counter()
            status = 200
            try:
                if self.path == "/health":
                    self._send_json(
                        200,
                        {
                            "status": "healthy",
                            "version": __version__,
                            "uptime_seconds": int(max(0.0, time.monotonic() - started_at)),
                        },
                    )
                    return
                if self.path == "/frameworks":
                    self._send_json(200, {"frameworks": sorted(FRAMEWORK_CHECKS.keys())})
                    return
                if self.path in {"/scan/skill", "/scan/mcp", "/scan/policy", "/scan/ioc"}:
                    status = 405
                    self._error(405, "Method Not Allowed")
                    return
                status = 404
                self._error(404, "Not Found")
            finally:
                duration_ms = (time.perf_counter() - started) * 1000.0
                LOGGER.info(
                    "scanner_api request ts=%s method=%s path=%s status=%s duration_ms=%.2f",
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "GET",
                    self.path,
                    status,
                    duration_ms,
                )

        def do_POST(self) -> None:  # noqa: N802
            started = time.perf_counter()
            status = 200
            try:
                payload = self._read_json_body()
                if payload is None:
                    return
                if self.path == "/scan/skill":
                    content = payload.get("content")
                    if not isinstance(content, str):
                        status = 400
                        self._error(400, "Field 'content' must be a string")
                        return
                    findings = _scan_content_with(skill_scanner, ".md", content)
                    risk_score = min(100, sum({"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(f.severity.upper(), 1) for f in findings))
                    self._send_json(
                        200,
                        {
                            "status": "ok",
                            "findings": [_finding_to_payload(item) for item in findings],
                            "risk_score": risk_score,
                            "risk_level": _risk_level(risk_score),
                        },
                    )
                    return
                if self.path == "/scan/mcp":
                    if "config" in payload:
                        config = payload.get("config")
                        if not isinstance(config, dict):
                            status = 400
                            self._error(400, "Field 'config' must be an object")
                            return
                        content = json.dumps(config, ensure_ascii=False)
                        findings = _scan_content_with(mcp_scanner, ".json", content)
                    elif "config_path" in payload:
                        config_path = payload.get("config_path")
                        if not isinstance(config_path, str) or not config_path.strip():
                            status = 400
                            self._error(400, "Field 'config_path' must be a string")
                            return
                        if not allow_file_access:
                            status = 403
                            self._error(403, "File access is disabled; use --allow-file-access")
                            return
                        source = Path(config_path)
                        if not source.exists() or not source.is_file():
                            status = 404
                            self._error(404, "config_path not found")
                            return
                        report = mcp_scanner.scan(str(source))
                        findings = report.findings
                    else:
                        status = 400
                        self._error(400, "Provide 'config' or 'config_path'")
                        return
                    risk_score = min(100, sum({"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(f.severity.upper(), 1) for f in findings))
                    self._send_json(
                        200,
                        {
                            "status": "ok",
                            "findings": [_finding_to_payload(item) for item in findings],
                            "risk_score": risk_score,
                            "risk_level": _risk_level(risk_score),
                        },
                    )
                    return
                if self.path == "/scan/policy":
                    content = payload.get("content")
                    if not isinstance(content, str):
                        status = 400
                        self._error(400, "Field 'content' must be a string")
                        return
                    try:
                        findings = _scan_content_with(policy_scanner, ".yaml", content)
                    except Exception:
                        status = 400
                        self._error(400, "Invalid policy YAML")
                        return
                    score = max(0, 100 - min(100, sum({"CRITICAL": 40, "HIGH": 20, "MEDIUM": 10, "LOW": 5}.get(f.severity.upper(), 1) for f in findings)))
                    self._send_json(
                        200,
                        {
                            "status": "ok",
                            "findings": [_finding_to_payload(item) for item in findings],
                            "score": score,
                        },
                    )
                    return
                if self.path == "/scan/ioc":
                    content = payload.get("content")
                    if not isinstance(content, str):
                        status = 400
                        self._error(400, "Field 'content' must be a string")
                        return
                    self._send_json(200, {"status": "ok", "matches": ioc_matcher.scan_text(content)})
                    return
                status = 404
                self._error(404, "Not Found")
            finally:
                duration_ms = (time.perf_counter() - started) * 1000.0
                LOGGER.info(
                    "scanner_api request ts=%s method=%s path=%s status=%s duration_ms=%.2f",
                    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "POST",
                    self.path,
                    status,
                    duration_ms,
                )

        def do_PUT(self) -> None:  # noqa: N802
            self._error(405, "Method Not Allowed")

        def do_DELETE(self) -> None:  # noqa: N802
            self._error(405, "Method Not Allowed")

        def log_message(self, format: str, *args: Any) -> None:
            _ = (format, args)

    return ThreadingHTTPServer((host, int(port)), ScannerHandler)


def run_scanner_http_server(
    *,
    host: str = "127.0.0.1",
    port: int = 8081,
    policy_path: str | None = None,
    allow_file_access: bool = False,
) -> None:
    server = create_scanner_http_server(
        host=host,
        port=port,
        policy_path=policy_path,
        allow_file_access=allow_file_access,
    )
    stop_event = threading.Event()

    def _shutdown_handler(_signum: int, _frame: Any) -> None:
        if stop_event.is_set():
            return
        stop_event.set()
        server.shutdown()

    signal.signal(signal.SIGINT, _shutdown_handler)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, _shutdown_handler)
    try:
        server.serve_forever()
    finally:
        server.server_close()
