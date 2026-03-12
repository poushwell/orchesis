from __future__ import annotations

import json
import os
import socket
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

import pytest

from orchesis.openclaw_auditor import OpenClawAuditor, OpenClawFinding


def _write_json(path: Path, payload: dict[str, Any]) -> Path:
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _write_yaml(path: Path, text: str) -> Path:
    path.write_text(text, encoding="utf-8")
    return path


def _clean_config(workspace: str) -> dict[str, Any]:
    return {
        "mode": "production",
        "workspace": workspace,
        "env": {"NODE_ENV": "production"},
        "tools": {
            "exec": {
                "mode": "sandboxed",
                "allowedCommands": ["python", "ls"],
                "blockedPaths": ["/etc", "/root", "~/.ssh"],
                "maxFileSizeMb": 10,
            }
        },
        "skills": [{"name": "safe-skill", "version": "1.0.0"}],
        "skillAllowlist": ["safe-skill"],
        "plugins": [],
    }


def _ids(result: Any) -> set[str]:
    return {item.id for item in result.findings}


def test_clean_config_scores_high(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    cfg_path = _write_json(tmp_path / "openclaw.json", _clean_config(str(tmp_path / "workspace")))
    auditor = OpenClawAuditor()
    result = auditor.audit_config(str(cfg_path))
    assert result.score >= 90
    assert result.grade == "A"


def test_exposed_gateway_critical(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    path = _write_yaml(
        tmp_path / "gateway.yaml",
        "server:\n  host: 0.0.0.0\nauth:\n  enabled: true\ntls:\n  enabled: true\nrateLimit:\n  rpm: 100\n",
    )
    result = OpenClawAuditor().audit_gateway_config(str(path))
    assert "OC-001" in _ids(result)


def test_auth_disabled_critical(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path / "gateway.yaml", "server:\n  host: 127.0.0.1\n")
    result = OpenClawAuditor().audit_gateway_config(str(path))
    assert "OC-002" in _ids(result)


def test_default_api_key_detected(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["apiKey"] = "sk-openclaw-example-key-change-me"
    path = _write_json(tmp_path / "openclaw.json", cfg)
    result = OpenClawAuditor().audit_config(str(path))
    assert "OC-003" in _ids(result)


@pytest.mark.parametrize(
    "key",
    [
        "sk-proj-abc123456789ABCDEFG",
        "sk-ant-abc123456789ABCDEFG",
        "ghp_abcdefghijklmnopqrstuvwxyz1234",
    ],
)
def test_hardcoded_keys_detected(tmp_path: Path, key: str) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["env"]["API_KEY"] = key
    path = _write_json(tmp_path / "openclaw.json", cfg)
    result = OpenClawAuditor().audit_config(str(path))
    assert "OC-005" in _ids(result)


def test_unrestricted_exec_mode(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["tools"]["exec"]["mode"] = "unrestricted"
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-009" in _ids(result)


def test_no_command_allowlist(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["tools"]["exec"]["allowedCommands"] = []
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-010" in _ids(result)


def test_no_blocked_paths_configured(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["tools"]["exec"]["blockedPaths"] = []
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-011" in _ids(result)


@pytest.mark.parametrize("workspace", ["/", "/home/user", "C:/"])
def test_broad_workspace_path_detected(tmp_path: Path, workspace: str) -> None:
    cfg = _clean_config(workspace)
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-013" in _ids(result)


def test_dev_mode_detected(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["mode"] = "development"
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-012" in _ids(result)


def test_no_tls_no_proxy(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path / "gateway.yaml",
        "server:\n  host: 127.0.0.1\nauth:\n  enabled: true\ntls:\n  enabled: false\n",
    )
    result = OpenClawAuditor().audit_gateway_config(str(path))
    assert "OC-017" in _ids(result)


def test_cors_wildcard(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path / "gateway.yaml",
        "server:\n  host: 127.0.0.1\nauth:\n  enabled: true\ntls:\n  enabled: true\ncors:\n  allowedOrigins: ['*']\nrateLimit:\n  rpm: 50\n",
    )
    result = OpenClawAuditor().audit_gateway_config(str(path))
    assert "OC-018" in _ids(result)


def test_unpinned_skills(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["skills"] = ["unsafe-skill"]
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-019" in _ids(result)


def test_no_skill_allowlist(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["skillAllowlist"] = []
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-020" in _ids(result)


def test_env_not_gitignored(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    path = _write_json(tmp_path / "openclaw.json", cfg)
    result = OpenClawAuditor().audit_config(str(path))
    assert "OC-007" in _ids(result)


def test_config_world_readable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    cfg = _clean_config(str(tmp_path))
    path = _write_json(tmp_path / "openclaw.json", cfg)

    @dataclass
    class _St:
        st_mode: int = 0o100666

    monkeypatch.setattr("orchesis.openclaw_auditor.os.stat", lambda *_args, **_kwargs: _St())
    result = OpenClawAuditor().audit_config(str(path))
    if os.name == "nt":
        assert "OC-008" not in _ids(result)
    else:
        assert "OC-008" in _ids(result)


def test_database_credentials_detected(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["database"] = "postgres://user:pass@db.local:5432/app"
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-006" in _ids(result)


def test_browser_automation_unrestricted(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["plugins"] = ["playwright-runner"]
    cfg["browser"] = {}
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-015" in _ids(result)


def test_no_file_limits_configured(tmp_path: Path) -> None:
    cfg = _clean_config(str(tmp_path))
    cfg["tools"]["exec"].pop("maxFileSizeMb", None)
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-014" in _ids(result)


def test_no_rate_limiting_configured(tmp_path: Path) -> None:
    path = _write_yaml(
        tmp_path / "gateway.yaml",
        "server:\n  host: 127.0.0.1\nauth:\n  enabled: true\ntls:\n  enabled: true\n",
    )
    result = OpenClawAuditor().audit_gateway_config(str(path))
    assert "OC-016" in _ids(result)


def test_score_perfect_config(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", _clean_config(str(tmp_path / "w")))))
    assert result.score == 100
    assert result.grade == "A"


def test_score_all_critical() -> None:
    auditor = OpenClawAuditor()
    findings = [
        OpenClawFinding("OC-x1", "critical", "auth", "t", "d", "e", "f", []),
        OpenClawFinding("OC-x2", "critical", "auth", "t", "d", "e", "f", []),
        OpenClawFinding("OC-x3", "critical", "auth", "t", "d", "e", "f", []),
        OpenClawFinding("OC-x4", "critical", "auth", "t", "d", "e", "f", []),
    ]
    result = auditor._build_result(findings, "x")
    assert result.score == 0
    assert result.grade == "F"


def test_score_mixed_findings() -> None:
    auditor = OpenClawAuditor()
    findings = [
        OpenClawFinding("OC-a", "critical", "auth", "t", "d", "e", "f", []),
        OpenClawFinding("OC-b", "high", "auth", "t", "d", "e", "f", []),
        OpenClawFinding("OC-c", "medium", "auth", "t", "d", "e", "f", []),
    ]
    result = auditor._build_result(findings, "x")
    assert result.score == 60
    assert result.grade in {"C", "D"}


@pytest.mark.parametrize(
    ("score_seed", "expected"),
    [
        ([], "A"),
        ([OpenClawFinding("a", "high", "x", "t", "d", "e", "f", [])], "B"),
        ([OpenClawFinding("a", "high", "x", "t", "d", "e", "f", []), OpenClawFinding("b", "high", "x", "t", "d", "e", "f", [])], "B"),
        ([OpenClawFinding("a", "critical", "x", "t", "d", "e", "f", []), OpenClawFinding("b", "high", "x", "t", "d", "e", "f", []), OpenClawFinding("c", "high", "x", "t", "d", "e", "f", [])], "D"),
        ([OpenClawFinding("a", "critical", "x", "t", "d", "e", "f", []), OpenClawFinding("b", "critical", "x", "t", "d", "e", "f", [])], "D"),
    ],
)
def test_grade_boundaries(score_seed: list[OpenClawFinding], expected: str) -> None:
    result = OpenClawAuditor()._build_result(score_seed, "x")
    assert result.grade == expected


def test_report_text_format(tmp_path: Path) -> None:
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", {"mode": "development"})))
    text = OpenClawAuditor().generate_report(result, format="text")
    assert "OpenClaw Security Audit Report" in text
    assert "Score:" in text


def test_report_json_format(tmp_path: Path) -> None:
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", {"mode": "development"})))
    text = OpenClawAuditor().generate_report(result, format="json")
    payload = json.loads(text)
    assert "score" in payload
    assert "findings" in payload


def test_report_markdown_format(tmp_path: Path) -> None:
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", {"mode": "development"})))
    text = OpenClawAuditor().generate_report(result, format="markdown")
    assert "# OpenClaw Security Audit Report" in text
    assert "## Summary" in text


def test_report_empty_findings(tmp_path: Path) -> None:
    (tmp_path / ".gitignore").write_text(".env\n", encoding="utf-8")
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", _clean_config(str(tmp_path / "w")))))
    text = OpenClawAuditor().generate_report(result, format="text")
    assert "No findings detected." in text


def test_missing_config_file(tmp_path: Path) -> None:
    result = OpenClawAuditor().audit_config(str(tmp_path / "missing.json"))
    assert "OC-900" in _ids(result)


def test_malformed_json(tmp_path: Path) -> None:
    path = tmp_path / "openclaw.json"
    path.write_text("{bad-json}", encoding="utf-8")
    result = OpenClawAuditor().audit_config(str(path))
    assert "OC-902" in _ids(result)


def test_malformed_yaml(tmp_path: Path) -> None:
    path = _write_yaml(tmp_path / "gateway.yaml", "server:\n  host: [")
    result = OpenClawAuditor().audit_gateway_config(str(path))
    assert "OC-902" in _ids(result)


def test_empty_config(tmp_path: Path) -> None:
    path = _write_json(tmp_path / "openclaw.json", {})
    result = OpenClawAuditor().audit_config(str(path))
    assert isinstance(result.findings, list)


def test_partial_config(tmp_path: Path) -> None:
    path = _write_json(tmp_path / "openclaw.json", {"tools": {"exec": {"mode": "sandboxed"}}})
    result = OpenClawAuditor().audit_config(str(path))
    assert isinstance(result.score, int)


def test_unicode_in_paths(tmp_path: Path) -> None:
    name = "конфиг-openclaw.json"
    path = _write_json(tmp_path / name, _clean_config(str(tmp_path / "рабочая")))
    result = OpenClawAuditor().audit_config(str(path))
    assert result.config_path.endswith(name)


def test_windows_paths(tmp_path: Path) -> None:
    cfg = _clean_config("C:/Users/Legion")
    result = OpenClawAuditor().audit_config(str(_write_json(tmp_path / "openclaw.json", cfg)))
    assert "OC-013" in _ids(result)


def test_relative_paths(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.chdir(tmp_path)
    _write_json(Path("openclaw.json"), _clean_config("./workspace"))
    result = OpenClawAuditor().audit_config("openclaw.json")
    assert result.config_path.endswith("openclaw.json")


class _HealthHandler(BaseHTTPRequestHandler):
    status_code = 200
    server_header = "OpenClaw/1.0"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self.send_response(self.status_code)
            self.send_header("Server", self.server_header)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
            return
        self.send_response(404)
        self.end_headers()

    def log_message(self, format: str, *args: Any) -> None:
        return


def _start_server(status_code: int) -> tuple[HTTPServer, int, threading.Thread]:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = int(sock.getsockname()[1])
    sock.close()
    _HealthHandler.status_code = status_code
    server = HTTPServer(("127.0.0.1", port), _HealthHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server, port, thread


def test_instance_reachable_no_auth() -> None:
    server, port, thread = _start_server(200)
    try:
        result = OpenClawAuditor().audit_instance("127.0.0.1", port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    criticals = [f for f in result.findings if f.severity == "critical"]
    assert len(criticals) >= 1


def test_instance_reachable_with_auth() -> None:
    server, port, thread = _start_server(401)
    try:
        result = OpenClawAuditor().audit_instance("127.0.0.1", port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    assert "OC-002" not in _ids(result)


def test_instance_unreachable() -> None:
    # Use a likely free high port without binding a server.
    result = OpenClawAuditor().audit_instance("127.0.0.1", 6553)
    assert result.score == 100


def test_instance_health_check() -> None:
    server, port, thread = _start_server(200)
    try:
        result = OpenClawAuditor().audit_instance("127.0.0.1", port)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=1)
    assert result.config_path.endswith(f":{port}")


def test_instance_public_interface_exposure(monkeypatch: pytest.MonkeyPatch) -> None:
    class _Resp:
        status = 200

        def read(self, _n: int = 4096) -> bytes:
            return b"ok"

        def getheader(self, _name: str, _default: str = "") -> str:
            return "OpenClaw/1.0"

    class _Conn:
        def __init__(self, host: str, port: int, timeout: float) -> None:
            self.host = host

        def request(self, method: str, path: str) -> None:
            return

        def getresponse(self) -> _Resp:
            return _Resp()

        def close(self) -> None:
            return

    monkeypatch.setattr("orchesis.openclaw_auditor.HTTPConnection", _Conn)
    result = OpenClawAuditor().audit_instance("8.8.8.8", 18789)
    assert "OC-004" in _ids(result)


def test_run_audit_cli_config_mode(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    class Args:
        config = str(_write_json(tmp_path / "openclaw.json", {"mode": "development"}))
        gateway = None
        host = None
        port = 18789
        format = "json"

    from orchesis.openclaw_auditor import run_audit_cli

    run_audit_cli(Args())
    out = capsys.readouterr().out
    assert '"score"' in out

