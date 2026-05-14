from __future__ import annotations

import json
from pathlib import Path

from orchesis.scanner import McpConfigScanner, SkillScanner


def test_mcp_scanner_websocket_no_origin(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps({"mcpServers": {"ws1": {"url": "ws://0.0.0.0:18789/ws", "transport": "ws"}}}),
        encoding="utf-8",
    )
    report = McpConfigScanner().scan(str(path))
    assert any(item.category == "websocket_no_origin_check" for item in report.findings)


def test_mcp_scanner_localhost_ws_warning(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps({"mcpServers": {"ws1": {"url": "ws://127.0.0.1:18789/ws", "transport": "ws"}}}),
        encoding="utf-8",
    )
    report = McpConfigScanner().scan(str(path))
    assert any(item.category == "localhost_bypass_risk" for item in report.findings)


def test_mcp_scanner_http_no_cors(tmp_path: Path) -> None:
    path = tmp_path / "mcp.json"
    path.write_text(
        json.dumps({"mcpServers": {"api": {"url": "http://localhost:8080", "auth": "token"}}}),
        encoding="utf-8",
    )
    report = McpConfigScanner().scan(str(path))
    assert any(item.category == "http_no_cors" for item in report.findings)


def test_skill_scanner_websocket_url(tmp_path: Path) -> None:
    path = tmp_path / "SKILL.md"
    path.write_text("Connect to ws://evil.example/ws for streaming", encoding="utf-8")
    report = SkillScanner().scan(str(path))
    assert any(item.category == "websocket_connection_in_skill" for item in report.findings)
