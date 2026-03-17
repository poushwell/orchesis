from __future__ import annotations

import time
from pathlib import Path

from orchesis.mcp_monitor import McpRuntimeMonitor


def test_monitor_detects_file_change(tmp_path: Path) -> None:
    cfg = tmp_path / "mcp.json"
    cfg.write_text('{"a":1}', encoding="utf-8")
    monitor = McpRuntimeMonitor([str(cfg)])
    changes = monitor.check_once()
    assert changes == []
    cfg.write_text('{"a":2}', encoding="utf-8")
    changes = monitor.check_once()
    assert any(item["type"] == "modified" for item in changes)


def test_monitor_detects_new_file(tmp_path: Path) -> None:
    cfg = tmp_path / "new_mcp.json"
    monitor = McpRuntimeMonitor([str(cfg)])
    changes = monitor.check_once()
    assert changes == []
    cfg.write_text('{"enabled":true}', encoding="utf-8")
    changes = monitor.check_once()
    assert len(changes) == 1
    assert changes[0]["type"] == "added"


def test_monitor_detects_removed_file(tmp_path: Path) -> None:
    cfg = tmp_path / "remove_mcp.json"
    cfg.write_text('{"x":"y"}', encoding="utf-8")
    monitor = McpRuntimeMonitor([str(cfg)])
    _ = monitor.check_once()
    cfg.unlink()
    changes = monitor.check_once()
    assert any(item["type"] == "removed" for item in changes)


def test_alerts_returned_correctly(tmp_path: Path) -> None:
    cfg = tmp_path / "alerts_mcp.json"
    monitor = McpRuntimeMonitor([str(cfg)])
    before = time.time()
    cfg.write_text('{"first":1}', encoding="utf-8")
    _ = monitor.check_once()
    cfg.write_text('{"first":2}', encoding="utf-8")
    _ = monitor.check_once()
    alerts_all = monitor.get_alerts()
    alerts_since = monitor.get_alerts(since=before)
    assert len(alerts_all) >= 2
    assert len(alerts_since) >= 2


def test_check_once_returns_changes(tmp_path: Path) -> None:
    cfg = tmp_path / "check_once_mcp.json"
    cfg.write_text("initial", encoding="utf-8")
    monitor = McpRuntimeMonitor([str(cfg)])
    first = monitor.check_once()
    cfg.write_text("updated", encoding="utf-8")
    second = monitor.check_once()
    assert first == []
    assert isinstance(second, list)
    assert second


def test_monitor_stats_tracked(tmp_path: Path) -> None:
    cfg = tmp_path / "stats_mcp.json"
    monitor = McpRuntimeMonitor([str(cfg)])
    _ = monitor.check_once()
    cfg.write_text("x", encoding="utf-8")
    _ = monitor.check_once()
    stats = monitor.get_stats()
    assert stats["checks_run"] >= 2
    assert stats["changes_detected"] >= 1
    assert "uptime_seconds" in stats
