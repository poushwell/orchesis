"""Dashboard UI components — modular HTML/CSS/JS generators.

Each function returns an HTML string for a specific dashboard section.
"""

from __future__ import annotations

import html
from typing import Any


def _safe_num(value: Any, default: int | float = 0) -> int | float:
    if isinstance(value, bool):
        return default
    if isinstance(value, int | float):
        return value
    return default


def _esc(value: Any) -> str:
    return html.escape(str(value), quote=True)


def render_overview_tab(data: dict) -> str:
    """Render overview/stats tab HTML."""
    payload = data if isinstance(data, dict) else {}
    total = _safe_num(payload.get("total_requests"), 0)
    blocked = _safe_num(payload.get("blocked_requests"), 0)
    uptime = _safe_num(payload.get("uptime_seconds"), 0)
    sessions = payload.get("active_sessions")
    session_rows = sessions if isinstance(sessions, list) else []
    if session_rows:
        session_html = "".join(
            (
                '<li class="session-row">'
                f'<span class="session-agent">{_esc(item.get("agent_id", "unknown"))}</span> '
                f'<span class="session-last">last request: {_esc(item.get("last_request_ts", "--"))}</span> '
                f'<span class="session-tools">tools(5m): {int(_safe_num(item.get("tool_calls_5m"), 0))}</span> '
                f'<span class="session-status">{_esc(item.get("status", "idle"))}</span>'
                "</li>"
            )
            for item in session_rows
            if isinstance(item, dict)
        )
    else:
        session_html = (
            '<li class="session-row">'
            '<span class="session-agent">No active sessions</span>'
            '<span class="session-last">last request: --</span> '
            '<span class="session-tools">tools(5m): 0</span> '
            '<span class="session-status">idle</span>'
            "</li>"
        )
    return (
        '<section id="overview" class="tab-section">'
        '<h2>Overview</h2>'
        f'<div class="stats-grid"><div id="overview-total">Total requests: {_esc(total)}</div>'
        f'<div id="overview-blocked">Blocked: {_esc(blocked)}</div>'
        f'<div id="overview-uptime">Uptime: {_esc(uptime)}</div></div>'
        '<div id="active-sessions"><h3>Active Sessions</h3>'
        f'<ul id="active-sessions-list">{session_html}</ul></div>'
        "</section>"
    )


def render_security_tab(data: dict) -> str:
    """Render security findings tab HTML."""
    payload = data if isinstance(data, dict) else {}
    findings = payload.get("security_findings", [])
    count = len(findings) if isinstance(findings, list) else 0
    return (
        '<section id="security" class="tab-section">'
        "<h2>Security</h2>"
        f'<div id="security-summary">Security findings: {_esc(count)}</div>'
        '<div id="security-content" class="subtle">Security content</div>'
        "</section>"
    )


def render_ecosystem_tab(data: dict) -> str:
    """Render ecosystem (CASURA/AABB/ARE) tab HTML."""
    payload = data if isinstance(data, dict) else {}
    return (
        '<section id="ecosystem" class="tab-section">'
        "<h2>Ecosystem</h2>"
        f'<div id="eco-casura">CASURA: {_esc(payload.get("casura", "n/a"))}</div>'
        f'<div id="eco-aabb">AABB: {_esc(payload.get("aabb", "n/a"))}</div>'
        f'<div id="eco-are">ARE: {_esc(payload.get("are", "n/a"))}</div>'
        "</section>"
    )


def render_fleet_tab(data: dict) -> str:
    """Render fleet management tab HTML."""
    payload = data if isinstance(data, dict) else {}
    active_agents = _safe_num(payload.get("active_agents"), 0)
    return (
        '<section id="fleet" class="tab-section">'
        "<h2>Fleet</h2>"
        f'<div id="fleet-active">Active agents: {_esc(active_agents)}</div>'
        '<div id="fleet-content" class="subtle">Fleet management</div>'
        "</section>"
    )


def render_css(theme: str = "dark") -> str:
    """Return CSS styles for the given theme."""
    selected = "light" if str(theme).lower() == "light" else "dark"
    return (
        ":root[data-theme=\"dark\"] { background: #090909; color: #e4e4e7; }\n"
        ":root[data-theme=\"light\"] { background: #ffffff; color: #111111; }\n"
        ".stats-grid { display: grid; gap: 8px; grid-template-columns: repeat(3, 1fr); }\n"
        ".tab-section { border: 1px solid #27272a; border-radius: 8px; padding: 12px; }\n"
        f"/* active-theme: {_esc(selected)} */"
    )


def render_js() -> str:
    """Return JavaScript for dashboard interactivity."""
    return (
        "const DASHBOARD_REFRESH_MS = 5000;\n"
        "let _refreshInProgress = false;\n"
        "let _lastDataHash = '';\n"
        "let _activeTab = 'overview';\n"
        "function updateDOM(_data) {\n"
        "  // Stable placeholder updater for component-level tests.\n"
        "  const root = document.getElementById(_activeTab);\n"
        "  if (!root) { return; }\n"
        "  requestAnimationFrame(() => {});\n"
        "}\n"
        "function showDashboardError(msg) {\n"
        "  const root = document.getElementById('overview');\n"
        "  if (root) { root.setAttribute('data-error', msg || 'Dashboard: connection error, retrying...'); }\n"
        "}\n"
        "async function refreshDashboard() {\n"
        "  if (_refreshInProgress) return;\n"
        "  _refreshInProgress = true;\n"
        "  try {\n"
        "    const resp = await fetch('/api/v1/dashboard/data');\n"
        "    const data = await resp.json();\n"
        "    const hash = JSON.stringify(data);\n"
        "    if (hash === _lastDataHash) return;\n"
        "    _lastDataHash = hash;\n"
        "    updateDOM(data);\n"
        "    switchDashboardTab(_activeTab);\n"
        "  } catch (e) {\n"
        "    console.error('Dashboard refresh failed:', e);\n"
        "    showDashboardError('Dashboard: connection error, retrying...');\n"
        "  } finally {\n"
        "    _refreshInProgress = false;\n"
        "  }\n"
        "}\n"
        "function switchDashboardTab(tabId) {\n"
        "  _activeTab = tabId || _activeTab;\n"
        "  const tabs = document.querySelectorAll('.tab-section');\n"
        "  tabs.forEach((el) => { el.style.display = (el.id === _activeTab ? 'block' : 'none'); });\n"
        "}\n"
        "document.addEventListener('DOMContentLoaded', () => {\n"
        "  switchDashboardTab('overview');\n"
        "  const overview = document.getElementById('overview');\n"
        "  if (overview) { overview.setAttribute('data-loading', 'Loading...'); }\n"
        "  refreshDashboard();\n"
        "  setInterval(refreshDashboard, DASHBOARD_REFRESH_MS);\n"
        "});\n"
    )

