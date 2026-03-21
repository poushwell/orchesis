"""Dashboard UI components — modular HTML/CSS/JS generators.

Each function returns an HTML string for a specific dashboard section.
"""

from __future__ import annotations

from typing import Any


def _safe_num(value: Any, default: int | float = 0) -> int | float:
    if isinstance(value, bool):
        return default
    if isinstance(value, int | float):
        return value
    return default


def render_overview_tab(data: dict) -> str:
    """Render overview/stats tab HTML."""
    payload = data if isinstance(data, dict) else {}
    total = _safe_num(payload.get("total_requests"), 0)
    blocked = _safe_num(payload.get("blocked_requests"), 0)
    uptime = _safe_num(payload.get("uptime_seconds"), 0)
    return (
        '<section id="overview" class="tab-section">'
        '<h2>Overview</h2>'
        f'<div class="stats-grid"><div id="overview-total">Total requests: {total}</div>'
        f'<div id="overview-blocked">Blocked: {blocked}</div>'
        f'<div id="overview-uptime">Uptime: {uptime}</div></div>'
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
        f'<div id="security-summary">Security findings: {count}</div>'
        '<div id="security-content" class="subtle">Security content</div>'
        "</section>"
    )


def render_ecosystem_tab(data: dict) -> str:
    """Render ecosystem (CASURA/AABB/ARE) tab HTML."""
    payload = data if isinstance(data, dict) else {}
    return (
        '<section id="ecosystem" class="tab-section">'
        "<h2>Ecosystem</h2>"
        f'<div id="eco-casura">CASURA: {payload.get("casura", "n/a")}</div>'
        f'<div id="eco-aabb">AABB: {payload.get("aabb", "n/a")}</div>'
        f'<div id="eco-are">ARE: {payload.get("are", "n/a")}</div>'
        "</section>"
    )


def render_fleet_tab(data: dict) -> str:
    """Render fleet management tab HTML."""
    payload = data if isinstance(data, dict) else {}
    active_agents = _safe_num(payload.get("active_agents"), 0)
    return (
        '<section id="fleet" class="tab-section">'
        "<h2>Fleet</h2>"
        f'<div id="fleet-active">Active agents: {active_agents}</div>'
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
        f"/* active-theme: {selected} */"
    )


def render_js() -> str:
    """Return JavaScript for dashboard interactivity."""
    return (
        "function switchDashboardTab(tabId) {\n"
        "  const tabs = document.querySelectorAll('.tab-section');\n"
        "  tabs.forEach((el) => { el.style.display = (el.id === tabId ? 'block' : 'none'); });\n"
        "}\n"
        "document.addEventListener('DOMContentLoaded', () => {\n"
        "  switchDashboardTab('overview');\n"
        "});\n"
    )

