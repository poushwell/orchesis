"""Embedded single-file dashboard HTML for Orchesis proxy."""

from __future__ import annotations

import re
import os
from pathlib import Path

from orchesis.dashboard_components import (
    render_css,
    render_ecosystem_tab,
    render_fleet_tab,
    render_js,
    render_overview_tab,
    render_security_tab,
)

def _dashboard_dist_dir() -> Path:
    return Path(__file__).resolve().parents[2] / "dashboard" / "dist"


def _packaged_dashboard_dist_dir() -> Path:
    return Path(__file__).resolve().parent / "dashboard_dist"


def _inline_dist_assets(index_html: str, dist_dir: Path) -> str:
    """Inline built Vite assets so /dashboard works without extra routes."""

    def _read_asset(asset_path: str) -> str | None:
        normalized = asset_path.lstrip("/")
        if normalized.startswith("dashboard/"):
            normalized = normalized[len("dashboard/") :]
        candidate = (dist_dir / normalized).resolve()
        if not str(candidate).startswith(str(dist_dir.resolve())):
            return None
        if not candidate.exists() or not candidate.is_file():
            return None
        return candidate.read_text(encoding="utf-8")

    html = index_html
    html = re.sub(r'<script[^>]*type="module"[^>]*src="([^"]+)"[^>]*>\s*</script>', "", html)
    html = re.sub(r'<link[^>]*rel="modulepreload"[^>]*>', "", html)

    css_chunks: list[str] = []
    for match in re.finditer(r'<link[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>', html):
        css_text = _read_asset(match.group(1))
        if css_text is not None:
            css_chunks.append(css_text)
    html = re.sub(r'<link[^>]*rel="stylesheet"[^>]*href="([^"]+)"[^>]*>', "", html)

    js_chunks: list[str] = []
    for match in re.finditer(r'<script[^>]*src="([^"]+)"[^>]*>\s*</script>', index_html):
        js_text = _read_asset(match.group(1))
        if js_text is not None:
            js_chunks.append(js_text)

    if css_chunks:
        html = html.replace("</head>", "<style>\n" + "\n".join(css_chunks) + "\n</style>\n</head>")
    if js_chunks:
        html = html.replace("</body>", "<script>\n" + "\n".join(js_chunks) + "\n</script>\n</body>")
    return html


def register_dashboard_static_routes(app) -> None:
    """Optional Flask-style static route registration for /dashboard/* assets."""
    try:
        from flask import send_from_directory
    except Exception:
        return

    dist_dir = _dashboard_dist_dir()

    @app.route("/dashboard/<path:path>")
    def serve_dashboard(path):  # type: ignore[unused-ignore]
        return send_from_directory(str(dist_dir), path)


def _assemble_page(css: str, tabs: list[str], js: str) -> str:
    return (
        "<!doctype html>"
        '<html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1.0">'
        "<title>Orchesis Dashboard</title>"
        f"<style>{css}</style>"
        "</head><body>"
        '<main id="main-content">'
        + "".join(tabs)
        + "</main>"
        + f"<script>{js}</script>"
        + "</body></html>"
    )


def render_dashboard(data: dict, theme: str = "dark") -> str:
    """Render modular dashboard HTML via component functions."""
    payload = data if isinstance(data, dict) else {}
    css = render_css(theme)
    tabs = [
        render_overview_tab(payload),
        render_security_tab(payload),
        render_ecosystem_tab(payload),
        render_fleet_tab(payload),
    ]
    js = render_js()
    return _assemble_page(css, tabs, js)


def get_dashboard_html(demo_mode: bool = False) -> str:
    """Return a fully self-contained dashboard HTML page."""
    packaged_dist_dir = _packaged_dashboard_dist_dir()
    dev_dist_dir = _dashboard_dist_dir()
    dist_candidates = [packaged_dist_dir / "index.html", dev_dist_dir / "index.html"]
    if "PYTEST_CURRENT_TEST" not in os.environ:
        for dist_index in dist_candidates:
            if dist_index.exists():
                built = dist_index.read_text(encoding="utf-8")
                return _inline_dist_assets(built, dist_index.parent)

    html = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Orchesis Dashboard</title>
  <style>
    :root[data-theme="light"] {
      --bg: #ffffff;
      --surface: #f5f5f5;
      --text: #111111;
      --border: #e0e0e0;
      --accent: #7c3aed;
      --panel: var(--surface);
      --text-secondary: #5f5f6f;
      --hero-radial: #dcdff0;
    }
    :root[data-theme="dark"] {
      --bg: #090909;
      --surface: #111114;
      --text: #e4e4e7;
      --border: #27272a;
      --accent: #a855f7;
      --panel: var(--surface);
      --text-secondary: #6B6B80;
      --hero-radial: #18203A;
    }
    :root {
      --bg: #090909;
      --surface: #111114;
      --text: #e4e4e7;
      --border: #27272a;
      --accent: #a855f7;
      --panel: var(--surface);
      --text-secondary: #6B6B80;
      --hero-radial: #18203A;
      --ok: #00E5A0;
      --warn: #FFB800;
      --danger: #FF3B5C;
      --info: #5AA8FF;
      --radius: 12px;
      --radius-sm: 8px;
    }
    :root[data-hc="true"] {
      --bg: #000000;
      --surface: #000000;
      --text: #ffffff;
      --border: #ffffff;
      --accent: #ffff00;
      --danger: #ff6666;
      --ok: #66ff66;
      --panel: #000000;
      --text-secondary: #f0f0f0;
      --hero-radial: #000000;
    }
    * { box-sizing: border-box; }
    .skip-link {
      position: absolute;
      top: -40px;
      left: 10px;
      z-index: 10002;
      background: var(--surface);
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
      text-decoration: none;
    }
    .skip-link:focus {
      top: 10px;
    }
    :focus-visible {
      outline: 2px solid var(--accent);
      outline-offset: 2px;
    }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, sans-serif;
      background: radial-gradient(1200px 600px at 20% -20%, var(--hero-radial) 0%, var(--bg) 55%);
      color: var(--text);
      min-height: 100vh;
    }
    .app {
      max-width: 1400px;
      margin: 0 auto;
      padding: 18px;
      display: grid;
      gap: 16px;
    }
    .topbar {
      background: linear-gradient(90deg, var(--surface), color-mix(in srgb, var(--surface) 86%, var(--bg)));
      border: 1px solid var(--border);
      border-bottom: 1px solid var(--border);
      border-radius: var(--radius);
      backdrop-filter: blur(12px);
      box-shadow: 0 1px 0 rgba(0,229,160,0.05);
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 14px 16px;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 10px;
      font-weight: 700;
      letter-spacing: 0.2px;
    }
    .brand .logo {
      font-size: 19px;
      filter: drop-shadow(0 0 8px rgba(0,229,160,0.4));
    }
    .badges { display: flex; gap: 10px; align-items: center; }
    .badge {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 12px;
      color: var(--text-secondary);
      background: var(--surface);
    }
    #notif-bell {
      display: inline-flex;
      align-items: center;
      gap: 6px;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 4px 10px;
      cursor: pointer;
      user-select: none;
      background: var(--surface);
      color: var(--text);
      font-size: 12px;
    }
    #notif-count {
      min-width: 20px;
      text-align: center;
      font-weight: 700;
      color: var(--text);
      border-color: var(--accent);
    }
    .notif-panel {
      position: fixed;
      top: 74px;
      right: 16px;
      width: min(420px, calc(100vw - 32px));
      max-height: calc(100vh - 96px);
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--surface);
      box-shadow: 0 8px 32px rgba(0,0,0,0.35);
      z-index: 9998;
      transform: translateX(0);
      opacity: 1;
      transition: transform 0.2s ease, opacity 0.2s ease;
    }
    .notif-panel.hidden {
      transform: translateX(110%);
      opacity: 0;
      pointer-events: none;
    }
    .notif-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 10px;
      padding: 12px;
      border-bottom: 1px solid var(--border);
      font-weight: 700;
    }
    .notif-header button {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 4px 8px;
      background: var(--surface);
      color: var(--text);
      cursor: pointer;
    }
    #notif-list {
      display: grid;
      gap: 8px;
      padding: 10px 12px 12px;
    }
    .notif-item {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: color-mix(in srgb, var(--surface) 90%, var(--bg));
      padding: 8px 10px;
      display: grid;
      gap: 3px;
    }
    .notif-item small {
      color: var(--text-secondary);
      font-size: 11px;
    }
    .conn-dot {
      width: 10px; height: 10px; border-radius: 50%;
      display: inline-block; margin-right: 6px;
      background: var(--ok);
      box-shadow: 0 0 12px rgba(0,229,160,0.6);
    }
    .conn-dot.lost { background: var(--danger); box-shadow: 0 0 12px rgba(255,59,92,0.5); }
    .tabs {
      display: flex;
      gap: 8px;
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 8px;
      backdrop-filter: blur(12px);
      flex-wrap: wrap;
    }
    .tab-btn {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface);
      color: var(--text);
      padding: 10px 16px;
      min-height: 44px;
      cursor: pointer;
      font-weight: 600;
    }
    button {
      min-height: 36px;
    }
    #mobile-nav-toggle {
      display: none;
      align-items: center;
      justify-content: center;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface);
      color: var(--text);
      padding: 8px 12px;
      font-size: 16px;
      cursor: pointer;
    }
    .tab-btn.active {
      background: linear-gradient(135deg, rgba(0,229,160,0.12), rgba(0,229,160,0.06));
      border-color: rgba(0,229,160,0.4);
      color: var(--ok);
      box-shadow: 0 0 16px rgba(0,229,160,0.1), inset 0 1px 0 rgba(0,229,160,0.15);
    }
    .tab-btn:hover:not(.active) {
      background: color-mix(in srgb, var(--surface) 86%, var(--text));
      border-color: rgba(255,255,255,0.12);
    }
    #theme-toggle {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface);
      color: var(--text);
      padding: 6px 10px;
      cursor: pointer;
      font-size: 14px;
    }
    #theme-toggle:hover {
      border-color: var(--accent);
    }
    #hc-toggle {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface);
      color: var(--text);
      padding: 6px 10px;
      cursor: pointer;
      font-size: 14px;
    }
    #hc-toggle:hover {
      border-color: var(--accent);
    }
    #perf-toggle {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface);
      color: var(--text);
      padding: 6px 10px;
      cursor: pointer;
      font-size: 14px;
      opacity: 0.4;
    }
    #perf-toggle:hover {
      border-color: var(--accent);
    }
    .search-wrap {
      position: relative;
      min-width: 320px;
      max-width: 560px;
      width: min(48vw, 560px);
    }
    #global-search {
      width: 100%;
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: var(--surface);
      color: var(--text);
      padding: 8px 10px;
      font-size: 13px;
      outline: none;
    }
    #global-search:focus {
      border-color: var(--accent);
      box-shadow: 0 0 0 2px color-mix(in srgb, var(--accent) 28%, transparent);
    }
    .search-dropdown {
      position: absolute;
      top: 40px;
      right: 0;
      width: min(560px, calc(100vw - 32px));
      max-height: 380px;
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--surface);
      box-shadow: 0 8px 24px rgba(0,0,0,0.35);
      z-index: 10000;
      padding: 6px;
    }
    .search-dropdown.hidden {
      display: none;
    }
    .modal {
      position: fixed;
      inset: 0;
      background: rgba(0, 0, 0, 0.55);
      display: grid;
      place-items: center;
      z-index: 10001;
      padding: 16px;
    }
    .modal.hidden { display: none; }
    .modal-content {
      width: min(560px, 100%);
      max-height: min(80vh, 640px);
      overflow: auto;
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--surface);
      box-shadow: 0 12px 36px rgba(0,0,0,0.45);
      padding: 14px;
    }
    .shortcuts-table {
      width: 100%;
      border-collapse: collapse;
      margin-top: 8px;
      font-size: 13px;
    }
    .shortcuts-table td {
      border-bottom: 1px solid var(--border);
      padding: 8px 6px;
    }
    .shortcuts-table td:first-child {
      width: 120px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
      color: var(--ok);
      font-weight: 700;
    }
    .shortcuts-hint {
      margin: 0 auto;
      max-width: 1400px;
      color: var(--text-secondary);
      font-size: 12px;
      padding: 0 20px 16px;
    }
    kbd {
      border: 1px solid var(--border);
      border-bottom-width: 2px;
      border-radius: 6px;
      padding: 1px 6px;
      background: color-mix(in srgb, var(--surface) 92%, var(--bg));
      color: var(--text);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
      font-size: 11px;
    }
    .search-section {
      color: var(--text-secondary);
      font-size: 11px;
      text-transform: uppercase;
      letter-spacing: 0.04em;
      padding: 8px 10px 6px;
      font-weight: 700;
    }
    .search-item {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
      margin-bottom: 6px;
      cursor: pointer;
      background: color-mix(in srgb, var(--surface) 92%, var(--bg));
    }
    .search-item:hover {
      border-color: var(--accent);
    }
    .toast {
      position: fixed;
      right: 18px;
      bottom: 18px;
      z-index: 9999;
      padding: 10px 14px;
      border-radius: var(--radius-sm);
      color: #06110D;
      background: #00E5A0;
      border: 1px solid rgba(0,0,0,0.12);
      font-weight: 700;
      opacity: 0;
      transform: translateY(8px);
      pointer-events: none;
      transition: opacity 0.18s ease, transform 0.18s ease;
    }
    .toast.show {
      opacity: 1;
      transform: translateY(0);
    }
    .screen { display: none; gap: 12px; }
    .screen.active { display: grid; animation: fadeIn 0.25s ease; }
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    .grid-4 { display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(160px, 1fr)); }
    .grid-2 { display: grid; gap: 12px; grid-template-columns: 1.4fr 1fr; }
    .hero-metrics {
      display: grid;
      gap: 12px;
      grid-template-columns: repeat(3, minmax(220px, 1fr));
    }
    .hero-card {
      --hero-accent: var(--info);
      border-radius: var(--radius);
      padding: 20px;
      border: 1px solid color-mix(in srgb, var(--hero-accent) 25%, transparent);
      text-align: center;
      background: linear-gradient(135deg, color-mix(in srgb, var(--hero-accent) 6%, transparent), color-mix(in srgb, var(--hero-accent) 2%, transparent));
      box-shadow: 0 0 30px color-mix(in srgb, var(--hero-accent) 8%, transparent), inset 0 1px 0 rgba(255,255,255,0.04);
      position: relative;
      overflow: hidden;
    }
    .hero-card::before {
      content: "";
      position: absolute;
      inset: -1px;
      border-radius: inherit;
      padding: 1px;
      background: linear-gradient(135deg, color-mix(in srgb, var(--hero-accent) 65%, transparent), color-mix(in srgb, #ffffff 18%, transparent), color-mix(in srgb, var(--hero-accent) 55%, transparent));
      -webkit-mask: linear-gradient(#000 0 0) content-box, linear-gradient(#000 0 0);
      -webkit-mask-composite: xor;
      mask-composite: exclude;
      pointer-events: none;
    }
    .hero-number {
      font-size: clamp(48px, 6vw, 72px);
      line-height: 1;
      font-weight: 800;
      font-variant-numeric: tabular-nums;
    }
    .hero-label { margin-top: 8px; color: var(--text-secondary); font-weight: 650; }
    .hero-blocked .hero-number { color: var(--danger); }
    .hero-blocked { --hero-accent: rgba(255,59,92,0.95); }
    .hero-saved .hero-number {
      background: linear-gradient(90deg, var(--ok), #5AA8FF);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .hero-saved { --hero-accent: rgba(0,229,160,0.95); }
    .hero-health .hero-number {
      background: linear-gradient(90deg, #34d399, #5AA8FF);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .hero-health { --hero-accent: rgba(90,168,255,0.95); }
    .token-yield-widget {
      border: 1px solid rgba(255, 99, 132, 0.28);
      border-radius: var(--radius);
      padding: 12px;
      background: linear-gradient(135deg, rgba(255, 99, 132, 0.08), rgba(255, 99, 132, 0.03));
      display: grid;
      gap: 10px;
    }
    .token-yield-head {
      display: flex;
      align-items: baseline;
      justify-content: space-between;
      gap: 10px;
      flex-wrap: wrap;
    }
    .token-yield-percent {
      font-size: clamp(34px, 6vw, 52px);
      font-weight: 800;
      line-height: 1;
      color: #34d399;
      font-variant-numeric: tabular-nums;
    }
    .token-yield-warning {
      color: var(--danger);
      font-size: 12px;
      font-weight: 700;
    }
    .token-yield-bar {
      width: 100%;
      height: 8px;
      border-radius: 999px;
      overflow: hidden;
      background: rgba(255,255,255,0.08);
    }
    .token-yield-bar > div {
      height: 100%;
      width: 0%;
      background: linear-gradient(90deg, #f59e0b, #ef4444);
    }
    .token-yield-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 12px;
    }
    .token-yield-table th, .token-yield-table td {
      text-align: left;
      padding: 5px 6px;
      border-bottom: 1px solid var(--border);
      font-variant-numeric: tabular-nums;
    }
    .context-budget-widget {
      border: 1px solid rgba(245,158,11,0.35);
      border-radius: var(--radius);
      background: linear-gradient(135deg, rgba(245,158,11,0.12), rgba(245,158,11,0.04));
      padding: 12px;
      display: grid;
      gap: 10px;
    }
    .cbg-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; }
    .cbg-pill {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 4px 10px;
      font-weight: 800;
      font-size: 12px;
      letter-spacing: 0.2px;
    }
    .cbg-pill.normal { color: #34d399; border-color: rgba(52,211,153,0.4); }
    .cbg-pill.l0 { color: #facc15; border-color: rgba(250,204,21,0.45); }
    .cbg-pill.l1 { color: #fb923c; border-color: rgba(251,146,60,0.45); }
    .cbg-pill.l2 { color: #ef4444; border-color: rgba(239,68,68,0.45); }
    .cbg-counters { display: grid; grid-template-columns: repeat(3, minmax(80px, 1fr)); gap: 8px; }
    .cbg-counter { border: 1px solid rgba(255,255,255,0.08); border-radius: var(--radius-sm); padding: 6px 8px; }
    .cbg-counter .k { font-size: 11px; color: var(--text-secondary); }
    .cbg-counter .v { font-weight: 800; font-variant-numeric: tabular-nums; }
    .cbg-progress { display: grid; gap: 6px; }
    .cbg-bar { height: 10px; border-radius: 999px; background: rgba(255,255,255,0.08); overflow: hidden; }
    .cbg-bar > div { height: 100%; border-radius: inherit; width: 0%; background: #34d399; }
    .rate-limit-widget {
      border: 1px solid rgba(52, 211, 153, 0.35);
      border-radius: var(--radius);
      background: linear-gradient(135deg, rgba(52, 211, 153, 0.1), rgba(52, 211, 153, 0.03));
      padding: 12px;
      display: grid;
      gap: 10px;
    }
    .rl-head { display: flex; justify-content: space-between; align-items: center; gap: 8px; flex-wrap: wrap; }
    .rl-counters { display: flex; gap: 12px; flex-wrap: wrap; }
    .rl-counter { font-size: 12px; color: var(--text-secondary); }
    .rl-counter .v { font-weight: 800; color: var(--text-primary); font-variant-numeric: tabular-nums; }
    .rl-rows { display: grid; gap: 8px; }
    .rl-row { display: grid; gap: 4px; }
    .rl-row-head { display: flex; justify-content: space-between; align-items: center; font-size: 12px; }
    .rl-bar { height: 8px; border-radius: 999px; background: rgba(255,255,255,0.08); overflow: hidden; }
    .rl-bar > div { height: 100%; width: 0%; border-radius: inherit; background: #34d399; }
    .rl-status-ok { color: #34d399; }
    .rl-status-warning { color: #facc15; }
    .rl-status-throttled { color: #ef4444; }
    .community-widget {
      border: 1px solid rgba(90, 168, 255, 0.35);
      border-radius: var(--radius);
      background: linear-gradient(135deg, rgba(90, 168, 255, 0.1), rgba(90, 168, 255, 0.03));
      padding: 12px;
      display: grid;
      gap: 10px;
    }
    .community-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; }
    .community-toggle { display: inline-flex; align-items: center; gap: 8px; font-size: 12px; color: var(--text-secondary); }
    .community-toggle input { accent-color: #34d399; width: 16px; height: 16px; }
    .community-stats { display: grid; grid-template-columns: repeat(2, minmax(160px, 1fr)); gap: 8px; }
    .community-stat { border: 1px solid rgba(255,255,255,0.08); border-radius: var(--radius-sm); padding: 6px 8px; }
    .community-stat .k { font-size: 11px; color: var(--text-secondary); }
    .community-stat .v { font-size: 16px; font-weight: 800; font-variant-numeric: tabular-nums; }
    .privacy-badge {
      display: inline-block;
      border: 1px solid rgba(52, 211, 153, 0.5);
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 700;
      color: #34d399;
      background: rgba(52, 211, 153, 0.1);
    }
    .agent-health-widget {
      border: 1px solid rgba(90,168,255,0.35);
      border-radius: var(--radius);
      background: linear-gradient(135deg, rgba(90,168,255,0.12), rgba(90,168,255,0.04));
      padding: 12px;
      display: grid;
      gap: 10px;
    }
    .ah-head { display: flex; justify-content: space-between; align-items: center; gap: 10px; flex-wrap: wrap; }
    .ah-score {
      font-size: clamp(44px, 8vw, 68px);
      line-height: 1;
      font-weight: 800;
      font-variant-numeric: tabular-nums;
      color: #34d399;
    }
    .ah-grade {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 4px 10px;
      font-weight: 800;
      font-size: 13px;
    }
    .ah-trend {
      font-size: 12px;
      color: var(--text-secondary);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    }
    .ah-grid { display: grid; gap: 8px; }
    .ah-row { display: grid; gap: 4px; }
    .ah-row-head { display: flex; justify-content: space-between; align-items: center; font-size: 12px; color: var(--text-secondary); }
    .ah-bar { height: 8px; border-radius: 999px; background: rgba(255,255,255,0.08); overflow: hidden; }
    .ah-bar > div { height: 100%; border-radius: inherit; background: #34d399; width: 0%; }
    .panel {
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      padding: 12px;
      backdrop-filter: blur(12px);
      transition: border-color 0.3s ease, box-shadow 0.3s ease;
    }
    .panel:hover {
      border-color: rgba(0,229,160,0.15);
      box-shadow: 0 0 20px rgba(0,229,160,0.05);
    }
    .panel-primary {
      background: linear-gradient(180deg, rgba(255,255,255,0.04) 0%, rgba(255,255,255,0.02) 100%);
      border-color: rgba(255,255,255,0.1);
      box-shadow: 0 4px 24px rgba(0,0,0,0.3);
    }
    .section-title {
      font-size: 11px;
      font-weight: 700;
      letter-spacing: 0.8px;
      text-transform: uppercase;
      color: var(--text-secondary);
      margin-bottom: 10px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }
    .hero { display: grid; grid-template-columns: auto 1fr; gap: 14px; align-items: center; }
    .pulse {
      width: 28px; height: 28px; border-radius: 50%;
      position: relative;
    }
    .pulse::before, .pulse::after {
      content: "";
      position: absolute; inset: 0;
      border-radius: 50%;
      background: currentColor;
      opacity: 0.28;
      animation: pulseRing 1.8s infinite;
    }
    .pulse::after { animation-delay: 0.9s; }
    @keyframes pulseRing {
      from { transform: scale(1); opacity: 0.32; }
      to { transform: scale(2.2); opacity: 0; }
    }
    .status-clear { color: var(--ok); animation: pulseGlow 2s ease infinite; }
    .status-monitoring { color: var(--warn); }
    .status-alert { color: var(--danger); }
    @keyframes pulseGlow {
      0%, 100% { box-shadow: 0 0 0 0 rgba(0,229,160,0.4); }
      50% { box-shadow: 0 0 0 12px rgba(0,229,160,0); }
    }
    .metric-value {
      font-size: 28px;
      font-weight: 750;
      font-variant-numeric: tabular-nums;
      transition: opacity 0.2s ease;
    }
    .metric-value.updating { opacity: 0.6; }
    .metric-label { color: var(--text-secondary); font-size: 12px; }
    .event-feed { max-height: 260px; overflow-y: auto; display: grid; gap: 8px; }
    .event {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 8px;
      font-size: 12px;
      display: grid;
      grid-template-columns: auto auto 1fr;
      gap: 8px;
      align-items: center;
    }
    .event[data-severity="critical"],
    .event:has(.sev.critical) { border-left: 3px solid var(--danger); }
    .event[data-severity="high"],
    .event:has(.sev.high) { border-left: 3px solid var(--warn); }
    .event[data-severity="medium"],
    .event:has(.sev.medium) { border-left: 3px solid #FFB800; }
    .event[data-severity="low"],
    .event:has(.sev.low) { border-left: 3px solid var(--info); }
    .event-item { animation: fadeSlideIn 0.3s ease; }
    @keyframes fadeSlideIn {
      from { opacity: 0; transform: translateY(-8px); }
      to { opacity: 1; transform: translateY(0); }
    }
    .sev { padding: 2px 7px; border-radius: 999px; font-size: 11px; font-weight: 700; }
    .sev.info { background: rgba(90,168,255,0.15); color: var(--info); }
    .sev.low { background: rgba(90,168,255,0.13); color: var(--info); }
    .sev.medium { background: rgba(255,184,0,0.15); color: var(--warn); }
    .sev.high, .sev.critical { background: rgba(255,59,92,0.18); color: var(--danger); }
    .cb-pill {
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 11px;
      font-weight: 700;
      border: 1px solid var(--border);
      text-transform: uppercase;
      letter-spacing: 0.3px;
    }
    .cb-pill.closed { color: var(--ok); }
    .cb-pill.open { color: var(--danger); }
    .cb-pill.half-open { color: var(--warn); }
    .progress {
      width: 100%;
      height: 11px;
      border-radius: 999px;
      background: rgba(255,255,255,0.07);
      overflow: hidden;
    }
    .progress > div { height: 100%; background: var(--ok); }
    .progress-bar-wrap {
      height: 6px;
      background: rgba(255,255,255,0.06);
      border-radius: 999px;
      overflow: hidden;
      margin-top: 6px;
    }
    .progress-bar-fill {
      height: 100%;
      border-radius: 999px;
      background: linear-gradient(90deg, var(--ok), #5AA8FF);
      transition: width 0.8s cubic-bezier(0.4, 0, 0.2, 1);
    }
    .table { width: 100%; border-collapse: collapse; font-size: 13px; }
    .table th, .table td {
      border-bottom: 1px solid var(--border);
      padding: 8px;
      text-align: left;
      vertical-align: top;
    }
    .subtle { color: var(--text-secondary); font-size: 12px; }
    .empty {
      border: 1px dashed var(--border);
      border-radius: var(--radius-sm);
      color: var(--text-secondary);
      padding: 16px;
      text-align: center;
    }
    .chart-wrap { width: 100%; overflow: hidden; }
    .chart-tooltip {
      font-size: 11px; color: var(--text-secondary); margin-top: 6px;
      min-height: 14px;
    }
    .score-gauge { display: grid; grid-template-columns: 140px 1fr; gap: 8px; align-items: center; }
    .pattern-card {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 10px;
      margin-bottom: 8px;
      background: rgba(255,255,255,0.02);
    }
    .confidence {
      width: 100%; height: 8px; border-radius: 999px;
      background: rgba(255,255,255,0.08); overflow: hidden;
    }
    .confidence > div { height: 100%; background: var(--info); }
    .timeline {
      border-left: 2px solid rgba(255,255,255,0.14);
      margin-left: 8px; padding-left: 12px;
      display: grid; gap: 8px;
    }
    .node-row { font-size: 12px; color: var(--text-secondary); }
    .variant-card {
      background: rgba(255,255,255,0.04);
      border-radius: 10px;
      padding: 14px;
      flex: 1;
    }
    .variant-card.winner {
      border: 1px solid var(--ok);
      box-shadow: 0 0 12px rgba(0,229,160,0.2);
    }
    .variant-pair {
      display: flex;
      gap: 12px;
      margin: 12px 0;
    }
    .h-bar {
      display: flex;
      align-items: center;
      gap: 8px;
      margin: 4px 0;
    }
    .h-bar-fill {
      height: 18px;
      background: linear-gradient(90deg, var(--ok), rgba(0,229,160,0.4));
      border-radius: 4px;
      transition: width 0.5s ease;
    }
    .sev-critical { background: #ef4444; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .sev-high { background: #f97316; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .sev-medium { background: #eab308; color: #111; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .sev-low { background: #6b7280; color: white; padding: 2px 8px; border-radius: 4px; font-size: 11px; }
    .outcome-bar {
      display: flex;
      height: 24px;
      border-radius: 6px;
      overflow: hidden;
      margin: 8px 0;
    }
    .outcome-bar > div { transition: width 0.5s ease; }
    .outcome-success { background: var(--ok); }
    .outcome-failure { background: #ef4444; }
    .outcome-loop { background: #f97316; }
    .outcome-abandoned { background: #6b7280; }
    .outcome-timeout { background: #eab308; }
    .outcome-escalated { background: #8b5cf6; }
    .sparkline {
      width: 100%;
      height: 24px;
      margin-top: 6px;
      opacity: 0.7;
    }
    .sparkline polyline {
      fill: none;
      stroke: var(--ok);
      stroke-width: 1.5;
      stroke-linecap: round;
      stroke-linejoin: round;
    }
    .profile-badges { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin:8px 0; }
    .profile-tag {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 2px 8px;
      font-size: 11px;
      color: var(--text-secondary);
      background: rgba(255,255,255,0.03);
    }
    .profile-tag.cold { color: var(--warn); border-color: rgba(255,184,0,0.35); }
    .profile-grid { display:grid; gap:8px; grid-template-columns: repeat(4, minmax(120px, 1fr)); }
    .profile-kv { font-size: 12px; color: var(--text-secondary); }
    .profile-list { margin: 8px 0 0 0; padding-left: 18px; color: var(--text); }
    .profile-alert { margin:6px 0; padding:8px; border:1px solid var(--border); border-radius:8px; font-size:12px; }
    .savings-panel {
      background: linear-gradient(135deg, rgba(0,229,160,0.05) 0%, var(--panel) 60%);
      border: 1px solid rgba(0,229,160,0.15);
    }
    .savings-total {
      font-size: 28px;
      background: linear-gradient(90deg, var(--ok), #5AA8FF);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .savings-grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
      gap: 8px;
      margin-top: 12px;
    }
    .savings-item {
      background: rgba(255,255,255,0.03);
      border-radius: var(--radius-sm);
      padding: 10px;
    }
    .savings-item .label { font-size: 11px; color: var(--text-secondary); }
    .savings-item .amount { font-size: 16px; font-weight: 600; color: var(--ok); }
    .savings-bar {
      height: 3px;
      background: rgba(255,255,255,0.06);
      border-radius: 2px;
      margin-top: 6px;
      overflow: hidden;
    }
    .savings-bar-fill {
      height: 100%;
      background: var(--ok);
      border-radius: 2px;
      transition: width 0.8s ease;
    }
    .savings-card {
      border: 1px solid rgba(0,229,160,0.20);
      background: linear-gradient(135deg, rgba(0,229,160,0.06) 0%, var(--panel) 60%);
    }
    .savings-breakdown {
      display: grid;
      gap: 6px;
      margin-top: 8px;
      color: var(--text-secondary);
      font-size: 13px;
    }
    .savings-breakdown span { color: var(--ok); font-weight: 700; }
    .heatmap-panel {
      border: 1px solid var(--border);
      background: rgba(168, 85, 247, 0.04);
    }
    .heatmap-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 8px;
    }
    .heatmap-grid {
      display: grid;
      gap: 4px;
      grid-template-columns: 44px repeat(24, minmax(10px, 1fr));
      width: 100%;
      overflow-x: auto;
      padding-bottom: 4px;
    }
    .heatmap-hour-label {
      font-size: 10px;
      color: var(--text-secondary);
      text-align: center;
      line-height: 14px;
    }
    .heatmap-day-label {
      font-size: 11px;
      color: var(--text-secondary);
      display: flex;
      align-items: center;
      min-height: 14px;
    }
    .heatmap-cell {
      min-height: 14px;
      border-radius: 3px;
      border: 1px solid rgba(255,255,255,0.08);
      cursor: pointer;
      transition: transform 0.12s ease, border-color 0.12s ease;
    }
    .heatmap-cell:hover {
      transform: translateY(-1px);
      border-color: rgba(255,255,255,0.4);
    }
    .heatmap-meta {
      margin-top: 8px;
      display: flex;
      gap: 12px;
      flex-wrap: wrap;
      font-size: 12px;
      color: var(--text-secondary);
    }
    .heatmap-tooltip {
      margin-top: 6px;
      min-height: 14px;
      font-size: 12px;
      color: var(--text-secondary);
    }
    .flow-graph {
      background: rgba(0,0,0,0.2);
      border-radius: var(--radius-sm);
      overflow: visible;
    }
    .flow-node {
      cursor: pointer;
      transition: opacity 0.2s;
    }
    .flow-node:hover { opacity: 0.8; }
    .flow-edge {
      stroke: rgba(255,255,255,0.15);
      stroke-width: 1.5;
      fill: none;
    }
    .flow-label {
      fill: var(--text-secondary);
      font-size: 10px;
      text-anchor: middle;
      pointer-events: none;
    }
    .flow-cost-label {
      fill: var(--ok);
      font-size: 9px;
      text-anchor: middle;
    }
    .demo-banner {
      border: 1px solid #facc15;
      color: #fde68a;
      background: rgba(250, 204, 21, 0.14);
      border-radius: var(--radius-sm);
      padding: 10px 12px;
      font-weight: 700;
      text-align: center;
    }
    .approval-row {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 10px;
      margin-bottom: 8px;
      background: rgba(255,255,255,0.02);
    }
    .approval-actions { display: flex; gap: 8px; margin-bottom: 6px; }
    .approval-actions .tab-btn { padding: 6px 10px; }
    .ow-wrap { display: grid; gap: 12px; }
    .ow-summary {
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: linear-gradient(135deg, rgba(168,85,247,0.14), rgba(168,85,247,0.04));
      color: #d8b4fe;
      padding: 10px 12px;
      font-weight: 700;
      letter-spacing: 0.2px;
    }
    .ow-toolbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
      flex-wrap: wrap;
    }
    .ow-switch { display: flex; gap: 8px; }
    .ow-view-btn {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: rgba(255,255,255,0.02);
      color: var(--text);
      padding: 8px 12px;
      font-weight: 600;
      cursor: pointer;
    }
    .ow-view-btn.active {
      border-color: rgba(168,85,247,0.55);
      color: #e9d5ff;
      background: rgba(168,85,247,0.16);
      box-shadow: inset 0 1px 0 rgba(255,255,255,0.08), 0 0 16px rgba(168,85,247,0.12);
    }
    .ow-cards {
      display: grid;
      grid-template-columns: repeat(3, minmax(240px, 1fr));
      gap: 12px;
    }
    .ow-card {
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--panel);
      padding: 12px;
      display: grid;
      gap: 9px;
    }
    .ow-card.threat { border-color: rgba(239,68,68,0.75); box-shadow: 0 0 0 1px rgba(239,68,68,0.25) inset; }
    .ow-card.pending { border-color: rgba(249,115,22,0.8); box-shadow: 0 0 0 1px rgba(249,115,22,0.25) inset; }
    .ow-head {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 8px;
    }
    .ow-agent-id {
      display: flex;
      align-items: center;
      gap: 8px;
      min-width: 0;
      font-weight: 700;
    }
    .ow-name {
      overflow: hidden;
      text-overflow: ellipsis;
      white-space: nowrap;
    }
    .ow-dot {
      width: 9px; height: 9px; border-radius: 50%;
      display: inline-block;
      box-shadow: 0 0 10px currentColor;
      color: var(--green);
      background: currentColor;
      flex: 0 0 auto;
    }
    .ow-dot.idle { color: #9ca3af; }
    .ow-dot.alert { color: var(--red); }
    .ow-dot.warning { color: var(--orange); }
    .ow-badge {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      font-weight: 700;
    }
    .ow-badge.grade-a { color: var(--green); border-color: rgba(0,255,65,0.4); }
    .ow-badge.grade-b { color: #a3e635; border-color: rgba(163,230,53,0.35); }
    .ow-badge.grade-c { color: #facc15; border-color: rgba(250,204,21,0.35); }
    .ow-badge.grade-d, .ow-badge.grade-f { color: var(--red); border-color: rgba(239,68,68,0.45); }
    .ow-task { color: var(--text-secondary); font-size: 13px; }
    .ow-budget-line { display: grid; gap: 4px; }
    .ow-budget-bar { height: 8px; border-radius: 999px; background: rgba(255,255,255,0.08); overflow: hidden; }
    .ow-budget-bar > div { height: 100%; background: var(--green); border-radius: inherit; }
    .ow-meta {
      font-size: 12px;
      color: var(--text-secondary);
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
    }
    .ow-actions { display: flex; gap: 6px; flex-wrap: wrap; }
    .ow-btn {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      background: rgba(255,255,255,0.02);
      color: var(--text);
      padding: 6px 9px;
      font-size: 12px;
      font-weight: 700;
      cursor: pointer;
    }
    .ow-btn.review {
      border-color: rgba(249,115,22,0.5);
      color: #fdba74;
      background: rgba(249,115,22,0.14);
    }
    .ow-empty {
      border: 1px dashed var(--border);
      border-radius: var(--radius);
      padding: 26px 18px;
      text-align: center;
      color: var(--text-secondary);
      display: grid;
      gap: 10px;
    }
    .ow-empty .icon { font-size: 26px; color: #c084fc; }
    .ow-empty .cmd {
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
      display: inline-block;
      background: rgba(255,255,255,0.02);
    }
    .ow-radar-wrap { display: grid; gap: 10px; }
    .ow-radar-box {
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: rgba(255,255,255,0.01);
      padding: 10px;
      position: relative;
      overflow: hidden;
      min-height: 470px;
    }
    .ow-radar-svg { width: 100%; height: 460px; display: block; }
    .ow-radar-tooltip {
      position: absolute;
      top: 12px;
      left: 12px;
      z-index: 2;
      background: rgba(10,10,18,0.94);
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
      color: var(--text);
      max-width: 320px;
      display: none;
      font-size: 12px;
    }
    .ow-radar-footer { display: flex; justify-content: flex-end; }
    .ow-teams-wrap { display: grid; gap: 12px; }
    .ow-graph-wrap { display: grid; gap: 10px; }
    .ow-graph-box {
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: rgba(255,255,255,0.01);
      padding: 10px;
      min-height: 470px;
    }
    .ow-graph-svg { width: 100%; height: 460px; display: block; }
    .ow-graph-detail {
      border: 1px solid var(--border);
      border-radius: var(--radius-sm);
      padding: 8px 10px;
      color: var(--text-secondary);
      font-size: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, "Liberation Mono", monospace;
      background: rgba(255,255,255,0.02);
    }
    .ow-team-cards {
      display: grid;
      grid-template-columns: repeat(3, minmax(220px, 1fr));
      gap: 10px;
    }
    .ow-team-card {
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--panel);
      padding: 10px;
      cursor: pointer;
      display: grid;
      gap: 6px;
    }
    .ow-team-card:hover {
      border-color: rgba(168,85,247,0.55);
    }
    .ow-team-title {
      font-weight: 700;
      color: #e9d5ff;
      text-transform: lowercase;
    }
    .ow-team-detail {
      border: 1px solid var(--border);
      border-radius: var(--radius);
      background: var(--panel);
      padding: 10px;
      display: grid;
      gap: 8px;
    }
    .ow-team-detail .table {
      margin-top: 6px;
    }
    .ow-ap-section { display: grid; gap: 10px; }
    .ow-ap-item {
      border: 1px solid rgba(249,115,22,0.4);
      border-radius: var(--radius-sm);
      padding: 10px;
      background: rgba(249,115,22,0.08);
    }
    .ow-ap-actions { margin-top: 8px; display: flex; gap: 8px; }
    @media (max-width: 1100px) {
      .grid-4 { grid-template-columns: repeat(2, minmax(160px, 1fr)); }
      .grid-2 { grid-template-columns: 1fr; }
      .score-gauge { grid-template-columns: 1fr; }
      .ow-cards { grid-template-columns: repeat(2, minmax(220px, 1fr)); }
    }
    /* Tablet: 768px */
    @media (max-width: 768px) {
      .stats-grid { grid-template-columns: repeat(2, 1fr); }
      .grid-4 { grid-template-columns: repeat(2, minmax(160px, 1fr)); }
      .topbar { flex-wrap: wrap; gap: 8px; }
      #global-search { width: 150px; }
      .nav-tabs { overflow-x: auto; white-space: nowrap; flex-wrap: nowrap; }
      #mobile-nav-toggle { display: inline-flex; }
      .nav-tabs { display: none; }
      .nav-tabs.mobile-open { display: flex; }
    }
    @media (max-width: 760px) {
      .ow-cards { grid-template-columns: 1fr; }
    }
    /* Mobile: 480px */
    @media (max-width: 480px) {
      .stats-grid { grid-template-columns: 1fr; }
      .grid-4 { grid-template-columns: 1fr; }
      .topbar { flex-direction: column; }
      #global-search { width: 100%; }
      .notif-panel { width: 100vw; right: 0; }
      .card, .panel { padding: 12px; }
    }
  </style>
</head>
<body>
  <a href="#main-content" class="skip-link">Skip to main content</a>
  <div class="app" id="main-content">
    <div class="topbar">
      <div class="brand"><span class="logo">🛡️ Orchesis</span><span class="subtle">Dashboard MVP</span></div>
      <div class="badges">
        <div class="search-wrap">
          <input id="global-search" type="text" placeholder="Search agents, sessions, threats..." oninput="debounceSearch(this.value)" aria-label="Global search" />
          <div id="search-results" class="search-dropdown hidden">
            <div class="search-section">Agents</div>
            <div class="search-section">Sessions</div>
            <div class="search-section">Threats</div>
          </div>
        </div>
        <span class="badge"><span id="conn-dot" class="conn-dot"></span><span id="conn-text">Connected</span></span>
        <span class="badge" id="perf-indicator">[⚡ Standard mode] | Orchesis v0.2.1 | Connected</span>
        <span class="badge" id="status-badge">Status: --</span>
        <button id="mobile-nav-toggle" onclick="toggleMobileNav()" aria-label="Toggle mobile navigation">☰</button>
        <button id="export-all-btn" onclick="exportAll()" aria-label="Export all data">⬇️ Export</button>
        <button id="perf-toggle" onclick="togglePerfMode()" title="Performance mode" aria-pressed="false" aria-label="Toggle performance mode">⚡</button>
        <button id="theme-toggle" onclick="toggleTheme()" aria-pressed="true" aria-label="Toggle light or dark theme">☀️</button>
        <button id="hc-toggle" onclick="toggleHighContrast()" aria-pressed="false" aria-label="Toggle high contrast mode">◑</button>
        <button id="notif-bell" onclick="toggleNotifications()" aria-expanded="false" aria-controls="notif-panel" aria-label="Toggle notifications panel">🔔 <span id="notif-count" class="badge">0</span></button>
        <button id="autopsy-btn" onclick="openAutopsy()">🔬 Autopsy</button>
      </div>
    </div>
    <div id="notif-panel" class="notif-panel hidden" role="region" aria-label="Notifications panel">
      <div class="notif-header">
        Notifications <button onclick="clearNotifications()" aria-label="Clear all notifications">Clear all</button>
      </div>
      <div id="notif-list"></div>
    </div>
    {{DEMO_BANNER}}

    <div id="nav-tabs" class="tabs nav-tabs" role="tablist" aria-label="Dashboard sections">
      <button id="tab-shield" class="tab-btn active" data-tab="shield" role="tab" aria-selected="true" aria-controls="shield">🛡️ Shield</button>
      <button id="tab-agents" class="tab-btn" data-tab="agents" role="tab" aria-selected="false" aria-controls="agents">🤖 Agents</button>
      <button id="tab-sessions" class="tab-btn" data-tab="sessions" role="tab" aria-selected="false" aria-controls="sessions">💾 Sessions</button>
      <button id="tab-flow" class="tab-btn" data-tab="flow" role="tab" aria-selected="false" aria-controls="flow">🔬 Flow X-Ray</button>
      <button id="tab-experiments" class="tab-btn" data-tab="experiments" role="tab" aria-selected="false" aria-controls="experiments">🧪 Experiments</button>
      <button id="tab-threats" class="tab-btn" data-tab="threats" role="tab" aria-selected="false" aria-controls="threats">🛡️ Threats</button>
      <button id="tab-cache" class="tab-btn" data-tab="cache" role="tab" aria-selected="false" aria-controls="cache">⚡ Cache</button>
      <button id="tab-cost" class="tab-btn" data-tab="cost" role="tab" aria-selected="false" aria-controls="cost" onclick="switchTab('cost')">💰 Cost</button>
      <button id="tab-research" class="tab-btn" data-tab="research" role="tab" aria-selected="false" aria-controls="research">🔬 Research</button>
      <button id="tab-compliance" class="tab-btn" data-tab="compliance" role="tab" aria-selected="false" aria-controls="compliance">📘 Compliance</button>
      <button id="tab-overwatch" class="tab-btn" data-tab="overwatch" role="tab" aria-selected="false" aria-controls="overwatch">🛰️ Overwatch</button>
      <button id="tab-channels" class="tab-btn" data-tab="channels" role="tab" aria-selected="false" aria-controls="channels">📡 Channels</button>
      <button id="tab-ecosystem" class="tab-btn" data-tab="ecosystem" role="tab" aria-selected="false" aria-controls="ecosystem">🌐 Ecosystem</button>
      <button id="tab-approvals" class="tab-btn" data-tab="approvals" role="tab" aria-selected="false" aria-controls="approvals">✅ Approvals</button>
    </div>

    <section id="shield" class="screen active" role="tabpanel" aria-labelledby="tab-shield">
      <div class="agent-health-widget">
        <div class="ah-head">
          <div>
            <div class="subtle">Agent Health Score</div>
            <div id="ah-score" class="ah-score">0</div>
          </div>
          <div style="display:grid;justify-items:end;gap:6px;">
            <span id="ah-grade" class="ah-grade">D</span>
            <span id="ah-trend" class="ah-trend">→ stable</span>
          </div>
        </div>
        <div class="ah-grid">
          <div class="ah-row">
            <div class="ah-row-head"><span>Security</span><span id="ah-security">0</span></div>
            <div class="ah-bar"><div id="ah-bar-security"></div></div>
          </div>
          <div class="ah-row">
            <div class="ah-row-head"><span>Cost Efficiency</span><span id="ah-cost-efficiency">0</span></div>
            <div class="ah-bar"><div id="ah-bar-cost-efficiency"></div></div>
          </div>
          <div class="ah-row">
            <div class="ah-row-head"><span>Context Quality</span><span id="ah-context-quality">0</span></div>
            <div class="ah-bar"><div id="ah-bar-context-quality"></div></div>
          </div>
          <div class="ah-row">
            <div class="ah-row-head"><span>Reliability</span><span id="ah-reliability">0</span></div>
            <div class="ah-bar"><div id="ah-bar-reliability"></div></div>
          </div>
        </div>
      </div>
      <div class="hero-metrics" role="region" aria-label="Security metrics">
        <div class="hero-card hero-blocked">
          <div class="hero-number" id="blocked-count">0</div>
          <div class="hero-label">Threats Blocked</div>
        </div>
        <div class="hero-card hero-saved">
          <div class="hero-number" id="money-saved">$0.00</div>
          <div class="hero-label">Money Saved</div>
        </div>
        <div class="hero-card hero-health">
          <div class="hero-number" id="overwatch-health">A</div>
          <div class="hero-label">Overwatch Health</div>
        </div>
      </div>
      <div class="token-yield-widget">
        <div class="token-yield-head">
          <div>
            <div class="subtle">Token Yield</div>
            <div id="ty-percent" class="token-yield-percent">0.0%</div>
          </div>
          <div id="ty-collapse" class="token-yield-warning"></div>
        </div>
        <div class="subtle">Waste: <span id="ty-waste-text">0.0%</span></div>
        <div class="token-yield-bar"><div id="ty-waste-bar"></div></div>
        <div class="subtle">Cache savings: <span id="ty-cache-savings">0</span> tokens</div>
        <table class="token-yield-table">
          <thead><tr><th>Iteration</th><th>Tokens</th></tr></thead>
          <tbody id="ty-iterations"><tr><td colspan="2" class="subtle">No data</td></tr></tbody>
        </table>
      </div>
      <div class="context-budget-widget">
        <div class="cbg-head">
          <div>
            <div class="subtle">Context Budget</div>
            <div id="cbg-pressure" class="subtle">Context window pressure</div>
          </div>
          <span id="cbg-level" class="cbg-pill normal">normal</span>
        </div>
        <div class="cbg-counters">
          <div class="cbg-counter"><div class="k">L0</div><div id="cbg-l0" class="v">0</div></div>
          <div class="cbg-counter"><div class="k">L1</div><div id="cbg-l1" class="v">0</div></div>
          <div class="cbg-counter"><div class="k">L2</div><div id="cbg-l2" class="v">0</div></div>
        </div>
        <div class="cbg-progress">
          <div class="subtle">Used / Max tokens: <span id="cbg-used-max">0 / 0</span></div>
          <div class="cbg-bar"><div id="cbg-used-bar"></div></div>
        </div>
      </div>
      <div class="rate-limit-widget">
        <div class="rl-head">
          <div>
            <div class="subtle">Rate Limits</div>
            <div id="rl-reset-at" class="subtle">Resets at --</div>
          </div>
          <div class="rl-counters">
            <div class="rl-counter">Global req/min: <span id="rl-global-rpm" class="v">0</span></div>
            <div class="rl-counter">Throttled agents: <span id="rl-throttled" class="v">0</span></div>
          </div>
        </div>
        <div id="rl-agent-rows" class="rl-rows">
          <div class="empty">No rate limit data.</div>
        </div>
      </div>
      <div class="community-widget">
        <div class="community-head">
          <div>
            <div class="subtle">Community Intel</div>
            <div id="community-last-sync" class="subtle">Last sync: --</div>
          </div>
          <label class="community-toggle">
            <input id="community-enabled-toggle" type="checkbox">
            <span>Opt-in sharing</span>
          </label>
        </div>
        <div class="community-stats">
          <div class="community-stat"><div class="k">Threats shared</div><div id="community-threats-shared" class="v">0</div></div>
          <div class="community-stat"><div class="k">Updates received</div><div id="community-updates-received" class="v">0</div></div>
        </div>
        <div>
          <span class="privacy-badge">Privacy: zero PII shared</span>
        </div>
      </div>
      <div class="grid-4">
        <div class="panel panel-primary">
          <div class="subtle">📥 Total Requests</div>
          <div id="m-requests" class="metric-value" data-raw="0">0</div>
          <svg id="spark-requests" class="sparkline" viewBox="0 0 60 20" preserveAspectRatio="none"></svg>
        </div>
        <div class="panel">
          <div class="subtle">🚫 Blocked / Flagged</div>
          <div id="m-blocked" class="metric-value" data-raw="0">0</div>
          <svg id="spark-blocked" class="sparkline" viewBox="0 0 60 20" preserveAspectRatio="none"></svg>
        </div>
        <div class="panel">
          <div class="subtle">💰 Total Cost USD</div>
          <div id="m-cost" class="metric-value" data-raw="0">$0.00</div>
          <svg id="spark-cost" class="sparkline" viewBox="0 0 60 20" preserveAspectRatio="none"></svg>
        </div>
        <div class="panel">
          <div class="subtle">⚡ Cost Velocity</div>
          <div id="m-cost-velocity" class="metric-value" data-raw="0">$0.00/h</div>
          <div class="subtle">24h projection: <span id="m-cost-projection">$0.00</span></div>
        </div>
      </div>
      <div class="grid-2">
        <div class="panel panel-primary">
          <div><strong>Cost Timeline</strong></div>
          <div class="chart-wrap"><svg id="cost-chart" width="100%" height="220" viewBox="0 0 900 220"></svg></div>
          <div id="cost-tooltip" class="chart-tooltip"></div>
        </div>
        <div class="panel savings-panel">
          <div style="display:flex;justify-content:space-between;align-items:center;">
            <strong>💰 Cost Savings</strong>
            <div id="total-savings" class="metric-value savings-total" data-raw="0">$0.00</div>
          </div>
          <div id="savings-breakdown" class="savings-grid"></div>
        </div>
      </div>
      <div class="panel heatmap-panel">
        <div class="heatmap-head">
          <div><strong>Session Activity Heatmap (7d)</strong></div>
          <div class="subtle">Requests by day/hour</div>
        </div>
        <div id="session-heatmap-grid" class="heatmap-grid"></div>
        <div class="heatmap-meta">
          <span id="session-heatmap-peak">Peak: --</span>
          <span id="session-heatmap-quiet">Quiet: --</span>
          <span id="session-heatmap-total">Total: 0</span>
        </div>
        <div id="session-heatmap-tooltip" class="heatmap-tooltip">Hover a cell to inspect count, cost, and blocked requests.</div>
      </div>
      <div class="panel savings-card">
        <h3 style="margin:0 0 8px 0;">💰 Savings Today</h3>
        <div id="savings-total" class="metric-value savings-total" data-raw="0">$0.00</div>
        <div class="savings-breakdown">
          <div>Cached responses: <span id="savings-cache">$0.00</span></div>
          <div>Model downgrades: <span id="savings-cascade">$0.00</span></div>
          <div>Loops prevented: <span id="savings-loops">$0.00</span></div>
        </div>
      </div>
      <div class="panel">
        <div class="section-title"><strong>Recent Events</strong></div>
        <div id="events" class="event-feed"></div>
      </div>
      <div class="grid-4" style="margin-top: 12px;">
        <div class="panel">
          <div class="subtle">🔍 Threats Detected</div>
          <div id="m-threats" class="metric-value" data-raw="0">0</div>
        </div>
        <div class="panel">
          <div class="subtle">⚡ Cache Hit Rate</div>
          <div id="m-cache-rate" class="metric-value" data-raw="0">0%</div>
        </div>
        <div class="panel">
          <div class="subtle">🧪 Active Experiments</div>
          <div id="m-experiments" class="metric-value" data-raw="0">0</div>
        </div>
        <div class="panel">
          <div class="subtle">📊 Task Success</div>
          <div id="m-task-success" class="metric-value" data-raw="0">0%</div>
        </div>
      </div>
      <div class="panel">
        <div><strong>System Runtime</strong></div>
        <div id="cb-list" class="subtle">No data</div>
        <hr style="border-color: var(--border); border-width: 1px 0 0; margin: 10px 0;">
        <div><strong>Connection Pool</strong></div>
        <div id="pool-stats" class="subtle">No pool data</div>
        <hr style="border-color: var(--border); border-width: 1px 0 0; margin: 10px 0;">
        <div><strong>Budget Progress</strong></div>
        <div id="budget-label" class="subtle">No budget configured</div>
        <div class="progress"><div id="budget-bar" style="width:0%"></div></div>
      </div>
    </section>

    <section id="experiments" class="screen" role="tabpanel" aria-labelledby="tab-experiments">
      <div class="grid-4">
        <div class="panel"><div class="subtle">Active Experiments</div><div id="exp-active" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Total Assignments</div><div id="exp-assignments" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Task Success Rate</div><div id="exp-success-rate" class="metric-value">0%</div></div>
        <div class="panel"><div class="subtle">Tracked Sessions</div><div id="exp-sessions" class="metric-value">0</div></div>
      </div>
      <div id="exp-cards"></div>
      <div class="panel">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
          <div class="section-title" style="margin:0;padding:0;border:0;"><strong>Benchmark</strong></div>
          <div style="display:flex;gap:8px;">
            <button id="exp-benchmark-run" class="ow-btn">Run Benchmark</button>
            <button id="exp-benchmark-export" class="ow-btn">Export Results</button>
          </div>
        </div>
        <div id="exp-benchmark-score" class="subtle" style="margin-top:8px;">Overall score vs baseline: --</div>
        <table id="exp-benchmark-table" class="table" style="margin-top:8px;">
          <thead><tr><th>Case</th><th>Category</th><th>Expected</th><th>Status</th></tr></thead>
          <tbody><tr><td colspan="4" class="subtle">No benchmark data yet.</td></tr></tbody>
        </table>
      </div>
      <div class="panel panel-primary">
        <div class="section-title"><strong>Task Correlations & Insights</strong></div>
        <div id="exp-correlations" class="event-feed"></div>
      </div>
      <div class="panel">
        <div class="section-title"><strong>Outcome Distribution</strong></div>
        <div id="exp-outcome-bar" class="outcome-bar"></div>
        <div id="exp-outcomes" class="grid-4"></div>
      </div>
    </section>

    <section id="threats" class="screen" role="tabpanel" aria-labelledby="tab-threats">
      <div class="grid-4">
        <div class="panel"><div class="subtle">Signatures</div><div id="th-sigs" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Scans</div><div id="th-scans" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Matches</div><div id="th-matches" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Blocks</div><div id="th-blocks" class="metric-value">0</div></div>
      </div>
      <div class="panel panel-primary">
        <div class="section-title"><strong>Top Threats</strong></div>
        <div id="th-top"></div>
      </div>
      <div class="grid-2">
        <div class="panel">
          <strong>Matches by Category</strong>
          <div id="th-by-cat"></div>
        </div>
        <div class="panel">
          <strong>Matches by Severity</strong>
          <div id="th-by-sev"></div>
        </div>
      </div>
      <div class="panel">
        <strong>All Signatures</strong>
        <table id="th-table" class="table">
          <thead><tr><th>ID</th><th>Name</th><th>Category</th><th>Severity</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </section>

    <section id="cache" class="screen" role="tabpanel" aria-labelledby="tab-cache">
      <div class="grid-4">
        <div class="panel"><div class="subtle">Cache Hit Rate</div><div id="c-hit-rate" class="metric-value">0%</div></div>
        <div class="panel"><div class="subtle">Tokens Saved</div><div id="c-tokens" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Cost Saved</div><div id="c-cost" class="metric-value">$0.00</div></div>
        <div class="panel"><div class="subtle">Entries</div><div id="c-entries" class="metric-value">0/0</div></div>
      </div>
      <div class="panel panel-primary">
        <div class="section-title"><strong>Semantic Cache</strong></div>
        <div id="c-semantic-breakdown"></div>
      </div>
      <div class="panel">
        <div class="section-title"><strong>Context Engine</strong></div>
        <div id="c-context"></div>
      </div>
    </section>

    <section id="cost" class="screen" role="tabpanel" aria-labelledby="tab-cost">
      <div id="cost-summary"></div>
      <div id="cost-of-freedom-widget"></div>
      <div id="token-yield-chart"></div>
      <div class="grid-4">
        <div class="panel"><div class="subtle">Total Cost (period)</div><div id="cost-total" class="metric-value">$0.00</div></div>
        <div class="panel"><div class="subtle">24h Forecast</div><div id="cost-forecast" class="metric-value">$0.00</div></div>
        <div class="panel"><div class="subtle">Top Model</div><div id="cost-top-model" class="metric-value">--</div></div>
        <div class="panel"><div class="subtle">Top Agent</div><div id="cost-top-agent" class="metric-value">--</div></div>
      </div>
      <div class="grid-2">
        <div class="panel panel-primary">
          <div class="section-title"><strong>Cost by Model</strong></div>
          <div id="cost-by-model"></div>
        </div>
        <div class="panel panel-primary">
          <div class="section-title"><strong>Cost by Agent</strong></div>
          <div id="cost-by-agent"></div>
        </div>
      </div>
      <div class="panel">
        <div class="section-title"><strong>Hourly Cost Timeline</strong></div>
        <div id="cost-hourly"></div>
      </div>
      <div class="grid-2">
        <div class="panel">
          <div class="section-title"><strong>Savings Breakdown</strong></div>
          <div id="cost-savings"></div>
        </div>
        <div class="panel">
          <div class="section-title"><strong>Top Expensive Sessions</strong></div>
          <div id="cost-top-sessions"></div>
        </div>
      </div>
    </section>

    <section id="agents" class="screen" role="tabpanel" aria-labelledby="tab-agents">
      <div class="panel panel-primary">
        <div class="section-title"><strong>Agent DNA</strong></div>
        <div id="agents-empty" class="empty" style="display:none;">No agents detected yet.</div>
        <table id="agents-table" class="table">
          <thead><tr><th>Agent ID</th><th>Status</th><th>Requests</th><th>Cost</th><th>ARS Score</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="panel">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
          <div class="section-title"><strong>Profile</strong></div>
          <select id="agent-profile-select" class="tab-btn" style="padding:6px 10px; min-width:220px;"></select>
        </div>
        <div id="agent-profile-empty" class="empty" style="display:none;">Select an agent to view profile.</div>
        <div id="agent-profile-body" style="display:none;">
          <div class="profile-badges">
            <span class="profile-tag">Age: <span id="ap-age">0h</span></span>
            <span id="ap-cold" class="profile-tag cold">Cold Start</span>
          </div>
          <div class="profile-grid">
            <div class="panel"><div class="subtle">Avg Prompt</div><div id="ap-avg-prompt" class="metric-value">0</div></div>
            <div class="panel"><div class="subtle">Tool Frequency</div><div id="ap-tool-freq" class="metric-value">0</div></div>
            <div class="panel"><div class="subtle">Cache Hit Rate</div><div id="ap-cache-hit" class="metric-value">0%</div></div>
            <div class="panel"><div class="subtle">Error Rate</div><div id="ap-error-rate" class="metric-value">0%</div></div>
          </div>
          <div class="grid-2" style="margin-top:10px;">
            <div class="panel">
              <strong>Detected Patterns</strong>
              <div id="ap-patterns" style="margin-top:8px;"></div>
              <strong style="display:block;margin-top:12px;">Cost Optimizations</strong>
              <ul id="ap-optimizations" class="profile-list"></ul>
            </div>
            <div class="panel">
              <strong>Reliability (7d)</strong>
              <svg id="ap-reliability-spark" class="sparkline" viewBox="0 0 120 24" preserveAspectRatio="none"></svg>
              <div id="ap-alerts" style="margin-top:10px;"></div>
            </div>
          </div>
        </div>
      </div>
    </section>

    <section id="sessions" class="screen" role="tabpanel" aria-labelledby="tab-sessions">
      <div class="panel panel-primary">
        <div class="section-title"><strong>Time Machine Sessions</strong></div>
        <div id="sessions-empty" class="empty" style="display:none;">No sessions recorded.</div>
        <table id="sessions-table" class="table">
          <thead><tr><th>Session ID</th><th>Agent</th><th>Requests</th><th>Duration</th><th>Cost</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </section>

    <section id="flow" class="screen" role="tabpanel" aria-labelledby="tab-flow">
      <div class="panel panel-primary">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
          <strong class="section-title" style="margin:0;padding:0;border:0;">Flow X-Ray</strong>
          <div style="display:flex;align-items:center;gap:8px;">
            <select id="flow-session-select" class="tab-btn" style="padding:6px 10px;"></select>
            <button id="flow-share-btn" class="tab-btn" style="padding:6px 10px;">Share</button>
          </div>
        </div>
      </div>
      <div class="grid-4">
        <div class="panel"><div class="subtle">Depth</div><div id="f-depth" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Width</div><div id="f-width" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Density</div><div id="f-density" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Total Cost</div><div id="f-cost" class="metric-value">$0.00</div></div>
      </div>
      <div class="grid-2">
        <div class="panel">
          <div class="score-gauge">
            <svg id="health-gauge" viewBox="0 0 180 110" width="140" height="90"></svg>
            <div>
              <div><strong>Health Score</strong></div>
              <div id="health-score" class="metric-value">0.00</div>
            </div>
          </div>
          <div class="subtle">Critical Path: <span id="critical-path">n/a</span></div>
        </div>
        <div class="panel" style="min-height: 300px;">
          <div><strong>Flow Graph</strong></div>
          <svg id="flow-graph-svg" width="100%" height="400" class="flow-graph"></svg>
        </div>
      </div>
      <div class="panel">
        <div><strong>Detected Patterns</strong></div>
        <div id="patterns-empty" class="empty" style="display:none;">No data yet.</div>
        <div id="patterns"></div>
      </div>
      <div class="panel">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
          <strong>Timeline View</strong>
          <div style="display:flex;gap:8px;">
            <button id="flow-view-list" class="tab-btn" style="padding:6px 10px;">List view</button>
            <button id="flow-view-timeline" class="tab-btn" style="padding:6px 10px;">Timeline view</button>
          </div>
        </div>
        <div id="flow-list-view" style="margin-top:10px;"></div>
        <div id="flow-timeline-view" style="margin-top:10px;display:none;">
          <svg id="flow-timeline-svg" width="100%" height="360" class="flow-graph"></svg>
          <div id="flow-timeline-details" class="subtle" style="margin-top:8px;">Click a cell to inspect phase details.</div>
        </div>
      </div>
      <div class="panel">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap;">
          <strong>Request Inspector</strong>
          <input id="request-inspector-search" type="text" placeholder="Search request id..." style="min-width:220px;padding:6px 10px;border:1px solid var(--border);border-radius:8px;background:var(--surface);color:var(--text);">
        </div>
        <div class="grid-2" style="margin-top:10px;">
          <div>
            <div class="subtle">Recent requests (20)</div>
            <div id="request-inspector-list" style="margin-top:8px;display:grid;gap:6px;"></div>
          </div>
          <div>
            <div id="request-inspector-meta" class="subtle">Select a request to inspect all 17 phases.</div>
            <div id="request-inspector-pipeline" style="margin-top:8px;display:grid;grid-template-columns:repeat(6,minmax(80px,1fr));gap:6px;"></div>
          </div>
        </div>
      </div>
    </section>

    <section id="compliance" class="screen" role="tabpanel" aria-labelledby="tab-compliance">
      <div class="grid-2">
        <div class="panel panel-primary">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
            <strong class="section-title" style="margin:0;padding:0;border:0;">Compliance Coverage Overview</strong>
            <button id="export-compliance-btn" class="tab-btn" style="padding:6px 10px;">Export Report JSON</button>
          </div>
          <div class="grid-2" style="margin-top:10px;">
            <div class="panel">
              <div class="subtle">OWASP LLM Top 10</div>
              <div id="cmp-owasp-percent" class="metric-value">0%</div>
              <div class="progress-bar-wrap"><div id="cmp-owasp-bar" class="progress-bar-fill" style="width:0%"></div></div>
            </div>
            <div class="panel">
              <div class="subtle">NIST AI RMF</div>
              <div id="cmp-nist-percent" class="metric-value">0%</div>
              <div class="progress-bar-wrap"><div id="cmp-nist-bar" class="progress-bar-fill" style="width:0%"></div></div>
            </div>
          </div>
        </div>
        <div class="panel">
          <div class="section-title"><strong>Recent Compliance Findings</strong></div>
          <div id="cmp-findings" class="event-feed"></div>
        </div>
      </div>
      <div class="panel">
        <div class="section-title"><strong>OWASP Top 10 Coverage</strong></div>
        <table id="cmp-owasp-table" class="table">
          <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Modules</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
      <div class="panel">
        <div class="section-title"><strong>Compliance Overview</strong></div>
        <div id="cmp-overview-text" class="subtle" style="margin-top:8px;"></div>
      </div>
      <div class="panel">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
          <div class="section-title"><strong>Evidence Record</strong></div>
          <span class="badge">EU AI Act Article 12</span>
        </div>
        <div class="subtle" style="margin-top:8px;">
          Record ID: <span id="evidence-record-id">--</span> ·
          Session ID: <span id="evidence-session-id">--</span> ·
          Integrity Hash: <span id="evidence-record-hash">--</span>
        </div>
        <div style="margin-top:10px;display:flex;gap:8px;flex-wrap:wrap;">
          <button id="export-evidence-json-btn" class="tab-btn" style="padding:6px 10px;">Export Evidence Record (JSON)</button>
          <button id="export-evidence-text-btn" class="tab-btn" style="padding:6px 10px;">Export Text Report</button>
        </div>
      </div>
    </section>

    <section id="overwatch" class="screen" role="tabpanel" aria-labelledby="tab-overwatch">
      <div class="ow-wrap">
        <div id="ow-summary" class="ow-summary">0 active · $0.00/day · 0 blocked · 0 pending</div>
        <div class="ow-toolbar">
          <div class="section-title" style="margin:0;padding:0;border:0;">Fleet View</div>
          <div class="ow-switch">
            <button id="ow-view-cards" class="ow-view-btn active">Cards</button>
            <button id="ow-view-radar" class="ow-view-btn">Radar</button>
            <button id="ow-view-teams" class="ow-view-btn">Teams</button>
            <button id="ow-view-graph" class="ow-view-btn">Graph</button>
          </div>
        </div>
        <div id="ow-cards-view">
          <div id="ow-cards" class="ow-cards"></div>
          <div id="ow-empty" class="ow-empty" style="display:none;">
            <div class="icon">◈</div>
            <div style="font-size:18px;color:var(--text);font-weight:700;">No agents detected</div>
            <div class="cmd">orchesis demo</div>
            <div><button id="ow-load-demo" class="ow-btn">Load Demo Data</button></div>
          </div>
        </div>
        <div id="ow-radar-view" class="ow-radar-wrap" style="display:none;">
          <div class="ow-radar-box">
            <div id="ow-radar-tooltip" class="ow-radar-tooltip"></div>
            <svg id="ow-radar" class="ow-radar-svg" viewBox="0 0 620 460"></svg>
          </div>
          <div class="ow-radar-footer"><button id="ow-share" class="ow-btn">Share</button></div>
        </div>
        <div id="ow-teams-view" class="ow-teams-wrap" style="display:none;">
          <div id="ow-teams-cards" class="ow-team-cards"></div>
          <div id="ow-team-detail" class="ow-team-detail">
            <div class="subtle">Select a team card to view its agents.</div>
          </div>
        </div>
        <div id="ow-graph-view" class="ow-graph-wrap" style="display:none;">
          <div class="ow-graph-box">
            <svg id="ow-graph-svg" class="ow-graph-svg" viewBox="0 0 620 460"></svg>
          </div>
          <div id="ow-graph-detail" class="ow-graph-detail">Click a node to inspect agent interactions.</div>
        </div>
        <div id="ow-approvals-section" class="ow-ap-section" style="display:none;">
          <div class="section-title"><strong>Pending Approvals</strong></div>
          <div id="ow-approvals-list"></div>
        </div>
      </div>
    </section>

    <section id="approvals" class="screen" role="tabpanel" aria-labelledby="tab-approvals">
      <div class="panel panel-primary">
        <div class="section-title"><strong>PENDING APPROVALS (<span id="ap-pending-count">0</span>)</strong></div>
        <div id="approvals-pending" style="margin-top:10px;"></div>
      </div>
      <div class="panel">
        <div class="section-title"><strong>HISTORY</strong></div>
        <div id="approvals-history" style="margin-top:10px;"></div>
      </div>
    </section>
    <section id="research" class="screen tab-section hidden" role="tabpanel">
      <div id="nlce-confirmed-results"></div>
      <div id="nlce-theorems"></div>
      <div id="nlce-pipeline-state"></div>
    </section>
    <section id="channels" class="screen tab-section hidden" role="tabpanel" aria-labelledby="tab-channels">
      <div class="grid-2">
        <div class="panel panel-primary">
          <div class="section-title"><strong>Telegram</strong></div>
          <div id="telegram-status" class="subtle">No data</div>
        </div>
        <div class="panel panel-primary">
          <div class="section-title"><strong>WhatsApp</strong></div>
          <div id="whatsapp-status" class="subtle">No data</div>
        </div>
      </div>
      <div class="panel">
        <div class="section-title"><strong>WebChat</strong></div>
        <div id="webchat-status" class="subtle">No data</div>
      </div>
      <div class="panel">
        <div class="section-title"><strong>Channel Alerts</strong></div>
        <div id="channel-alerts" class="subtle">No alerts.</div>
      </div>
    </section>
    <section id="ecosystem" class="screen" role="tabpanel" aria-labelledby="tab-ecosystem">
      <div class="grid-2">
        <div class="panel panel-primary">
          <div class="section-title"><strong>CASURA</strong></div>
          <div id="eco-casura" class="subtle">No data</div>
        </div>
        <div class="panel panel-primary">
          <div class="section-title"><strong>AABB</strong></div>
          <div id="eco-aabb" class="subtle">No data</div>
        </div>
      </div>
      <div class="grid-2">
        <div class="panel">
          <div class="section-title"><strong>ARE</strong></div>
          <div id="eco-are" class="subtle">No data</div>
        </div>
        <div class="panel">
          <div class="section-title"><strong>Monitoring</strong></div>
          <div id="eco-competitive" class="subtle">No data</div>
        </div>
      </div>
    </section>
  </div>
  <div class="subtle" style="text-align:center; margin-top:8px;">
    <span id="version-badge" onclick="showChangelog()"
      style="cursor:pointer" title="Click for changelog">
      v0.2.1 ✨
    </span>
  </div>
  <div class="shortcuts-hint">Press <kbd>?</kbd> for keyboard shortcuts</div>
  <div id="shortcuts-modal" class="modal hidden">
    <div class="modal-content">
      <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
        <h3 style="margin:0;">Keyboard Shortcuts</h3>
        <button id="shortcuts-close-btn" class="tab-btn" style="padding:4px 8px;">Close</button>
      </div>
      <table class="shortcuts-table">
        <tbody>
          <tr><td>g s</td><td>Go to Shield</td></tr>
          <tr><td>g a</td><td>Go to Agents</td></tr>
          <tr><td>g t</td><td>Go to Threats</td></tr>
          <tr><td>g c</td><td>Go to Cache</td></tr>
          <tr><td>g o</td><td>Go to Overwatch</td></tr>
          <tr><td>g p</td><td>Go to Compliance</td></tr>
          <tr><td>r</td><td>Refresh current tab</td></tr>
          <tr><td>?</td><td>Show this help</td></tr>
          <tr><td>Esc</td><td>Close modal/panel</td></tr>
        </tbody>
      </table>
    </div>
  </div>
  <div id="changelog-modal" class="modal hidden">
    <div class="modal-content">
      <h3>What's new in Orchesis</h3>
      <div id="changelog-content"></div>
      <button onclick="closeChangelog()">Close</button>
    </div>
  </div>
  <div id="autopsy-modal" class="modal hidden">
    <div class="modal-content">
      <h3>🔬 Agent Autopsy</h3>
      <input id="autopsy-session-id" type="text" placeholder="Session ID..." />
      <button onclick="runAutopsy()">Run Autopsy</button>
      <div id="autopsy-result"></div>
      <button onclick="closeAutopsy()">Close</button>
    </div>
  </div>
  <div id="toast" class="toast"></div>

  <script>
    const POLL_INTERVAL = 5000;
    const POLL_INTERVALS = {
      normal: {
        shield: 10000,
        agents: 12000,
        sessions: 12000,
        threats: 12000,
        flow: 30000,
        cost: 30000,
        cache: 30000,
        overwatch: 30000,
        experiments: 60000,
        compliance: 30000,
      },
      performance: {
        shield: 20000,
        agents: 24000,
        sessions: 24000,
        threats: 24000,
        flow: 60000,
        cost: 60000,
        cache: 60000,
        overwatch: 60000,
        experiments: 120000,
        compliance: 60000,
      }
    };
    const RATE_LIMIT_REFRESH_MS = 10000;
    let perfMode = localStorage.getItem('orchesis-perf') === 'true';
    const loadedTabs = new Set(['shield']);
    let currentTab = "shield";
    let _activeTab = "shield";
    let _refreshInProgress = false;
    let _lastDataHash = "";
    let _dashboardErrorShown = false;
    let pollTimer = null;
    let selectedAgentProfileId = "";
    let lastOverview = null;
    let overwatchView = "cards";
    let overwatchUseDemo = false;
    let overwatchSnapshot = null;
    let overwatchTeamDetail = null;
    let notifTimer = null;
    let notifLastTs = 0;
    let rateLimitSnapshot = null;
    let lastRateLimitFetchMs = 0;
    let overviewCache = { value: null, fetchedAt: 0, ttlMs: 4000 };
    let statsCache = { value: null, fetchedAt: 0, ttlMs: 4000 };
    const API_TOKEN = String((window && window.API_TOKEN) || localStorage.getItem("API_TOKEN") || "").trim();
    let searchTimer = null;
    const SHORTCUTS = {
      "g s": "shield",
      "g a": "agents",
      "g t": "threats",
      "g c": "cache",
      "g o": "overwatch",
      "g p": "compliance",
      "?": "shortcuts",
      "r": "refresh",
      "Escape": "close",
    };
    let keySequence = [];
    let keyTimer = null;
    const notifications = [];
    const NOTIF_LIMIT = 50;
    const NOTIF_POLL_INTERVAL = 5000;
    const NOTIFICATION_TYPES = {
      threat_blocked: { icon: "🔴", fallback: "Threat blocked" },
      budget_warning: { icon: "🟡", fallback: "Budget warning" },
      cache_milestone: { icon: "🔵", fallback: "Cache milestone" },
      loop_detected: { icon: "⚪", fallback: "Loop detected" },
    };
    const HC_COLORS = {
      bg: "#000000",
      text: "#ffffff",
      accent: "#ffff00",
      danger: "#ff6666",
      success: "#66ff66",
    };
    const sparkHistory = {};
    const SPARK_MAX = 20;
    function applyTheme(theme){
      const next = theme === "light" ? "light" : "dark";
      document.documentElement.setAttribute("data-theme", next);
      localStorage.setItem("orchesis-theme", next);
      const btn = document.getElementById("theme-toggle");
      if(btn){
        btn.textContent = next === "dark" ? "☀️" : "🌙";
        btn.setAttribute("aria-pressed", next === "dark" ? "true" : "false");
      }
    }
    function applyHighContrast(enabled){
      const isEnabled = enabled === true || String(enabled) === "true";
      document.documentElement.setAttribute("data-hc", isEnabled ? "true" : "false");
      localStorage.setItem("orchesis-hc", isEnabled ? "true" : "false");
      const root = document.documentElement;
      const resetKeys = ["bg", "text", "accent", "danger", "success", "surface", "border", "panel", "text-secondary", "hero-radial"];
      if(isEnabled){
        root.style.setProperty("--bg", HC_COLORS.bg);
        root.style.setProperty("--surface", HC_COLORS.bg);
        root.style.setProperty("--text", HC_COLORS.text);
        root.style.setProperty("--border", HC_COLORS.text);
        root.style.setProperty("--accent", HC_COLORS.accent);
        root.style.setProperty("--danger", HC_COLORS.danger);
        root.style.setProperty("--ok", HC_COLORS.success);
        root.style.setProperty("--panel", HC_COLORS.bg);
        root.style.setProperty("--text-secondary", HC_COLORS.text);
        root.style.setProperty("--hero-radial", HC_COLORS.bg);
      } else {
        resetKeys.forEach((k)=> root.style.removeProperty(`--${k}`));
      }
      const btn = document.getElementById("hc-toggle");
      if(btn){
        btn.setAttribute("aria-pressed", isEnabled ? "true" : "false");
        btn.textContent = isEnabled ? "◐" : "◑";
      }
    }
    function toggleHighContrast() {
      const hc = document.documentElement.getAttribute("data-hc") === "true";
      applyHighContrast(!hc);
    }
    function toggleTheme() {
      const current = document.documentElement.getAttribute("data-theme");
      const next = current === "dark" ? "light" : "dark";
      applyTheme(next);
    }

    function fmtNum(v){ return Number(v||0).toLocaleString(); }
    function fmtMoney(v){ return "$" + Number(v||0).toFixed(2); }
    function fmtTs(ts){
      if(!ts){ return "--"; }
      const d = new Date(Number(ts) * 1000);
      if (Number.isNaN(d.getTime())) { return "--"; }
      return d.toLocaleString();
    }
    function fmtDuration(sec){
      sec = Math.max(0, Number(sec||0));
      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = Math.floor(sec % 60);
      if (h > 0) return `${h}h ${m}m ${s}s`;
      if (m > 0) return `${m}m ${s}s`;
      return `${s}s`;
    }
    function toRiskBadgeClass(grade){
      const g = String(grade || "A").toUpperCase();
      if (g.startsWith("A")) return "grade-a";
      if (g.startsWith("B")) return "grade-b";
      if (g.startsWith("C")) return "grade-c";
      if (g.startsWith("D")) return "grade-d";
      return "grade-f";
    }
    function formatGrade(grade){
      const g = String(grade || "A").toUpperCase().trim();
      return g || "A";
    }
    function copyText(text){
      const done = () => {};
      if (navigator && navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(done).catch(done);
        return;
      }
      const box = document.createElement("textarea");
      box.value = text;
      document.body.appendChild(box);
      box.select();
      try { document.execCommand("copy"); } catch (_err) {}
      document.body.removeChild(box);
    }
    function showToast(message){
      const el = document.getElementById("toast");
      if(!el){ return; }
      el.textContent = String(message || "Link copied!");
      el.classList.add("show");
      if(showToast._timer){ clearTimeout(showToast._timer); }
      showToast._timer = setTimeout(()=>{ el.classList.remove("show"); }, 3000);
    }
    function fmtNotifTs(ts){
      const d = new Date(Number(ts || 0) * 1000);
      if (Number.isNaN(d.getTime())) { return "--"; }
      return d.toLocaleTimeString();
    }
    function notifMessageForType(type, payload){
      const t = String(type || "loop_detected");
      const data = payload && typeof payload === "object" ? payload : {};
      if (t === "threat_blocked") return `Threat blocked: ${String(data.threat_type || "unknown")}`;
      if (t === "budget_warning") return `Budget at ${Number(data.percent || 0)}%`;
      if (t === "cache_milestone") return `Cache saved $${Number(data.saved_usd || 0).toFixed(2)}`;
      if (t === "loop_detected") return `Loop detected for ${String(data.agent_id || "agent")}`;
      return String(data.message || "Notification");
    }
    function renderNotifications(){
      const countEl = document.getElementById("notif-count");
      if (countEl) countEl.textContent = String(notifications.length);
      const listEl = document.getElementById("notif-list");
      if (!listEl) return;
      if (notifications.length === 0) {
        listEl.innerHTML = `<div class="notif-item"><div>No notifications yet</div><small>Waiting for events...</small></div>`;
        return;
      }
      listEl.innerHTML = notifications.map((item)=>{
        const t = String(item.type || "");
        const meta = NOTIFICATION_TYPES[t] || { icon: "⚪", fallback: "Notification" };
        return `<div class="notif-item"><div>${meta.icon} ${String(item.message || meta.fallback)}</div><small>${fmtNotifTs(item.timestamp)}</small></div>`;
      }).join("");
    }
    function addNotification(type, message, timestamp, id){
      notifications.unshift({
        id: String(id || `${Date.now()}-${Math.random()}`),
        type: String(type || "loop_detected"),
        message: String(message || "Notification"),
        timestamp: Number(timestamp || (Date.now() / 1000)),
      });
      if (notifications.length > NOTIF_LIMIT) notifications.length = NOTIF_LIMIT;
      renderNotifications();
      showToast(message);
    }
    function toggleNotifications() {
      const panel = document.getElementById("notif-panel");
      const bell = document.getElementById("notif-bell");
      if (!panel) return;
      panel.classList.toggle("hidden");
      if (bell) {
        const expanded = panel.classList.contains("hidden") ? "false" : "true";
        bell.setAttribute("aria-expanded", expanded);
      }
    }
    function clearNotifications() {
      notifications.length = 0;
      renderNotifications();
    }
    function toggleMobileNav() {
      const nav = document.getElementById('nav-tabs');
      nav.classList.toggle('mobile-open');
    }
    async function pollNotifications() {
      try {
        const endpoint = `/api/v1/notifications?since=${encodeURIComponent(notifLastTs)}&limit=20`;
        const response = await fetch(endpoint, { cache: "no-store" });
        if (!response.ok) return;
        const payload = await response.json();
        const rows = Array.isArray(payload.notifications) ? payload.notifications : [];
        for (const row of rows) {
          const t = String(row.type || "");
          const ts = Number(row.timestamp || (Date.now() / 1000));
          const msg = String(row.message || notifMessageForType(t, row));
          addNotification(t, msg, ts, row.id);
          if (ts > notifLastTs) notifLastTs = ts;
        }
      } catch (_err) {}
    }
    async function shareFlowXRay(sessionId) {
      if(!sessionId){ return; }
      const resp = await fetch(`/api/v1/flow/${encodeURIComponent(sessionId)}/share-token`);
      if(!resp.ok){ throw new Error(`share token failed (${resp.status})`); }
      const payload = await resp.json();
      const token = payload && typeof payload.token === "string" ? payload.token : "";
      const url = payload && typeof payload.url === "string" && payload.url
        ? payload.url
        : `http://localhost:8080/flow/${token}`;
      await navigator.clipboard.writeText(url);
      showToast("Link copied!");
    }
    async function exportAll() {
      const token = String((window && window.API_TOKEN) || localStorage.getItem("API_TOKEN") || "").trim();
      const headers = token ? { "Authorization": `Bearer ${token}` } : {};
      const resp = await fetch("/api/v1/export/all", { headers, cache: "no-store" });
      if(!resp.ok){ throw new Error(`export failed (${resp.status})`); }
      const blob = await resp.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `orchesis-export-${Date.now()}.zip`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      showToast("Export downloaded");
    }
    function mockOverwatchData(){
      return {
        summary: {
          active_agents: 5,
          total_cost_day_usd: 31.82,
          threats_blocked: 14,
          pending_approvals: 2,
        },
        agents: [
          { agent_id: "planner-core", status: "active", security_grade: "A", current_task: "route intent graph", budget_used_usd: 4.2, budget_limit_usd: 12, cost_day_usd: 4.2, model: "gpt-4o", threats_today: 0, pending_approvals: 0, requests_today: 520 },
          { agent_id: "ops-bot", status: "warning", security_grade: "B+", current_task: "deploy verification", budget_used_usd: 9.7, budget_limit_usd: 10, cost_day_usd: 9.7, model: "claude-sonnet-4-20250514", threats_today: 2, pending_approvals: 1, requests_today: 860 },
          { agent_id: "support-qa", status: "idle", security_grade: "A+", current_task: "", budget_used_usd: 1.4, budget_limit_usd: 8, cost_day_usd: 1.4, model: "gpt-4o-mini", threats_today: 0, pending_approvals: 0, requests_today: 130 },
          { agent_id: "research-scout", status: "alert", security_grade: "C", current_task: "crawl failed endpoint", budget_used_usd: 7.9, budget_limit_usd: 9, cost_day_usd: 7.9, model: "claude-haiku-4-5-20251001", threats_today: 5, pending_approvals: 0, requests_today: 1100 },
          { agent_id: "invoice-guard", status: "active", security_grade: "B", current_task: "invoice anomaly checks", budget_used_usd: 8.62, budget_limit_usd: 12, cost_day_usd: 8.62, model: "gpt-4o", threats_today: 1, pending_approvals: 1, requests_today: 740 },
        ],
        approvals: [
          { approval_id: "ow-demo-1", agent_id: "ops-bot", description: "system.run deployment command", risk: "high", reason: "destructive file operation suspected", timestamp: Date.now() / 1000 },
          { approval_id: "ow-demo-2", agent_id: "invoice-guard", description: "web_fetch internal.corp.com", risk: "medium", reason: "blocked domain requires approval", timestamp: Date.now() / 1000 },
        ],
        graph: {
          nodes: [
            { id: "planner-core", requests: 520, cost: 4.2 },
            { id: "ops-bot", requests: 860, cost: 9.7 },
            { id: "invoice-guard", requests: 740, cost: 8.62 },
          ],
          edges: [
            { from: "planner-core", to: "ops-bot", weight: 8, type: "context_share" },
            { from: "ops-bot", to: "invoice-guard", weight: 4, type: "tool_call" },
          ],
          central_agent: "ops-bot",
          isolated_agents: [],
        },
      };
    }
    function normalizeOverwatch(payload){
      if (!payload || typeof payload !== "object") return { summary: null, agents: [], approvals: [], teams: [], graph: { nodes: [], edges: [], central_agent: "", isolated_agents: [] } };
      const summaryRaw = (payload.summary && typeof payload.summary === "object")
        ? payload.summary
        : ((payload.overwatch_summary && typeof payload.overwatch_summary === "object") ? payload.overwatch_summary : payload);
      const agents = Array.isArray(payload.agents) ? payload.agents : (Array.isArray(payload.items) ? payload.items : []);
      const approvals = Array.isArray(payload.approvals) ? payload.approvals : (Array.isArray(payload.pending) ? payload.pending : []);
      const teams = Array.isArray(payload.teams) ? payload.teams : [];
      const graph = (payload.graph && typeof payload.graph === "object") ? payload.graph : { nodes: [], edges: [], central_agent: "", isolated_agents: [] };
      return {
        summary: {
          active_agents: Number(summaryRaw.active_agents ?? summaryRaw.active ?? agents.filter((a)=> String(a.status || "").toLowerCase() === "working").length ?? 0),
          total_cost_day_usd: Number(summaryRaw.total_cost_day_usd ?? summaryRaw.cost_day_usd ?? summaryRaw.cost_per_day ?? summaryRaw.total_cost_today ?? 0),
          threats_blocked: Number(summaryRaw.threats_blocked ?? summaryRaw.blocked ?? 0),
          pending_approvals: Number(summaryRaw.pending_approvals ?? approvals.length ?? 0),
        },
        agents,
        approvals,
        teams,
        graph,
      };
    }
    function animateValue(el, start, end, duration, formatter) {
      if (!el) return;
      if (start === end) {
        el.textContent = formatter(end);
        return;
      }
      const range = end - start;
      const startTime = performance.now();
      el.classList.add("updating");
      function step(now) {
        const elapsed = now - startTime;
        const progress = Math.min(elapsed / duration, 1);
        const eased = 1 - Math.pow(1 - progress, 3);
        const current = start + range * eased;
        el.textContent = formatter(current);
        if (progress < 1) {
          requestAnimationFrame(step);
        } else {
          el.classList.remove("updating");
        }
      }
      requestAnimationFrame(step);
    }
    function updateAnimatedMetric(id, value, formatter, duration = 600) {
      const el = document.getElementById(id);
      if (!el) return;
      const prev = Number(el.dataset.raw || "0");
      el.dataset.raw = String(value);
      animateValue(el, prev, Number(value || 0), duration, formatter);
    }
    function updateSparkline(id, value) {
      if (!sparkHistory[id]) sparkHistory[id] = [];
      sparkHistory[id].push(Number(value || 0));
      if (sparkHistory[id].length > SPARK_MAX) sparkHistory[id].shift();
      const data = sparkHistory[id];
      const svg = document.getElementById(`spark-${id}`);
      if (!svg || data.length < 2) return;
      const min = Math.min(...data);
      const max = Math.max(...data);
      const range = max - min || 1;
      const w = 60, h = 20;
      const points = data.map((v, i) => {
        const x = (i / (data.length - 1)) * w;
        const y = h - ((v - min) / range) * (h - 2) - 1;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }).join(" ");
      const areaPoints = points + ` ${w},${h} 0,${h}`;
      const lastY = (h - ((data[data.length - 1] - min) / range) * (h - 2) - 1).toFixed(1);
      svg.innerHTML = `
        <defs><linearGradient id="sg-${id}" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stop-color="var(--ok)" stop-opacity="0.3"/>
          <stop offset="100%" stop-color="var(--ok)" stop-opacity="0"/>
        </linearGradient></defs>
        <polygon points="${areaPoints}" fill="url(#sg-${id})" opacity="0.4"/>
        <polyline points="${points}" fill="none" stroke="var(--ok)" stroke-width="1.5" stroke-linecap="round"/>
        <circle cx="${w}" cy="${lastY}" r="2" fill="var(--ok)"/>
      `;
    }

    async function fetchData(endpoint){
      try{
        const response = await fetch(endpoint, { cache: "no-store" });
        if(!response.ok){ throw new Error("HTTP " + response.status); }
        const data = await response.json();
        setConnection(true);
        return data;
      }catch(_err){
        setConnection(false);
        return null;
      }
    }
    function hideSearchResults() {
      const box = document.getElementById("search-results");
      if (box) box.classList.add("hidden");
    }
    function openShortcutsModal(){
      const modal = document.getElementById("shortcuts-modal");
      if(modal){ modal.classList.remove("hidden"); }
    }
    function closeShortcutsModal(){
      const modal = document.getElementById("shortcuts-modal");
      if(modal){ modal.classList.add("hidden"); }
    }
    function openAutopsy() {
      const modal = document.getElementById("autopsy-modal");
      if(modal){ modal.classList.remove("hidden"); }
    }
    function closeAutopsy() {
      const modal = document.getElementById("autopsy-modal");
      if(modal){ modal.classList.add("hidden"); }
    }
    async function runAutopsy() {
      const sessionId = document.getElementById("autopsy-session-id").value.trim();
      if (!sessionId) { showToast("Enter session ID"); return; }
      const resp = await fetch(`/api/v1/autopsy/${sessionId}`, {
        method: "POST",
        headers: API_TOKEN ? { "Authorization": `Bearer ${API_TOKEN}` } : {},
      });
      const data = await resp.json();
      renderAutopsyResult(data);
    }
    function renderAutopsyResult(data) {
      if (data && data.error) {
        document.getElementById("autopsy-result").innerHTML = `<p class="danger">${data.error}</p>`;
        return;
      }
      document.getElementById("autopsy-result").innerHTML = `
        <div class="autopsy-card">
          <h4>Cause: ${data && data.cause_of_death ? data.cause_of_death : "unknown"}</h4>
          <p>Severity: ${data && data.severity ? data.severity : "-"}</p>
          <p>Preventable: ${data && data.preventable ? "Yes" : "No"}</p>
          <ul>${(data && Array.isArray(data.recommendations) ? data.recommendations : []).map(r => `<li>${r}</li>`).join("")}</ul>
        </div>
      `;
    }
    async function showChangelog() {
      const resp = await fetch('/api/v1/changelog');
      const data = await resp.json();
      renderChangelog(Array.isArray(data.entries) ? data.entries : []);
      document.getElementById('changelog-modal').classList.remove('hidden');
    }
    function closeChangelog() {
      document.getElementById('changelog-modal').classList.add('hidden');
    }
    function renderChangelog(entries) {
      const root = document.getElementById("changelog-content");
      if(!root){ return; }
      if(!Array.isArray(entries) || entries.length === 0){
        root.innerHTML = `<div class="subtle">No changelog entries available.</div>`;
        return;
      }
      root.innerHTML = entries.map((entry)=>{
        const version = String(entry.version || "unknown");
        const date = String(entry.date || "--");
        const highlights = Array.isArray(entry.highlights) ? entry.highlights : [];
        const changes = Array.isArray(entry.changes) ? entry.changes : [];
        const hl = highlights.map((item)=> `<li>${String(item)}</li>`).join("");
        const ch = changes.map((item)=> `<li>${String(item)}</li>`).join("");
        return `
          <div class="panel" style="margin-top:8px;">
            <div style="display:flex;justify-content:space-between;gap:8px;align-items:center;">
              <strong>v${version}</strong>
              <span class="subtle">${date}</span>
            </div>
            <div style="margin-top:6px;"><strong>Highlights</strong></div>
            <ul style="margin:6px 0 0 18px;">${hl}</ul>
            <div style="margin-top:8px;"><strong>Changes</strong></div>
            <ul style="margin:6px 0 0 18px;">${ch}</ul>
          </div>
        `;
      }).join("");
    }
    function resetKeySequence(){
      keySequence = [];
      if(keyTimer){ clearTimeout(keyTimer); keyTimer = null; }
    }
    function isTypingTarget(target){
      if(!target){ return false; }
      const tag = String(target.tagName || "").toUpperCase();
      return tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT" || Boolean(target.isContentEditable);
    }
    function handleKeydown(e) {
      if (isTypingTarget(e.target)) return;
      if (e.metaKey || e.ctrlKey || e.altKey) return;
      const key = String(e.key || "");
      if (key === "Escape") {
        closeShortcutsModal();
        closeChangelog();
        const panel = document.getElementById("notif-panel");
        if(panel && !panel.classList.contains("hidden")){ panel.classList.add("hidden"); }
        resetKeySequence();
        return;
      }
      if (key === "?") {
        e.preventDefault();
        openShortcutsModal();
        resetKeySequence();
        return;
      }
      if (key.toLowerCase() === "r" && key.length === 1) {
        e.preventDefault();
        refreshDashboard();
        showToast("Refreshed");
        resetKeySequence();
        return;
      }
      if (key.length !== 1) return;
      keySequence.push(key.toLowerCase());
      if (keySequence.length > 2) keySequence = keySequence.slice(-2);
      if (keyTimer) clearTimeout(keyTimer);
      keyTimer = setTimeout(()=>{ keySequence = []; }, 900);
      const seq = keySequence.join(" ");
      const targetTab = SHORTCUTS[seq];
      if (typeof targetTab === "string" && ["shield", "agents", "threats", "cache", "overwatch", "compliance"].includes(targetTab)) {
        e.preventDefault();
        switchTab(targetTab);
        resetKeySequence();
      }
    }
    function navigateTo(tab, id){
      switchTab(String(tab || "shield"));
      if (tab === "agents" && id) {
        const select = document.getElementById("agent-profile-select");
        if (select) {
          select.value = String(id);
          selectedAgentProfileId = String(id);
          loadAgentProfile(String(id));
        }
      }
      hideSearchResults();
    }
    function renderSearchResults(data){
      const root = document.getElementById("search-results");
      if (!root) return;
      const results = (data && data.results && typeof data.results === "object") ? data.results : {};
      const agents = Array.isArray(results.agents) ? results.agents : [];
      const sessions = Array.isArray(results.sessions) ? results.sessions : [];
      const threats = Array.isArray(results.threats) ? results.threats : [];
      function escapeHtml(v){
        return String(v || "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
      }
      function item(tab, id, text, sub){
        const encoded = encodeURIComponent(String(id || ""));
        return `<div class="search-item" onclick="navigateTo('${tab}', decodeURIComponent('${encoded}'))"><div>${escapeHtml(text)}</div><div class="subtle">${escapeHtml(sub)}</div></div>`;
      }
      const html = [
        `<div class="search-section">Agents</div>`,
        agents.length
          ? agents.map((row)=> item("agents", row.id, row.id, `status: ${row.status || "unknown"}`)).join("")
          : `<div class="search-item"><div>No agent matches</div></div>`,
        `<div class="search-section">Sessions</div>`,
        sessions.length
          ? sessions.map((row)=> item("sessions", row.id, row.id, `agent: ${row.agent || "unknown"}`)).join("")
          : `<div class="search-item"><div>No session matches</div></div>`,
        `<div class="search-section">Threats</div>`,
        threats.length
          ? threats.map((row)=> item("threats", row.type, row.type, row.timestamp || "--")).join("")
          : `<div class="search-item"><div>No threat matches</div></div>`,
      ].join("");
      root.innerHTML = html;
      root.classList.remove("hidden");
    }
    function debounceSearch(query) {
      if(searchTimer){ clearTimeout(searchTimer); }
      searchTimer = setTimeout(()=> performSearch(query), 300);
    }
    async function performSearch(query) {
      const q = String(query || "").trim();
      if (q.length < 2) { hideSearchResults(); return; }
      try{
        const resp = await fetch(`/api/v1/search?q=${encodeURIComponent(q)}&limit=8`, { cache: "no-store" });
        if(!resp.ok){ hideSearchResults(); return; }
        const data = await resp.json();
        renderSearchResults(data);
      }catch(_err){
        hideSearchResults();
      }
    }

    function setConnection(ok){
      const dot = document.getElementById("conn-dot");
      const text = document.getElementById("conn-text");
      if(ok){
        dot.classList.remove("lost");
        text.textContent = "Connected";
      }else{
        dot.classList.add("lost");
        text.textContent = "Connection lost";
      }
      renderPerfIndicator();
    }

    function setStableHTML(el, html){
      if(!el){ return; }
      const next = String(html || "");
      if (el.dataset && el.dataset.lastHtml === next) {
        return;
      }
      requestAnimationFrame(()=>{
        el.innerHTML = next;
        if (el.dataset) {
          el.dataset.lastHtml = next;
        }
      });
    }

    function renderPerfIndicator(){
      const indicator = document.getElementById("perf-indicator");
      const conn = document.getElementById("conn-text");
      const perfToggle = document.getElementById("perf-toggle");
      const connectionText = conn ? String(conn.textContent || "Connected") : "Connected";
      if(indicator){
        indicator.textContent = perfMode
          ? `[⚡ Performance mode] | Orchesis v0.2.1 | ${connectionText}`
          : `[⚡ Standard mode] | Orchesis v0.2.1 | ${connectionText}`;
      }
      if(perfToggle){
        perfToggle.style.opacity = perfMode ? "1" : "0.4";
        perfToggle.setAttribute("aria-pressed", perfMode ? "true" : "false");
      }
    }

    function pollIntervalForTab(tab){
      const mode = perfMode ? "performance" : "normal";
      const intervals = POLL_INTERVALS[mode] || {};
      const fallback = perfMode ? 30000 : POLL_INTERVAL;
      return Math.max(5000, Number(intervals[tab] || fallback));
    }

    function applyPollIntervals(){
      if(pollTimer){ clearInterval(pollTimer); }
      const intervalMs = pollIntervalForTab(currentTab);
      pollTimer = setInterval(()=>{ refreshDashboard(); }, intervalMs);
      renderPerfIndicator();
    }

    function refreshCacheTtl(){
      const ttl = Math.max(1000, pollIntervalForTab(currentTab) - 1000);
      overviewCache.ttlMs = ttl;
      statsCache.ttlMs = ttl;
    }

    function cacheFresh(cache){
      if(!cache || !cache.value){ return false; }
      return (Date.now() - Number(cache.fetchedAt || 0)) < Number(cache.ttlMs || 0);
    }

    async function getOverviewSnapshot(force = false){
      refreshCacheTtl();
      if(!force && cacheFresh(overviewCache)){ return overviewCache.value; }
      const snapshot = await fetchData("/api/dashboard/overview");
      if(!snapshot){ return null; }
      overviewCache = { value: snapshot, fetchedAt: Date.now(), ttlMs: overviewCache.ttlMs };
      return snapshot;
    }

    async function getStatsSnapshot(force = false){
      refreshCacheTtl();
      if(!force && cacheFresh(statsCache)){ return statsCache.value; }
      const stats = await fetchData("/stats");
      if(!stats){ return null; }
      statsCache = { value: stats, fetchedAt: Date.now(), ttlMs: statsCache.ttlMs };
      return stats;
    }

    function togglePerfMode() {
      perfMode = !perfMode;
      localStorage.setItem('orchesis-perf', perfMode);
      applyPollIntervals();
      document.getElementById('perf-toggle').style.opacity = perfMode ? '1' : '0.4';
      showToast(perfMode ? 'Performance mode ON' : 'Performance mode OFF');
    }

    function setStatus(status){
      const pulse = document.getElementById("hero-pulse");
      const label = document.getElementById("hero-label");
      const badge = document.getElementById("status-badge");
      if (pulse && label) {
        pulse.classList.remove("status-clear", "status-monitoring", "status-alert");
        if(status === "alert"){
          pulse.classList.add("status-alert");
          label.textContent = "ALERT";
        }else if(status === "monitoring"){
          pulse.classList.add("status-monitoring");
          label.textContent = "MONITORING";
        }else{
          pulse.classList.add("status-clear");
          label.textContent = "ALL CLEAR";
        }
      }
      if (badge) {
        badge.textContent = "Status: " + (status || "--");
      }
    }

    function renderCostChart(points){
      const svg = document.getElementById("cost-chart");
      const tooltip = document.getElementById("cost-tooltip");
      svg.innerHTML = "";
      if(!Array.isArray(points) || points.length < 2){
        tooltip.textContent = "Not enough points";
        return;
      }
      const w = 900, h = 220, pad = 30;
      const xs = points.map((p)=>Number(p.timestamp||0));
      const ys = points.map((p)=>Number(p.cumulative_cost||0));
      const minX = Math.min(...xs), maxX = Math.max(...xs);
      const minY = Math.min(...ys), maxY = Math.max(...ys, minY + 0.0001);
      const toX = (v)=> pad + ((v - minX) / Math.max(1e-6, (maxX - minX))) * (w - pad*2);
      const toY = (v)=> h - pad - ((v - minY) / Math.max(1e-6, (maxY - minY))) * (h - pad*2);
      const polyPoints = points.map((p)=> `${toX(Number(p.timestamp||0)).toFixed(1)},${toY(Number(p.cumulative_cost||0)).toFixed(1)}`).join(" ");
      const grid = document.createElementNS("http://www.w3.org/2000/svg", "path");
      grid.setAttribute("d", `M${pad},${h-pad} H${w-pad}`);
      grid.setAttribute("stroke", "rgba(255,255,255,0.15)");
      grid.setAttribute("fill", "none");
      svg.appendChild(grid);
      const line = document.createElementNS("http://www.w3.org/2000/svg", "polyline");
      line.setAttribute("points", polyPoints);
      line.setAttribute("fill", "none");
      line.setAttribute("stroke", "#00E5A0");
      line.setAttribute("stroke-width", "2.5");
      svg.appendChild(line);
      for(let i=0;i<points.length;i++){
        const cx = toX(Number(points[i].timestamp||0));
        const cy = toY(Number(points[i].cumulative_cost||0));
        const c = document.createElementNS("http://www.w3.org/2000/svg", "circle");
        c.setAttribute("cx", cx); c.setAttribute("cy", cy); c.setAttribute("r", 3.5);
        c.setAttribute("fill", "#00E5A0");
        c.addEventListener("mouseenter", ()=>{
          tooltip.textContent = `${fmtTs(points[i].timestamp)}  |  ${fmtMoney(points[i].cumulative_cost)}`;
        });
        svg.appendChild(c);
      }
    }

    function renderGauge(score){
      const svg = document.getElementById("health-gauge");
      const val = Math.max(0, Math.min(1, Number(score||0)));
      const angle = Math.PI * val;
      const x = 20 + 70 * (1 - Math.cos(angle));
      const y = 90 - 70 * Math.sin(angle);
      svg.innerHTML = `
        <path d="M20 90 A70 70 0 0 1 160 90" fill="none" stroke="rgba(255,255,255,0.12)" stroke-width="12"/>
        <path d="M20 90 A70 70 0 ${val > 0.5 ? 1 : 0} 1 ${x.toFixed(2)} ${y.toFixed(2)}" fill="none" stroke="${val < 0.4 ? '#FF3B5C' : (val < 0.7 ? '#FFB800' : '#00E5A0')}" stroke-width="12"/>
      `;
      document.getElementById("health-score").textContent = val.toFixed(2);
    }

    function renderRateLimits(payload){
      const model = (payload && typeof payload === "object") ? payload : {};
      const global = (model.global && typeof model.global === "object") ? model.global : {};
      const agents = (model.agents && typeof model.agents === "object") ? model.agents : {};
      const globalEl = document.getElementById("rl-global-rpm");
      const throttledEl = document.getElementById("rl-throttled");
      const resetEl = document.getElementById("rl-reset-at");
      const rowsEl = document.getElementById("rl-agent-rows");
      if(globalEl) globalEl.textContent = fmtNum(Number(global.requests_this_minute || 0));
      const entries = Object.entries(agents);
      const throttled = entries.filter(([, item])=> String((item && item.status) || "").toLowerCase() === "throttled").length;
      if(throttledEl) throttledEl.textContent = fmtNum(throttled);
      if(resetEl){
        const first = entries.length > 0 && entries[0][1] ? entries[0][1].reset_at : null;
        resetEl.textContent = first ? `Resets at ${fmtTs(first)}` : "Resets at --";
      }
      if(!rowsEl){ return; }
      if(entries.length === 0){
        rowsEl.innerHTML = `<div class="empty">No rate limit data.</div>`;
        return;
      }
      const sorted = entries.sort((a, b)=> Number((b[1] && b[1].percent_used) || 0) - Number((a[1] && a[1].percent_used) || 0));
      rowsEl.innerHTML = sorted.map(([agentId, item])=>{
        const used = Number((item && item.requests_this_minute) || 0);
        const limit = Math.max(1, Number((item && item.limit_per_minute) || 1));
        const percent = Math.max(0, Number((item && item.percent_used) || 0));
        const status = String((item && item.status) || "ok").toLowerCase();
        const width = Math.min(100, percent);
        const color = status === "throttled" ? "#ef4444" : (status === "warning" ? "#facc15" : "#34d399");
        return `<div class="rl-row">
          <div class="rl-row-head">
            <span>${agentId}</span>
            <span class="rl-status-${status}">${used}/${limit} (${percent.toFixed(1)}%)</span>
          </div>
          <div class="rl-bar"><div style="width:${width.toFixed(1)}%;background:${color};"></div></div>
        </div>`;
      }).join("");
    }

    function renderCommunityIntel(statusPayload, statsPayload){
      const status = (statusPayload && typeof statusPayload === "object") ? statusPayload : {};
      const stats = (statsPayload && typeof statsPayload === "object") ? statsPayload : {};
      const enabled = Boolean((typeof status.enabled === "boolean" ? status.enabled : stats.enabled));
      const toggle = document.getElementById("community-enabled-toggle");
      if(toggle){ toggle.checked = enabled; }
      const threatsEl = document.getElementById("community-threats-shared");
      if(threatsEl){ threatsEl.textContent = fmtNum(Number(stats.threats_submitted || 0)); }
      const updatesEl = document.getElementById("community-updates-received");
      if(updatesEl){ updatesEl.textContent = fmtNum(Number(stats.updates_pulled || 0)); }
      const syncEl = document.getElementById("community-last-sync");
      if(syncEl){
        const stamp = status.last_sync || stats.last_sync || "";
        syncEl.textContent = stamp ? `Last sync: ${fmtTs((new Date(stamp).getTime() / 1000))}` : "Last sync: --";
      }
    }

    async function toggleCommunityIntel(enabled){
      const endpoint = enabled ? "/api/v1/community/enable" : "/api/v1/community/disable";
      try{
        const response = await fetch(endpoint, { method: "POST", cache: "no-store" });
        if(!response.ok){ throw new Error("toggle failed"); }
        const [status, stats] = await Promise.all([
          fetchData("/api/v1/community/status"),
          fetchData("/api/v1/community/stats"),
        ]);
        renderCommunityIntel(status || {}, stats || {});
      }catch(_err){
        const toggle = document.getElementById("community-enabled-toggle");
        if(toggle){ toggle.checked = !enabled; }
        showToast("Community toggle failed");
      }
    }

    function renderOverview(data, stats, savings, tokenYield, contextBudget, rateLimits){
      if(!data){ return; }
      lastOverview = data;
      setStatus(data.status || "clear");
      const blocked = Number(data.blocked_requests || 0);
      const total = Math.max(1, Number(data.total_requests || 0));
      updateAnimatedMetric("m-requests", Number(data.total_requests || 0), (v)=>Math.round(v).toLocaleString());
      updateAnimatedMetric("m-blocked", blocked, (v)=>`${Math.round(v).toLocaleString()} (${((v/total)*100).toFixed(1)}%)`);
      updateAnimatedMetric("m-cost", Number(data.total_cost_usd || 0), (v)=>"$" + Number(v || 0).toFixed(2));
      const velocity = (data && data.cost_velocity) ? data.cost_velocity : {};
      updateAnimatedMetric("m-cost-velocity", Number(velocity.current_rate_per_hour || 0), (v)=>"$" + Number(v || 0).toFixed(2) + "/h");
      const projectionEl = document.getElementById("m-cost-projection");
      if (projectionEl) {
        projectionEl.textContent = fmtMoney(Number(velocity.projection_24h || 0));
      }
      updateSparkline("requests", Number(data.total_requests || 0));
      updateSparkline("blocked", blocked);
      updateSparkline("cost", Number(data.total_cost_usd || 0));
      updateSparkline("cost-velocity", Number(velocity.current_rate_per_hour || 0));
      const blockedHero = document.getElementById("blocked-count");
      if (blockedHero) {
        blockedHero.textContent = Math.round(blocked).toLocaleString();
      }
      const moneySavedHero = document.getElementById("money-saved");
      if (moneySavedHero) {
        moneySavedHero.textContent = fmtMoney(Number(data.money_saved_usd || 0));
      }
      const overwatchHero = document.getElementById("overwatch-health");
      if (overwatchHero) {
        const grade = String(data.overwatch_health || "A").toUpperCase();
        overwatchHero.textContent = grade;
        const colorMap = { A: "#22c55e", B: "#84cc16", C: "#facc15", D: "#f97316", F: "#ef4444" };
        overwatchHero.style.webkitTextFillColor = colorMap[grade] || "#22c55e";
      }

      const ti = (stats && stats.threat_intel) ? stats.threat_intel : {};
      const sc = (stats && stats.semantic_cache) ? stats.semantic_cache : {};
      const exp = (stats && stats.experiments) ? stats.experiments : {};
      const task = (stats && stats.task_tracking) ? stats.task_tracking : {};
      updateAnimatedMetric("m-threats", Number(ti.total_matches || 0), (v)=>Math.round(v).toLocaleString());
      const semanticRate = Number(sc.hit_rate_percent || 0);
      const cascadeRate = Number((stats && (stats.cache_hit_rate_percent ?? stats.cache_hit_rate)) || 0);
      updateAnimatedMetric("m-cache-rate", Math.max(semanticRate, cascadeRate), (v)=>Number(v || 0).toFixed(1) + "%");
      updateAnimatedMetric("m-experiments", Number(exp.active || 0), (v)=>Math.round(v).toLocaleString());
      const sr = Number(task.overall_success_rate || 0);
      updateAnimatedMetric("m-task-success", sr * 100, (v)=>Number(v || 0).toFixed(1) + "%");

      const eventsEl = document.getElementById("events");
      setStableHTML(eventsEl, "");
      const events = Array.isArray(data.recent_events) ? data.recent_events.slice(0, 10) : [];
      if(events.length === 0){
        setStableHTML(eventsEl, `<div class="empty">No recent events.</div>`);
      }else{
        const eventRows = [];
        events.forEach((ev)=>{
          const sev = String(ev.severity || "info").toLowerCase();
          const type = String(ev.type || "event").toUpperCase();
          eventRows.push(`<div class="event event-item"><span class="subtle">${fmtTs(ev.timestamp)}</span><span class="sev ${sev}">${type}</span><span>${ev.description || ""}</span></div>`);
        });
        setStableHTML(eventsEl, eventRows.join(""));
      }

      const cb = data.circuit_breakers || {};
      const cbEl = document.getElementById("cb-list");
      const names = Object.keys(cb);
      if(names.length === 0){
        setStableHTML(cbEl, `<div class="empty">No circuit breaker data.</div>`);
      }else{
        setStableHTML(cbEl, names.map((name)=>{
          const st = String(cb[name].state || "closed").toLowerCase();
          return `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);"><span>${name}</span><span class="cb-pill ${st}">${st}</span><span class="subtle">failures: ${fmtNum(cb[name].failures||0)}</span></div>`;
        }).join(""));
      }

      const pool = data.connection_pool || {};
      const poolEl = document.getElementById("pool-stats");
      const hits = Number(pool.hits || 0);
      const misses = Number(pool.misses || 0);
      const poolHitRatio = (hits + misses) > 0 ? (hits / (hits + misses) * 100.0) : 0.0;
      const hosts = pool.pools || {};
      const hostRows = Object.keys(hosts).map((k)=> `${k}: ${hosts[k]}`).join(" | ");
      setStableHTML(poolEl, `
        <div>active: ${fmtNum(pool.active || 0)}, total: ${fmtNum(pool.total_connections || 0)}</div>
        <div>hits/misses: ${fmtNum(hits)}/${fmtNum(misses)} (${poolHitRatio.toFixed(1)}% hit)</div>
        <div class="subtle">${hostRows || "no hosts"}</div>
      `);

      const budget = data.budget || {};
      const limit = Number(budget.limit_usd || 0);
      const spent = Number(budget.spent_usd || 0);
      const ratio = limit > 0 ? Math.min(100, (spent / limit) * 100) : 0;
      const bar = document.getElementById("budget-bar");
      bar.style.width = ratio.toFixed(2) + "%";
      bar.style.background = ratio > 90 ? "var(--danger)" : (ratio > 70 ? "var(--warn)" : "var(--ok)");
      document.getElementById("budget-label").textContent = limit > 0 ? `${fmtMoney(spent)} / ${fmtMoney(limit)} (${ratio.toFixed(1)}%)` : "No budget configured";

      renderCostChart(Array.isArray(data.cost_timeline) ? data.cost_timeline : []);
      renderSavings(stats || {});
      renderOpenClawSavings(savings || {});
      renderTokenYield(tokenYield || {});
      renderContextBudget(contextBudget || {});
      renderRateLimits(rateLimits || {});
    }

    function renderSessionHeatmap(payload){
      const gridEl = document.getElementById("session-heatmap-grid");
      const tooltipEl = document.getElementById("session-heatmap-tooltip");
      const peakEl = document.getElementById("session-heatmap-peak");
      const quietEl = document.getElementById("session-heatmap-quiet");
      const totalEl = document.getElementById("session-heatmap-total");
      if(!gridEl){ return; }
      const model = (payload && typeof payload === "object") ? payload : {};
      const cells = Array.isArray(model.cells) ? model.cells : [];
      if(cells.length === 0){
        gridEl.innerHTML = `<div class="empty" style="grid-column: 1 / -1;">No heatmap activity data.</div>`;
        if(peakEl){ peakEl.textContent = "Peak: --"; }
        if(quietEl){ quietEl.textContent = "Quiet: --"; }
        if(totalEl){ totalEl.textContent = "Total: 0"; }
        return;
      }

      const days = [];
      const grouped = {};
      cells.forEach((cell)=>{
        const day = String(cell.day || "");
        if(!grouped[day]){
          grouped[day] = {};
          days.push(day);
        }
        grouped[day][Number(cell.hour || 0)] = cell;
      });

      const nodes = [];
      nodes.push(`<div></div>`);
      for(let hour = 0; hour < 24; hour += 1){
        nodes.push(`<div class="heatmap-hour-label">${hour}</div>`);
      }

      days.forEach((day)=>{
        nodes.push(`<div class="heatmap-day-label">${escapeHtml(day)}</div>`);
        for(let hour = 0; hour < 24; hour += 1){
          const cell = grouped[day][hour] || { count: 0, cost: 0, blocked: 0, intensity: 0 };
          const intensity = Math.max(0, Math.min(1, Number(cell.intensity || 0)));
          const alpha = (0.08 + intensity * 0.78).toFixed(3);
          const blocked = Number(cell.blocked || 0);
          const style = blocked > 0
            ? `background: rgba(239, 68, 68, ${Math.max(0.25, intensity).toFixed(3)});`
            : `background: rgba(168, 85, 247, ${alpha});`;
          nodes.push(
            `<div class="heatmap-cell" data-day="${escapeHtml(day)}" data-hour="${hour}" data-count="${Number(cell.count || 0)}" data-cost="${Number(cell.cost || 0)}" data-blocked="${blocked}" style="${style}"></div>`
          );
        }
      });
      gridEl.innerHTML = nodes.join("");

      gridEl.querySelectorAll(".heatmap-cell").forEach((cell)=>{
        cell.addEventListener("mouseenter", ()=>{
          if(!tooltipEl){ return; }
          const day = String(cell.getAttribute("data-day") || "");
          const hour = Number(cell.getAttribute("data-hour") || 0);
          const count = Number(cell.getAttribute("data-count") || 0);
          const cost = Number(cell.getAttribute("data-cost") || 0);
          const blocked = Number(cell.getAttribute("data-blocked") || 0);
          tooltipEl.textContent = `${day} ${hour}:00 — requests ${fmtNum(count)}, cost ${fmtMoney(cost)}, blocked ${fmtNum(blocked)}`;
        });
      });

      const peak = (model.peak && typeof model.peak === "object") ? model.peak : {};
      const quiet = (model.quiet && typeof model.quiet === "object") ? model.quiet : {};
      if(peakEl){
        peakEl.textContent = `Peak: ${String(peak.day || "--")} ${Number(peak.hour || 0)}:00 (${fmtNum(Number(peak.count || 0))})`;
      }
      if(quietEl){
        quietEl.textContent = `Quiet: ${String(quiet.day || "--")} ${Number(quiet.hour || 0)}:00 (${fmtNum(Number(quiet.count || 0))})`;
      }
      if(totalEl){
        totalEl.textContent = `Total: ${fmtNum(Number(model.total_requests || 0))}`;
      }
    }

    function renderTokenYield(payload){
      const model = (payload && typeof payload === "object") ? payload : {};
      const yieldValue = Math.max(0, Math.min(1, Number(model.token_yield || 0)));
      const wasteValue = Math.max(0, Math.min(1, Number(model.waste_percent || (1 - yieldValue))));
      const collapse = Boolean(model.context_collapses && Number(model.context_collapses) > 0);
      const percentEl = document.getElementById("ty-percent");
      const warningEl = document.getElementById("ty-collapse");
      const wasteTextEl = document.getElementById("ty-waste-text");
      const wasteBarEl = document.getElementById("ty-waste-bar");
      const cacheEl = document.getElementById("ty-cache-savings");
      const tableEl = document.getElementById("ty-iterations");
      if (percentEl) {
        percentEl.textContent = `${(yieldValue * 100).toFixed(1)}%`;
        percentEl.style.color = yieldValue >= 0.6 ? "#34d399" : (yieldValue >= 0.4 ? "#facc15" : "#f97316");
      }
      if (warningEl) {
        warningEl.textContent = collapse ? "⚠ Context collapse detected" : "";
      }
      if (wasteTextEl) {
        wasteTextEl.textContent = `${(wasteValue * 100).toFixed(1)}%`;
      }
      if (wasteBarEl) {
        wasteBarEl.style.width = `${(wasteValue * 100).toFixed(1)}%`;
      }
      if (cacheEl) {
        cacheEl.textContent = fmtNum(Number(model.cache_savings || 0));
      }
      if (tableEl) {
        const top = Array.isArray(model.top_sessions) && model.top_sessions.length > 0 ? model.top_sessions[0] : {};
        const history = Array.isArray(top.history) ? top.history : [];
        if (history.length === 0) {
          tableEl.innerHTML = `<tr><td colspan="2" class="subtle">No data</td></tr>`;
        } else {
          tableEl.innerHTML = history.slice(-8).map((item, index)=>{
            const rowNumber = history.length - Math.min(8, history.length) + index + 1;
            return `<tr><td>#${rowNumber}</td><td>${fmtNum(Number(item || 0))}</td></tr>`;
          }).join("");
        }
      }
    }

    function renderContextBudget(payload){
      const model = (payload && typeof payload === "object") ? payload : {};
      const levelRaw = String(model.current_level || "normal").toLowerCase();
      const level = ["normal", "l0", "l1", "l2"].includes(levelRaw) ? levelRaw : "normal";
      const levelEl = document.getElementById("cbg-level");
      const l0El = document.getElementById("cbg-l0");
      const l1El = document.getElementById("cbg-l1");
      const l2El = document.getElementById("cbg-l2");
      const usedMaxEl = document.getElementById("cbg-used-max");
      const barEl = document.getElementById("cbg-used-bar");
      const pressureEl = document.getElementById("cbg-pressure");
      const events = (model.degradation_events && typeof model.degradation_events === "object") ? model.degradation_events : {};
      const saved = Math.max(0, Number(model.tokens_saved_by_degradation || 0));
      const maxTokens = Math.max(1, Number(model.context_window || 128000));
      const used = Math.max(0, Math.min(maxTokens, maxTokens - saved));
      const pressurePct = Math.max(0, Math.min(100, (used / maxTokens) * 100));
      if (levelEl) {
        levelEl.textContent = level === "normal" ? "normal" : level.toUpperCase();
        levelEl.className = `cbg-pill ${level}`;
      }
      if (l0El) l0El.textContent = fmtNum(Number(events.L0 || 0));
      if (l1El) l1El.textContent = fmtNum(Number(events.L1 || 0));
      if (l2El) l2El.textContent = fmtNum(Number(events.L2 || 0));
      if (usedMaxEl) usedMaxEl.textContent = `${fmtNum(used)} / ${fmtNum(maxTokens)}`;
      if (barEl) {
        barEl.style.width = `${pressurePct.toFixed(1)}%`;
        barEl.style.background = pressurePct >= 98 ? "#ef4444" : (pressurePct >= 90 ? "#fb923c" : (pressurePct >= 80 ? "#facc15" : "#34d399"));
      }
      if (pressureEl) {
        pressureEl.textContent = `Context window pressure: ${pressurePct.toFixed(1)}% (${String(model.model || "gpt-4o-mini")})`;
      }
    }

    function renderAgentHealth(payload){
      const health = (payload && typeof payload === "object") ? payload : {};
      const score = Math.max(0, Math.min(100, Number(health.score || 0)));
      const grade = String(health.grade || "D").toUpperCase();
      const trend = String(health.trend || "stable").toLowerCase();
      const breakdown = (health.breakdown && typeof health.breakdown === "object") ? health.breakdown : {};
      const scoreEl = document.getElementById("ah-score");
      const gradeEl = document.getElementById("ah-grade");
      const trendEl = document.getElementById("ah-trend");
      if (scoreEl) {
        scoreEl.textContent = score.toFixed(0);
        scoreEl.style.color = score >= 85 ? "#34d399" : (score >= 70 ? "#facc15" : "#f97316");
      }
      if (gradeEl) {
        gradeEl.textContent = grade;
      }
      if (trendEl) {
        const trendMap = {
          improving: "↑ improving",
          stable: "→ stable",
          degrading: "↓ degrading",
        };
        trendEl.textContent = trendMap[trend] || "→ stable";
      }
      const keys = [
        ["security", "ah-security", "ah-bar-security"],
        ["cost_efficiency", "ah-cost-efficiency", "ah-bar-cost-efficiency"],
        ["context_quality", "ah-context-quality", "ah-bar-context-quality"],
        ["reliability", "ah-reliability", "ah-bar-reliability"],
      ];
      keys.forEach(([key, textId, barId])=>{
        const value = Math.max(0, Math.min(100, Number(breakdown[key] || 0)));
        const textEl = document.getElementById(textId);
        const barEl = document.getElementById(barId);
        if (textEl) textEl.textContent = value.toFixed(0);
        if (barEl) {
          barEl.style.width = `${value.toFixed(1)}%`;
          barEl.style.background = value >= 85 ? "#34d399" : (value >= 70 ? "#facc15" : "#f97316");
        }
      });
    }

    function renderSavings(stats) {
      const items = [
        { label: "Semantic Cache", key: "semantic_cache", field: "total_cost_saved_usd" },
        { label: "Cascade Routing", key: "cascade", field: "cost_saved_usd" },
        { label: "Context Trim", key: "context_engine", field: "total_tokens_saved", isTok: true },
        { label: "Loop Prevention", key: "loop_detection", field: "total_cost_saved_usd" },
      ];
      let total = 0;
      const values = items.map((item) => {
        const section = (stats && stats[item.key]) ? stats[item.key] : {};
        let val = Number(section[item.field] || 0);
        if (item.key === "cascade" && !val) {
          val = Number(stats.cascade_savings_today_usd || 0);
        }
        if (item.key === "loop_detection" && !val) {
          const loopStats = stats.loop_stats || stats.loop_detector || {};
          val = Number(loopStats.total_cost_saved_usd || 0);
        }
        if (item.isTok) val = val * 0.000003;
        total += val;
        return { ...item, value: val };
      });
      const box = document.getElementById("savings-breakdown");
      if (!box) return;
      box.innerHTML = values.map((v) => {
        const pct = total > 0 ? (v.value / total * 100) : 0;
        return `<div class="savings-item">
          <div class="label">${v.label}</div>
          <div class="amount">$${v.value.toFixed(2)}</div>
          <div class="savings-bar"><div class="savings-bar-fill" style="width:${pct.toFixed(1)}%"></div></div>
        </div>`;
      }).join("");
      updateAnimatedMetric("total-savings", total, (v)=>"$" + Number(v || 0).toFixed(2), 800);
    }

    function renderOpenClawSavings(savings) {
      const data = (savings && typeof savings === "object") ? savings : {};
      const cache = Number(data.cache_savings || 0);
      const cascade = Number(data.cascade_savings || 0);
      const loops = Number(data.loop_savings || 0);
      const total = Number(data.total_savings || (cache + cascade + loops));
      updateAnimatedMetric("savings-total", total, (v)=>"$" + Number(v || 0).toFixed(2), 700);
      const cacheEl = document.getElementById("savings-cache");
      const cascadeEl = document.getElementById("savings-cascade");
      const loopsEl = document.getElementById("savings-loops");
      if (cacheEl) cacheEl.textContent = "$" + cache.toFixed(2);
      if (cascadeEl) cascadeEl.textContent = "$" + cascade.toFixed(2);
      if (loopsEl) loopsEl.textContent = "$" + loops.toFixed(2);
    }

    function renderAgents(data){
      const table = document.querySelector("#agents-table tbody");
      const empty = document.getElementById("agents-empty");
      const profileSelect = document.getElementById("agent-profile-select");
      table.innerHTML = "";
      const agents = (data && Array.isArray(data.agents)) ? data.agents : [];
      if(agents.length === 0){
        empty.style.display = "block";
        document.getElementById("agents-table").style.display = "none";
        if(profileSelect){ profileSelect.innerHTML = ""; }
        renderAgentProfile(null);
        return;
      }
      empty.style.display = "none";
      document.getElementById("agents-table").style.display = "table";
      if(profileSelect){
        profileSelect.innerHTML = agents.map((a)=>{
          const aid = String(a.agent_id || a.id || "unknown");
          return `<option value="${aid}">${aid}</option>`;
        }).join("");
        if(selectedAgentProfileId && agents.some((a)=>String(a.agent_id || a.id || "") === selectedAgentProfileId)){
          profileSelect.value = selectedAgentProfileId;
        } else {
          selectedAgentProfileId = String(agents[0].agent_id || agents[0].id || "unknown");
          profileSelect.value = selectedAgentProfileId;
        }
      }
      agents.forEach((a)=>{
        const score = Number(a.ars_score ?? a.anomaly_score ?? 0);
        const status = String(a.status || a.state || "active");
        const reqs = Number(a.total_requests || a.requests_today || 0);
        const cost = Number(a.total_cost_usd || a.cost_day_usd || 0);
        const grade = String(a.ars_grade || "").toUpperCase();
        const aid = String(a.agent_id || a.id || "unknown");
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${aid}</strong></td>
          <td>${status}</td>
          <td>${fmtNum(reqs)}</td>
          <td>${fmtMoney(cost)}</td>
          <td>${grade ? `${grade} (${score.toFixed(1)})` : score.toFixed(3)}</td>
        `;
        tr.addEventListener("click", ()=>{
          selectedAgentProfileId = aid;
          const sel = document.getElementById("agent-profile-select");
          if(sel){ sel.value = aid; }
          loadAgentProfile(aid);
        });
        table.appendChild(tr);
      });
      if(selectedAgentProfileId){
        loadAgentProfile(selectedAgentProfileId);
      }
    }
    function drawProfileSparkline(values){
      const svg = document.getElementById("ap-reliability-spark");
      if(!svg || !Array.isArray(values) || values.length === 0){ return; }
      const data = values.map((v)=>Number(v || 0));
      const min = Math.min(...data);
      const max = Math.max(...data, min + 0.0001);
      const range = max - min || 1;
      const w = 120, h = 24;
      const points = data.map((v, i)=>{
        const x = (i / Math.max(1, data.length - 1)) * w;
        const y = h - ((v - min) / range) * (h - 2) - 1;
        return `${x.toFixed(1)},${y.toFixed(1)}`;
      }).join(" ");
      svg.innerHTML = `<polyline points="${points}" />`;
    }
    function renderAgentProfile(profile){
      const empty = document.getElementById("agent-profile-empty");
      const body = document.getElementById("agent-profile-body");
      if(!profile || typeof profile !== "object"){
        if(empty){ empty.style.display = "block"; }
        if(body){ body.style.display = "none"; }
        return;
      }
      if(empty){ empty.style.display = "none"; }
      if(body){ body.style.display = "block"; }
      const baseline = (profile.baseline_metrics && typeof profile.baseline_metrics === "object") ? profile.baseline_metrics : {};
      document.getElementById("ap-age").textContent = `${Number(profile.profile_age_hours || 0).toFixed(1)}h`;
      document.getElementById("ap-cold").style.display = profile.cold_start ? "" : "none";
      document.getElementById("ap-avg-prompt").textContent = fmtNum(Math.round(Number(baseline.avg_prompt_length || 0)));
      document.getElementById("ap-tool-freq").textContent = Number(baseline.tool_call_frequency || 0).toFixed(2);
      document.getElementById("ap-cache-hit").textContent = `${(Number(baseline.cache_hit_rate || 0) * 100).toFixed(1)}%`;
      document.getElementById("ap-error-rate").textContent = `${(Number(baseline.error_rate || 0) * 100).toFixed(1)}%`;
      const patterns = Array.isArray(profile.detected_patterns) ? profile.detected_patterns : [];
      document.getElementById("ap-patterns").innerHTML = patterns.map((p)=> `<span class="profile-tag">${p}</span>`).join(" ");
      const optimizations = Array.isArray(profile.cost_optimizations) ? profile.cost_optimizations : [];
      document.getElementById("ap-optimizations").innerHTML = optimizations.map((o)=> `<li>${o}</li>`).join("");
      const alerts = Array.isArray(profile.anomaly_alerts) ? profile.anomaly_alerts : [];
      document.getElementById("ap-alerts").innerHTML = alerts.slice(-5).map((a)=>{
        return `<div class="profile-alert"><strong>${String(a.severity || "low").toUpperCase()}</strong> · ${String(a.reason || "n/a")}<div class="profile-kv">${String(a.timestamp || "")}</div></div>`;
      }).join("");
      drawProfileSparkline(Array.isArray(profile.reliability_history) ? profile.reliability_history : []);
    }
    async function loadAgentProfile(agentId){
      if(!agentId){ renderAgentProfile(null); return; }
      const profile = await fetchData(`/api/v1/agents/${encodeURIComponent(agentId)}/profile`);
      renderAgentProfile(profile);
    }

    function renderSessions(data){
      const table = document.querySelector("#sessions-table tbody");
      const empty = document.getElementById("sessions-empty");
      table.innerHTML = "";
      const sessions = (data && Array.isArray(data.sessions)) ? data.sessions : [];
      if(sessions.length === 0){
        empty.style.display = "block";
        document.getElementById("sessions-table").style.display = "none";
        return;
      }
      empty.style.display = "none";
      document.getElementById("sessions-table").style.display = "table";
      sessions.forEach((s)=>{
        const sid = String(s.session_id || "");
        const durationSec = Math.max(0, Number(s.duration_seconds || ((Number(s.end_time || 0) - Number(s.start_time || 0)))));
        const reqCount = Number(s.request_count || s.requests || 0);
        const agentId = String(s.agent_id || s.agent || s.user || "unknown");
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${sid.slice(0,12)}</strong></td>
          <td>${agentId}</td>
          <td>${fmtNum(reqCount)}</td>
          <td>${fmtDuration(durationSec)}</td>
          <td>${fmtMoney(s.total_cost || s.cost_usd || 0)}</td>
        `;
        table.appendChild(tr);
      });
    }

    let flowViewMode = "list";
    let flowTimelinePayload = null;
    let requestInspectorItems = [];
    let requestInspectorActiveId = "";

    function renderRequestInspectorList() {
      const root = document.getElementById("request-inspector-list");
      if(!root){ return; }
      const searchEl = document.getElementById("request-inspector-search");
      const q = String((searchEl && searchEl.value) || "").trim().toLowerCase();
      const rows = requestInspectorItems.filter((item)=>{
        const rid = String(item.request_id || "").toLowerCase();
        const aid = String(item.agent_id || "").toLowerCase();
        const tool = String(item.tool || "").toLowerCase();
        if(!q){ return true; }
        return rid.includes(q) || aid.includes(q) || tool.includes(q);
      });
      if(rows.length === 0){
        root.innerHTML = `<div class="empty">No requests found.</div>`;
        return;
      }
      root.innerHTML = rows.map((item)=>{
        const rid = String(item.request_id || "");
        const active = rid === requestInspectorActiveId;
        const decision = String(item.final_decision || "ALLOW").toUpperCase();
        const sevClass = decision === "DENY" ? "high" : "low";
        return `<button class="tab-btn ${active ? "active" : ""}" data-request-inspect="${rid}" style="text-align:left;">
          <div><strong>${rid.slice(0, 12)}</strong> <span class="sev ${sevClass}" style="margin-left:6px;">${decision}</span></div>
          <div class="subtle">${String(item.tool || "-")} · ${String(item.agent_id || "-")}</div>
        </button>`;
      }).join("");
      root.querySelectorAll("[data-request-inspect]").forEach((btn)=>{
        btn.addEventListener("click", ()=> {
          const rid = String(btn.getAttribute("data-request-inspect") || "");
          if(rid){ loadRequestInspection(rid); }
        });
      });
    }

    function renderRequestInspection(inspection){
      const meta = document.getElementById("request-inspector-meta");
      const pipeline = document.getElementById("request-inspector-pipeline");
      if(!meta || !pipeline){ return; }
      if(!inspection || typeof inspection !== "object"){
        meta.textContent = "Select a request to inspect all 17 phases.";
        pipeline.innerHTML = "";
        return;
      }
      const blocking = (inspection.blocking_phase && typeof inspection.blocking_phase === "object") ? inspection.blocking_phase : null;
      const phases = Array.isArray(inspection.phases) ? inspection.phases : [];
      const colors = { pass: "#00E5A0", warn: "#fbbf24", block: "#ef4444", skip: "#6b7280" };
      const finalDecision = String(inspection.final_decision || "ALLOW").toUpperCase();
      meta.innerHTML = `Request <strong>${String(inspection.request_id || "").slice(0, 16)}</strong> · ${String(inspection.tool || "-")} · ${String(inspection.agent_id || "-")} · <span class="sev ${finalDecision === "DENY" ? "high" : "low"}">${finalDecision}</span>`;
      pipeline.innerHTML = phases.map((phase)=>{
        const result = String(phase.result || "skip");
        const phaseName = String(phase.phase_name || "");
        const number = Number(phase.phase_number || 0);
        const duration = Number(phase.duration_us || 0);
        const isBlocking = blocking && String(blocking.phase_name || "") === phaseName;
        const border = isBlocking ? "2px solid #ef4444" : "1px solid var(--border)";
        return `<div style="border:${border};border-radius:8px;padding:6px;background:color-mix(in srgb, ${colors[result] || "#6b7280"} 18%, var(--surface));">
          <div class="subtle">#${number}</div>
          <div style="font-weight:700;font-size:12px;">${phaseName}</div>
          <div class="subtle">${result.toUpperCase()} · ${duration}us</div>
        </div>`;
      }).join("");
    }

    async function loadRequestInspection(requestId){
      if(!requestId){ return; }
      requestInspectorActiveId = requestId;
      renderRequestInspectorList();
      const inspection = await fetchData(`/api/v1/requests/${encodeURIComponent(requestId)}/inspect`);
      renderRequestInspection(inspection);
    }

    function renderFlowTimeline(payload) {
      const svg = document.getElementById("flow-timeline-svg");
      const details = document.getElementById("flow-timeline-details");
      if(!svg){ return; }
      const requests = (payload && Array.isArray(payload.requests)) ? payload.requests : [];
      const phases = (payload && Array.isArray(payload.phase_order)) ? payload.phase_order : [];
      if(requests.length === 0 || phases.length === 0){
        svg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="var(--text-secondary)">No timeline data</text>`;
        if(details){ details.textContent = "No timeline data available for selected session."; }
        return;
      }
      const cell = 14;
      const gap = 3;
      const leftPad = 160;
      const topPad = 16;
      const width = leftPad + (requests.length * (cell + gap)) + 30;
      const height = topPad + (phases.length * (cell + gap)) + 40;
      svg.setAttribute("viewBox", `0 0 ${width} ${height}`);
      svg.setAttribute("height", String(Math.max(280, height)));
      let html = "";
      phases.forEach((phase, i) => {
        const y = topPad + i * (cell + gap) + 11;
        html += `<text x="8" y="${y}" fill="var(--text-secondary)" font-size="10">${i+1}. ${phase}</text>`;
      });
      requests.forEach((req, xIndex) => {
        const x = leftPad + xIndex * (cell + gap);
        html += `<text x="${x + 2}" y="${height - 10}" fill="var(--text-secondary)" font-size="9">${xIndex + 1}</text>`;
        const phaseCells = Array.isArray(req.phases) ? req.phases : [];
        phaseCells.forEach((phaseCell, yIndex) => {
          const y = topPad + yIndex * (cell + gap);
          const fill = String(phaseCell.color || "#00FF41");
          const phaseName = String(phaseCell.phase || "");
          const decision = String(phaseCell.decision || "");
          const timestamp = String(req.timestamp || "");
          const tool = String(req.tool_name || "");
          const reasons = Array.isArray(phaseCell.reasons) ? phaseCell.reasons.join("; ") : "";
          const tip = `#${xIndex + 1} ${phaseName} ${decision.toUpperCase()} ${tool} ${timestamp} ${reasons}`;
          html += `<rect class="flow-node flow-timeline-cell" data-tip="${escapeHtml(tip)}" x="${x}" y="${y}" width="${cell}" height="${cell}" rx="2" fill="${fill}" stroke="rgba(255,255,255,0.12)" stroke-width="1"></rect>`;
        });
      });
      svg.innerHTML = html;
      svg.querySelectorAll(".flow-timeline-cell").forEach((el)=>{
        el.addEventListener("click", ()=>{
          if(details){ details.textContent = el.getAttribute("data-tip") || ""; }
        });
      });
    }

    function renderFlowAnalysis(analysis, graph, timeline){
      if(!analysis){
        document.getElementById("patterns").innerHTML = "";
        document.getElementById("patterns-empty").style.display = "block";
        document.getElementById("patterns-empty").textContent = "Select a session above";
        renderFlowGraph(null);
        const listView = document.getElementById("flow-list-view");
        if(listView){ listView.innerHTML = ""; }
        renderFlowTimeline(null);
        return;
      }
      const topo = analysis.topology || {};
      document.getElementById("f-depth").textContent = fmtNum(topo.depth);
      document.getElementById("f-width").textContent = fmtNum(topo.width);
      document.getElementById("f-density").textContent = Number(topo.density || 0).toFixed(3);
      document.getElementById("f-cost").textContent = fmtMoney(topo.total_cost_usd || 0);
      renderGauge((analysis.summary && analysis.summary.health_score) || 0);
      document.getElementById("critical-path").textContent = (topo.critical_path || []).join(" → ") || "n/a";

      const patterns = Array.isArray(analysis.patterns) ? analysis.patterns : [];
      const box = document.getElementById("patterns");
      box.innerHTML = "";
      const phaseKeys = [
        "parse","experiment","flow_xray","cascade","circuit_breaker","loop_detection","behavioral",
        "mast_request","auto_healing","budget","policy","threat_intel","model_router","secrets",
        "context","upstream","post_upstream","send",
      ];
      const blocked = Number((analysis.summary && analysis.summary.blocked_count) || 0);
      const warned = Number((analysis.summary && analysis.summary.warning_count) || 0);
      const phaseState = blocked > 0 ? "block" : (warned > 0 ? "warn" : "pass");
      const phaseStateClass = phaseState === "block" ? "high" : (phaseState === "warn" ? "medium" : "low");
      const phaseRows = phaseKeys.map((p)=> `<div class="event event-item"><span class="sev ${phaseStateClass}">${phaseState.toUpperCase()}</span><span>${p}</span></div>`).join("");
      const listView = document.getElementById("flow-list-view");
      if(listView){
        listView.innerHTML = `<div class="panel" style="margin-bottom:10px;"><strong>Pipeline Phases</strong><div style="margin-top:8px;">${phaseRows}</div></div>`;
      }
      flowTimelinePayload = timeline || null;
      renderFlowTimeline(flowTimelinePayload);
      if(patterns.length === 0){
        document.getElementById("patterns-empty").style.display = "block";
        document.getElementById("patterns-empty").textContent = "No data yet";
      }else{
        document.getElementById("patterns-empty").style.display = "none";
        patterns.forEach((p)=>{
          const sev = String(p.severity || "info").toLowerCase();
          const conf = Math.max(0, Math.min(100, Number(p.confidence || 0)*100));
          const color = sev === "critical" || sev === "high" ? "var(--danger)" : (sev === "medium" ? "var(--warn)" : "var(--info)");
          const card = document.createElement("div");
          card.className = "pattern-card";
          card.innerHTML = `
            <div style="display:flex;justify-content:space-between;gap:8px;align-items:center;">
              <strong>${p.pattern_type}</strong><span class="sev ${sev}">${sev}</span>
            </div>
            <div class="subtle" style="margin:6px 0;">${p.description || ""}</div>
            <div class="confidence"><div style="width:${conf.toFixed(1)}%;background:${color};"></div></div>
            <div class="subtle" style="margin-top:6px;">Suggestion: ${p.suggestion || ""}</div>
          `;
          box.appendChild(card);
        });
      }

      renderFlowGraph(graph);
    }

    function renderFlowGraph(graph) {
      const svg = document.getElementById("flow-graph-svg");
      if (!svg) return;
      const nodes = (graph && Array.isArray(graph.nodes)) ? graph.nodes.slice(0, 50) : [];
      const edges = (graph && Array.isArray(graph.edges)) ? graph.edges : [];
      if (nodes.length === 0) {
        svg.innerHTML = `<text x="50%" y="50%" text-anchor="middle" fill="var(--text-secondary)">No flow data</text>`;
        return;
      }
      const layerMap = {};
      const COL_W = 120, ROW_H = 70, PAD_X = 60, PAD_Y = 40;
      const childrenOf = {};
      edges.forEach((e) => {
        if (!childrenOf[e.source]) childrenOf[e.source] = [];
        childrenOf[e.source].push(e.target);
      });
      const visited = new Set();
      const queue = [];
      const hasIncoming = new Set(edges.map((e) => e.target));
      const roots = nodes.filter((n) => !hasIncoming.has(n.node_id));
      if (roots.length === 0 && nodes.length > 0) roots.push(nodes[0]);
      roots.forEach((r, ri) => {
        layerMap[r.node_id] = { x: PAD_X + ri * COL_W, y: PAD_Y, layer: 0 };
        queue.push(r.node_id);
        visited.add(r.node_id);
      });
      while (queue.length > 0) {
        const current = queue.shift();
        const pos = layerMap[current];
        const children = childrenOf[current] || [];
        children.forEach((childId, ci) => {
          if (visited.has(childId)) return;
          visited.add(childId);
          const spread = children.length > 1 ? (ci - (children.length - 1) / 2) * COL_W : 0;
          layerMap[childId] = { x: pos.x + spread, y: pos.y + ROW_H, layer: (pos.layer || 0) + 1 };
          queue.push(childId);
        });
      }
      let extraY = PAD_Y;
      nodes.forEach((n) => {
        if (!layerMap[n.node_id]) {
          layerMap[n.node_id] = { x: PAD_X + 400, y: extraY, layer: 0 };
          extraY += ROW_H;
        }
      });
      const allX = Object.values(layerMap).map((p) => p.x);
      const allY = Object.values(layerMap).map((p) => p.y);
      const maxX = Math.max(...allX) + COL_W;
      const maxY = Math.max(...allY) + ROW_H;
      svg.setAttribute("viewBox", `0 0 ${maxX} ${maxY}`);
      svg.setAttribute("height", String(Math.min(500, maxY)));
      let html = "";
      edges.forEach((e) => {
        const src = layerMap[e.source];
        const tgt = layerMap[e.target];
        if (!src || !tgt) return;
        const midY = (src.y + tgt.y) / 2;
        html += `<path class="flow-edge" d="M${src.x},${src.y + 16} C${src.x},${midY} ${tgt.x},${midY} ${tgt.x},${tgt.y - 16}"/>`;
      });
      nodes.forEach((n) => {
        const pos = layerMap[n.node_id];
        if (!pos) return;
        const type = String(n.node_type || "").toLowerCase();
        const isLLM = type.includes("llm");
        const isTool = type.includes("tool");
        const isError = type.includes("error");
        const cost = Number(n.cost_usd || 0);
        let fill = "rgba(90,168,255,0.3)";
        let stroke = "rgba(90,168,255,0.6)";
        if (isLLM) { fill = "rgba(0,229,160,0.2)"; stroke = "var(--ok)"; }
        if (isTool) { fill = "rgba(255,184,0,0.2)"; stroke = "var(--warn)"; }
        if (isError) { fill = "rgba(255,59,92,0.2)"; stroke = "var(--danger)"; }
        if (isLLM) {
          html += `<circle class="flow-node" cx="${pos.x}" cy="${pos.y}" r="14" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>`;
        } else if (isError) {
          html += `<polygon class="flow-node" points="${pos.x},${pos.y-14} ${pos.x+14},${pos.y} ${pos.x},${pos.y+14} ${pos.x-14},${pos.y}" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>`;
        } else {
          html += `<rect class="flow-node" x="${pos.x-12}" y="${pos.y-12}" width="24" height="24" rx="4" fill="${fill}" stroke="${stroke}" stroke-width="1.5"/>`;
        }
        const label = String(n.tool_name || n.model || type).substring(0, 15);
        html += `<text class="flow-label" x="${pos.x}" y="${pos.y + 26}">${label}</text>`;
        if (cost > 0) {
          html += `<text class="flow-cost-label" x="${pos.x}" y="${pos.y + 36}">$${cost.toFixed(3)}</text>`;
        }
      });
      svg.innerHTML = html;
    }

    function renderBenchmark(casesPayload, resultsPayload){
      const scoreEl = document.getElementById("exp-benchmark-score");
      const body = document.querySelector("#exp-benchmark-table tbody");
      if(!body){ return; }
      const cases = (casesPayload && Array.isArray(casesPayload.cases)) ? casesPayload.cases : [];
      const report = (resultsPayload && resultsPayload.results && typeof resultsPayload.results === "object")
        ? resultsPayload.results
        : null;
      const comparison = report && report.comparison && typeof report.comparison === "object" ? report.comparison : null;
      const byId = {};
      const rows = report && Array.isArray(report.results) ? report.results : [];
      rows.forEach((item)=>{
        if(item && item.case_id){ byId[String(item.case_id)] = item; }
      });
      if(scoreEl){
        if(comparison){
          scoreEl.textContent = `Overall score vs baseline: ${Number(comparison.score || 0).toFixed(1)} · percentile ${Number(comparison.percentile || 0).toFixed(1)}`;
        }else{
          scoreEl.textContent = "Overall score vs baseline: --";
        }
      }
      if(cases.length === 0){
        body.innerHTML = `<tr><td colspan="4" class="subtle">No benchmark cases available.</td></tr>`;
        return;
      }
      body.innerHTML = cases.map((c)=>{
        const r = byId[String(c.id)] || null;
        const status = r ? (r.passed ? "PASS" : "FAIL") : "--";
        const cls = status === "PASS" ? "low" : (status === "FAIL" ? "high" : "info");
        return `<tr><td>${c.id}</td><td>${c.category}</td><td>${c.expected_action}</td><td><span class="sev ${cls}">${status}</span></td></tr>`;
      }).join("");
    }

    async function runBenchmarkSuite(){
      await fetch("/api/v1/benchmark/run-all", { method: "POST" });
      await pollExperiments();
    }

    function exportBenchmarkResults(resultsPayload){
      const report = (resultsPayload && resultsPayload.results && typeof resultsPayload.results === "object")
        ? resultsPayload.results
        : null;
      if(!report){ return; }
      const blob = new Blob([JSON.stringify(report, null, 2)], { type: "application/json" });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "benchmark_results.json";
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    }

    function renderExperiments(experiments, outcomes, correlations, stats, benchmarkCases, benchmarkResults){
      const exp = (stats && stats.experiments) ? stats.experiments : {};
      const task = (stats && stats.task_tracking) ? stats.task_tracking : {};
      document.getElementById("exp-active").textContent = fmtNum(exp.active || 0);
      document.getElementById("exp-assignments").textContent = fmtNum(exp.total_assignments || 0);
      const sr = Number(task.overall_success_rate || 0);
      document.getElementById("exp-success-rate").textContent = (sr * 100).toFixed(1) + "%";
      document.getElementById("exp-sessions").textContent = fmtNum(task.tracked_sessions || 0);

      const cards = document.getElementById("exp-cards");
      cards.innerHTML = "";
      const exps = (experiments && Array.isArray(experiments.experiments)) ? experiments.experiments : [];
      const running = exps.filter((e)=> String(e.status || "").toLowerCase() === "running" || !e.status);
      if(running.length === 0){
        cards.innerHTML = `<div class="panel empty">No experiments running.</div>`;
      }else{
        const rows = running.map((exp)=>{
          const reqs = Number(exp.total_requests || exp.requests || 0);
          const pValue = Number(exp.p_value || exp.pvalue || 0);
          return `<tr>
            <td>${exp.name || exp.experiment_id || "Experiment"}</td>
            <td>${exp.variant || exp.assigned_variant || "-"}</td>
            <td>${fmtNum(reqs)}</td>
            <td>${pValue ? pValue.toFixed(4) : "-"}</td>
          </tr>`;
        }).join("");
        cards.innerHTML = `<div class="panel"><table class="table"><thead><tr><th>Experiment</th><th>Variant</th><th>Requests</th><th>P-value</th></tr></thead><tbody>${rows}</tbody></table></div>`;
      }

      const corrEl = document.getElementById("exp-correlations");
      const insights = (correlations && Array.isArray(correlations.insights)) ? correlations.insights : [];
      if(insights.length === 0){
        corrEl.innerHTML = `<div class="empty">No correlations yet.</div>`;
      }else{
        corrEl.innerHTML = insights.slice(0, 10).map((s)=> `<div class="event event-item"><span class="sev info">INSIGHT</span><span>${s}</span></div>`).join("");
      }

      const outEl = document.getElementById("exp-outcomes");
      const barEl = document.getElementById("exp-outcome-bar");
      const out = (task && task.outcomes) ? task.outcomes : {};
      const total = Object.values(out).reduce((a,b)=> a + Number(b||0), 0);
      const order = ["success","failure","loop","abandoned","timeout","escalated"];
      const cls = { success: "outcome-success", failure: "outcome-failure", loop: "outcome-loop", abandoned: "outcome-abandoned", timeout: "outcome-timeout", escalated: "outcome-escalated" };
      if(total === 0){
        barEl.innerHTML = "";
        outEl.innerHTML = `<div class="empty">No outcome data.</div>`;
      }else{
        barEl.innerHTML = order.map((k)=>{
          const v = Number(out[k] || 0);
          const pct = (v / total * 100).toFixed(1);
          return `<div class="${cls[k] || "outcome-abandoned"}" style="width:${pct}%"></div>`;
        }).join("");
        outEl.innerHTML = order.map((k)=>{
          const v = Number(out[k] || 0);
          const pct = (v / total * 100).toFixed(1);
          return `<div class="panel"><div class="subtle">${k}</div><div class="metric-value">${fmtNum(v)} (${pct}%)</div></div>`;
        }).join("");
      }
      renderBenchmark(benchmarkCases, benchmarkResults);
      const runBtn = document.getElementById("exp-benchmark-run");
      const exportBtn = document.getElementById("exp-benchmark-export");
      if(runBtn){
        runBtn.onclick = ()=> runBenchmarkSuite();
      }
      if(exportBtn){
        exportBtn.onclick = ()=> exportBenchmarkResults(benchmarkResults);
      }
    }

    function renderThreats(threats, stats){
      const s = (stats && stats.enabled) ? stats : {};
      document.getElementById("th-sigs").textContent = fmtNum(s.total_signatures || 0);
      document.getElementById("th-scans").textContent = fmtNum(s.total_scans || 0);
      document.getElementById("th-matches").textContent = fmtNum(s.total_matches || 0);
      document.getElementById("th-blocks").textContent = fmtNum(s.blocks || 0);

      const topEl = document.getElementById("th-top");
      const top = Array.isArray(s.top_threats) ? s.top_threats : [];
      if(top.length === 0){
        topEl.innerHTML = `<div class="empty">Not configured or no matches.</div>`;
      }else{
        const maxC = Math.max(...top.map((t)=> Number(t[1]||0)), 1);
        topEl.innerHTML = top.map((t)=>{
          const pct = (Number(t[1]||0) / maxC * 100).toFixed(0);
          return `<div class="h-bar"><div class="h-bar-fill" style="width:${pct}%;min-width:40px;"></div><span>${t[0] || ""} (${t[1]})</span></div>`;
        }).join("");
      }

      const byCat = (s.matches_by_category && typeof s.matches_by_category === "object") ? s.matches_by_category : {};
      document.getElementById("th-by-cat").innerHTML = Object.entries(byCat).map(([k,v])=> `<div class="h-bar"><div class="h-bar-fill" style="width:${Math.min(100, Number(v)*10)}%;min-width:30px;"></div><span>${k}: ${v}</span></div>`).join("") || '<div class="empty">No data</div>';
      const bySev = (s.matches_by_severity && typeof s.matches_by_severity === "object") ? s.matches_by_severity : {};
      document.getElementById("th-by-sev").innerHTML = Object.entries(bySev).map(([k,v])=> `<div class="h-bar"><div class="h-bar-fill" style="width:${Math.min(100, Number(v)*10)}%;min-width:30px;"></div><span>${k}: ${v}</span></div>`).join("") || '<div class="empty">No data</div>';

      const table = document.querySelector("#th-table tbody");
      table.innerHTML = "";
      const list = (threats && Array.isArray(threats.threats)) ? threats.threats : [];
      list.forEach((t)=>{
        const sev = String(t.severity || "low").toLowerCase();
        const tr = document.createElement("tr");
        tr.innerHTML = `<td>${t.threat_id || ""}</td><td>${t.name || ""}</td><td>${t.category || ""}</td><td><span class="sev-${sev}">${(t.severity||"").toUpperCase()}</span></td>`;
        table.appendChild(tr);
      });
    }

    function renderCache(stats){
      const sc = (stats && stats.semantic_cache) ? stats.semantic_cache : {};
      const ce = (stats && stats.context_engine) ? stats.context_engine : {};
      const semanticRate = Number(sc.hit_rate_percent || 0);
      const cascadeRate = Number((stats && (stats.cache_hit_rate_percent ?? stats.cache_hit_rate)) || 0);
      const semanticEntries = Number(sc.entries || 0);
      const cascadeEntries = Number((stats && stats.cache_entries_count) || 0);
      const totalEntries = semanticEntries + cascadeEntries;
      document.getElementById("c-hit-rate").textContent = Math.max(semanticRate, cascadeRate).toFixed(1) + "%";
      document.getElementById("c-tokens").textContent = fmtNum((sc.total_tokens_saved || 0) + (ce.total_tokens_saved || 0));
      document.getElementById("c-cost").textContent = fmtMoney(sc.total_cost_saved_usd || 0);
      const maxEntries = Number(sc.max_entries || 0);
      const entriesLabel = maxEntries > 0
        ? `${fmtNum(totalEntries)}/${fmtNum(maxEntries)}`
        : `${fmtNum(totalEntries)}`;
      document.getElementById("c-entries").textContent = entriesLabel;
      const hitRateEl = document.getElementById("c-hit-rate");
      if(hitRateEl){
        const pct = Math.max(semanticRate, cascadeRate);
        hitRateEl.innerHTML = `${pct.toFixed(1)}%<div class="progress" style="margin-top:6px;"><div style="width:${Math.max(0, Math.min(100, pct)).toFixed(1)}%;background:var(--ok);"></div></div>`;
      }

      const semEl = document.getElementById("c-semantic-breakdown");
      if(!sc.enabled){
        semEl.innerHTML = `
          <div class="empty">Semantic cache disabled.</div>
          <div style="margin-top:8px;">Cascade cache hit rate: ${cascadeRate.toFixed(1)}% | Entries: ${fmtNum(cascadeEntries)}</div>
        `;
      }else{
        const exact = Number(sc.exact_hits || 0);
        const sem = Number(sc.semantic_hits || 0);
        const miss = Number(sc.misses || 0);
        const tot = exact + sem + miss || 1;
        semEl.innerHTML = `
          <div>Exact hits: ${fmtNum(exact)} | Semantic hits: ${fmtNum(sem)} | Misses: ${fmtNum(miss)}</div>
          <div style="margin-top:6px;">Cascade hits rate: ${cascadeRate.toFixed(1)}% | Cascade entries: ${fmtNum(cascadeEntries)}</div>
          <div class="outcome-bar" style="margin-top:8px;">
            <div class="outcome-success" style="width:${(exact/tot*100).toFixed(1)}%"></div>
            <div class="outcome-escalated" style="width:${(sem/tot*100).toFixed(1)}%"></div>
            <div class="outcome-abandoned" style="width:${(miss/tot*100).toFixed(1)}%"></div>
          </div>
        `;
      }

      const ctxEl = document.getElementById("c-context");
      if(!ce.enabled){
        ctxEl.innerHTML = `<div class="empty">Context engine not configured.</div>`;
      }else{
        const hits = (ce.strategy_hits && typeof ce.strategy_hits === "object") ? ce.strategy_hits : {};
        const maxH = Math.max(...Object.values(hits).map(Number), 1);
        ctxEl.innerHTML = `
          <div>Optimizations: ${fmtNum(ce.total_optimizations || 0)} | Tokens saved: ${fmtNum(ce.total_tokens_saved || 0)}</div>
          <div style="margin-top:10px;">${Object.entries(hits).map(([k,v])=> `<div class="h-bar"><div class="h-bar-fill" style="width:${(Number(v)/maxH*100).toFixed(0)}%;min-width:30px;"></div><span>${k}: ${v}</span></div>`).join("") || '<div class="empty">No strategy hits</div>'}</div>
        `;
      }
    }

    function renderCost(payload){
      const unwrapSettled = (entry) => {
        if(entry && entry.status === "fulfilled"){
          if(entry.value && typeof entry.value === "object"){
            return entry.value;
          }
          return {};
        }
        return entry && typeof entry === "object" ? entry : {};
      };
      const hasSettled = payload && typeof payload === "object" && ("analytics" in payload || "freedom" in payload);
      const analytics = hasSettled ? unwrapSettled(payload.analytics) : payload;
      const freedom = hasSettled ? unwrapSettled(payload.freedom) : {};
      const data = (analytics && typeof analytics === "object") ? analytics : {};
      const total = Number(data.total_cost || 0);
      const forecast = Number(data.forecast_24h || 0);
      const byModel = (data.cost_by_model && typeof data.cost_by_model === "object") ? data.cost_by_model : {};
      const byAgent = (data.cost_by_agent && typeof data.cost_by_agent === "object") ? data.cost_by_agent : {};
      const byHour = Array.isArray(data.cost_by_hour) ? data.cost_by_hour : [];
      const savingsObj = (data.savings && typeof data.savings === "object") ? data.savings : {};
      const savings = (data.savings && typeof data.savings === "object") ? data.savings : {};
      const topSessions = Array.isArray(data.top_expensive_sessions) ? data.top_expensive_sessions : [];

      document.getElementById("cost-total").textContent = fmtMoney(total);
      document.getElementById("cost-forecast").textContent = fmtMoney(forecast);

      const summaryEl = document.getElementById("cost-summary");
      if(summaryEl){
        summaryEl.innerHTML = `<div class="panel panel-primary"><strong>Cost summary</strong> · Total: ${fmtMoney(total)} · Forecast: ${fmtMoney(forecast)}</div>`;
      }
      const cofEl = document.getElementById("cost-of-freedom-widget");
      if(cofEl){
        const b = freedom && typeof freedom === "object" && freedom.benchmarks ? freedom.benchmarks : {};
        const redundancy = Number(b.redundancy_rate || 0) * 100;
        const retry = Number(b.retry_reduction || 0);
        cofEl.innerHTML = `<div class="panel"><strong>Cost of Freedom</strong><div>Redundancy: ${redundancy.toFixed(2)}% · Retry reduction: ${retry.toFixed(2)}x</div></div>`;
      }
      const tyEl = document.getElementById("token-yield-chart");
      if(tyEl){
        const savingsTotal = Number(savingsObj.total || 0);
        tyEl.innerHTML = `<div class="panel"><strong>Token Yield chart</strong><div>Saved: ${fmtMoney(savingsTotal)}</div></div>`;
      }

      const modelEntries = Object.entries(byModel);
      const agentEntries = Object.entries(byAgent);
      document.getElementById("cost-top-model").textContent = modelEntries.length ? String(modelEntries[0][0]) : "--";
      document.getElementById("cost-top-agent").textContent = agentEntries.length ? String(agentEntries[0][0]) : "--";

      const maxModel = Math.max(...modelEntries.map((row)=> Number(row[1] || 0)), 1);
      document.getElementById("cost-by-model").innerHTML = modelEntries.length
        ? modelEntries.map(([name, value])=> {
            const pct = (Number(value || 0) / maxModel * 100).toFixed(0);
            return `<div class="h-bar"><div class="h-bar-fill" style="width:${pct}%;min-width:40px;"></div><span>${name}: ${fmtMoney(value)}</span></div>`;
          }).join("")
        : `<div class="empty">No model cost data.</div>`;

      const maxAgent = Math.max(...agentEntries.map((row)=> Number(row[1] || 0)), 1);
      document.getElementById("cost-by-agent").innerHTML = agentEntries.length
        ? agentEntries.map(([name, value])=> {
            const pct = (Number(value || 0) / maxAgent * 100).toFixed(0);
            return `<div class="h-bar"><div class="h-bar-fill" style="width:${pct}%;min-width:40px;"></div><span>${name}: ${fmtMoney(value)}</span></div>`;
          }).join("")
        : `<div class="empty">No agent cost data.</div>`;

      const maxHour = Math.max(...byHour.map((row)=> Number((row && row.cost) || 0)), 1);
      document.getElementById("cost-hourly").innerHTML = byHour.length
        ? byHour.map((row)=> {
            const c = Number((row && row.cost) || 0);
            const pct = (c / maxHour * 100).toFixed(0);
            return `<div class="h-bar"><div class="h-bar-fill" style="width:${pct}%;min-width:24px;"></div><span>${String((row && row.hour) || "--")}: ${fmtMoney(c)}</span></div>`;
          }).join("")
        : `<div class="empty">No hourly data.</div>`;

      const cacheSaved = Number(savings.cache || 0);
      const loopSaved = Number(savings.loop_prevention || 0);
      const compressionSaved = Number(savings.compression || 0);
      const totalSaved = Number(savings.total || (cacheSaved + loopSaved + compressionSaved));
      document.getElementById("cost-savings").innerHTML = `
        <div>Cache: <strong>${fmtMoney(cacheSaved)}</strong></div>
        <div>Loop prevention: <strong>${fmtMoney(loopSaved)}</strong></div>
        <div>Compression: <strong>${fmtMoney(compressionSaved)}</strong></div>
        <div style="margin-top:6px;">Total: <strong>${fmtMoney(totalSaved)}</strong></div>
      `;

      document.getElementById("cost-top-sessions").innerHTML = topSessions.length
        ? topSessions.map((item)=> `<div class="event-item">${String(item.session_id || "__default__")} <span class="subtle">(${fmtMoney(item.cost || 0)})</span></div>`).join("")
        : `<div class="empty">No session cost data.</div>`;
    }

    function renderBudgetAdvice(advice, quickWinsPayload){
      const model = (advice && typeof advice === "object") ? advice : {};
      const winsPayload = (quickWinsPayload && typeof quickWinsPayload === "object") ? quickWinsPayload : {};
      const wins = Array.isArray(winsPayload.quick_wins) ? winsPayload.quick_wins : [];
      const recommendations = Array.isArray(model.recommendations) ? model.recommendations : [];
      const waste = (model.waste_detected && typeof model.waste_detected === "object") ? model.waste_detected : {};

      const projectedEl = document.getElementById("budget-projected-monthly");
      if(projectedEl){
        projectedEl.textContent = fmtMoney(Number(model.projected_monthly || 0));
      }

      const wasteEl = document.getElementById("budget-waste");
      if(wasteEl){
        wasteEl.innerHTML = `
          <div>Loop waste: <strong>${fmtMoney(Number(waste.loop_waste || 0))}</strong></div>
          <div>Cache miss waste: <strong>${fmtMoney(Number(waste.cache_miss_waste || 0))}</strong></div>
          <div style="margin-top:4px;">Total waste: <strong>${fmtMoney(Number(waste.total_waste || 0))}</strong></div>
        `;
      }

      const winsEl = document.getElementById("budget-quick-wins");
      if(winsEl){
        winsEl.innerHTML = wins.length
          ? `<ul class="profile-list">${wins.slice(0, 3).map((item)=> `<li>${String(item || "")}</li>`).join("")}</ul>`
          : `<div class="empty">No quick wins available.</div>`;
      }

      const recEl = document.getElementById("budget-recommendations");
      if(recEl){
        recEl.innerHTML = recommendations.length
          ? recommendations.map((item, idx)=> {
              const type = String(item.type || "recommendation");
              const reason = String(item.reason || "-");
              const suggested = Number(item.suggested_value || 0);
              const savings = Number(item.estimated_savings || 0);
              const priority = String(item.priority || "low");
              return `<div class="event-item" style="border:1px solid var(--border);border-radius:8px;padding:8px;margin-bottom:8px;">
                <div><strong>${type}</strong> <span class="subtle">(${priority})</span></div>
                <div class="subtle" style="margin-top:4px;">${reason}</div>
                <div style="margin-top:6px;">Suggested: ${suggested.toFixed(2)} · Est. savings: ${fmtMoney(savings)}</div>
                <button class="ow-btn" data-budget-apply="${idx}" style="margin-top:8px;">Apply recommendation</button>
              </div>`;
            }).join("")
          : `<div class="empty">No recommendations yet.</div>`;
        recEl.querySelectorAll("[data-budget-apply]").forEach((btn)=>{
          btn.addEventListener("click", ()=> showToast("Recommendation applied (preview)"));
        });
      }
    }

    function renderCompliance(summary, coverage, findings, overview){
      const fw = (summary && summary.frameworks) ? summary.frameworks : {};
      const owasp = fw["owasp_llm_top10_2025"] || { percent: 0 };
      const nist = fw["nist_ai_rmf_1_0"] || { percent: 0 };
      const oPct = Number(owasp.percent || 0);
      const nPct = Number(nist.percent || 0);
      document.getElementById("cmp-owasp-percent").textContent = `${oPct.toFixed(1)}%`;
      document.getElementById("cmp-nist-percent").textContent = `${nPct.toFixed(1)}%`;
      document.getElementById("cmp-owasp-bar").style.width = `${Math.max(0, Math.min(100, oPct)).toFixed(1)}%`;
      document.getElementById("cmp-nist-bar").style.width = `${Math.max(0, Math.min(100, nPct)).toFixed(1)}%`;

      const rows = document.querySelector("#cmp-owasp-table tbody");
      rows.innerHTML = "";
      const owaspReport = coverage && coverage.frameworks ? coverage.frameworks["owasp_llm_top10_2025"] : null;
      const items = (owaspReport && Array.isArray(owaspReport.items)) ? owaspReport.items : [];
      items.forEach((item)=>{
        const status = String(item.status || "not_covered");
        const sevClass = status === "covered" ? "low" : (status === "partial" || status === "detect_only" ? "medium" : "high");
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${item.id || ""}</td>
          <td>${item.name || ""}</td>
          <td><span class="sev ${sevClass}">${status}</span></td>
          <td>${(item.modules || []).join(", ") || "-"}</td>
        `;
        rows.appendChild(tr);
      });

      const findingsEl = document.getElementById("cmp-findings");
      findingsEl.innerHTML = "";
      const list = (findings && Array.isArray(findings.findings)) ? findings.findings.slice(0, 10) : [];
      if(list.length === 0){
        findingsEl.innerHTML = `<div class="empty">No data yet.</div>`;
      }else{
        list.forEach((f)=>{
          const sev = String(f.severity || "info").toLowerCase();
          const mapText = Array.isArray(f.framework_mappings) ? f.framework_mappings.map((m)=> `${m[0]}:${m[1]}`).join(", ") : "-";
          const row = document.createElement("div");
          row.className = "event event-item";
          row.innerHTML = `<span class="subtle">${f.timestamp || ""}</span><span class="sev ${sev}">${sev.toUpperCase()}</span><span>${f.description || ""}<div class="subtle">${mapText}</div></span>`;
          findingsEl.appendChild(row);
        });
      }
      const ov = (overview && overview.compliance_overview) ? overview.compliance_overview : {};
      const mast = ov.mast || { score: 0, covered: 0, total: 14, gaps: [] };
      const owaspAi = ov.owasp_agentic_ai || { score: oPct, covered: 0, total: 10, gaps: [] };
      const eu = ov.eu_ai_act || { score: 0, audit_trail: false, incident_reporting: false, risk_assessment: "partial", human_oversight: "partial", documentation: false };
      const nistRmf = ov.nist_ai_rmf || { score: nPct, govern: "partial", map: "partial", measure: "partial", manage: "partial" };
      const overviewEl = document.getElementById("cmp-overview-text");
      if (overviewEl) {
        overviewEl.innerHTML = `
          <div><strong>MAST:</strong> ${Number(mast.score || 0).toFixed(1)}% | Covered ${mast.covered || 0}/${mast.total || 14} | Gaps: ${(mast.gaps || []).join(", ") || "-"}</div>
          <div style="margin-top:6px;"><strong>OWASP Agentic AI:</strong> ${Number(owaspAi.score || 0).toFixed(1)}% | Covered ${owaspAi.covered || 0}/${owaspAi.total || 10} | Gaps: ${(owaspAi.gaps || []).join(", ") || "-"}</div>
          <div style="margin-top:6px;"><strong>EU AI Act:</strong> ${Number(eu.score || 0).toFixed(1)}% | Audit trail: ${eu.audit_trail ? "✅" : "❌"} | Incident reporting: ${eu.incident_reporting ? "✅" : "❌"} | Risk assessment: ${eu.risk_assessment || "partial"} | Human oversight: ${eu.human_oversight || "partial"} | Documentation: ${eu.documentation ? "✅" : "❌"}</div>
          <div style="margin-top:6px;"><strong>NIST AI RMF:</strong> ${Number(nistRmf.score || 0).toFixed(1)}% | Govern: ${nistRmf.govern || "partial"} | Map: ${nistRmf.map || "partial"} | Measure: ${nistRmf.measure || "partial"} | Manage: ${nistRmf.manage || "partial"}</div>
        `;
      }
    }

    async function applyApproval(id, action){
      const endpoint = `/api/v1/approvals/${encodeURIComponent(id)}/${action}`;
      await fetch(endpoint, { method: "POST" });
      await pollApprovals();
    }

    function renderApprovals(data){
      const pendingEl = document.getElementById("approvals-pending");
      const historyEl = document.getElementById("approvals-history");
      const countEl = document.getElementById("ap-pending-count");
      const pending = (data && Array.isArray(data.pending)) ? data.pending : [];
      const history = (data && Array.isArray(data.history)) ? data.history : [];
      if (countEl) countEl.textContent = String(pending.length);
      if (pendingEl) {
        if (pending.length === 0) {
          pendingEl.innerHTML = `<div class="empty">No pending approvals.</div>`;
        } else {
          pendingEl.innerHTML = pending.map((item)=>{
            const id = String(item.approval_id || "");
            const args = item.tool_args ? JSON.stringify(item.tool_args) : "{}";
            const risk = String(item.risk || "medium").toUpperCase();
            return `<div class="approval-row">
              <div class="approval-actions">
                <button class="tab-btn" data-approve="${id}">APPROVE</button>
                <button class="tab-btn" data-deny="${id}">DENY</button>
              </div>
              <div>agent: ${item.agent_id || "unknown"} | tool: ${item.tool_name || "unknown"} | action: ${args}</div>
              <div class="subtle">Risk: ${risk} | Reason: ${item.reason || "-"} | ${fmtTs(item.timestamp)}</div>
            </div>`;
          }).join("");
          pendingEl.querySelectorAll("button[data-approve]").forEach((btn)=>{
            btn.addEventListener("click", ()=> applyApproval(String(btn.getAttribute("data-approve") || ""), "approve"));
          });
          pendingEl.querySelectorAll("button[data-deny]").forEach((btn)=>{
            btn.addEventListener("click", ()=> applyApproval(String(btn.getAttribute("data-deny") || ""), "deny"));
          });
        }
      }
      if (historyEl) {
        if (history.length === 0) {
          historyEl.innerHTML = `<div class="empty">No approval history.</div>`;
        } else {
          historyEl.innerHTML = history.slice(0, 20).map((item)=>{
            const status = String(item.status || "").toLowerCase() === "approved" ? "✅ Approved" : "❌ Denied";
            return `<div class="approval-row">${status}: ${item.agent_id || "unknown"} → ${item.tool_name || "unknown"} (${fmtTs(item.timestamp)})</div>`;
          }).join("");
        }
      }
    }

    async function applyOverwatchApproval(id, action){
      if(!id){ return; }
      await fetch(`/api/v1/approvals/${encodeURIComponent(id)}/${action}`, { method: "POST" });
      await pollOverwatch();
    }

    function renderOverwatchCards(model){
      const cardsEl = document.getElementById("ow-cards");
      const emptyEl = document.getElementById("ow-empty");
      if (!cardsEl || !emptyEl) return;
      const agents = model.agents || [];
      if (agents.length === 0) {
        cardsEl.innerHTML = "";
        emptyEl.style.display = "grid";
        return;
      }
      emptyEl.style.display = "none";
      cardsEl.innerHTML = agents.map((agent)=>{
        const name = String(agent.agent_id || agent.id || agent.name || "unknown-agent");
        const status = String(agent.status || "active").toLowerCase();
        const grade = formatGrade(agent.security_grade || agent.ars_grade || "A");
        const task = String(agent.current_task || "").trim() || "Idle";
        const threats = Number(agent.threats_today || 0);
        const pending = Number(agent.pending_approvals || 0);
        const modelName = String(agent.model || agent.primary_model || "-");
        const costDay = Number(agent.cost_day_usd || agent.cost_today || agent.total_cost_usd || 0);
        const reqs = Number(agent.requests_today || agent.total_requests || 0);
        const budgetLimit = Number(agent.budget_limit_usd || agent.budget_limit || 0);
        const budgetUsed = Number(agent.budget_used_usd || costDay || 0);
        const budgetRatio = budgetLimit > 0 ? Math.max(0, Math.min(100, (budgetUsed / budgetLimit) * 100)) : 0;
        const budgetColor = budgetRatio > 90 ? "var(--red)" : (budgetRatio > 70 ? "var(--orange)" : "var(--green)");
        const cardClass = pending > 0 ? "ow-card pending" : (threats > 0 ? "ow-card threat" : "ow-card");
        return `<div class="${cardClass}">
          <div class="ow-head">
            <div class="ow-agent-id"><span class="ow-dot ${status === "idle" ? "idle" : (status === "alert" ? "alert" : (status === "warning" ? "warning" : ""))}"></span><span class="ow-name">${name}</span></div>
            <span class="ow-badge ${toRiskBadgeClass(grade)}">${grade}</span>
          </div>
          <div class="ow-task">${task}</div>
          <div class="ow-budget-line">
            ${budgetLimit > 0 ? `<div class="ow-meta">${fmtMoney(budgetUsed)} / ${fmtMoney(budgetLimit)}</div><div class="ow-budget-bar"><div style="width:${budgetRatio.toFixed(1)}%;background:${budgetColor};"></div></div>` : `<div class="ow-meta">No budget limit</div>`}
          </div>
          <div class="ow-meta">${fmtMoney(costDay)}/day · ${modelName} · ${fmtNum(threats)} threats${agent.team_id ? ` · team:${agent.team_id}` : ""}</div>
          <div class="ow-actions">
            <button class="ow-btn">Set Budget</button>
            <button class="ow-btn">Threats</button>
            <button class="ow-btn">Policy</button>
            ${pending > 0 ? `<button class="ow-btn review">Review ${fmtNum(pending)}</button>` : ""}
          </div>
          <div class="ow-meta">requests today: ${fmtNum(reqs)}</div>
        </div>`;
      }).join("");
    }

    async function loadTeamDetail(teamId){
      const data = await fetchData(`/api/v1/overwatch/teams/${encodeURIComponent(teamId)}`);
      if(data && typeof data === "object"){
        overwatchTeamDetail = data;
        renderOverwatchTeams(overwatchSnapshot || normalizeOverwatch({}));
      }
    }

    function renderOverwatchTeams(model){
      const cardsEl = document.getElementById("ow-teams-cards");
      const detailEl = document.getElementById("ow-team-detail");
      if(!cardsEl || !detailEl){ return; }
      const teams = Array.isArray(model.teams) ? model.teams : [];
      if(teams.length === 0){
        cardsEl.innerHTML = `<div class="ow-empty" style="grid-column:1 / -1;"><div>No teams configured.</div></div>`;
        detailEl.innerHTML = `<div class="subtle">Assign agents to teams to view rollups.</div>`;
        return;
      }
      cardsEl.innerHTML = teams.map((team)=>{
        const teamId = String(team.team_id || "unknown");
        const selected = overwatchTeamDetail && String(overwatchTeamDetail.team_id || "") === teamId;
        return `<button class="ow-team-card${selected ? " active" : ""}" data-ow-team="${teamId}">
          <div class="ow-team-title">${teamId}</div>
          <div class="ow-meta">Cost: ${fmtMoney(team.cost_today || 0)}</div>
          <div class="ow-meta">Agents: ${fmtNum((Array.isArray(team.agents) ? team.agents.length : 0))}</div>
          <div class="ow-meta">Threats: ${fmtNum(team.threats_today || 0)}</div>
        </button>`;
      }).join("");
      cardsEl.querySelectorAll("[data-ow-team]").forEach((btn)=>{
        btn.addEventListener("click", ()=> loadTeamDetail(String(btn.getAttribute("data-ow-team") || "")));
      });
      const detail = overwatchTeamDetail || teams[0];
      const detailAgents = Array.isArray(detail.agents) ? detail.agents : [];
      detailEl.innerHTML = `
        <div><strong>Team:</strong> ${detail.team_id || "unknown"} · <strong>Budget:</strong> ${fmtMoney(detail.budget_remaining || 0)} / ${fmtMoney(detail.budget_limit || 0)} remaining</div>
        <table class="table">
          <thead><tr><th>Agent</th><th>Cost Today</th><th>Requests</th><th>Threats</th><th>Budget Left</th></tr></thead>
          <tbody>
            ${detailAgents.map((agent)=> `<tr>
              <td>${agent.id || agent.agent_id || "unknown-agent"}</td>
              <td>${fmtMoney(agent.cost_today || 0)}</td>
              <td>${fmtNum(agent.requests_today || 0)}</td>
              <td>${fmtNum(agent.threats_today || 0)}</td>
              <td>${fmtMoney(agent.budget_remaining || 0)}</td>
            </tr>`).join("") || `<tr><td colspan="5" class="subtle">No agents in team.</td></tr>`}
          </tbody>
        </table>
      `;
    }

    function renderOverwatchRadar(model){
      const svg = document.getElementById("ow-radar");
      const tooltip = document.getElementById("ow-radar-tooltip");
      if(!svg){ return; }
      const agents = model.agents || [];
      const cx = 310;
      const cy = 230;
      const rings = [80, 155, 215];
      const maxRequests = Math.max(1, ...agents.map((a)=> Number(a.requests_today || a.total_requests || 0)));
      const sweepId = "ow-sweep-grad";
      let html = `
        <defs>
          <radialGradient id="ow-ring-safe" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="rgba(0,255,65,0.12)"/><stop offset="100%" stop-color="rgba(0,255,65,0.02)"/>
          </radialGradient>
          <radialGradient id="ow-ring-warn" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="rgba(249,115,22,0.08)"/><stop offset="100%" stop-color="rgba(249,115,22,0.02)"/>
          </radialGradient>
          <radialGradient id="ow-ring-danger" cx="50%" cy="50%" r="50%">
            <stop offset="0%" stop-color="rgba(239,68,68,0.06)"/><stop offset="100%" stop-color="rgba(239,68,68,0.01)"/>
          </radialGradient>
          <linearGradient id="${sweepId}" x1="0" y1="0" x2="1" y2="0">
            <stop offset="0%" stop-color="rgba(168,85,247,0.0)"/>
            <stop offset="65%" stop-color="rgba(168,85,247,0.0)"/>
            <stop offset="100%" stop-color="rgba(168,85,247,0.42)"/>
          </linearGradient>
        </defs>
        <circle cx="${cx}" cy="${cy}" r="${rings[2]}" fill="url(#ow-ring-danger)" stroke="rgba(239,68,68,0.16)"/>
        <circle cx="${cx}" cy="${cy}" r="${rings[1]}" fill="url(#ow-ring-warn)" stroke="rgba(249,115,22,0.20)"/>
        <circle cx="${cx}" cy="${cy}" r="${rings[0]}" fill="url(#ow-ring-safe)" stroke="rgba(0,255,65,0.22)"/>
        <circle cx="${cx}" cy="${cy}" r="8" fill="var(--purple)" stroke="#ffffff" stroke-opacity="0.25"/>
        <text x="${cx}" y="${cy - 15}" fill="var(--text-secondary)" font-size="11" text-anchor="middle">orchestrator</text>
        <g>
          <line x1="${cx}" y1="${cy}" x2="${cx}" y2="${cy - rings[2]}" stroke="url(#${sweepId})" stroke-width="2.5" stroke-linecap="round">
            <animateTransform attributeName="transform" attributeType="XML" type="rotate" from="0 ${cx} ${cy}" to="360 ${cx} ${cy}" dur="3s" repeatCount="indefinite"/>
          </line>
        </g>
      `;
      agents.forEach((agent, idx)=>{
        const grade = formatGrade(agent.security_grade || agent.ars_grade || "A");
        const score = grade.startsWith("A") ? 0 : (grade.startsWith("B") ? 1 : 2);
        const rMin = score === 0 ? 26 : (score === 1 ? rings[0] + 10 : rings[1] + 10);
        const rMax = score === 0 ? rings[0] - 10 : (score === 1 ? rings[1] - 10 : rings[2] - 10);
        const rr = rMin + (idx % 5) * Math.max(8, (rMax - rMin) / 5);
        const angle = (idx / Math.max(1, agents.length)) * (Math.PI * 2);
        const x = cx + Math.cos(angle) * rr;
        const y = cy + Math.sin(angle) * rr;
        const requests = Number(agent.requests_today || agent.total_requests || 0);
        const radius = 4 + ((requests / maxRequests) * 8);
        const status = String(agent.status || "active").toLowerCase();
        const color = status === "alert" ? "var(--red)" : (status === "warning" ? "var(--orange)" : (status === "idle" ? "#9ca3af" : "var(--green)"));
        const id = `ow-point-${idx}`;
        html += `<circle id="${id}" cx="${x.toFixed(2)}" cy="${y.toFixed(2)}" r="${radius.toFixed(2)}" fill="${color}" fill-opacity="0.95" stroke="#ffffff" stroke-opacity="0.25"/>`;
      });
      svg.innerHTML = html;
      if (tooltip) {
        tooltip.style.display = "none";
      }
      agents.forEach((agent, idx)=>{
        const el = document.getElementById(`ow-point-${idx}`);
        if(!el) return;
        el.addEventListener("click", ()=>{
          if(!tooltip) return;
          const threats = Number(agent.threats_today || 0);
          tooltip.innerHTML = `<strong>${agent.agent_id || "unknown-agent"}</strong><div style="margin-top:4px;">${agent.current_task || "Idle"}</div><div class="subtle" style="margin-top:4px;">${fmtMoney(agent.cost_day_usd || 0)}/day · ${agent.model || "-"} · ${fmtNum(threats)} threats</div>`;
          tooltip.style.display = "block";
        });
      });
    }

    function renderOverwatchGraph(model){
      const svg = document.getElementById("ow-graph-svg");
      const detailEl = document.getElementById("ow-graph-detail");
      if(!svg){ return; }
      const graph = (model && model.graph && typeof model.graph === "object") ? model.graph : {};
      const nodesIn = Array.isArray(graph.nodes) ? graph.nodes : [];
      const edges = Array.isArray(graph.edges) ? graph.edges : [];
      if(nodesIn.length === 0){
        svg.innerHTML = "";
        if(detailEl){
          detailEl.textContent = "No collaboration data yet.";
        }
        return;
      }
      const w = 620;
      const h = 460;
      const nodes = nodesIn.map((node, idx)=>{
        const angle = (idx / Math.max(1, nodesIn.length)) * (Math.PI * 2);
        return {
          id: String(node.id || `agent-${idx}`),
          requests: Number(node.requests || 0),
          cost: Number(node.cost || 0),
          x: w / 2 + Math.cos(angle) * 150,
          y: h / 2 + Math.sin(angle) * 130,
          vx: 0,
          vy: 0,
        };
      });
      const byId = {};
      nodes.forEach((node)=>{ byId[node.id] = node; });
      for(let iter = 0; iter < 120; iter += 1){
        for(let i = 0; i < nodes.length; i += 1){
          for(let j = i + 1; j < nodes.length; j += 1){
            const a = nodes[i];
            const b = nodes[j];
            let dx = b.x - a.x;
            let dy = b.y - a.y;
            const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
            const force = 2500 / (dist * dist);
            dx /= dist;
            dy /= dist;
            a.vx -= dx * force * 0.01;
            a.vy -= dy * force * 0.01;
            b.vx += dx * force * 0.01;
            b.vy += dy * force * 0.01;
          }
        }
        edges.forEach((edge)=>{
          const a = byId[String(edge.from || "")];
          const b = byId[String(edge.to || "")];
          if(!a || !b){ return; }
          const dx = b.x - a.x;
          const dy = b.y - a.y;
          const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
          const rest = 90 + Math.min(120, Number(edge.weight || 1) * 4);
          const stretch = dist - rest;
          const k = 0.004;
          const fx = (dx / dist) * stretch * k;
          const fy = (dy / dist) * stretch * k;
          a.vx += fx;
          a.vy += fy;
          b.vx -= fx;
          b.vy -= fy;
        });
        nodes.forEach((node)=>{
          node.x = Math.max(24, Math.min(w - 24, node.x + node.vx));
          node.y = Math.max(24, Math.min(h - 24, node.y + node.vy));
          node.vx *= 0.85;
          node.vy *= 0.85;
        });
      }
      const maxReq = Math.max(1, ...nodes.map((node)=> node.requests));
      let html = "";
      edges.forEach((edge, idx)=>{
        const a = byId[String(edge.from || "")];
        const b = byId[String(edge.to || "")];
        if(!a || !b){ return; }
        const width = Math.max(1, Math.min(8, Number(edge.weight || 1)));
        html += `<line x1="${a.x.toFixed(2)}" y1="${a.y.toFixed(2)}" x2="${b.x.toFixed(2)}" y2="${b.y.toFixed(2)}" stroke="rgba(168,85,247,0.55)" stroke-width="${width.toFixed(1)}" />`;
        if(idx < 24){
          const mx = ((a.x + b.x) / 2).toFixed(2);
          const my = ((a.y + b.y) / 2).toFixed(2);
          html += `<text x="${mx}" y="${my}" fill="var(--text-secondary)" font-size="10" text-anchor="middle">${String(edge.type || "link")}</text>`;
        }
      });
      nodes.forEach((node, idx)=>{
        const r = 6 + (node.requests / maxReq) * 10;
        const isCentral = String(graph.central_agent || "") === node.id;
        const fill = isCentral ? "#22c55e" : "#a855f7";
        html += `<circle id="ow-graph-node-${idx}" cx="${node.x.toFixed(2)}" cy="${node.y.toFixed(2)}" r="${r.toFixed(2)}" fill="${fill}" fill-opacity="0.95" stroke="rgba(255,255,255,0.35)" stroke-width="1.2"/>`;
        html += `<text x="${node.x.toFixed(2)}" y="${(node.y + r + 11).toFixed(2)}" fill="var(--text-secondary)" font-size="11" text-anchor="middle">${node.id}</text>`;
      });
      svg.innerHTML = html;
      nodes.forEach((node, idx)=>{
        const el = document.getElementById(`ow-graph-node-${idx}`);
        if(!el){ return; }
        el.addEventListener("click", ()=>{
          if(!detailEl){ return; }
          const outEdges = edges.filter((edge)=> String(edge.from || "") === node.id || String(edge.to || "") === node.id);
          detailEl.textContent = `${node.id} · requests:${fmtNum(node.requests)} · cost:${fmtMoney(node.cost)} · links:${fmtNum(outEdges.length)}`;
        });
      });
      if(detailEl){
        const isolated = Array.isArray(graph.isolated_agents) ? graph.isolated_agents : [];
        detailEl.textContent = `Central agent: ${String(graph.central_agent || "n/a")} · isolated: ${isolated.length ? isolated.join(", ") : "none"}`;
      }
    }

    function renderOverwatchApprovals(model){
      const section = document.getElementById("ow-approvals-section");
      const listEl = document.getElementById("ow-approvals-list");
      if(!section || !listEl){ return; }
      const pending = (model.approvals || []).filter((item)=> String(item.status || "pending").toLowerCase() === "pending");
      if (pending.length === 0) {
        section.style.display = "none";
        listEl.innerHTML = "";
        return;
      }
      section.style.display = "grid";
      listEl.innerHTML = pending.map((item)=>{
        const id = String(item.approval_id || item.id || "");
        const actionText = item.description || item.action || item.tool_name || "approval requested";
        return `<div class="ow-ap-item">
          <div><strong>${item.agent_id || "unknown-agent"}</strong> · ${actionText}</div>
          <div class="subtle" style="margin-top:4px;">${item.reason || "-"} · ${fmtTs(item.timestamp)}</div>
          <div class="ow-ap-actions">
            <button class="ow-btn" data-ow-approve="${id}">Approve</button>
            <button class="ow-btn" data-ow-deny="${id}">Deny</button>
          </div>
        </div>`;
      }).join("");
      listEl.querySelectorAll("[data-ow-approve]").forEach((btn)=>{
        btn.addEventListener("click", ()=> applyOverwatchApproval(String(btn.getAttribute("data-ow-approve") || ""), "approve"));
      });
      listEl.querySelectorAll("[data-ow-deny]").forEach((btn)=>{
        btn.addEventListener("click", ()=> applyOverwatchApproval(String(btn.getAttribute("data-ow-deny") || ""), "deny"));
      });
    }

    function renderOverwatch(payload){
      const model = overwatchUseDemo ? normalizeOverwatch(mockOverwatchData()) : normalizeOverwatch(payload);
      overwatchSnapshot = model;
      const summaryEl = document.getElementById("ow-summary");
      if (summaryEl) {
        const s = model.summary || { active_agents: 0, total_cost_day_usd: 0, threats_blocked: 0, pending_approvals: 0 };
        summaryEl.textContent = `${fmtNum(s.active_agents)} active · ${fmtMoney(s.total_cost_day_usd)}/day · ${fmtNum(s.threats_blocked)} blocked · ${fmtNum(s.pending_approvals)} pending`;
      }
      renderOverwatchCards(model);
      renderOverwatchRadar(model);
      renderOverwatchTeams(model);
      renderOverwatchGraph(model);
      renderOverwatchApprovals(model);
    }

    async function pollOverwatch(){
      const snapshot = await fetchData("/api/v1/overwatch");
      const teams = await fetchData("/api/v1/overwatch/teams");
      const graph = await fetchData("/api/v1/agents/graph");
      if(!snapshot || !teams || !graph){
        return;
      }
      const payload = Object.assign({}, snapshot || {});
      payload.teams = (teams && Array.isArray(teams.teams)) ? teams.teams : [];
      payload.graph = (graph && typeof graph === "object") ? graph : { nodes: [], edges: [], central_agent: "", isolated_agents: [] };
      renderOverwatch(payload);
    }

    async function pollShield(shared){
      const data = shared && shared.overview ? shared.overview : await getOverviewSnapshot();
      const stats = shared && shared.stats ? shared.stats : await getStatsSnapshot();
      const savings = await fetchData("/api/v1/savings");
      const health = await fetchData("/api/v1/agents/__global__/health");
      const tokenYield = await fetchData("/api/v1/token-yield/global");
      const contextBudget = await fetchData("/api/v1/context-budget/stats");
      const communityStatus = await fetchData("/api/v1/community/status");
      const communityStats = await fetchData("/api/v1/community/stats");
      const heatmap = await fetchData("/api/v1/heatmap?days=7");
      if(!data || !stats || !savings || !health || !tokenYield || !contextBudget || !communityStatus || !communityStats || !heatmap){
        return;
      }
      const now = Date.now();
      if (!rateLimitSnapshot || (now - lastRateLimitFetchMs) >= RATE_LIMIT_REFRESH_MS) {
        const freshRateLimits = await fetchData("/api/v1/rate-limits/status");
        if (freshRateLimits) {
          rateLimitSnapshot = freshRateLimits;
          lastRateLimitFetchMs = now;
        }
      }
      renderOverview(data, stats, savings, tokenYield, contextBudget, rateLimitSnapshot || {});
      renderAgentHealth((health && typeof health === "object") ? health : (data && data.agent_health ? data.agent_health : {}));
      renderCommunityIntel(communityStatus || {}, communityStats || {});
      renderSessionHeatmap(heatmap || {});
    }
    async function pollAgents(){
      const data = await fetchData("/api/dashboard/agents");
      if(!data){ return; }
      renderAgents(data);
    }
    async function pollSessions(){
      const data = await fetchData("/api/sessions");
      if(!data){ return; }
      renderSessions(data);
    }
    async function pollFlow(){
      const sessionsResp = await fetchData("/api/flow/sessions");
      if(!sessionsResp){ return; }
      const sessions = (sessionsResp && Array.isArray(sessionsResp.sessions)) ? sessionsResp.sessions : [];
      const select = document.getElementById("flow-session-select");
      const current = select.value;
      select.innerHTML = sessions.map((s)=> `<option value="${s.id}">${s.id}</option>`).join("");
      if(current && sessions.some((s)=>s.id === current)){ select.value = current; }
      const sid = select.value || (sessions[0] ? sessions[0].id : "");
      const recent = await fetchData("/api/v1/requests/recent?limit=20");
      if(!recent){ return; }
      requestInspectorItems = (recent && Array.isArray(recent.requests)) ? recent.requests : [];
      renderRequestInspectorList();
      if(!sid){ renderFlowAnalysis(null, null, null); return; }
      let timelinePromise = fetchData(`/api/v1/flow/timeline?session_id=${encodeURIComponent(sid)}&limit=40`);
      const analysis = await fetchData(`/api/flow/analyze/${encodeURIComponent(sid)}`);
      const graph = await fetchData(`/api/flow/graph/${encodeURIComponent(sid)}`);
      if(!analysis || !graph){
        return;
      }
      let timeline = await timelinePromise;
      if(!timeline){
        timeline = await fetchData(`/api/flow/timeline?session_id=${encodeURIComponent(sid)}&limit=40`);
      }
      if(!timeline){ return; }
      renderFlowAnalysis(analysis, graph, timeline);
      if(!requestInspectorActiveId && requestInspectorItems.length > 0){
        loadRequestInspection(String(requestInspectorItems[0].request_id || ""));
      }
    }
    async function pollCompliance(shared){
      const summary = await fetchData("/api/compliance/summary");
      const coverage = await fetchData("/api/compliance/coverage");
      const findings = await fetchData("/api/compliance/findings?limit=10");
      const overview = shared && shared.overview ? shared.overview : await getOverviewSnapshot();
      if(!summary || !coverage || !findings || !overview){
        return;
      }
      renderCompliance(summary, coverage, findings, overview);
    }

    async function pollApprovals(){
      const data = await fetchData("/api/v1/approvals");
      renderApprovals(data || {});
    }

    async function pollExperiments(shared){
      const experiments = await fetchData("/api/experiments");
      const outcomes = await fetchData("/api/tasks/outcomes");
      const correlations = await fetchData("/api/tasks/correlations");
      const stats = shared && shared.stats ? shared.stats : await getStatsSnapshot();
      const benchmarkCases = await fetchData("/api/v1/benchmark/cases");
      const benchmarkResults = await fetchData("/api/v1/benchmark/results");
      if(!experiments || !outcomes || !correlations || !stats || !benchmarkCases || !benchmarkResults){
        return;
      }
      renderExperiments(experiments, outcomes, correlations, stats, benchmarkCases, benchmarkResults);
    }

    async function pollThreats(){
      const threats = await fetchData("/api/threats");
      const stats = await fetchData("/api/threats/stats");
      if(!threats || !stats){ return; }
      renderThreats(threats, stats);
    }

    async function pollCache(shared){
      const stats = shared && shared.stats ? shared.stats : await getStatsSnapshot();
      if(!stats){ return; }
      renderCache(stats);
    }

    async function pollCost(){
      const [analytics, freedom] = await Promise.allSettled([
        fetch('/api/v1/cost/analytics'),
        fetch('/api/v1/cost-of-freedom/benchmarks'),
      ]);
      async function toJson(result){
        if(!result || result.status !== "fulfilled"){ return {}; }
        const response = result.value;
        if(!response || typeof response.ok !== "boolean" || !response.ok){ return {}; }
        try { return await response.json(); } catch(_err) { return {}; }
      }
      renderCost({
        analytics: { status: "fulfilled", value: await toJson(analytics) },
        freedom: { status: "fulfilled", value: await toJson(freedom) },
      });
      const [advice, quickWins] = await Promise.all([
        fetchData("/api/v1/budget/advice"),
        fetchData("/api/v1/budget/quick-wins"),
      ]);
      renderBudgetAdvice(advice, quickWins);
    }

    function renderEcosystem(payload){
      const casura = payload && payload.casura && payload.casura.value ? payload.casura.value : {};
      const aabb = payload && payload.aabb && payload.aabb.value ? payload.aabb.value : {};
      const are = payload && payload.are && payload.are.value ? payload.are.value : {};
      const competitive = payload && payload.competitive && payload.competitive.value ? payload.competitive.value : {};

      const casuraEl = document.getElementById("eco-casura");
      if(casuraEl){
        const total = Number(casura.total_incidents || casura.total || 0);
        const severe = Number(casura.open_critical || casura.critical_open || 0);
        casuraEl.textContent = `Incidents: ${fmtNum(total)} · Critical open: ${fmtNum(severe)}`;
      }
      const aabbEl = document.getElementById("eco-aabb");
      if(aabbEl){
        const rows = Array.isArray(aabb.leaderboard) ? aabb.leaderboard.slice(0, 5) : [];
        if(!rows.length){
          aabbEl.textContent = "Leaderboard is empty.";
        } else {
          aabbEl.textContent = rows.map((row, idx)=> `${idx + 1}. ${row.agent_id || row.agent || "agent"} (${Number(row.score || 0).toFixed(2)})`).join(" · ");
        }
      }
      const areEl = document.getElementById("eco-are");
      if(areEl){
        const total = Number(are.total_slos || 0);
        const exhausted = Number(are.exhausted || 0);
        areEl.textContent = `SLOs: ${fmtNum(total)} · Exhausted budgets: ${fmtNum(exhausted)}`;
      }
      const cmpEl = document.getElementById("eco-competitive");
      if(cmpEl){
        const rows = Array.isArray(competitive.alerts) ? competitive.alerts.slice(0, 5) : [];
        cmpEl.textContent = rows.length ? rows.map((row)=> String(row.title || row.event || "alert")).join(" · ") : "No competitive alerts.";
      }
    }

    async function pollEcosystem() {
      const [casura, aabb, are, competitive] = await Promise.allSettled([
        fetch('/api/v1/casura/incidents/stats'),
        fetch('/api/v1/aabb/leaderboard'),
        fetch('/api/v1/are/report'),
        fetch('/api/v1/competitive/latest'),
      ]);
      async function toJson(result){
        if(!result || result.status !== "fulfilled"){ return {}; }
        const response = result.value;
        if(!response || typeof response.ok !== "boolean" || !response.ok){ return {}; }
        try { return await response.json(); } catch(_err) { return {}; }
      }
      renderEcosystem({
        casura: { value: await toJson(casura) },
        aabb: { value: await toJson(aabb) },
        are: { value: await toJson(are) },
        competitive: { value: await toJson(competitive) },
      });
    }

    function renderChannels(payload){
      const statuses = payload && payload.statuses && typeof payload.statuses === "object" ? payload.statuses : {};
      const alerts = Array.isArray(payload && payload.alerts) ? payload.alerts : [];
      const tg = document.getElementById("telegram-status");
      if(tg){ tg.textContent = `Status: ${String(statuses.telegram || "unknown")}`; }
      const wa = document.getElementById("whatsapp-status");
      if(wa){ wa.textContent = `Status: ${String(statuses.whatsapp || "unknown")}`; }
      const wc = document.getElementById("webchat-status");
      if(wc){ wc.textContent = `Status: ${String(statuses.webchat || "unknown")}`; }
      const alertsEl = document.getElementById("channel-alerts");
      if(alertsEl){
        alertsEl.textContent = alerts.length
          ? alerts.map((a)=> `${String(a.channel || "channel")}: ${String(a.type || "alert")}`).join(" · ")
          : "No alerts.";
      }
    }

    async function pollChannels() {
      const resp = await fetch('/api/v1/channels/health');
      const data = await resp.json();
      renderChannels(data);
    }

    function renderResearch({metrics, theorems}) {
      const metricsData = metrics && metrics.value ? metrics.value : {};
      const theoremData = theorems && theorems.value ? theorems.value : {};
      const resultsRoot = document.getElementById("nlce-confirmed-results");
      if(resultsRoot){
        resultsRoot.innerHTML = `
          <div class="panel panel-primary">
            <div class="section-title"><strong>Confirmed NLCE results</strong></div>
            <div>Zipf α: <strong>${Number(metricsData.zipf_alpha || 0).toFixed(3)}</strong></div>
            <div>N*: <strong>${Number(metricsData.n_star || 0).toFixed(0)}</strong></div>
            <div>Overhead: <strong>${Number(metricsData.overhead_ms || 0).toFixed(1)} ms</strong></div>
          </div>
        `;
      }
      const theoremRoot = document.getElementById("nlce-theorems");
      if(theoremRoot){
        const rows = Array.isArray(theoremData.theorems) ? theoremData.theorems : ["T1", "T2", "T3", "T4", "T5"];
        theoremRoot.innerHTML = `
          <div class="panel">
            <div class="section-title"><strong>Impossibility theorems T1-T5</strong></div>
            <ul>${rows.map((row)=> `<li>${String(row)}</li>`).join("")}</ul>
          </div>
        `;
      }
      const pipelineRoot = document.getElementById("nlce-pipeline-state");
      if(pipelineRoot){
        pipelineRoot.innerHTML = `
          <div class="panel">
            <div class="section-title"><strong>Current pipeline state</strong></div>
            <div>Ψ: <strong>${Number(metricsData.psi || 0.5).toFixed(3)}</strong></div>
            <div>phase: <strong>${String(metricsData.phase || "LIQUID")}</strong></div>
            <div>slope_alert: <strong>${Boolean(metricsData.slope_alert) ? "true" : "false"}</strong></div>
            <div style="margin-top:8px;">Token Yield chart (placeholder): <strong>${Number(metricsData.token_yield || 0).toFixed(2)}</strong></div>
          </div>
        `;
      }
    }

    async function pollResearch() {
      const [metrics, theorems] = await Promise.allSettled([
        fetch('/api/v1/nlce/metrics'),
        fetch('/api/v1/nlce/impossibility-theorems'),
      ]);
      async function toJson(result){
        if(!result || result.status !== "fulfilled"){ return {}; }
        const response = result.value;
        if(!response || typeof response.ok !== "boolean" || !response.ok){ return {}; }
        try { return await response.json(); } catch(_err) { return {}; }
      }
      renderResearch({
        metrics: { value: await toJson(metrics) },
        theorems: { value: await toJson(theorems) },
      });
    }

    async function pollTab(tab, shared){
      if(tab === "shield") return pollShield(shared);
      if(tab === "agents") return pollAgents();
      if(tab === "sessions") return pollSessions();
      if(tab === "flow") return pollFlow();
      if(tab === "experiments") return pollExperiments(shared);
      if(tab === "threats") return pollThreats();
      if(tab === "cache") return pollCache(shared);
      if(tab === "cost") return pollCost();
      if(tab === "research") return pollResearch();
      if(tab === "compliance") return pollCompliance(shared);
      if(tab === "overwatch") return pollOverwatch();
      if(tab === "channels") return pollChannels();
      if(tab === "ecosystem") return pollEcosystem();
      if(tab === "approvals") return pollApprovals();
    }

    async function pollCurrent(shared){
      return pollTab(currentTab, shared);
    }

    function showDashboardLoading(){
      const eventsEl = document.getElementById("events");
      if(eventsEl && !eventsEl.innerHTML.trim()){
        eventsEl.textContent = "Loading...";
      }
    }

    function showDashboardError(){
      if(_dashboardErrorShown){ return; }
      _dashboardErrorShown = true;
      const eventsEl = document.getElementById("events");
      if(eventsEl){
        eventsEl.textContent = "Dashboard: connection error, retrying...";
      }
    }

    async function refreshDashboard(){
      if (_refreshInProgress) { return; }
      _refreshInProgress = true;
      try {
        refreshCacheTtl();
        const snapshot = await getOverviewSnapshot();
        const stats = await getStatsSnapshot();
        if(!snapshot || !stats){
          showDashboardError();
          return;
        }
        const hash = JSON.stringify({ overview: snapshot, stats });
        if(hash === _lastDataHash){
          return;
        }
        _lastDataHash = hash;
        _dashboardErrorShown = false;
        await pollCurrent({ overview: snapshot, stats });
      } catch (e) {
        console.error("Dashboard refresh failed:", e);
        showDashboardError();
      } finally {
        _refreshInProgress = false;
      }
    }

    function switchTab(tab){
      currentTab = tab;
      _activeTab = tab;
      document.querySelectorAll(".tab-btn[data-tab]").forEach((btn)=>{
        const isActive = btn.dataset.tab === tab;
        btn.classList.toggle("active", isActive);
        btn.setAttribute("aria-selected", isActive ? "true" : "false");
        btn.setAttribute("tabindex", isActive ? "0" : "-1");
      });
      document.querySelectorAll(".screen").forEach((el)=>{
        const isActive = el.id === tab;
        el.classList.toggle("active", isActive);
        el.classList.toggle("hidden", !isActive);
        el.setAttribute("aria-hidden", isActive ? "false" : "true");
      });
      if (!loadedTabs.has(tab)) {
        loadedTabs.add(tab);
        pollTab(tab);
      } else {
        pollCurrent();
      }
      applyPollIntervals();
    }

    function bindUI(){
      document.addEventListener("keydown", handleKeydown);
      document.querySelectorAll(".tab-btn[data-tab]").forEach((btn)=>{
        btn.addEventListener("click", ()=> switchTab(btn.dataset.tab));
      });
      const shortcutsCloseBtn = document.getElementById("shortcuts-close-btn");
      if(shortcutsCloseBtn){
        shortcutsCloseBtn.addEventListener("click", ()=> closeShortcutsModal());
      }
      const shortcutsModal = document.getElementById("shortcuts-modal");
      if(shortcutsModal){
        shortcutsModal.addEventListener("click", (event)=>{
          if(event.target === shortcutsModal){ closeShortcutsModal(); }
        });
      }
      const changelogModal = document.getElementById("changelog-modal");
      if(changelogModal){
        changelogModal.addEventListener("click", (event)=>{
          if(event.target === changelogModal){ closeChangelog(); }
        });
      }
      document.addEventListener("click", (event)=>{
        const root = document.querySelector(".search-wrap");
        if(root && event && !root.contains(event.target)){ hideSearchResults(); }
      });
      const profileSelect = document.getElementById("agent-profile-select");
      if(profileSelect){
        profileSelect.addEventListener("change", ()=>{
          selectedAgentProfileId = profileSelect.value || "";
          loadAgentProfile(selectedAgentProfileId);
        });
      }
      document.getElementById("flow-session-select").addEventListener("change", ()=> pollFlow());
      const requestSearch = document.getElementById("request-inspector-search");
      if(requestSearch){
        requestSearch.addEventListener("input", ()=> renderRequestInspectorList());
      }
      const flowListBtn = document.getElementById("flow-view-list");
      const flowTimelineBtn = document.getElementById("flow-view-timeline");
      function applyFlowViewMode(){
        const listView = document.getElementById("flow-list-view");
        const timelineView = document.getElementById("flow-timeline-view");
        if(listView){ listView.style.display = flowViewMode === "list" ? "block" : "none"; }
        if(timelineView){ timelineView.style.display = flowViewMode === "timeline" ? "block" : "none"; }
      }
      if(flowListBtn){
        flowListBtn.addEventListener("click", ()=>{
          flowViewMode = "list";
          applyFlowViewMode();
        });
      }
      if(flowTimelineBtn){
        flowTimelineBtn.addEventListener("click", ()=>{
          flowViewMode = "timeline";
          applyFlowViewMode();
          renderFlowTimeline(flowTimelinePayload);
        });
      }
      applyFlowViewMode();
      const flowShareBtn = document.getElementById("flow-share-btn");
      if(flowShareBtn){
        flowShareBtn.addEventListener("click", async ()=>{
          const sid = (document.getElementById("flow-session-select") || {}).value || "";
          if(!sid){ return; }
          try {
            await shareFlowXRay(sid);
          } catch (_err) {
            const fallback = `http://localhost:8080/flow/${encodeURIComponent(sid)}`;
            copyText(fallback);
            showToast("Link copied!");
          }
        });
      }
      const communityToggle = document.getElementById("community-enabled-toggle");
      if(communityToggle){
        communityToggle.addEventListener("change", ()=> toggleCommunityIntel(Boolean(communityToggle.checked)));
      }
      const exportBtn = document.getElementById("export-compliance-btn");
      if(exportBtn){
        exportBtn.addEventListener("click", ()=>{
          window.open("/api/compliance/report?format=json", "_blank");
        });
      }
      const evidenceJsonBtn = document.getElementById("export-evidence-json-btn");
      const evidenceTextBtn = document.getElementById("export-evidence-text-btn");
      function syncEvidenceMeta(record){
        if(!record || typeof record !== "object"){ return; }
        const rid = document.getElementById("evidence-record-id");
        const sid = document.getElementById("evidence-session-id");
        const hash = document.getElementById("evidence-record-hash");
        if(rid){ rid.textContent = String(record.record_id || "--"); }
        if(sid){ sid.textContent = String(record.session_id || "--"); }
        if(hash){ hash.textContent = String((record.integrity || {}).record_hash || "--"); }
      }
      if(evidenceJsonBtn){
        evidenceJsonBtn.addEventListener("click", async ()=>{
          const sid = (prompt("Session ID for Evidence Record:", "") || "").trim();
          if(!sid){ return; }
          try{
            const record = await fetchData(`http://localhost:8090/api/v1/evidence/${encodeURIComponent(sid)}`);
            syncEvidenceMeta(record);
          }catch(_err){}
          window.open(`http://localhost:8090/api/v1/evidence/${encodeURIComponent(sid)}/download`, "_blank");
        });
      }
      if(evidenceTextBtn){
        evidenceTextBtn.addEventListener("click", ()=>{
          const sid = (prompt("Session ID for Evidence Record:", "") || "").trim();
          if(!sid){ return; }
          window.open(`http://localhost:8090/api/v1/evidence/${encodeURIComponent(sid)}/text`, "_blank");
        });
      }
      const owCards = document.getElementById("ow-view-cards");
      const owRadar = document.getElementById("ow-view-radar");
      const owTeams = document.getElementById("ow-view-teams");
      const owGraph = document.getElementById("ow-view-graph");
      const cardsView = document.getElementById("ow-cards-view");
      const radarView = document.getElementById("ow-radar-view");
      const teamsView = document.getElementById("ow-teams-view");
      const graphView = document.getElementById("ow-graph-view");
      if (owCards && owRadar && owTeams && owGraph && cardsView && radarView && teamsView && graphView) {
        owCards.addEventListener("click", ()=>{
          overwatchView = "cards";
          owCards.classList.add("active");
          owRadar.classList.remove("active");
          owTeams.classList.remove("active");
          owGraph.classList.remove("active");
          cardsView.style.display = "";
          radarView.style.display = "none";
          teamsView.style.display = "none";
          graphView.style.display = "none";
        });
        owRadar.addEventListener("click", ()=>{
          overwatchView = "radar";
          owRadar.classList.add("active");
          owCards.classList.remove("active");
          owTeams.classList.remove("active");
          owGraph.classList.remove("active");
          radarView.style.display = "";
          cardsView.style.display = "none";
          teamsView.style.display = "none";
          graphView.style.display = "none";
          if (overwatchSnapshot) renderOverwatchRadar(overwatchSnapshot);
        });
        owTeams.addEventListener("click", ()=>{
          overwatchView = "teams";
          owTeams.classList.add("active");
          owCards.classList.remove("active");
          owRadar.classList.remove("active");
          owGraph.classList.remove("active");
          teamsView.style.display = "";
          cardsView.style.display = "none";
          radarView.style.display = "none";
          graphView.style.display = "none";
          if (overwatchSnapshot) renderOverwatchTeams(overwatchSnapshot);
        });
        owGraph.addEventListener("click", ()=>{
          overwatchView = "graph";
          owGraph.classList.add("active");
          owCards.classList.remove("active");
          owRadar.classList.remove("active");
          owTeams.classList.remove("active");
          graphView.style.display = "";
          cardsView.style.display = "none";
          radarView.style.display = "none";
          teamsView.style.display = "none";
          if (overwatchSnapshot) renderOverwatchGraph(overwatchSnapshot);
        });
      }
      const owLoadDemo = document.getElementById("ow-load-demo");
      if (owLoadDemo) {
        owLoadDemo.addEventListener("click", ()=>{
          overwatchUseDemo = true;
          renderOverwatch(mockOverwatchData());
        });
      }
      const owShare = document.getElementById("ow-share");
      if (owShare) {
        owShare.addEventListener("click", ()=>{
          const model = overwatchSnapshot || normalizeOverwatch(mockOverwatchData());
          const s = model.summary || { active_agents: 0, total_cost_day_usd: 0, threats_blocked: 0 };
          const text = `My AI fleet: ${fmtNum(s.active_agents)} agents · ${fmtMoney(s.total_cost_day_usd)}/day · ${fmtNum(s.threats_blocked)} threats blocked · orchesis.io`;
          copyText(text);
        });
      }
    }

    async function boot(){
      const savedTheme = localStorage.getItem("orchesis-theme") || "dark";
      applyTheme(savedTheme);
      applyHighContrast(localStorage.getItem("orchesis-hc") === "true");
      bindUI();
      switchTab("shield");
      showDashboardLoading();
      renderNotifications();
      renderPerfIndicator();
      await refreshDashboard();
      await pollNotifications();
      applyPollIntervals();
      if(notifTimer){ clearInterval(notifTimer); }
      notifTimer = setInterval(()=>{ pollNotifications(); }, NOTIF_POLL_INTERVAL);
    }

    boot();
  </script>
</body>
</html>
"""
    banner = (
        '<div class="demo-banner">DEMO MODE — showing sample data. Install Orchesis to see real metrics.</div>'
        if demo_mode
        else ""
    )
    return html.replace("{{DEMO_BANNER}}", banner)
