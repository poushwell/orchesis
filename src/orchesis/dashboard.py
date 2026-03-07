"""Embedded single-file dashboard HTML for Orchesis proxy."""

from __future__ import annotations


def get_dashboard_html() -> str:
    """Return a fully self-contained dashboard HTML page."""
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Orchesis Dashboard</title>
  <style>
    :root {
      --bg: #0A0A12;
      --panel: rgba(255,255,255,0.03);
      --border: rgba(255,255,255,0.06);
      --text: #E8E8F0;
      --text-secondary: #6B6B80;
      --ok: #00E5A0;
      --warn: #FFB800;
      --danger: #FF3B5C;
      --info: #5AA8FF;
      --radius: 12px;
      --radius-sm: 8px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: system-ui, -apple-system, sans-serif;
      background: radial-gradient(1200px 600px at 20% -20%, #18203A 0%, var(--bg) 55%);
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
      background: var(--panel);
      border: 1px solid var(--border);
      border-radius: var(--radius);
      backdrop-filter: blur(12px);
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
    .brand .logo { font-size: 19px; }
    .badges { display: flex; gap: 10px; align-items: center; }
    .badge {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 4px 10px;
      font-size: 12px;
      color: var(--text-secondary);
      background: rgba(255,255,255,0.02);
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
      background: rgba(255,255,255,0.02);
      color: var(--text);
      padding: 8px 12px;
      cursor: pointer;
      font-weight: 600;
    }
    .tab-btn.active {
      border-color: rgba(0,229,160,0.45);
      box-shadow: inset 0 0 0 1px rgba(0,229,160,0.2);
      color: var(--ok);
    }
    .screen { display: none; gap: 12px; }
    .screen.active { display: grid; animation: fadeIn 0.25s ease; }
    @keyframes fadeIn {
      from { opacity: 0; }
      to { opacity: 1; }
    }
    .grid-4 { display: grid; gap: 12px; grid-template-columns: repeat(4, minmax(160px, 1fr)); }
    .grid-2 { display: grid; gap: 12px; grid-template-columns: 1.4fr 1fr; }
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
    @media (max-width: 1100px) {
      .grid-4 { grid-template-columns: repeat(2, minmax(160px, 1fr)); }
      .grid-2 { grid-template-columns: 1fr; }
      .score-gauge { grid-template-columns: 1fr; }
    }
  </style>
</head>
<body>
  <div class="app">
    <div class="topbar">
      <div class="brand"><span class="logo">🛡️ Orchesis</span><span class="subtle">Dashboard MVP</span></div>
      <div class="badges">
        <span class="badge"><span id="conn-dot" class="conn-dot"></span><span id="conn-text">Connected</span></span>
        <span class="badge" id="status-badge">Status: --</span>
      </div>
    </div>

    <div class="tabs">
      <button class="tab-btn active" data-tab="shield">🛡️ Shield</button>
      <button class="tab-btn" data-tab="agents">🤖 Agents</button>
      <button class="tab-btn" data-tab="sessions">💾 Sessions</button>
      <button class="tab-btn" data-tab="flow">🔬 Flow X-Ray</button>
      <button class="tab-btn" data-tab="experiments">🧪 Experiments</button>
      <button class="tab-btn" data-tab="threats">🛡️ Threats</button>
      <button class="tab-btn" data-tab="cache">⚡ Cache</button>
      <button class="tab-btn" data-tab="compliance">📘 Compliance</button>
    </div>

    <section id="shield" class="screen active">
      <div class="panel hero">
        <div id="hero-pulse" class="pulse status-clear"></div>
        <div>
          <div id="hero-label" class="metric-value">ALL CLEAR</div>
          <div class="subtle">Uptime: <span id="hero-uptime">--</span></div>
        </div>
      </div>
      <div class="grid-4">
        <div class="panel">
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
          <div class="subtle">🤖 Active Agents</div>
          <div id="m-agents" class="metric-value" data-raw="0">0</div>
          <svg id="spark-agents" class="sparkline" viewBox="0 0 60 20" preserveAspectRatio="none"></svg>
        </div>
      </div>
      <div class="grid-2">
        <div class="panel">
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
        <div><strong>Recent Events</strong></div>
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

    <section id="experiments" class="screen">
      <div class="grid-4">
        <div class="panel"><div class="subtle">Active Experiments</div><div id="exp-active" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Total Assignments</div><div id="exp-assignments" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Task Success Rate</div><div id="exp-success-rate" class="metric-value">0%</div></div>
        <div class="panel"><div class="subtle">Tracked Sessions</div><div id="exp-sessions" class="metric-value">0</div></div>
      </div>
      <div id="exp-cards"></div>
      <div class="panel">
        <strong>Task Correlations & Insights</strong>
        <div id="exp-correlations" class="event-feed"></div>
      </div>
      <div class="panel">
        <strong>Outcome Distribution</strong>
        <div id="exp-outcome-bar" class="outcome-bar"></div>
        <div id="exp-outcomes" class="grid-4"></div>
      </div>
    </section>

    <section id="threats" class="screen">
      <div class="grid-4">
        <div class="panel"><div class="subtle">Signatures</div><div id="th-sigs" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Scans</div><div id="th-scans" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Matches</div><div id="th-matches" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Blocks</div><div id="th-blocks" class="metric-value">0</div></div>
      </div>
      <div class="panel">
        <strong>Top Threats</strong>
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

    <section id="cache" class="screen">
      <div class="grid-4">
        <div class="panel"><div class="subtle">Cache Hit Rate</div><div id="c-hit-rate" class="metric-value">0%</div></div>
        <div class="panel"><div class="subtle">Tokens Saved</div><div id="c-tokens" class="metric-value">0</div></div>
        <div class="panel"><div class="subtle">Cost Saved</div><div id="c-cost" class="metric-value">$0.00</div></div>
        <div class="panel"><div class="subtle">Entries</div><div id="c-entries" class="metric-value">0/0</div></div>
      </div>
      <div class="panel">
        <strong>Semantic Cache</strong>
        <div id="c-semantic-breakdown"></div>
      </div>
      <div class="panel">
        <strong>Context Engine</strong>
        <div id="c-context"></div>
      </div>
    </section>

    <section id="agents" class="screen">
      <div class="panel">
        <div><strong>Agent DNA</strong></div>
        <div id="agents-empty" class="empty" style="display:none;">No agent sessions recorded yet.</div>
        <table id="agents-table" class="table">
          <thead><tr><th>Agent ID</th><th>Requests</th><th>Avg Tokens</th><th>Anomaly</th><th>Tools</th><th>Last Seen</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </section>

    <section id="sessions" class="screen">
      <div class="panel">
        <div><strong>Time Machine Sessions</strong></div>
        <div id="sessions-empty" class="empty" style="display:none;">No sessions recorded yet.</div>
        <table id="sessions-table" class="table">
          <thead><tr><th>Session</th><th>Start</th><th>Duration</th><th>Requests</th><th>Cost</th><th>Errors</th><th>Status</th><th>Export</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </section>

    <section id="flow" class="screen">
      <div class="panel">
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
          <strong>Flow X-Ray</strong>
          <select id="flow-session-select" class="tab-btn" style="padding:6px 10px;"></select>
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
        <div id="patterns-empty" class="empty" style="display:none;">No patterns detected.</div>
        <div id="patterns"></div>
      </div>
    </section>

    <section id="compliance" class="screen">
      <div class="grid-2">
        <div class="panel">
          <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;">
            <strong>Compliance Coverage Overview</strong>
            <button id="export-compliance-btn" class="tab-btn" style="padding:6px 10px;">Export Report JSON</button>
          </div>
          <div class="grid-2" style="margin-top:10px;">
            <div class="panel">
              <div class="subtle">OWASP LLM Top 10</div>
              <div id="cmp-owasp-percent" class="metric-value">0%</div>
              <div class="progress"><div id="cmp-owasp-bar" style="width:0%"></div></div>
            </div>
            <div class="panel">
              <div class="subtle">NIST AI RMF</div>
              <div id="cmp-nist-percent" class="metric-value">0%</div>
              <div class="progress"><div id="cmp-nist-bar" style="width:0%"></div></div>
            </div>
          </div>
        </div>
        <div class="panel">
          <strong>Recent Compliance Findings</strong>
          <div id="cmp-findings" class="event-feed"></div>
        </div>
      </div>
      <div class="panel">
        <strong>OWASP Top 10 Coverage</strong>
        <table id="cmp-owasp-table" class="table">
          <thead><tr><th>ID</th><th>Name</th><th>Status</th><th>Modules</th></tr></thead>
          <tbody></tbody>
        </table>
      </div>
    </section>
  </div>

  <script>
    const POLL_INTERVAL = 3000;
    let currentTab = "shield";
    let pollTimer = null;
    let lastOverview = null;
    const sparkHistory = {};
    const SPARK_MAX = 20;

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
    }

    function setStatus(status){
      const pulse = document.getElementById("hero-pulse");
      const label = document.getElementById("hero-label");
      const badge = document.getElementById("status-badge");
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
      badge.textContent = "Status: " + (status || "--");
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

    function renderOverview(data, stats, savings){
      if(!data){ return; }
      lastOverview = data;
      setStatus(data.status || "clear");
      document.getElementById("hero-uptime").textContent = fmtDuration(data.uptime_seconds || 0);
      const blocked = Number(data.blocked_requests || 0);
      const total = Math.max(1, Number(data.total_requests || 0));
      updateAnimatedMetric("m-requests", Number(data.total_requests || 0), (v)=>Math.round(v).toLocaleString());
      updateAnimatedMetric("m-blocked", blocked, (v)=>`${Math.round(v).toLocaleString()} (${((v/total)*100).toFixed(1)}%)`);
      updateAnimatedMetric("m-cost", Number(data.total_cost_usd || 0), (v)=>"$" + Number(v || 0).toFixed(2));
      updateAnimatedMetric("m-agents", Number(data.active_agents || 0), (v)=>Math.round(v).toLocaleString());
      updateSparkline("requests", Number(data.total_requests || 0));
      updateSparkline("blocked", blocked);
      updateSparkline("cost", Number(data.total_cost_usd || 0));
      updateSparkline("agents", Number(data.active_agents || 0));

      const ti = (stats && stats.threat_intel) ? stats.threat_intel : {};
      const sc = (stats && stats.semantic_cache) ? stats.semantic_cache : {};
      const exp = (stats && stats.experiments) ? stats.experiments : {};
      const task = (stats && stats.task_tracking) ? stats.task_tracking : {};
      updateAnimatedMetric("m-threats", Number(ti.total_matches || 0), (v)=>Math.round(v).toLocaleString());
      updateAnimatedMetric("m-cache-rate", Number(sc.hit_rate_percent || 0), (v)=>Number(v || 0).toFixed(1) + "%");
      updateAnimatedMetric("m-experiments", Number(exp.active || 0), (v)=>Math.round(v).toLocaleString());
      const sr = Number(task.overall_success_rate || 0);
      updateAnimatedMetric("m-task-success", sr * 100, (v)=>Number(v || 0).toFixed(1) + "%");

      const eventsEl = document.getElementById("events");
      eventsEl.innerHTML = "";
      const events = Array.isArray(data.recent_events) ? data.recent_events.slice(0, 10) : [];
      if(events.length === 0){
        eventsEl.innerHTML = `<div class="empty">No recent events.</div>`;
      }else{
        events.forEach((ev)=>{
          const sev = String(ev.severity || "info").toLowerCase();
          const type = String(ev.type || "event").toUpperCase();
          const row = document.createElement("div");
          row.className = "event event-item";
          row.innerHTML = `<span class="subtle">${fmtTs(ev.timestamp)}</span><span class="sev ${sev}">${type}</span><span>${ev.description || ""}</span>`;
          eventsEl.appendChild(row);
        });
      }

      const cb = data.circuit_breakers || {};
      const cbEl = document.getElementById("cb-list");
      const names = Object.keys(cb);
      if(names.length === 0){
        cbEl.innerHTML = `<div class="empty">No circuit breaker data.</div>`;
      }else{
        cbEl.innerHTML = names.map((name)=>{
          const st = String(cb[name].state || "closed").toLowerCase();
          return `<div style="display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid var(--border);"><span>${name}</span><span class="cb-pill ${st}">${st}</span><span class="subtle">failures: ${fmtNum(cb[name].failures||0)}</span></div>`;
        }).join("");
      }

      const pool = data.connection_pool || {};
      const poolEl = document.getElementById("pool-stats");
      const hits = Number(pool.hits || 0);
      const misses = Number(pool.misses || 0);
      const ratio = (hits + misses) > 0 ? (hits / (hits + misses) * 100.0) : 0.0;
      const hosts = pool.pools || {};
      const hostRows = Object.keys(hosts).map((k)=> `${k}: ${hosts[k]}`).join(" | ");
      poolEl.innerHTML = `
        <div>active: ${fmtNum(pool.active || 0)}, total: ${fmtNum(pool.total_connections || 0)}</div>
        <div>hits/misses: ${fmtNum(hits)}/${fmtNum(misses)} (${ratio.toFixed(1)}% hit)</div>
        <div class="subtle">${hostRows || "no hosts"}</div>
      `;

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
      table.innerHTML = "";
      const agents = (data && Array.isArray(data.agents)) ? data.agents : [];
      if(agents.length === 0){
        empty.style.display = "block";
        document.getElementById("agents-table").style.display = "none";
        return;
      }
      empty.style.display = "none";
      document.getElementById("agents-table").style.display = "table";
      agents.forEach((a)=>{
        const score = Number(a.anomaly_score || 0);
        const pct = Math.max(0, Math.min(100, score*100));
        const color = pct > 70 ? "var(--danger)" : (pct > 35 ? "var(--warn)" : "var(--ok)");
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${a.agent_id || "unknown"}</strong><div class="subtle">${a.state || ""}</div></td>
          <td>${fmtNum(a.total_requests)}</td>
          <td>${fmtNum(a.avg_tokens)}</td>
          <td><div class="progress"><div style="width:${pct.toFixed(1)}%;background:${color};"></div></div><div class="subtle">${score.toFixed(3)}</div></td>
          <td>${(a.tools_used || []).slice(0,4).join(", ") || "-"}</td>
          <td>${a.last_seen || "-"}</td>
        `;
        table.appendChild(tr);
      });
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
        const status = Number(s.error_count || 0) > 0 ? "issues" : "ok";
        const sid = String(s.session_id || "");
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td><strong>${sid.slice(0,12)}</strong></td>
          <td>${fmtTs(s.start_time)}</td>
          <td>${fmtDuration((Number(s.end_time||0)-Number(s.start_time||0)))}</td>
          <td>${fmtNum(s.request_count)}</td>
          <td>${fmtMoney(s.total_cost || 0)}</td>
          <td>${fmtNum(s.error_count)}</td>
          <td><span class="cb-pill ${status==='ok'?'closed':'open'}">${status}</span></td>
          <td><button class="tab-btn export-air-btn" data-session-id="${sid}" style="padding:5px 9px;">Export .air</button></td>
        `;
        table.appendChild(tr);
      });
      document.querySelectorAll(".export-air-btn").forEach((btn)=>{
        btn.addEventListener("click", ()=>{
          const sid = String(btn.getAttribute("data-session-id") || "");
          if(!sid){ return; }
          window.open(`/api/sessions/${encodeURIComponent(sid)}/export?download=true&content_level=full`, "_blank");
        });
      });
    }

    function renderFlowAnalysis(analysis, graph){
      if(!analysis){
        document.getElementById("patterns").innerHTML = "";
        document.getElementById("patterns-empty").style.display = "block";
        renderFlowGraph(null);
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
      if(patterns.length === 0){
        document.getElementById("patterns-empty").style.display = "block";
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

    function renderExperiments(experiments, outcomes, correlations, stats){
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
      const running = exps.filter((e)=> String(e.status || "").toLowerCase() === "running");
      if(running.length === 0){
        cards.innerHTML = `<div class="panel empty">Not configured or no active experiments.</div>`;
      }else{
        running.forEach((exp)=>{
          const card = document.createElement("div");
          card.className = "panel";
          card.innerHTML = `<strong>${exp.name || "Experiment"}</strong> <span class="cb-pill closed">RUNNING</span>`;
          const expId = String(exp.experiment_id || exp.id || "");
          if(expId){
            fetchData(`/api/experiments/${encodeURIComponent(expId)}/live`).then((live)=>{
              if(live){
                const requests = Number(live.total_requests || 0);
                card.innerHTML += `<div class="subtle">Live requests: ${fmtNum(requests)}</div>`;
              }
            });
          }
          cards.appendChild(card);
        });
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
      document.getElementById("c-hit-rate").textContent = (sc.hit_rate_percent != null ? sc.hit_rate_percent.toFixed(1) : "0") + "%";
      document.getElementById("c-tokens").textContent = fmtNum((sc.total_tokens_saved || 0) + (ce.total_tokens_saved || 0));
      document.getElementById("c-cost").textContent = fmtMoney(sc.total_cost_saved_usd || 0);
      document.getElementById("c-entries").textContent = `${fmtNum(sc.entries || 0)}/${fmtNum(sc.max_entries || 0)}`;

      const semEl = document.getElementById("c-semantic-breakdown");
      if(!sc.enabled){
        semEl.innerHTML = `<div class="empty">Semantic cache not configured.</div>`;
      }else{
        const exact = Number(sc.exact_hits || 0);
        const sem = Number(sc.semantic_hits || 0);
        const miss = Number(sc.misses || 0);
        const tot = exact + sem + miss || 1;
        semEl.innerHTML = `
          <div>Exact hits: ${fmtNum(exact)} | Semantic hits: ${fmtNum(sem)} | Misses: ${fmtNum(miss)}</div>
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

    function renderCompliance(summary, coverage, findings){
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
        findingsEl.innerHTML = `<div class="empty">No compliance findings.</div>`;
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
    }

    async function pollShield(){
      const [data, stats, savings] = await Promise.all([
        fetchData("/api/dashboard/overview"),
        fetchData("/stats"),
        fetchData("/api/v1/savings"),
      ]);
      renderOverview(data, stats, savings);
    }
    async function pollAgents(){
      const data = await fetchData("/api/dashboard/agents");
      renderAgents(data);
    }
    async function pollSessions(){
      const data = await fetchData("/api/sessions");
      renderSessions(data);
    }
    async function pollFlow(){
      const sessionsResp = await fetchData("/api/flow/sessions");
      const sessions = (sessionsResp && Array.isArray(sessionsResp.sessions)) ? sessionsResp.sessions : [];
      const select = document.getElementById("flow-session-select");
      const current = select.value;
      select.innerHTML = sessions.map((s)=> `<option value="${s.id}">${s.id}</option>`).join("");
      if(current && sessions.some((s)=>s.id === current)){ select.value = current; }
      const sid = select.value || (sessions[0] ? sessions[0].id : "");
      if(!sid){ renderFlowAnalysis(null, null); return; }
      const [analysis, graph] = await Promise.all([
        fetchData(`/api/flow/analyze/${encodeURIComponent(sid)}`),
        fetchData(`/api/flow/graph/${encodeURIComponent(sid)}`)
      ]);
      renderFlowAnalysis(analysis, graph);
    }
    async function pollCompliance(){
      const [summary, coverage, findings] = await Promise.all([
        fetchData("/api/compliance/summary"),
        fetchData("/api/compliance/coverage"),
        fetchData("/api/compliance/findings?limit=10")
      ]);
      renderCompliance(summary, coverage, findings);
    }

    async function pollExperiments(){
      const [experiments, outcomes, correlations, stats] = await Promise.all([
        fetchData("/api/experiments"),
        fetchData("/api/tasks/outcomes"),
        fetchData("/api/tasks/correlations"),
        fetchData("/stats"),
      ]);
      renderExperiments(experiments, outcomes, correlations, stats);
    }

    async function pollThreats(){
      const [threats, stats] = await Promise.all([
        fetchData("/api/threats"),
        fetchData("/api/threats/stats"),
      ]);
      renderThreats(threats, stats);
    }

    async function pollCache(){
      const stats = await fetchData("/stats");
      renderCache(stats);
    }

    async function pollCurrent(){
      if(currentTab === "shield") return pollShield();
      if(currentTab === "agents") return pollAgents();
      if(currentTab === "sessions") return pollSessions();
      if(currentTab === "flow") return pollFlow();
      if(currentTab === "experiments") return pollExperiments();
      if(currentTab === "threats") return pollThreats();
      if(currentTab === "cache") return pollCache();
      if(currentTab === "compliance") return pollCompliance();
    }

    function switchTab(tab){
      currentTab = tab;
      document.querySelectorAll(".tab-btn").forEach((btn)=>{
        btn.classList.toggle("active", btn.dataset.tab === tab);
      });
      document.querySelectorAll(".screen").forEach((el)=>{
        el.classList.toggle("active", el.id === tab);
      });
      pollCurrent();
    }

    function bindUI(){
      document.querySelectorAll(".tab-btn").forEach((btn)=>{
        btn.addEventListener("click", ()=> switchTab(btn.dataset.tab));
      });
      document.getElementById("flow-session-select").addEventListener("change", ()=> pollFlow());
      const exportBtn = document.getElementById("export-compliance-btn");
      if(exportBtn){
        exportBtn.addEventListener("click", ()=>{
          window.open("/api/compliance/report?format=json", "_blank");
        });
      }
    }

    async function boot(){
      bindUI();
      await pollShield();
      if(pollTimer){ clearInterval(pollTimer); }
      pollTimer = setInterval(()=>{ pollCurrent(); }, POLL_INTERVAL);
    }

    boot();
  </script>
</body>
</html>
"""
