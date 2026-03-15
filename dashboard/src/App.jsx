import { useEffect, useMemo, useState } from "react";
import CostTimeline from "./components/charts/CostTimeline";
import MetricCard from "./components/MetricCard";
import TabBar from "./components/TabBar";
import ThreatLog from "./components/ThreatLog";
import { useApiPolling } from "./hooks/useApi";
import { getStoredTheme, applyTheme } from "./themes";
import { initEasterEggs } from "./easter-eggs";

function money(value) {
  return `$${Number(value || 0).toFixed(2)}`;
}

function number(value) {
  return Number(value || 0).toLocaleString();
}

function buildHistory(prev, key, value, max = 20) {
  const series = [...(prev[key] || []), Number(value || 0)];
  if (series.length > max) series.shift();
  return series;
}

function duration(seconds) {
  const sec = Math.max(0, Number(seconds || 0));
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  const s = Math.floor(sec % 60);
  if (h > 0) return `${h}h ${m}m ${s}s`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

function RadarIndicator({ alert }) {
  return (
    <div className={`radar ${alert ? "alert" : ""}`}>
      <span className="ring r1" />
      <span className="ring r2" />
      <span className="ring r3" />
      <span className="sweep" />
      <span className="core" />
    </div>
  );
}

function StatusHero({ status, threats }) {
  const normalized = String(status || "clear").toLowerCase();
  const alert = normalized === "alert";
  const label = alert ? "ALERT" : "ALL CLEAR";
  const color = alert ? "var(--red)" : "var(--green)";
  return (
    <div className={`status-hero ${alert ? "alert" : "clear"}`}>
      <RadarIndicator alert={alert} />
      <div>
        <div className="status-main" style={{ color }}>
          {label}
        </div>
        <div className="status-sub mono">
          17-PHASE PIPELINE · {Number(threats || 0)} THREATS DETECTED · MONITORING ACTIVE
        </div>
      </div>
    </div>
  );
}

export default function App() {
  const [tab, setTab] = useState("Shield");
  const [, setTheme] = useState("default");
  const [sparkData, setSparkData] = useState({});
  const { data, connected } = useApiPolling(tab);

  const overview = data.overview || {};
  const stats = data.stats || {};
  const events = Array.isArray(overview.recent_events) ? overview.recent_events : [];
  const threatStats = data.threatStats || {};
  const compliance = data.compliance || {};
  const agentsPayload = data.agents || {};
  const sessionsPayload = data.sessions || {};

  function renderAgents(payload) {
    const agents = Array.isArray(payload?.agents) ? payload.agents : [];
    if (agents.length === 0) {
      return <div className="empty">No agents detected yet</div>;
    }
    return (
      <div className="card">
        <h3>Agents</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Agent ID</th>
              <th>Status</th>
              <th>Requests</th>
              <th>Cost</th>
              <th>ARS Score</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((agent) => {
              const id = agent.agent_id || agent.id || "unknown";
              const status = String(agent.status || agent.state || "active");
              const req = Number(agent.total_requests || agent.requests_today || 0);
              const cost = Number(agent.total_cost_usd || agent.cost_day_usd || 0);
              const score = Number(agent.ars_score ?? agent.anomaly_score ?? 0);
              const grade = String(agent.ars_grade || "").toUpperCase();
              return (
                <tr key={String(id)}>
                  <td className="mono">{id}</td>
                  <td>{status}</td>
                  <td className="mono">{number(req)}</td>
                  <td className="mono">{money(cost)}</td>
                  <td className="mono">{grade ? `${grade} (${score.toFixed(1)})` : score.toFixed(3)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  }

  function renderSessions(payload) {
    const sessions = Array.isArray(payload?.sessions) ? payload.sessions : [];
    if (sessions.length === 0) {
      return <div className="empty">No sessions recorded</div>;
    }
    return (
      <div className="card">
        <h3>Sessions</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Session ID</th>
              <th>Agent</th>
              <th>Requests</th>
              <th>Duration</th>
              <th>Cost</th>
            </tr>
          </thead>
          <tbody>
            {sessions.map((session) => {
              const id = String(session.session_id || "");
              const start = Number(session.start_time || 0);
              const end = Number(session.end_time || 0);
              const dur = Number(session.duration_seconds || Math.max(0, end - start));
              const req = Number(session.request_count || session.requests || 0);
              const cost = Number(session.total_cost || session.cost_usd || 0);
              const agent = session.agent_id || session.agent || session.user || "unknown";
              return (
                <tr key={id || `${agent}-${start}`}>
                  <td className="mono">{id.slice(0, 12) || "unknown"}</td>
                  <td>{agent}</td>
                  <td className="mono">{number(req)}</td>
                  <td className="mono">{duration(dur)}</td>
                  <td className="mono">{money(cost)}</td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    );
  }

  function renderFlowAnalysis(overviewData) {
    const sessions = Array.isArray(sessionsPayload?.sessions) ? sessionsPayload.sessions : [];
    if (sessions.length === 0) {
      return <div className="empty">Select a session above</div>;
    }
    const blocked = Number(overviewData?.blocked_requests || 0);
    const status = blocked > 0 ? "block" : "pass";
    const phases = [
      "parse",
      "experiment",
      "flow_xray",
      "cascade",
      "circuit_breaker",
      "loop_detection",
      "behavioral",
      "mast_request",
      "auto_healing",
      "budget",
      "policy",
      "threat_intel",
      "model_router",
      "secrets",
      "context",
      "upstream",
      "post_upstream",
      "send"
    ];
    return (
      <div className="card">
        <h3>Flow X-Ray</h3>
        <div className="phase-list">
          {phases.map((phase) => (
            <div key={phase} className="phase-row">
              <span className={`phase-pill ${status === "block" ? "bad" : "ok"}`}>{status.toUpperCase()}</span>
              <span className="mono">{phase}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  function renderExperiments(statsPayload) {
    const exp = statsPayload?.experiments || {};
    const names = Array.isArray(exp.running_experiments)
      ? exp.running_experiments
      : Array.isArray(exp.experiments)
        ? exp.experiments.map((item) => item.name || item.id || "Experiment")
        : [];
    if (names.length === 0) {
      return <div className="empty">No experiments running</div>;
    }
    return (
      <div className="card">
        <h3>Experiments</h3>
        <table className="data-table">
          <thead>
            <tr>
              <th>Experiment</th>
              <th>Variant</th>
              <th>Requests</th>
              <th>P-value</th>
            </tr>
          </thead>
          <tbody>
            {names.map((name, index) => (
              <tr key={`${name}-${index}`}>
                <td>{name}</td>
                <td className="mono">-</td>
                <td className="mono">{number(exp.total_assignments || 0)}</td>
                <td className="mono">-</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    );
  }

  function renderCache(statsPayload) {
    const cache = statsPayload?.semantic_cache || {};
    if (!cache.enabled) {
      return <div className="empty">Semantic cache disabled</div>;
    }
    const hitRate = Number(cache.hit_rate_percent || 0);
    return (
      <div className="card">
        <h3>Cache</h3>
        <div className="cache-grid">
          <div className="cache-item">
            <span>Hit rate</span>
            <strong className="mono">{hitRate.toFixed(1)}%</strong>
            <div className="progress-track">
              <div className="progress-fill" style={{ width: `${Math.max(0, Math.min(100, hitRate))}%` }} />
            </div>
          </div>
          <div className="cache-item">
            <span>Exact hits</span>
            <strong className="mono">{number(cache.exact_hits)}</strong>
          </div>
          <div className="cache-item">
            <span>Semantic hits</span>
            <strong className="mono">{number(cache.semantic_hits)}</strong>
          </div>
          <div className="cache-item">
            <span>Entries</span>
            <strong className="mono">
              {number(cache.entries)}
              {cache.max_entries ? ` / ${number(cache.max_entries)}` : ""}
            </strong>
          </div>
        </div>
      </div>
    );
  }

  useEffect(() => {
    const stored = getStoredTheme();
    setTheme(applyTheme(stored));
    const cleanup = initEasterEggs(setTheme);
    return cleanup;
  }, []);

  useEffect(() => {
    setSparkData((prev) => ({
      requests: buildHistory(prev, "requests", overview.total_requests),
      blocked: buildHistory(prev, "blocked", overview.blocked_requests),
      cost: buildHistory(prev, "cost", overview.total_cost_usd),
      agents: buildHistory(prev, "agents", overview.active_agents)
    }));
  }, [overview.total_requests, overview.blocked_requests, overview.total_cost_usd, overview.active_agents]);

  const metrics = useMemo(
    () => [
      {
        title: "Total Requests",
        value: number(overview.total_requests),
        points: sparkData.requests || []
      },
      {
        title: "Blocked",
        value: number(overview.blocked_requests),
        points: sparkData.blocked || []
      },
      {
        title: "Cost",
        value: money(overview.total_cost_usd),
        points: sparkData.cost || []
      },
      {
        title: "Active Agents",
        value: number(overview.active_agents),
        points: sparkData.agents || []
      }
    ],
    [overview, sparkData]
  );

  return (
    <div className="app-shell">
      <TabBar
        activeTab={tab}
        onTabChange={setTab}
        connected={connected}
        uptimeSeconds={overview.uptime_seconds || stats.uptime_seconds || 0}
      />

      {tab === "Shield" && (
        <main className="tab-screen">
          <StatusHero status={overview.status} threats={threatStats.total_matches} />

          <section className="grid metrics-grid">
            {metrics.map((metric) => (
              <MetricCard
                key={metric.title}
                title={metric.title}
                value={metric.value}
                points={metric.points}
                tone={
                  metric.title === "Blocked" && Number(overview.blocked_requests || 0) > 0
                    ? "red"
                    : metric.title === "Blocked"
                      ? "green"
                      : "purple"
                }
                accent={
                  metric.title === "Blocked" && Number(overview.blocked_requests || 0) > 0
                    ? "var(--red)"
                    : metric.title === "Blocked"
                      ? "var(--green)"
                      : metric.title === "Active Agents"
                        ? "var(--purple)"
                        : "var(--text)"
                }
              />
            ))}
          </section>

          <section className="grid two-col">
            <CostTimeline points={overview.cost_timeline || []} />
            <section className="card savings">
              <h3>Cost Savings</h3>
              <div className="saving-total mono">{money(overview.money_saved_usd)}</div>
              <div className="saving-row">
                <span>Semantic Cache</span>
                <strong className="mono">{money((stats.semantic_cache || {}).total_cost_saved_usd)}</strong>
              </div>
              <div className="saving-row">
                <span>Cascade Routing</span>
                <strong className="mono">
                  {money(Number(stats.cascade_savings_today_usd || (stats.cascade || {}).cost_saved_usd || 0))}
                </strong>
              </div>
              <div className="saving-row">
                <span>Loop Prevention</span>
                <strong className="mono">
                  {money(Number((stats.loop_detection || {}).total_cost_saved_usd || 0))}
                </strong>
              </div>
              <div className="saving-row">
                <span>Context Trim</span>
                <strong className="mono">
                  {money(Number((stats.context_engine || {}).total_tokens_saved || 0) * 0.000003)}
                </strong>
              </div>
            </section>
          </section>

        </main>
      )}

      {tab === "Threats" && (
        <main className="tab-screen">
          <section className="grid metrics-grid">
            <MetricCard
              title="Signatures"
              value={number(threatStats.total_signatures)}
              points={sparkData.blocked || []}
            />
            <MetricCard title="Scans" value={number(threatStats.total_scans)} points={sparkData.requests || []} />
            <MetricCard title="Matches" value={number(threatStats.total_matches)} points={sparkData.blocked || []} />
            <MetricCard title="Blocks" value={number(threatStats.blocks)} points={sparkData.blocked || []} />
          </section>
          <ThreatLog events={events} />
        </main>
      )}

      {tab === "Compliance" && (
        <main className="tab-screen">
          <section className="card compliance-card">
            <h3>Compliance Coverage</h3>
            {[
              ["MAST", (overview.compliance_overview || {}).mast?.score || 0],
              ["OWASP", (overview.compliance_overview || {}).owasp_agentic_ai?.score || 0],
              ["EU AI Act", (overview.compliance_overview || {}).eu_ai_act?.score || 0],
              ["NIST", (overview.compliance_overview || {}).nist_ai_rmf?.score || 0]
            ].map(([label, value]) => (
              <div key={label} className="progress-row">
                <div className="progress-head">
                  <span>{label}</span>
                  <span className="progress-big mono">{Number(value).toFixed(1)}%</span>
                </div>
                <div className="progress-track">
                  <div
                    className="progress-fill"
                    style={{
                      width: `${Math.max(0, Math.min(100, Number(value)))}%`,
                      background:
                        Number(value) >= 90
                          ? "var(--green)"
                          : Number(value) >= 70
                            ? "var(--purple)"
                            : "var(--orange)"
                    }}
                  />
                </div>
              </div>
            ))}
          </section>
          <section className="card">
            <h3>Framework Summary</h3>
            {Object.keys(compliance.frameworks || {}).length === 0 ? (
              <div className="empty">No data yet</div>
            ) : (
              <div className="phase-list">
                {Object.entries(compliance.frameworks || {}).map(([key, value]) => (
                  <div key={key} className="phase-row">
                    <span className="phase-pill ok">{String(value?.status || "ok").toUpperCase()}</span>
                    <span className="mono">
                      {key} · {Number(value?.percent || 0).toFixed(1)}%
                    </span>
                  </div>
                ))}
              </div>
            )}
          </section>
        </main>
      )}

      {tab === "Agents" && <main className="tab-screen">{renderAgents(agentsPayload)}</main>}
      {tab === "Sessions" && <main className="tab-screen">{renderSessions(sessionsPayload)}</main>}
      {tab === "Flow X-Ray" && <main className="tab-screen">{renderFlowAnalysis(overview)}</main>}
      {tab === "Experiments" && <main className="tab-screen">{renderExperiments(stats)}</main>}
      {tab === "Cache" && <main className="tab-screen">{renderCache(stats)}</main>}
    </div>
  );
}
