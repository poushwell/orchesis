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
  const [theme, setTheme] = useState("default");
  const [sparkData, setSparkData] = useState({});
  const { data, connected } = useApiPolling(tab);

  const overview = data.overview || {};
  const stats = data.stats || {};
  const events = Array.isArray(overview.recent_events) ? overview.recent_events : [];
  const threatStats = data.threatStats || {};
  const compliance = data.compliance || {};

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

  const safetyRatio = Number(overview.total_requests || 0) > 0
    ? 100 - (Number(overview.blocked_requests || 0) / Number(overview.total_requests || 1)) * 100
    : 100;

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

          <section className="card shield-meta">
            <div className="meta-item">
              <span className="mono">SAFETY RATIO</span>
              <strong>{safetyRatio.toFixed(1)}%</strong>
            </div>
            <div className="meta-item">
              <span className="mono">THEME</span>
              <strong>{theme.toUpperCase()}</strong>
            </div>
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
            <pre className="json">{JSON.stringify(compliance.frameworks || {}, null, 2)}</pre>
          </section>
        </main>
      )}

      {["Agents", "Sessions", "Flow X-Ray", "Experiments", "Cache"].includes(tab) && (
        <main className="tab-screen">
          <section className="card">
            <h3>{tab}</h3>
            <div className="subtle">
              Live data is preserved from existing API endpoints. This tab is styled and ready for gradual component
              enrichment.
            </div>
            <pre className="json">
              {JSON.stringify(
                tab === "Agents"
                  ? data.agents
                  : tab === "Sessions"
                    ? data.sessions
                    : tab === "Cache"
                      ? data.stats
                      : data.overview,
                null,
                2
              )}
            </pre>
          </section>
        </main>
      )}
    </div>
  );
}
