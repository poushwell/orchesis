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

function StatusBadge({ status }) {
  const normalized = String(status || "clear").toLowerCase();
  const label = normalized === "alert" ? "ALERT" : normalized === "monitoring" ? "MONITORING" : "ALL CLEAR";
  return (
    <div className={`status-pill ${normalized}`}>
      <span className="pulse-dot" />
      {label}
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
      <TabBar activeTab={tab} onTabChange={setTab} connected={connected} />

      {tab === "Shield" && (
        <main className="tab-screen">
          <section className="hero card">
            <div>
              <div className="hero-title">Shield Status</div>
              <StatusBadge status={overview.status} />
            </div>
            <div className="hero-right">
              <div className="hero-kpi">
                <span>Safety Ratio</span>
                <strong>{safetyRatio.toFixed(1)}%</strong>
              </div>
              <div className="hero-kpi">
                <span>Theme</span>
                <strong>{theme.toUpperCase()}</strong>
              </div>
            </div>
          </section>

          <section className="grid metrics-grid">
            {metrics.map((metric) => (
              <MetricCard key={metric.title} title={metric.title} value={metric.value} points={metric.points} />
            ))}
          </section>

          <section className="grid two-col">
            <CostTimeline points={overview.cost_timeline || []} />
            <section className="card savings">
              <h3>Cost Savings</h3>
              <div className="saving-row">
                <span>Total</span>
                <strong>{money(overview.money_saved_usd)}</strong>
              </div>
              <div className="saving-row">
                <span>Cache</span>
                <strong>{money((stats.semantic_cache || {}).total_cost_saved_usd)}</strong>
              </div>
              <div className="saving-row">
                <span>Context</span>
                <strong>{number((stats.context_engine || {}).total_tokens_saved)} tokens</strong>
              </div>
              <div className="saving-row">
                <span>Velocity / h</span>
                <strong>{money((overview.cost_velocity || {}).current_rate_per_hour || 0)}</strong>
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
          <section className="card">
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
                  <span>{Number(value).toFixed(1)}%</span>
                </div>
                <div className="progress-bar">
                  <div className="progress-fill" style={{ width: `${Math.max(0, Math.min(100, Number(value)))}%` }} />
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
