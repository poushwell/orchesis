const TABS = [
  "Shield",
  "Agents",
  "Sessions",
  "Flow X-Ray",
  "Experiments",
  "Threats",
  "Cache",
  "Compliance"
];

function HexShield() {
  return (
    <svg className="brand-icon" viewBox="0 0 24 24" aria-hidden="true">
      <path
        d="M12 1.8 20 6.4v11.2L12 22.2 4 17.6V6.4L12 1.8Z"
        fill="rgba(168,85,247,0.15)"
        stroke="#a855f7"
        strokeWidth="1.4"
      />
      <path d="M12 7.2v9.3" stroke="#a855f7" strokeWidth="1.2" />
      <path d="M8.6 10.5h6.8" stroke="#a855f7" strokeWidth="1.2" />
    </svg>
  );
}

function formatUptime(seconds) {
  const total = Math.max(0, Number(seconds || 0));
  const h = Math.floor(total / 3600);
  const m = Math.floor((total % 3600) / 60);
  return `${h}h ${m}m uptime`;
}

export default function TabBar({ activeTab, onTabChange, connected, uptimeSeconds }) {
  return (
    <>
      <header className="topbar">
        <div className="topbar-left">
          <div className="brand">
            <HexShield />
            <span className="logo">Orchesis</span>
          </div>
          <div className="uptime">{formatUptime(uptimeSeconds)}</div>
        </div>
        <div className={`conn-pill ${connected ? "ok" : "bad"}`}>
          <span className={`dot ${connected ? "ok" : "bad"}`} />
          {connected ? "CONNECTED" : "DISCONNECTED"}
        </div>
      </header>
      <nav className="tabs">
        {TABS.map((tab) => (
          <button
            key={tab}
            className={`tab ${activeTab === tab ? "active" : ""}`}
            onClick={() => onTabChange(tab)}
            type="button"
          >
            {tab}
          </button>
        ))}
      </nav>
    </>
  );
}
