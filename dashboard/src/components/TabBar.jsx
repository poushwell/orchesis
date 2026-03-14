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

export default function TabBar({ activeTab, onTabChange, connected }) {
  return (
    <>
      <header className="topbar">
        <div className="brand">
          <span className="logo">🛡 Orchesis</span>
          <span className="sub">Dashboard</span>
        </div>
        <div className="conn">
          <span className={`dot ${connected ? "ok" : "bad"}`} />
          {connected ? "Connected" : "Disconnected"}
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
