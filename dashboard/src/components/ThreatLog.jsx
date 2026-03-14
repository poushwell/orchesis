function eventType(event) {
  const type = String(event.type || "").toUpperCase();
  if (type === "BLOCKED") return "blocked";
  if (type === "PASS") return "pass";
  if (type === "CACHED") return "cached";
  if (type === "HEAL") return "heal";
  return "pass";
}

export default function ThreatLog({ events = [] }) {
  const rows = Array.isArray(events) ? events.slice(0, 50) : [];

  return (
    <section className="card">
      <h3>Threat Log</h3>
      <div className="threat-log">
        {rows.length === 0 ? (
          <div className="empty">No threat events</div>
        ) : (
          rows.map((event, index) => (
            <div key={`${event.timestamp || index}-${index}`} className={`threat-row ${eventType(event)}`}>
              <span className="event-time">
                {event.timestamp ? new Date(Number(event.timestamp) * 1000).toLocaleTimeString() : "--:--:--"}
              </span>
              <span className="event-type">{String(event.type || "PASS").toUpperCase()}</span>
              <span className="event-desc">{event.description || "Event"}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
