function eventType(event) {
  const type = String(event.type || "").toUpperCase();
  if (type === "BLOCKED") return "blocked";
  if (type === "PASS") return "pass";
  if (type === "CACHED") return "cached";
  if (type === "HEAL") return "heal";
  return "pass";
}

function modelFromEvent(event) {
  if (event.model) return String(event.model);
  if (event.provider_model) return String(event.provider_model);
  const text = String(event.description || "");
  const match = text.match(/\b(gpt[-\w.]+|claude[-\w.]+|gemini[-\w.]+)\b/i);
  return match ? match[1] : "--";
}

export default function ThreatLog({ events = [] }) {
  const rows = Array.isArray(events) ? events.slice(0, 50) : [];

  return (
    <section className="card threat-panel">
      <div className="threat-head">
        <h3>ORCHESIS_THREAT_LOG</h3>
        <div className="live">
          <span className="live-dot" />
          LIVE
        </div>
      </div>
      <div className="threat-columns">
        <span>TIMESTAMP</span>
        <span>STATE</span>
        <span>MESSAGE</span>
        <span>MODEL</span>
      </div>
      <div className="threat-log">
        {rows.length === 0 ? (
          <div className="empty">No threat events</div>
        ) : (
          rows.map((event, index) => (
            <div key={`${event.timestamp || index}-${index}`} className={`threat-row ${eventType(event)}`}>
              <span className="event-time mono">
                {event.timestamp ? new Date(Number(event.timestamp) * 1000).toLocaleTimeString() : "--:--:--"}
              </span>
              <span className={`event-type badge-${eventType(event)}`}>{String(event.type || "PASS").toUpperCase()}</span>
              <span className="event-desc">{event.description || "Event"}</span>
              <span className="event-model mono">{modelFromEvent(event)}</span>
            </div>
          ))
        )}
      </div>
    </section>
  );
}
