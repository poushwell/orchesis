function normalizeBars(points) {
  if (!Array.isArray(points) || points.length === 0) return [];
  const max = Math.max(...points.map((v) => Number(v || 0)), 1);
  return points.slice(-20).map((value) => {
    const n = Number(value || 0);
    return Math.max(10, Math.round((n / max) * 100));
  });
}

export default function MetricCard({ title, value, points, tone = "purple", accent = "var(--purple)" }) {
  const bars = normalizeBars(points);
  return (
    <article className={`card metric-card tone-${tone}`}>
      <div className="metric-label">{title}</div>
      <div className="metric-value" style={{ color: accent }}>
        {value}
      </div>
      <div className="mini-bars">
        {bars.length === 0
          ? Array.from({ length: 14 }).map((_, i) => <span key={i} style={{ height: "14%" }} />)
          : bars.map((height, i) => <span key={i} style={{ height: `${height}%` }} />)}
      </div>
    </article>
  );
}
