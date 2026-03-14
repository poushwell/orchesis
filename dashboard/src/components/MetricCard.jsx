import SparkLine from "./charts/SparkLine";

export default function MetricCard({ title, value, points }) {
  return (
    <article className="card metric-card">
      <div className="metric-title">{title}</div>
      <div className="metric-value">{value}</div>
      <SparkLine points={points} />
    </article>
  );
}
