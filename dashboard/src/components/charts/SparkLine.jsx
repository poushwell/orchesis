export default function SparkLine({ points = [] }) {
  if (!Array.isArray(points) || points.length < 2) {
    return <svg className="sparkline" viewBox="0 0 120 36" />;
  }
  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;
  const mapped = points
    .map((value, index) => {
      const x = (index / (points.length - 1)) * 120;
      const y = 32 - ((value - min) / range) * 28;
      return `${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");

  return (
    <svg className="sparkline" viewBox="0 0 120 36" preserveAspectRatio="none">
      <polyline points={mapped} />
    </svg>
  );
}
