import {
  Area,
  AreaChart,
  CartesianGrid,
  ReferenceDot,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";

function money(value) {
  return `$${Number(value || 0).toFixed(2)}`;
}

export default function CostTimeline({ points = [] }) {
  const data = Array.isArray(points)
    ? points.map((item) => ({
        t: Number(item.timestamp || 0),
        cost: Number(item.cumulative_cost || 0)
      }))
    : [];
  const last = data.length > 0 ? data[data.length - 1] : null;

  return (
    <div className="chart-card card">
      <h3>Cost Timeline</h3>
      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height={260}>
          <AreaChart data={data}>
            <defs>
              <linearGradient id="costFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--purple)" stopOpacity={0.2} />
                <stop offset="95%" stopColor="var(--purple)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="var(--border-dim)" vertical={false} />
            <XAxis
              dataKey="t"
              tickFormatter={(value) => new Date(value * 1000).toLocaleTimeString()}
              stroke="#444"
              tick={{ fontSize: 11, fontFamily: "'SF Mono', 'Fira Code', monospace" }}
            />
            <YAxis
              stroke="#444"
              tickFormatter={money}
              tick={{ fontSize: 11, fontFamily: "'SF Mono', 'Fira Code', monospace" }}
            />
            <Tooltip
              formatter={(value) => money(value)}
              labelFormatter={(value) => new Date(value * 1000).toLocaleString()}
              contentStyle={{
                background: "var(--card2)",
                border: "1px solid var(--border-dim)",
                borderRadius: 10,
                fontFamily: "'SF Mono', 'Fira Code', monospace"
              }}
            />
            <Area
              type="monotone"
              dataKey="cost"
              stroke="var(--purple)"
              fill="url(#costFill)"
              strokeWidth={1.5}
              dot={false}
            />
            {last ? (
              <ReferenceDot
                x={last.t}
                y={last.cost}
                r={4}
                fill="var(--purple)"
                stroke="rgba(168,85,247,0.5)"
                strokeWidth={2}
                className="last-point"
              />
            ) : null}
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
