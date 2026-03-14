import {
  Area,
  AreaChart,
  CartesianGrid,
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

  return (
    <div className="chart-card card">
      <h3>Cost Timeline</h3>
      <div className="chart-wrap">
        <ResponsiveContainer width="100%" height={260}>
          <AreaChart data={data}>
            <defs>
              <linearGradient id="costFill" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="var(--green)" stopOpacity={0.35} />
                <stop offset="95%" stopColor="var(--green)" stopOpacity={0} />
              </linearGradient>
            </defs>
            <CartesianGrid stroke="var(--border)" vertical={false} />
            <XAxis
              dataKey="t"
              tickFormatter={(value) => new Date(value * 1000).toLocaleTimeString()}
              stroke="var(--muted)"
              tick={{ fontSize: 11 }}
            />
            <YAxis stroke="var(--muted)" tickFormatter={money} tick={{ fontSize: 11 }} />
            <Tooltip
              formatter={(value) => money(value)}
              labelFormatter={(value) => new Date(value * 1000).toLocaleString()}
              contentStyle={{ background: "var(--card)", border: "1px solid var(--border)", borderRadius: 12 }}
            />
            <Area type="monotone" dataKey="cost" stroke="var(--green)" fill="url(#costFill)" strokeWidth={2} />
          </AreaChart>
        </ResponsiveContainer>
      </div>
    </div>
  );
}
