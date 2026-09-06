import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts';
import { SEVERITY_META, SEVERITIES } from '../../utils/helpers.js';

export function SeverityChart({ counts = {}, className = '' }) {
  const data = SEVERITIES.map((s) => ({
    name: SEVERITY_META[s].label,
    value: counts[s] || 0,
    color: SEVERITY_META[s].color,
  }));

  const total = data.reduce((a, b) => a + b.value, 0);

  return (
    <div className={className}>
      <div className="flex items-center gap-4 mb-2">
        <span className="text-xs text-slate-500 font-medium">{total} finding{total !== 1 ? 's' : ''}</span>
      </div>
      <ResponsiveContainer width="100%" height={90}>
        <BarChart data={data} margin={{ top: 0, right: 0, bottom: 0, left: 0 }} barSize={20}>
          <XAxis
            dataKey="name"
            tick={{ fontSize: 10, fill: '#94a3b8' }}
            axisLine={{ stroke: '#232d3d' }}
            tickLine={false}
          />
          <YAxis hide />
          <Tooltip
            cursor={false}
            contentStyle={{ background: '#131a23', border: '1px solid #232d3d', borderRadius: 6, fontSize: 12, color: '#e2e8f0' }}
            labelStyle={{ color: '#94a3b8', fontWeight: 500 }}
          />
          <Bar dataKey="value" radius={[4, 4, 0, 0]}>
            {data.map((entry, i) => (
              <Cell key={i} fill={entry.color} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}