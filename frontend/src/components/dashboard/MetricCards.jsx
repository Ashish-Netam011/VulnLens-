import { SecurityScore } from '../security/SecurityScore.jsx';
import { SeverityChart } from '../security/SeverityChart.jsx';

export function MetricCards({ severityCounts, projectCount, scanCount }) {
  return (
    <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
      <div className="card card-pad flex items-center justify-center">
        <SecurityScore score={null} size={90} strokeWidth={8} />
      </div>

      <div className="card card-pad flex flex-col justify-between">
        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Projects</span>
        <span className="mt-1 text-2xl font-bold text-slate-100">{projectCount ?? '—'}</span>
      </div>

      <div className="card card-pad flex flex-col justify-between">
        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Total Scans</span>
        <span className="mt-1 text-2xl font-bold text-slate-100">{scanCount ?? '—'}</span>
      </div>

      <div className="card card-pad">
        <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Severity Distribution</span>
        <SeverityChart counts={severityCounts} className="mt-1" />
      </div>
    </div>
  );
}