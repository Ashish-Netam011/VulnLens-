import { SeverityBadge } from '../ui/SeverityBadge.jsx';

/**
 * Summary card for a single finding in a findings list.
 * Clicking opens the detail modal/panel. Dependency findings (kind === 'dependency')
 * render their package + CVE badge instead of a code snippet.
 */
export function FindingCard({ finding, onClick, className = '' }) {
  const isDep = finding.kind === 'dependency';
  return (
    <button
      onClick={() => onClick?.(finding)}
      className={`group flex w-full flex-col gap-2 rounded-md border border-borderline bg-base-850 px-4 py-3 text-left transition-colors hover:border-slate-600 hover:bg-base-800 ${className}`}
    >
      <div className="flex items-start justify-between gap-2">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-sm font-medium text-slate-100 group-hover:text-white">
            {finding.title}
          </span>
          <SeverityBadge severity={finding.severity} />
        </div>
        {finding.confidence ? (
          <span className="mt-0.5 shrink-0 text-[11px] tabular-nums text-slate-500">
            {finding.confidence}%
          </span>
        ) : null}
      </div>

      {isDep ? (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="font-mono text-slate-300">{finding.packageName}@{finding.installedVersion}</span>
          <span className="rounded bg-amber-500/15 px-1.5 py-0.5 font-mono text-[10px] font-semibold text-amber-300">
            {finding.cveId}
          </span>
          {finding.recommendedVersion ? (
            <span className="text-emerald-400">fix: {finding.recommendedVersion}</span>
          ) : null}
        </div>
      ) : finding.affectedCode ? (
        <p className="rounded bg-base-900 px-2 py-1 font-mono text-[12px] text-slate-400 line-clamp-2">
          {finding.affectedCode}
        </p>
      ) : null}

      {finding.category ? (
        <span className="text-[11px] font-medium text-slate-500">{finding.category}</span>
      ) : null}
      {finding.filePath && finding.filePath !== 'submission.txt' ? (
        <span className="text-[11px] font-mono text-slate-600 truncate">{finding.filePath}</span>
      ) : null}
    </button>
  );
}
