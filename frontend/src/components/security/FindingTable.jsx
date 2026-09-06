import { useState } from 'react';
import { ChevronDown, ChevronRight, ChevronUp } from 'lucide-react';
import { SeverityBadge } from '../ui/SeverityBadge.jsx';
import { StatusBadge } from '../ui/StatusBadge.jsx';
import { severityMeta, verdictMeta, cx, fileTail, isDependency } from '../../utils/helpers.js';

const COLUMNS = [
  { key: 'severity', label: 'Severity' },
  { key: 'title', label: 'Finding' },
  { key: 'location', label: 'Location' },
  { key: 'confidence', label: 'Confidence' },
  { key: 'verdict', label: 'Verdict' },
];

function Confidence({ value }) {
  const n = Math.max(0, Math.min(100, value ?? 0));
  return (
    <span className="inline-flex items-center gap-1.5" title={`Deterministic confidence ${n}%`}>
      <span className="h-1 w-10 overflow-hidden rounded-full bg-base-700" aria-hidden="true">
        <span className={cx('block h-full rounded-full', n >= 80 ? 'bg-emerald-400' : n >= 60 ? 'bg-amber-400' : 'bg-slate-500')} style={{ width: `${n}%` }} />
      </span>
      <span className="text-xs tabular-nums text-slate-400">{n}%</span>
    </span>
  );
}

function RowLocation({ f }) {
  if (isDependency(f)) {
    return (
      <div className="min-w-0">
        <p className="truncate font-mono text-xs text-slate-300">
          {f.packageName}@{f.installedVersion}
        </p>
        <p className="truncate font-mono text-[10px] text-slate-600">{f.filePath || 'manifest'}</p>
      </div>
    );
  }
  const file = f.filePath || 'submission.txt';
  return (
    <div className="min-w-0">
      <p className="truncate font-mono text-xs text-slate-300">
        <span title={file}>{fileTail(file)}</span>
        {f.line ? <span className="text-slate-500">:{f.line}</span> : null}
      </p>
      <p className="truncate font-mono text-[10px] text-accent-300/70">{f.ruleId}</p>
    </div>
  );
}

/**
 * Findings table. Deterministic data only. Sorting is client-side over the
 * given rows; severity sort follows critical → informational.
 */
export function FindingTable({ findings, onOpen, statusOf, activeKey, className }) {
  const [sort, setSort] = useState({ key: 'severity', dir: 'asc' });

  const rows = [...findings].sort((a, b) => {
    const { key, dir } = sort;
    const m = dir === 'asc' ? 1 : -1;
    if (key === 'severity') return (severityMeta(a.severity).rank - severityMeta(b.severity).rank) * m;
    if (key === 'confidence') return ((a.confidence || 0) - (b.confidence || 0)) * m;
    if (key === 'location') return String(a.filePath || '').localeCompare(String(b.filePath || '')) * m || (a.line || 0) - (b.line || 0);
    return String(a.title || '').localeCompare(String(b.title || '')) * m;
  });

  function toggle(key) {
    setSort((s) => (s.key === key ? { key, dir: s.dir === 'asc' ? 'desc' : 'asc' } : { key, dir: 'asc' }));
  }

  const Arrow = ({ col }) => {
    if (sort.key !== col) return <ChevronDown size={11} className="opacity-0 group-hover:opacity-60" />;
    return sort.dir === 'asc' ? <ChevronUp size={11} /> : <ChevronDown size={11} />;
  };

  return (
    <div className={cx('overflow-x-auto', className)}>
      <table className="w-full min-w-[760px] border-collapse text-left">
        <caption className="sr-only">Security findings</caption>
        <thead>
          <tr className="border-b border-edge text-2xs uppercase tracking-wider text-slate-500">
            {COLUMNS.map((c) => (
              <th key={c.key} scope="col" className="px-4 py-2.5 font-semibold">
                <button type="button" onClick={() => toggle(c.key)} className="group inline-flex items-center gap-1 uppercase tracking-wider hover:text-slate-300">
                  {c.label}
                  <Arrow col={c.key} />
                </button>
              </th>
            ))}
            <th scope="col" className="px-4 py-2.5 font-semibold">Status</th>
            <th scope="col" className="w-8 px-2 py-2.5" />
          </tr>
        </thead>
        <tbody className="divide-y divide-edge">
          {rows.map((f) => {
            const st = statusOf ? statusOf(f) : null;
            const vmeta = verdictMeta(f.verdict);
            const active = activeKey && f.comparisonKey === activeKey;
            return (
              <tr
                key={f.comparisonKey || f.ruleId}
                tabIndex={0}
                onClick={() => onOpen?.(f)}
                onKeyDown={(e) => {
                  if ((e.key === 'Enter' || e.key === ' ') && onOpen) {
                    e.preventDefault();
                    onOpen(f);
                  }
                }}
                aria-label={`Open ${f.severity} ${f.title} in ${f.filePath || 'submission'}`}
                className={cx(
                  'cursor-pointer text-[13px] transition-colors focus-visible:outline-2',
                  active ? 'bg-accent-500/[0.07]' : 'hover:bg-base-850/60'
                )}
              >
                <td className="px-4 py-3">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="max-w-[320px] px-4 py-3">
                  <p className="truncate font-medium text-slate-100" title={f.title}>{f.title}</p>
                  {isDependency(f) ? (
                    <p className="truncate font-mono text-[11px] text-amber-300/90">{f.cveId}{f.recommendedVersion ? ` → fix ${f.recommendedVersion}` : ''}</p>
                  ) : (
                    <p className="truncate text-[11px] text-slate-500">{f.category}</p>
                  )}
                </td>
                <td className="px-4 py-3"><RowLocation f={f} /></td>
                <td className="px-4 py-3"><Confidence value={f.confidence} /></td>
                <td className="px-4 py-3">
                  {f.verdict ? <StatusBadge tone={vmeta.tone} label={vmeta.label} dot={false} /> : <span className="text-xs text-slate-600">—</span>}
                </td>
                <td className="px-4 py-3">
                  {st ? <StatusBadge tone={st.tone} label={st.label} /> : <span className="text-xs text-slate-700">—</span>}
                </td>
                <td className="px-2 py-3 text-slate-600">
                  <ChevronRight size={14} aria-hidden="true" />
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
