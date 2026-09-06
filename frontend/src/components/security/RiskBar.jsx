import { SEVERITIES, SEVERITY_META, sumCounts } from '../../utils/helpers.js';

/** Stacked horizontal severity bar + per-severity legend. Quiet, precise. */
export function RiskBar({ counts = {}, showLegend = true, height = 'h-2.5', className = '' }) {
  const total = sumCounts(counts) || 0;
  const items = SEVERITIES.map((s) => ({ ...SEVERITY_META[s], key: s, value: counts[s] || 0 })).filter(
    (x) => x.value > 0
  );
  const shown = total === 0 ? items : items.filter((x) => (x.value / total) * 100 >= 0.6);
  const hidden = items.filter((x) => !shown.includes(x));

  return (
    <div className={className}>
      {total === 0 ? (
        <p className="text-xs text-slate-600">No findings to display.</p>
      ) : (
        <>
          <div
            className={`flex w-full overflow-hidden rounded-sm ${height}`}
            role="img"
            aria-label={`Risk distribution: ${items.map((x) => `${x.value} ${x.key}`).join(', ')}`}
          >
            {shown.map((x) => (
              <div
                key={x.key}
                className={x.bar}
                style={{ width: `${(x.value / total) * 100}%` }}
                title={`${x.label}: ${x.value}`}
              />
            ))}
            {hidden.map((x) => (
              <div key={x.key} className={`${x.bar} opacity-70`} style={{ width: '2px' }} title={`${x.label}: ${x.value}`} />
            ))}
          </div>
          {showLegend ? (
            <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5">
              {items.map((x) => (
                <span key={x.key} className="inline-flex items-center gap-1.5 text-[11px] tabular-nums text-slate-400">
                  <span aria-hidden="true" className={`h-2 w-2 rounded-sm ${x.bar}`} />
                  <span className="capitalize">{x.key}</span>
                  <span className="font-semibold text-slate-200">{x.value}</span>
                </span>
              ))}
            </div>
          ) : null}
        </>
      )}
    </div>
  );
}
