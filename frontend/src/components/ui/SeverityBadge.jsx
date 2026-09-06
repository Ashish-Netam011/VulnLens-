import { severityMeta } from '../../utils/helpers.js';

export function SeverityBadge({ severity, showLabel = true, className = '' }) {
  const meta = severityMeta(severity);
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[11px] font-semibold uppercase tracking-wide ${meta.badge} ${className}`.trim()}
    >
      <span className={`h-1.5 w-1.5 rounded-full ${meta.dot}`} />
      {showLabel ? meta.label : null}
    </span>
  );
}