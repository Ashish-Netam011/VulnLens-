import { severityMeta } from '../../utils/helpers.js';
import { AlertCircle, AlertTriangle, OctagonAlert, Info, Hash } from 'lucide-react';

const ICONS = {
  critical: OctagonAlert,
  high: AlertTriangle,
  medium: AlertCircle,
  low: Info,
  informational: Hash,
};

/**
 * Severity indicator: icon + label + tone. Color is a supporting signal only —
 * the label and icon always carry the meaning.
 */
export function SeverityBadge({ severity, showLabel = true, size = 'md', className = '' }) {
  const meta = severityMeta(severity);
  const Icon = ICONS[severity] || Info;
  const pad = size === 'sm' ? 'px-1.5 py-px gap-1 text-[10px]' : 'px-2 py-0.5 gap-1.5 text-[11px]';
  const iconSize = size === 'sm' ? 11 : 12.5;
  return (
    <span
      className={`inline-flex items-center rounded border font-semibold uppercase tracking-wide ${meta.badge} ${pad} ${className}`.trim()}
      role="img"
      aria-label={`Severity ${meta.label}`}
    >
      <Icon size={iconSize} strokeWidth={2.4} aria-hidden="true" />
      {showLabel ? <span>{meta.label}</span> : null}
    </span>
  );
}
