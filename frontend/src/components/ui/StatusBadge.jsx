const TONES = {
  critical: { text: 'text-critical', border: 'border-critical/40', dot: 'bg-critical', bg: 'bg-critical/10' },
  high: { text: 'text-high', border: 'border-high/40', dot: 'bg-high', bg: 'bg-high/10' },
  medium: { text: 'text-medium', border: 'border-medium/40', dot: 'bg-medium', bg: 'bg-medium/10' },
  warn: { text: 'text-amber-300', border: 'border-amber-500/40', dot: 'bg-amber-400', bg: 'bg-amber-500/10' },
  success: { text: 'text-emerald-300', border: 'border-emerald-500/40', dot: 'bg-emerald-400', bg: 'bg-emerald-500/10' },
  slate: { text: 'text-slate-400', border: 'border-edge-strong', dot: 'bg-slate-500', bg: 'bg-base-850' },
  info: { text: 'text-sky-300', border: 'border-sky-500/40', dot: 'bg-sky-400', bg: 'bg-sky-500/10' },
  accent: { text: 'text-accent-300', border: 'border-accent-500/40', dot: 'bg-accent-400', bg: 'bg-accent-500/10' },
  flow: { text: 'text-cyan-300', border: 'border-cyan-500/40', dot: 'bg-flow', bg: 'bg-cyan-500/10' },
};

/**
 * Status pill with dot + label (label-only-unsafe tones keep text distinct).
 */
export function StatusBadge({ tone = 'slate', label, dot = true, className = '' }) {
  const t = TONES[tone] || TONES.slate;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${t.bg} ${t.text} ${t.border} ${className}`.trim()}
    >
      {dot ? <span aria-hidden="true" className={`h-1.5 w-1.5 rounded-full ${t.dot}`} /> : null}
      {label}
    </span>
  );
}
