import { scoreColor, scoreLabelText } from '../../utils/helpers.js';

/**
 * Radial score gauge – "radial speedometer style" per DESIGN.md §7.
 * Pure SVG, no external dependencies.
 */
export function SecurityScore({ score, size = 120, strokeWidth = 10, className = '' }) {
  const r = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * r;
  const clamped = Math.max(0, Math.min(100, score ?? 0));
  const offset = circumference - (clamped / 100) * circumference;
  const color = scoreColor(clamped);
  const label = scoreLabelText(clamped);
  const centre = size / 2;

  return (
    <div className={`relative inline-flex items-center justify-center ${className}`}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={centre} cy={centre} r={r} fill="none" stroke="#243040" strokeWidth={strokeWidth} />
        <circle
          cx={centre}
          cy={centre}
          r={r}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-[stroke-dashoffset] duration-700 ease-out"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-bold" style={{ color }}>{clamped}</span>
        <span className="text-[10px] font-medium uppercase tracking-wide text-slate-400">{label}</span>
      </div>
    </div>
  );
}