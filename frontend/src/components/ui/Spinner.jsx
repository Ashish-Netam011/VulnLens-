export function Spinner({ size = 'md', className = '' }) {
  const sizes = { sm: 'h-3.5 w-3.5', md: 'h-5 w-5', lg: 'h-8 w-8' };
  return (
    <svg className={`animate-spin text-slate-400 ${sizes[size]} ${className}`} viewBox="0 0 24 24" fill="none" role="status" aria-label="Loading">
      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
      <path className="opacity-90" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
    </svg>
  );
}

export function PageLoader({ label = 'Loading…', detail, className = '' }) {
  return (
    <div className={`flex flex-col items-center justify-center gap-3 py-24 text-center ${className}`} role="status">
      <Spinner size="lg" className="text-accent-400" />
      <p className="text-sm font-medium text-slate-300">{label}</p>
      {detail ? <p className="max-w-sm text-xs text-slate-500">{detail}</p> : null}
    </div>
  );
}
