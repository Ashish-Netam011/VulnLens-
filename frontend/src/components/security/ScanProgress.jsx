import { Spinner } from '../ui/Spinner.jsx';

/**
 * Progress indicator shown while scan is running (DESIGN.md §16).
 */
export function ScanProgress({ phase = 'scanning' }) {
  const labels = {
    pending: 'Queued...',
    scanning: 'Running static analysis rules...',
    ai: 'Generating AI explanations...',
    completed: 'Scan complete',
    failed: 'Scan failed',
  };

  return (
    <div className="flex flex-col items-center justify-center gap-4 py-14">
      <div className="relative">
        <Spinner size="lg" className="text-sky-500" />
        <div className="absolute inset-0 animate-ping rounded-full bg-sky-500/10" />
      </div>
      <p className="text-sm font-medium text-slate-200">{labels[phase] || 'Processing...'}</p>
      <div className="flex gap-1.5">
        {['pending', 'scanning', 'ai', 'completed'].map((s, i) => {
          const phases = ['pending', 'scanning', 'ai', 'completed'];
          const currentIdx = phases.indexOf(phase);
          const done = i < currentIdx || phase === 'completed';
          return (
            <div
              key={s}
              className={`h-1.5 w-8 rounded-full transition-colors duration-300 ${done ? 'bg-sky-500' : i === currentIdx ? 'bg-sky-500/50 animate-pulse' : 'bg-base-700'}`}
            />
          );
        })}
      </div>
    </div>
  );
}