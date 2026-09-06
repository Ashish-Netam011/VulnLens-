import { copyText } from '../../utils/helpers.js';

/**
 * Code display block with basic line highlighting.
 * variant='success' uses a green-tinted background for secure examples.
 */
export function CodeViewer({ code, highlightLine, variant = 'danger', className = '' }) {
  const lines = (code || '').split('\n');

  return (
    <div className={`rounded-lg border border-borderline bg-base-900 ${className}`}>
      <div className="flex items-center justify-between border-b border-borderline px-3 py-1.5">
        <span className="text-[10px] font-medium uppercase tracking-wider text-slate-500">Code</span>
        <button
          onClick={() => copyText(code)}
          className="text-[10px] text-slate-500 hover:text-slate-300"
          type="button"
        >
          Copy
        </button>
      </div>
      <pre className="overflow-x-auto p-3 text-[12px] leading-[1.65]">
        <code className="code-block">
          {lines.map((line, i) => {
            const lineNum = i + 1;
            const isHighlight = highlightLine && lineNum === highlightLine;
            return (
              <div
                key={i}
                className={`flex ${isHighlight ? (variant === 'success' ? 'bg-emerald-500/10' : 'bg-red-500/10') : ''}`}
              >
                <span className="mr-3 inline-block w-7 select-none text-right text-slate-600">{lineNum}</span>
                <span className={isHighlight ? (variant === 'success' ? 'text-emerald-300' : 'text-red-300') : 'text-slate-300'}>
                  {line || ' '}
                </span>
              </div>
            );
          })}
        </code>
      </pre>
    </div>
  );
}