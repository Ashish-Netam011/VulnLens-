import { TriangleAlert } from 'lucide-react';
import { Button } from './Button.jsx';
import { cx } from '../../utils/helpers.js';

export function ErrorState({ title = 'Something went wrong', message, onRetry, retryLabel = 'Retry', compact = false, className = '' }) {
  return (
    <div className={cx('flex flex-col items-center justify-center rounded-lg border border-critical/25 bg-critical/[0.04] px-6 text-center', compact ? 'py-8' : 'py-14', className)} role="alert">
      <div className="flex h-12 w-12 items-center justify-center rounded-full bg-critical/10 text-critical">
        <TriangleAlert size={22} aria-hidden="true" />
      </div>
      <p className="mt-3 text-sm font-semibold text-slate-100">{title}</p>
      {message ? <p className="mt-1 max-w-md text-[13px] leading-relaxed text-slate-400">{message}</p> : null}
      {onRetry ? (
        <Button variant="secondary" size="sm" className="mt-4" onClick={onRetry}>
          {retryLabel}
        </Button>
      ) : null}
    </div>
  );
}
