import { cx } from '../../utils/helpers.js';

export function Skeleton({ className = '', lines = 1 }) {
  if (lines > 1) {
    return (
      <div className={cx('flex flex-col gap-2', className)} aria-hidden="true">
        {Array.from({ length: lines }, (_, i) => (
          <div key={i} className="h-3 animate-pulse rounded bg-base-800" style={{ width: `${100 - i * 14}%` }} />
        ))}
      </div>
    );
  }
  return <div className={cx('animate-pulse rounded bg-base-800', className)} aria-hidden="true" />;
}
