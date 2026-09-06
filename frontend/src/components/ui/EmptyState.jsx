import { cx } from '../../utils/helpers.js';

/**
 * Meaningful empty state. tone='success' communicates "no problems found";
 * the default tone communicates "nothing here yet".
 */
export function EmptyState({ icon: Icon, title, message, action, tone = 'default', compact = false, className = '' }) {
  const ring =
    tone === 'success'
      ? 'border-emerald-500/25 bg-emerald-500/[0.03]'
      : 'border-dashed border-edge-strong';
  const iconWrap =
    tone === 'success'
      ? 'bg-emerald-500/10 text-emerald-300'
      : 'bg-base-800 text-slate-500';
  return (
    <div className={cx('flex flex-col items-center justify-center rounded-lg border px-6 py-14 text-center', ring, compact && 'py-10', className)}>
      {Icon ? (
        <div className={cx('flex h-12 w-12 items-center justify-center rounded-full', iconWrap)}>
          <Icon size={22} aria-hidden="true" />
        </div>
      ) : null}
      <p className="mt-3 text-sm font-semibold text-slate-200">{title}</p>
      {message ? <p className="mt-1 max-w-md text-[13px] leading-relaxed text-slate-500">{message}</p> : null}
      {action ? <div className="mt-4">{action}</div> : null}
    </div>
  );
}
