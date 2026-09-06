import { useEffect, useRef } from 'react';
import { X } from 'lucide-react';
import { cx } from '../../utils/helpers.js';

export function Modal({ open, onClose, title, children, maxWidth = 'max-w-2xl', labelledBy }) {
  const ref = useRef(null);

  // Close on Escape + lock body scroll.
  useEffect(() => {
    if (!open) return undefined;
    function onKey(e) {
      if (e.key === 'Escape') onClose();
    }
    document.addEventListener('keydown', onKey);
    const prev = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => {
      document.removeEventListener('keydown', onKey);
      document.body.style.overflow = prev;
    };
  }, [open, onClose]);

  // Move focus into the dialog when it opens; return it on close.
  useEffect(() => {
    if (!open) return undefined;
    const prevActive = document.activeElement;
    const t = window.setTimeout(() => ref.current?.focus(), 0);
    return () => {
      window.clearTimeout(t);
      if (prevActive && typeof prevActive.focus === 'function') prevActive.focus();
    };
  }, [open]);

  if (!open) return null;

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-base-950/80 p-4 pt-[8vh] backdrop-blur-[2px]"
      onClick={(e) => {
        if (ref.current && !ref.current.contains(e.target)) onClose();
      }}
    >
      <div
        ref={ref}
        tabIndex={-1}
        className={cx('card w-full outline-none', maxWidth)}
        role="dialog"
        aria-modal="true"
        aria-label={title}
        aria-labelledby={labelledBy}
      >
        <div className="flex items-center justify-between border-b border-edge px-5 py-3.5">
          <h2 id={labelledBy} className="text-sm font-semibold text-slate-100">{title}</h2>
          <button onClick={onClose} className="btn-ghost p-1.5" aria-label="Close dialog">
            <X size={16} />
          </button>
        </div>
        <div className="p-5">{children}</div>
      </div>
    </div>
  );
}
