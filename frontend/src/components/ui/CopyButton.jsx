import { useState } from 'react';
import { Copy, Check } from 'lucide-react';
import { copyText } from '../../utils/helpers.js';
import { cx } from '../../utils/helpers.js';

export function CopyButton({ text, label = 'Copy', className = '' }) {
  const [copied, setCopied] = useState(false);
  async function onCopy() {
    const ok = await copyText(text);
    if (ok) {
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1500);
    }
  }
  return (
    <button
      type="button"
      onClick={onCopy}
      aria-label={`${copied ? 'Copied' : 'Copy'} ${label}`}
      className={cx(
        'inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-[10px] font-medium transition-colors',
        copied ? 'text-emerald-300' : 'text-slate-500 hover:bg-base-800 hover:text-slate-300',
        className
      )}
    >
      {copied ? <Check size={11} /> : <Copy size={11} />}
      {copied ? 'Copied' : label}
    </button>
  );
}
