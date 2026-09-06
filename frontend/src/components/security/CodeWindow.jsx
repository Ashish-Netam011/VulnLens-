import { CopyButton } from '../ui/CopyButton.jsx';
import { cx } from '../../utils/helpers.js';

const LINE_STYLES = {
  source: { row: 'bg-cyan-500/[0.07]', bar: 'bg-flow', num: 'text-cyan-300', code: 'text-cyan-50' },
  sink: { row: 'bg-critical/[0.09]', bar: 'bg-critical', num: 'text-critical', code: 'text-red-50' },
  primary: { row: 'bg-critical/[0.09]', bar: 'bg-critical', num: 'font-semibold text-critical', code: 'text-red-50' },
  success: { row: 'bg-emerald-500/[0.06]', bar: 'bg-emerald-400', num: 'text-emerald-300', code: 'text-emerald-50' },
  default: { row: '', bar: 'bg-transparent', num: 'text-slate-600', code: 'text-slate-300' },
};

function normalize(code) {
  const text = String(code || '');
  return text.split('\n');
}

/**
 * Source code viewer.
 * - `window`  : { startLine, endLine, lines: [{line, code}] } from the source endpoint
 * - `code`    : raw string fallback (single snippet / secure examples)
 * - `highlights` : { [absoluteLineNumber]: 'source'|'sink'|'primary'|'success' }
 * - `highlightLine` : single absolute line to emphasise as primary
 */
export function CodeWindow({
  file,
  window: win,
  code,
  highlights = {},
  highlightLine,
  maxHeight = 'max-h-[440px]',
  footerNote,
  className = '',
}) {
  const raw = win ? win.lines.map((l) => l.code) : normalize(code);
  const startLine = win ? win.startLine : highlightLine ? Math.max(1, highlightLine - 0) : 1;
  const copyText = raw.join('\n');

  return (
    <div className={cx('overflow-hidden rounded-lg border border-edge bg-base-950', className)}>
      <div className="flex items-center justify-between gap-3 border-b border-edge bg-base-925/60 px-3 py-2">
        <div className="flex min-w-0 items-center gap-2">
          {file ? <span className="truncate font-mono text-[11px] text-slate-400">{file}</span> : null}
          {win && win.startLine !== win.endLine ? (
            <span className="shrink-0 text-[10px] tabular-nums text-slate-600">lines {win.startLine}–{win.endLine}</span>
          ) : null}
        </div>
        <CopyButton text={copyText} label="code" />
      </div>
      <div className={cx('overflow-auto p-0', maxHeight)}>
        <pre className="min-w-max p-0 font-mono text-[12.5px] leading-[1.7]">
          {raw.map((line, i) => {
            const lineNum = startLine + i;
            const styleKey = highlights[lineNum] || (highlightLine === lineNum ? 'primary' : null);
            const st = LINE_STYLES[styleKey] || LINE_STYLES.default;
            return (
              <div key={i} className={cx('flex', styleKey ? st.row : '')}>
                <span
                  aria-hidden="true"
                  className={cx('w-[3px] shrink-0', styleKey ? st.bar : 'bg-transparent')}
                />
                <span className={cx('w-11 shrink-0 select-none pr-3 text-right', styleKey ? st.num : 'text-slate-600')}>
                  {lineNum}
                </span>
                <span className={cx('whitespace-pre', styleKey ? st.code : 'text-slate-300')}>
                  {line || ' '}
                </span>
              </div>
            );
          })}
        </pre>
      </div>
      {footerNote ? <div className="border-t border-edge px-3 py-1.5 text-[11px] text-slate-500">{footerNote}</div> : null}
    </div>
  );
}
