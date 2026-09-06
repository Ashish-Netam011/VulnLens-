import { useState } from 'react';
import { ArrowDown, ShieldOff } from 'lucide-react';
import { extractFlows, flowFlags, sinkLabel } from '../../utils/flow.js';
import { StatusBadge } from '../ui/StatusBadge.jsx';
import { cx, truncate } from '../../utils/helpers.js';

function NodeChip({ tag, tone, children, line, note }) {
  const tones = {
    source: 'border-cyan-500/40 bg-cyan-500/[0.08] text-cyan-200',
    prop: 'border-edge-strong bg-base-850 text-slate-200',
    sink: 'border-critical/40 bg-critical/[0.08] text-red-100',
  }[tone];
  const tagColor = { source: 'text-cyan-400', prop: 'text-slate-500', sink: 'text-critical' }[tone];
  return (
    <div className="w-full">
      <div className={cx('flex items-center gap-2 rounded-md border px-3 py-2', tones)}>
        <span className={cx('text-[9px] font-bold uppercase tracking-widest2', tagColor)}>{tag}</span>
        <code className="min-w-0 flex-1 break-all font-mono text-[12.5px]">{truncate(children, 160)}</code>
        {line ? <span className="shrink-0 font-mono text-[10px] tabular-nums opacity-70">:{line}</span> : null}
      </div>
      {note ? <p className="mt-1 text-[11px] text-slate-500">{note}</p> : null}
    </div>
  );
}

function Rail() {
  return (
    <div className="flex justify-center py-0.5" aria-hidden="true">
      <ArrowDown size={13} className="flow-pulse text-flow" />
    </div>
  );
}

function FlowPath({ path, idx }) {
  const steps = path.steps || [];
  return (
    <div className="fade-in flex w-full flex-col">
      <NodeChip tag="Source" tone="source" line={path.source?.line}>
        {path.source?.expression || 'Untrusted input'}
      </NodeChip>
      {steps.map((s, i) => (
        <div key={i}>
          <Rail />
          <NodeChip tag="Propagation" tone="prop" line={s.line}>
            {s.expression}
          </NodeChip>
        </div>
      ))}
      <Rail />
      <NodeChip tag="Sink" tone="sink" line={path.sink?.line}>
        {sinkLabel(path.sink?.type)}
      </NodeChip>
    </div>
  );
}

/**
 * Data-flow diagram rendered from deterministic evidence.
 * Shows SOURCE → propagation → SINK chains; the flags strip repeats what the
 * scanner proved (parameterized / sanitized / constant-data).
 */
export function DataFlowGraph({ finding, className = '' }) {
  const flows = extractFlows(finding);
  const flags = flowFlags(finding);
  const [idx, setIdx] = useState(0);

  if (flows.length === 0) {
    return (
      <div className={cx('flex items-start gap-3 rounded-lg border border-edge bg-base-925/50 p-4', className)}>
        <ShieldOff size={16} className="mt-0.5 shrink-0 text-slate-500" />
        <p className="text-[13px] leading-relaxed text-slate-500">
          No traced source→sink flow for this finding. The pattern was reported on deterministic
          shape; confirm reachability in context.
        </p>
      </div>
    );
  }

  const flagBadges = [
    flags.parameterized && { tone: 'success', label: 'Parameterized' },
    flags.sanitized && { tone: 'info', label: 'Sanitized' },
    flags.constantData && { tone: 'slate', label: 'Constant data' },
    flags.direct && { tone: 'flow', label: 'Direct' },
  ].filter(Boolean);

  return (
    <div className={cx('rounded-lg border border-edge bg-base-925/40 p-4', className)}>
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <p className="eyebrow">Data flow</p>
        <div className="flex items-center gap-2">
          {flagBadges.map((b) => (
            <StatusBadge key={b.label} tone={b.tone} label={b.label} dot={false} />
          ))}
        </div>
      </div>
      {flows.length > 1 ? (
        <div className="mb-3 flex items-center gap-1">
          {flows.slice(0, 4).map((_, i) => (
            <button
              key={i}
              onClick={() => setIdx(i)}
              aria-label={`Flow path ${i + 1}`}
              className={cx('h-1.5 rounded-full transition-all', i === idx ? 'w-6 bg-flow' : 'w-3 bg-base-700 hover:bg-base-600')}
            />
          ))}
        </div>
      ) : null}
      <FlowPath key={idx} path={flows[idx % Math.max(flows.length, 1)]} idx={idx} />
    </div>
  );
}
