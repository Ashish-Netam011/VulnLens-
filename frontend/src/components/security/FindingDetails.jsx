import { SeverityBadge } from '../ui/SeverityBadge.jsx';
import { CodeViewer } from './CodeViewer.jsx';
import { severityMeta, formatDate } from '../../utils/helpers.js';

/**
 * Full finding detail view with AI-enhanced explanation.
 * Fits within a modal or side panel.
 */
export function FindingDetails({ finding, scanMeta }) {
  const ai = finding.ai || {};

  return (
    <div className="flex flex-col gap-4">
      {/* Header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-[15px] font-semibold text-slate-50">{finding.title}</h3>
          <SeverityBadge severity={finding.severity} />
        </div>
        {finding.confidence != null ? (
          <span className="text-xs tabular-nums text-slate-500">Confidence: {finding.confidence}%</span>
        ) : null}
      </div>

      {/* Meta */}
      <div className="flex flex-wrap gap-4 text-xs text-slate-500">
        {finding.category ? <span>{finding.category}</span> : null}
        {finding.filePath ? <span className="font-mono">{finding.filePath}</span> : null}
        {finding.line ? <span>Line {finding.line}</span> : null}
        {ai.source ? (
          <span className="flex items-center gap-1">
            <span className={`inline-block h-1.5 w-1.5 rounded-full ${ai.source === 'rule' ? 'bg-slate-500' : 'bg-sky-400'}`} />
            {ai.source === 'rule' ? 'Rule-based enrichment' : `AI (${ai.source})`}
          </span>
        ) : null}
      </div>

      {/* Affected Code */}
      {finding.affectedCode ? (
        <div>
          <p className="label">Affected Code</p>
          <CodeViewer code={finding.affectedCode} highlightLine={finding.line} />
        </div>
      ) : null}

      {/* AI Analysis Section */}
      {ai.explanation || ai.remediation ? (
        <div className="rounded-lg border border-slate-700/50 bg-slate-800/30 p-4">
          <div className="mb-3 flex items-center gap-2">
            <div className="flex h-5 w-5 items-center justify-center rounded bg-sky-500/20 text-sky-400">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <circle cx="12" cy="12" r="10"/>
                <path d="M12 16v-4M12 8h.01"/>
              </svg>
            </div>
            <span className="text-xs font-semibold uppercase tracking-wide text-sky-300">AI Analysis</span>
          </div>

          {ai.explanation && (
            <div className="mb-3">
              <h4 className="mb-1 text-xs font-semibold text-slate-400">Why This Matters</h4>
              <p className="text-sm leading-relaxed text-slate-200">{ai.explanation}</p>
            </div>
          )}

          {ai.impact && (
            <div className="mb-3">
              <h4 className="mb-1 text-xs font-semibold text-slate-400">Potential Impact</h4>
              <p className="text-sm leading-relaxed text-slate-200">{ai.impact}</p>
            </div>
          )}

          {ai.remediation && (
            <div className="mb-3">
              <h4 className="mb-1 text-xs font-semibold text-slate-400">How to Fix</h4>
              <p className="text-sm leading-relaxed text-slate-200">{ai.remediation}</p>
            </div>
          )}

          {ai.secureExample && (
            <div>
              <h4 className="mb-1 text-xs font-semibold text-slate-400">Secure Example</h4>
              <CodeViewer code={ai.secureExample} variant="success" />
            </div>
          )}
        </div>
      ) : null}

      {/* Reason / scanner rationale */}
      {finding.reason && !ai.explanation ? (
        <div>
          <p className="label">Detection Reason</p>
          <p className="text-sm text-slate-300">{finding.reason}</p>
        </div>
      ) : null}
    </div>
  );
}