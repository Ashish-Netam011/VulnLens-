import { SeverityBadge } from '../ui/SeverityBadge.jsx';
import { CodeViewer } from './CodeViewer.jsx';
import { ExternalLink, Package } from 'lucide-react';

/**
 * Detailed view for a single dependency / CVE finding (Phase 2).
 * Renders the OSV-derived metadata inside a modal.
 */
export function DependencyDetails({ finding }) {
  const enrich = finding._ruleEnrichment || {};
  const depType = finding.dependencyType === 'direct' ? 'Direct dependency' : 'Transitive dependency';

  return (
    <div className="flex flex-col gap-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <h3 className="text-[15px] font-semibold text-slate-50">{finding.title}</h3>
          <SeverityBadge severity={finding.severity} />
        </div>
        {finding.confidence != null ? (
          <span className="text-xs tabular-nums text-slate-500">Confidence: {finding.confidence}%</span>
        ) : null}
      </div>

      <div className="rounded-lg border border-amber-500/30 bg-amber-500/5 p-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-2 text-sm">
          <span className="inline-flex items-center gap-2">
            <Package size={14} className="text-slate-400" />
            <span className="font-mono text-slate-100">{finding.packageName}</span>
            <span className="text-slate-500">@{finding.installedVersion}</span>
          </span>
          <span className="rounded bg-amber-500/15 px-2 py-0.5 font-mono text-xs font-semibold text-amber-300">{finding.cveId}</span>
          {finding.recommendedVersion ? (
            <span className="inline-flex items-center gap-1.5">
              <span className="text-xs text-slate-500">fix available:</span>
              <span className="font-mono text-emerald-300">{finding.recommendedVersion}</span>
            </span>
          ) : (
            <span className="text-xs text-slate-500">no patched version identified</span>
          )}
        </div>
        <div className="mt-3 grid gap-x-8 gap-y-1 text-xs text-slate-500 sm:grid-cols-2">
          <span>{depType}</span>
          {finding.affectedVersionRange ? <span className="truncate">affected: {finding.affectedVersionRange}</span> : null}
        </div>
      </div>

      <div className="flex flex-wrap gap-4 text-xs text-slate-500">
        {finding.category ? <span>{finding.category}</span> : null}
        {finding.filePath ? <span className="font-mono">{finding.filePath}</span> : null}
      </div>

      {finding.description ? (
        <div>
          <p className="label">Advisory</p>
          <p className="text-sm leading-relaxed text-slate-200">{finding.description}</p>
          {finding.advisoryUrl ? (
            <a
              href={finding.advisoryUrl}
              target="_blank"
              rel="noopener noreferrer"
              className="mt-2 inline-flex items-center gap-1.5 rounded border border-sky-500/30 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-300 hover:bg-sky-500/20"
            >
              View advisory <ExternalLink size={12} />
            </a>
          ) : null}
        </div>
      ) : null}

      {enrich.explanation || enrich.remediation ? (
        <div className="rounded-lg border border-slate-700/50 bg-slate-800/30 p-4">
          <div className="mb-3 flex items-center gap-2">
            <div className="flex h-5 w-5 items-center justify-center rounded bg-amber-500/20 text-amber-400">
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                <path d="M12 9v4M12 17h.01" />
                <path d="M10.3 3.86 1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.7 3.86a2 2 0 0 0-3.4 0z" />
              </svg>
            </div>
            <span className="text-xs font-semibold uppercase tracking-wide text-amber-300">Vulnerability Remediation</span>
          </div>
          {enrich.explanation && (
            <div className="mb-3">
              <h4 className="mb-1 text-xs font-semibold text-slate-400">Why This Matters</h4>
              <p className="text-sm leading-relaxed text-slate-200">{enrich.explanation}</p>
            </div>
          )}
          {enrich.impact && (
            <div className="mb-3">
              <h4 className="mb-1 text-xs font-semibold text-slate-400">Potential Impact</h4>
              <p className="text-sm leading-relaxed text-slate-200">{enrich.impact}</p>
            </div>
          )}
          {enrich.remediation && (
            <div className="mb-3">
              <h4 className="mb-1 text-xs font-semibold text-slate-400">How to Fix</h4>
              <p className="text-sm leading-relaxed text-slate-200">{enrich.remediation}</p>
            </div>
          )}
          {enrich.secureExample ? (
            <div>
              <h4 className="mb-1 text-xs font-semibold text-slate-400">Recommended Manifest Entry</h4>
              <CodeViewer code={enrich.secureExample} variant="success" />
            </div>
          ) : null}
        </div>
      ) : null}

      {finding.reason && !enrich.explanation ? (
        <div>
          <p className="label">Detection Reason</p>
          <p className="text-sm text-slate-300">{finding.reason}</p>
        </div>
      ) : null}
    </div>
  );
}
