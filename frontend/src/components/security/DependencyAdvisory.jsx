import { Package, ExternalLink } from 'lucide-react';
import { SeverityBadge } from '../ui/SeverityBadge.jsx';
import { CodeWindow } from './CodeWindow.jsx';

export function DependencyAdvisory({ finding }) {
  const ai = finding.ai || {};
  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-wrap items-center gap-3">
        <SeverityBadge severity={finding.severity} />
        <span className="inline-flex items-center gap-1.5 font-mono text-sm text-slate-200">
          <Package size={14} className="text-slate-500" />
          {finding.packageName}
          <span className="text-slate-500">@{finding.installedVersion}</span>
        </span>
        <span className="rounded border border-amber-500/30 bg-amber-500/10 px-2 py-0.5 font-mono text-xs font-semibold text-amber-300">{finding.cveId}</span>
      </div>

      <dl className="grid gap-x-8 gap-y-2 rounded-lg border border-edge bg-base-925/50 p-4 text-[13px] sm:grid-cols-2">
        {finding.recommendedVersion ? (
          <div><dt className="text-2xs font-semibold uppercase tracking-wider text-slate-500">Fix available</dt><dd className="mt-0.5 font-mono text-emerald-300">{finding.recommendedVersion}</dd></div>
        ) : (
          <div><dt className="text-2xs font-semibold uppercase tracking-wider text-slate-500">Fix available</dt><dd className="mt-0.5 text-slate-500">No patched version identified</dd></div>
        )}
        {finding.affectedVersionRange ? (
          <div><dt className="text-2xs font-semibold uppercase tracking-wider text-slate-500">Affected</dt><dd className="mt-0.5 font-mono text-slate-300">{finding.affectedVersionRange}</dd></div>
        ) : null}
        {finding.dependencyType ? (
          <div><dt className="text-2xs font-semibold uppercase tracking-wider text-slate-500">Type</dt><dd className="mt-0.5 capitalize text-slate-300">{finding.dependencyType}</dd></div>
        ) : null}
        {finding.sourceFile ? (
          <div><dt className="text-2xs font-semibold uppercase tracking-wider text-slate-500">Manifest</dt><dd className="mt-0.5 truncate font-mono text-slate-300">{finding.sourceFile}</dd></div>
        ) : null}
      </dl>

      {finding.description ? (
        <div>
          <p className="label">Advisory</p>
          <p className="whitespace-pre-line text-sm leading-relaxed text-slate-200">{finding.description}</p>
          {finding.advisoryUrl ? (
            <a href={finding.advisoryUrl} target="_blank" rel="noopener noreferrer" className="mt-2 inline-flex items-center gap-1.5 text-xs font-medium text-accent-300 hover:text-accent-200">
              View advisory <ExternalLink size={12} />
            </a>
          ) : null}
        </div>
      ) : null}

      {ai.remediation ? (
        <div>
          <p className="label">How to fix</p>
          <p className="whitespace-pre-line text-sm leading-relaxed text-slate-200">{ai.remediation}</p>
        </div>
      ) : null}

      {ai.secureExample ? (
        <div>
          <p className="label">Recommended manifest entry</p>
          <CodeWindow code={ai.secureExample} maxHeight="max-h-48" />
        </div>
      ) : null}

      {finding.reason ? (
        <div>
          <p className="label">Detection reason</p>
          <p className="text-sm text-slate-300">{finding.reason}</p>
        </div>
      ) : null}
    </div>
  );
}
