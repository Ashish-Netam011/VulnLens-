import { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { Card } from '../components/ui/Card.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { SeverityBadge } from '../components/ui/SeverityBadge.jsx';
import { StatusBadge } from '../components/ui/StatusBadge.jsx';
import { CopyButton } from '../components/ui/CopyButton.jsx';
import { CodeWindow } from '../components/security/CodeWindow.jsx';
import { DataFlowGraph } from '../components/security/DataFlowGraph.jsx';
import { DependencyAdvisory } from '../components/security/DependencyAdvisory.jsx';
import { CopilotPanel } from '../components/ai/CopilotPanel.jsx';
import { useSourceWindow } from '../hooks/useSourceWindow.js';
import { extractFlows, flowFlags, sinkLabel } from '../utils/flow.js';
import { severityMeta, verdictMeta, sortFindings, formatDate, rescanStatus, isDependency, cx } from '../utils/helpers.js';
import { ShieldAlert, Check, X as XIcon, ArrowLeft, ArrowRight, FileSearch } from 'lucide-react';

function FactRow({ ok, label, value }) {
  return (
    <div className="flex items-start gap-2.5 py-2">
      <span aria-hidden="true" className={cx('mt-0.5 flex h-4 w-4 shrink-0 items-center justify-center rounded-full', ok ? 'bg-emerald-500/15 text-emerald-300' : 'bg-base-800 text-slate-500')}>
        {ok ? <Check size={10} strokeWidth={3} /> : <XIcon size={10} strokeWidth={3} />}
      </span>
      <div className="min-w-0">
        <p className="text-[13px] text-slate-200">{label}</p>
        {value ? <p className="mt-0.5 font-mono text-[11px] leading-relaxed text-slate-500">{value}</p> : null}
      </div>
    </div>
  );
}

export default function FindingDetailPage() {
  const { scanId, key } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [projectName, setProjectName] = useState('');
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const [{ data: s }, c, p] = await Promise.all([
          api.get(`/scans/${scanId}`),
          api.get(`/scans/${scanId}/comparison`).catch(() => null),
          api.get('/projects').catch(() => ({ data: { projects: [] } })),
        ]);
        if (!mounted) return;
        setScan(s.scan);
        if (c) setComparison(c.data);
        setProjectName((p.data.projects || []).find((x) => x.id === s.scan.project)?.name || '');
      } catch (err) {
        if (mounted) setError(err?.response?.data?.error || 'Failed to load finding');
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, [scanId]);

  const finding = useMemo(
    () => (scan?.findings || []).find((f) => f.comparisonKey === key) || null,
    [scan, key]
  );

  const ordered = useMemo(() => (scan ? sortFindings(scan.findings || []) : []), [scan]);
  const idx = ordered.findIndex((f) => f.comparisonKey === key);
  const isDep = isDependency(finding);

  // Bounded source window for the code viewer (folder + single-file scans).
  const { window: srcWin, loading: srcLoading, error: srcError } = useSourceWindow({
    scanId,
    file: finding?.filePath,
    line: finding?.line,
    enabled: !!finding && !isDep && !!finding?.filePath && !!finding?.line,
  });

  // Code context handed to the Copilot stays bounded to the ~40-line window.
  const contextCode = srcWin ? srcWin.lines.map((l) => l.code).join('\n') : undefined;

  const flows = useMemo(() => (finding ? extractFlows(finding) : []), [finding]);
  const flags = flowFlags(finding);
  const vmeta = verdictMeta(finding?.verdict);
  const status = finding && comparison ? rescanStatus(finding, comparison) : null;
  const meta = severityMeta(finding?.severity);

  // Highlights for the code window: finding line (sink) + traced source lines.
  const highlights = useMemo(() => {
    const h = {};
    if (!finding) return h;
    const sinkLine = finding.evidence?.sink?.line || finding.line;
    if (sinkLine) h[sinkLine] = 'sink';
    for (const f of flows) {
      if (f.source?.line && f.source.line !== sinkLine) h[f.source.line] = 'source';
      for (const s of f.steps || []) if (s.line && s.line !== sinkLine && !h[s.line]) h[s.line] = 'source';
      if (f.sink?.line && f.sink.line !== sinkLine) h[f.sink.line] = 'sink';
    }
    return h;
  }, [finding, flows]);

  // Keyboard navigation between findings of this scan (left/right arrows).
  useEffect(() => {
    function onKey(e) {
      const tag = (e.target?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target?.isContentEditable) return;
      if (idx < 0 || !ordered.length) return;
      if (e.key === 'ArrowLeft' && idx > 0) {
        const prev = ordered[idx - 1];
        navigate(`/findings/${scanId}/${encodeURIComponent(prev.comparisonKey)}`, { replace: false });
      } else if (e.key === 'ArrowRight' && idx < ordered.length - 1) {
        const next = ordered[idx + 1];
        navigate(`/findings/${scanId}/${encodeURIComponent(next.comparisonKey)}`, { replace: false });
      }
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [idx, ordered, scanId, navigate]);

  if (loading) return <Layout><PageLoader label="Loading finding…" detail="Preparing evidence, source context and data-flow analysis." /></Layout>;
  if (error) {
    return (
      <Layout>
        <ErrorState title="Could not load this finding" message={error} onRetry={() => window.location.reload()} />
      </Layout>
    );
  }
  if (!finding) {
    return (
      <Layout>
        <EmptyState
          icon={FileSearch}
          title="Finding not found"
          message="This finding no longer exists in the scan — it may have been resolved by a rescan."
          action={<Link to={`/scans/${scanId}`} className="btn-primary"><ArrowLeft size={14} /> Back to scan</Link>}
        />
      </Layout>
    );
  }

  const locationLabel = finding.filePath && finding.filePath !== 'submission.txt' ? `${finding.filePath}:${finding.line || '?'}` : `${scan?.fileName || 'submission.txt'}:${finding.line || '?'}`;

  return (
    <Layout>
      {/* Top navigation */}
      <div className="mb-4 flex items-center justify-between gap-3">
        <Link to={`/scans/${scanId}`} className="inline-flex items-center gap-1.5 text-xs text-slate-500 transition-colors hover:text-slate-300">
          <ArrowLeft size={13} /> {projectName || 'Scan'} · findings
        </Link>
        <div className="flex items-center gap-1 text-xs text-slate-600" role="navigation" aria-label="Finding navigation">
          <button
            type="button"
            disabled={idx <= 0}
            onClick={() => idx > 0 && navigate(`/findings/${scanId}/${encodeURIComponent(ordered[idx - 1].comparisonKey)}`)}
            className="btn-ghost p-1.5 disabled:opacity-30"
            aria-label="Previous finding"
          >
            <ArrowLeft size={14} />
          </button>
          <span className="px-1 tabular-nums">{idx + 1} / {ordered.length}</span>
          <button
            type="button"
            disabled={idx < 0 || idx >= ordered.length - 1}
            onClick={() => idx < ordered.length - 1 && navigate(`/findings/${scanId}/${encodeURIComponent(ordered[idx + 1].comparisonKey)}`)}
            className="btn-ghost p-1.5 disabled:opacity-30"
            aria-label="Next finding"
          >
            <ArrowRight size={14} />
          </button>
        </div>
      </div>

      {/* Hero header */}
      <div className="mb-5 flex flex-wrap items-start justify-between gap-4 rounded-lg border border-edge bg-base-900/80 p-5 shadow-lift">
        <div className="min-w-0">
          <p className="eyebrow">{finding.ruleId} · {finding.category || 'Finding'}</p>
          <h1 className="mt-1.5 flex flex-wrap items-center gap-3 text-xl font-bold tracking-tight text-slate-50">
            {finding.title}
          </h1>
          <p className="mt-2 font-mono text-[12.5px] text-slate-400">
            {locationLabel}
            <span className="mx-2 text-slate-700">·</span>
            <span className="tabular-nums">{formatDate(scan?.createdAt)}</span>
          </p>
        </div>
        <div className="flex shrink-0 flex-col items-end gap-2">
          <SeverityBadge severity={finding.severity} size="lg" />
          <div className="flex items-center gap-2">
            {finding.verdict ? <StatusBadge tone={vmeta.tone} label={`${vmeta.label} · ${finding.confidence}%`} /> : null}
            {status ? <StatusBadge tone={status.tone} label={status.label} /> : null}
          </div>
        </div>
      </div>

      <div className="grid gap-5 lg:grid-cols-[minmax(0,1fr)_350px]">
        {/* ── Main column ─────────────────────────────────────── */}
        <div className="flex min-w-0 flex-col gap-5">
          {isDep ? (
            <Card className="card-pad"><DependencyAdvisory finding={finding} /></Card>
          ) : (
            <>
              {/* What happened */}
              <Card className="p-5">
                <p className="eyebrow">What happened</p>
                <p className="mt-2 text-[14px] leading-relaxed text-slate-200">
                  {(finding.evidence?.explanation) || finding.reason || finding.description ||
                    `VulnLens flagged this ${finding.category ? finding.category.toLowerCase() : 'security'} pattern as requiring review.`}
                </p>
                {vmeta.note ? <p className="mt-2 text-xs text-slate-500">{vmeta.note}</p> : null}
              </Card>

              {/* Code */}
              <Card className="overflow-hidden">
                <div className="flex items-center justify-between border-b border-edge px-4 py-3">
                  <div className="flex items-center gap-2">
                    <ShieldAlert size={14} className={meta.text} />
                    <p className="text-[13px] font-semibold text-slate-100">Source context</p>
                    <span className="text-xs text-slate-500">line {finding.line}</span>
                  </div>
                  <CopyButton text={locationLabel} label="location" />
                </div>
                {srcLoading ? (
                  <div className="p-4 text-sm text-slate-500">Loading source window…</div>
                ) : srcWin ? (
                  <CodeWindow
                    file={srcWin.file}
                    window={srcWin}
                    highlights={highlights}
                    footerNote={
                      <span>
                        <span className="mr-3 inline-flex items-center gap-1 text-cyan-300"><span className="h-2 w-2 rounded-sm bg-flow" /> Source</span>
                        <span className="inline-flex items-center gap-1 text-red-300"><span className="h-2 w-2 rounded-sm bg-critical" /> Sink / finding line</span>
                      </span>
                    }
                  />
                ) : srcError ? (
                  <div className="p-4">
                    <p className="mb-2 text-xs text-slate-500">
                      Full source context is not available for this finding ({srcError}). Showing the captured snippet:
                    </p>
                    <CodeWindow code={finding.affectedCode} highlights={{ 1: 'primary' }} maxHeight="max-h-52" />
                  </div>
                ) : (
                  <div className="p-4">
                    <CodeWindow code={finding.affectedCode} highlights={{ 1: 'primary' }} maxHeight="max-h-52" />
                  </div>
                )}
              </Card>

              {/* Data flow */}
              <Card className="p-4">
                <DataFlowGraph finding={finding} />
              </Card>

              {/* Copilot */}
              <CopilotPanel scanId={scanId} finding={finding} code={contextCode} auto />
            </>
          )}
        </div>

        {/* ── Side column: deterministic evidence ─────────────── */}
        {!isDep ? (
          <div className="flex min-w-0 flex-col gap-5">
            <Card className="card-pad">
              <p className="eyebrow">Deterministic evidence</p>
              <div className="mt-1 divide-y divide-edge">
                <FactRow
                  ok={flags.established}
                  label="Untrusted input reaches the sink"
                  value={flags.sources.length ? flags.sources.join(', ') : undefined}
                />                <FactRow ok={flags.parameterized} label="Query is parameterized" />
                <FactRow ok={flags.sanitized} label="Input is sanitized before use" />
                <FactRow ok={flags.constantData} label="Data reaching the sink is constant" />
                {flags.sinkType ? (
                  <FactRow ok label="Sink identified" value={`${sinkLabel(flags.sinkType)}${flags.sinkLine ? ` (line ${flags.sinkLine})` : ''}`} />
                ) : null}
                <FactRow
                  ok={flows.length > 0}
                  label="Traced source→sink path"
                  value={flows.length ? `${flows.length} path${flows.length === 1 ? '' : 's'}` : undefined}
                />
              </div>
              <p className="mt-3 border-t border-edge pt-3 text-[11px] leading-relaxed text-slate-600">
                These assertions are produced by the deterministic scanner and were never modified by AI.
              </p>
            </Card>

            {flags.sources.length > 0 ? (
              <Card className="card-pad">
                <p className="eyebrow">Traced inputs</p>
                <ul className="mt-2 space-y-1.5">
                  {flags.sources.map((s, i) => (
                    <li key={i} className="flex items-center gap-2 rounded border border-edge bg-base-925 px-2.5 py-1.5 font-mono text-[11.5px] text-cyan-200">
                      <span className="text-cyan-500">●</span>
                      <span className="truncate">{s}</span>
                    </li>
                  ))}
                </ul>
              </Card>
            ) : null}
          </div>
        ) : null}
      </div>
    </Layout>
  );
}
