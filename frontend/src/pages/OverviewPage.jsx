import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card, CardHeader } from '../components/ui/Card.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { SeverityBadge } from '../components/ui/SeverityBadge.jsx';
import { RiskBar } from '../components/security/RiskBar.jsx';
import { SecurityScore } from '../components/security/SecurityScore.jsx';
import {
  severityMeta, sortFindings, scoreLabelText, scoreColor, formatDate, relativeTime,
} from '../utils/helpers.js';
import { ArrowRight, ScanSearch, ShieldCheck, FileSearch, FolderKanban } from 'lucide-react';

function CountStat({ severity, value, onNavigate }) {
  const meta = severityMeta(severity);
  return (
    <button
      type="button"
      onClick={onNavigate}
      className="group flex items-center gap-2.5 rounded-md border border-edge bg-base-925/60 px-3 py-2 text-left transition-colors hover:border-edge-strong hover:bg-base-850"
    >
      <span aria-hidden="true" className={`h-2.5 w-2.5 rounded-sm ${meta.dot}`} />
      <span className="text-sm font-bold tabular-nums text-slate-100">{value}</span>
      <span className="text-xs text-slate-500">{meta.label}</span>
    </button>
  );
}

export default function OverviewPage() {
  const [data, setData] = useState(null);
  const [projects, setProjects] = useState([]);
  const [latestScan, setLatestScan] = useState(null);
  const [latestLoading, setLatestLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const [{ data: dash }, { data: proj }] = await Promise.all([
          api.get('/dashboard'),
          api.get('/projects').catch(() => ({ data: { projects: [] } })),
        ]);
        if (!mounted) return;
        setData(dash);
        setProjects(proj.projects || []);
        setError('');

        const first = dash.recentScans?.[0];
        if (first?.id) {
          setLatestLoading(true);
          api
            .get(`/scans/${first.id}`)
            .then((res) => mounted && setLatestScan(res.data.scan))
            .catch(() => mounted && setLatestScan(null))
            .finally(() => mounted && setLatestLoading(false));
        }
      } catch (err) {
        if (mounted) setError(err?.response?.data?.error || 'Failed to load security posture');
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, []);

  if (loading) return <Layout><PageLoader label="Loading security posture…" detail="Aggregating scans, findings and risk across your projects." /></Layout>;

  const nameOf = (projectId) => projects.find((p) => p.id === projectId)?.name || 'Project';
  const noScans = !data?.recentScans?.length;
  const counts = data?.severityCounts || {};
  const totalFindings = data?.totalFindings || 0;
  const latestFindings = latestScan?.findings || [];
  const top = sortFindings(latestFindings).slice(0, 6);
  const confirmedCount = latestFindings.filter((f) => f.verdict === 'CONFIRMED').length;
  const potentialCount = latestFindings.filter((f) => f.verdict === 'POTENTIAL').length;

  return (
    <Layout>
      <PageHeader
        eyebrow="Overview"
        title="Security Posture"
        description="Your latest codebase security assessment — what VulnLens found and where your attention should go."
        actions={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> New Scan</Link>}
      />

      {error ? <ErrorState title="Could not load the overview" message={error} onRetry={() => window.location.reload()} /> : null}

      {!error && noScans ? (
        <EmptyState
          icon={ShieldCheck}
          title="No scans yet"
          message="Run your first security scan to establish your project's security baseline. Findings, data flows and risk scoring appear here."
          action={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> Start your first scan</Link>}
        />
      ) : null}

      {!error && !noScans && data ? (
        <div className="flex flex-col gap-5">
          {/* Score + latest scan summary */}
          <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
            <Card className="card-pad flex flex-col items-center justify-center gap-1">
              {data.overallScore !== null ? (
                <>
                  <SecurityScore score={data.overallScore} size={150} strokeWidth={11} />
                  <p className="mt-2 text-2xs text-slate-500">
                    Average posture across {data.scanCount} scan{data.scanCount === 1 ? '' : 's'}
                  </p>
                </>
              ) : null}
            </Card>

            <Card className="flex flex-col">
              <div className="flex-1 p-5">
                <p className="eyebrow">Latest assessment</p>
                <div className="mt-2 flex flex-wrap items-center gap-x-4 gap-y-2">
                  {(['critical', 'high', 'medium', 'low', 'informational']).map((s) => (
                    <SeverityBadge key={s} severity={s} />
                  ))}
                </div>
                <p className="mt-3 max-w-2xl text-[13.5px] leading-relaxed text-slate-400">
                  {totalFindings === 0
                    ? 'Your latest scans surfaced no actionable findings — the current posture is clean.'
                    : (counts.critical || counts.high
                        ? 'VulnLens found exploitable issues in your latest code: review the critical and high findings first, then work down.'
                        : 'VulnLens found issues worth attention in your latest code. Open a finding to see the attack path and remediation.')}{' '}
                  {latestScan ? (
                    <>
                      The most recent scan of <span className="font-medium text-slate-200">{nameOf(latestScan.project)}</span> analyzed{' '}
                      <span className="tabular-nums">{latestScan.fileCount} files</span> and reported{' '}
                      <span className="tabular-nums">{latestFindings.length} findings</span>.
                    </>
                  ) : null}
                </p>
                <div className="mt-4 flex flex-wrap gap-2">
                  <CountStat severity="critical" value={counts.critical || 0} onNavigate={() => window.location.assign('/findings')} />
                  <CountStat severity="high" value={counts.high || 0} onNavigate={() => window.location.assign('/findings')} />
                  <CountStat severity="medium" value={counts.medium || 0} onNavigate={() => window.location.assign('/findings')} />
                  <CountStat severity="low" value={counts.low || 0} onNavigate={() => window.location.assign('/findings')} />
                  <CountStat severity="informational" value={counts.informational || 0} onNavigate={() => window.location.assign('/findings')} />
                </div>
                {latestScan ? (
                  <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-1.5 border-t border-edge pt-3 text-xs text-slate-500">
                    <span className="inline-flex items-center gap-1.5"><FolderKanban size={13} className="text-slate-600" /> {nameOf(latestScan.project)}</span>
                    <span className="inline-flex items-center gap-1.5"><FileSearch size={13} className="text-slate-600" /> {latestScan.fileCount} files · {latestFindings.length} findings</span>
                    <span className="tabular-nums">{relativeTime(latestScan.createdAt)}</span>
                    <span className="text-slate-500">
                      {confirmedCount} confirmed · {potentialCount} potential
                    </span>
                    <Link to={`/scans/${latestScan.id}`} className="ml-auto inline-flex items-center gap-1 font-medium text-accent-300 hover:text-accent-200">
                      Open scan <ArrowRight size={12} />
                    </Link>
                  </div>
                ) : null}
              </div>
              {latestLoading ? (
                <div className="border-t border-edge px-5 py-3 text-xs text-slate-500">Loading latest scan details…</div>
              ) : null}
            </Card>
          </div>

          {/* Risk distribution */}
          <Card className="card-pad">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm font-semibold text-slate-100">Risk distribution</p>
                <p className="text-xs text-slate-500">Severity spread across your most recent scans</p>
              </div>
              <span className="text-lg font-bold tabular-nums" style={{ color: scoreColor(data.overallScore) }}>
                {scoreLabelText(data.overallScore)}
              </span>
            </div>
            <RiskBar counts={counts} className="mt-4" />
          </Card>

          <div className="grid gap-5 lg:grid-cols-2">
            {/* Recent scans */}
            <Card>
              <CardHeader
                title="Recent scans"
                subtitle="History across your projects"
                actions={<Link to="/scans" className="text-xs font-medium text-accent-300 hover:text-accent-200">View all</Link>}
              />
              {data.recentScans.length ? (
                <ul className="divide-y divide-edge">
                  {data.recentScans.slice(0, 6).map((s) => (
                    <li key={s.id}>
                      <Link to={`/scans/${s.id}`} className="flex items-center justify-between gap-3 px-5 py-3 text-[13px] transition-colors hover:bg-base-850/60">
                        <div className="min-w-0">
                          <p className="truncate font-medium text-slate-200">{nameOf(s.project)}</p>
                          <p className="text-xs text-slate-500">{formatDate(s.createdAt)} · {s.findingCount} findings</p>
                        </div>
                        <div className="flex items-center gap-3">
                          <span className="font-mono text-xs tabular-nums text-slate-500" title="Files analyzed">{s.fileCount ?? '—'} files</span>
                          <span className="w-12 text-right font-mono text-sm font-bold" style={{ color: scoreColor(s.score) }}>{s.score}</span>
                        </div>
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : null}
            </Card>

            {/* Top findings */}
            <Card>
              <CardHeader
                title="Priority findings"
                subtitle={latestScan ? `From the latest scan of ${nameOf(latestScan.project)}` : 'From the latest scan'}
                actions={latestScan ? <Link to={`/scans/${latestScan.id}`} className="text-xs font-medium text-accent-300 hover:text-accent-200">Open scan</Link> : null}
              />
              {latestScan && top.length > 0 ? (
                <ul className="divide-y divide-edge">
                  {top.map((f) => (
                    <li key={f.comparisonKey}>
                      <Link
                        to={`/findings/${latestScan.id}/${encodeURIComponent(f.comparisonKey)}`}
                        className="flex items-center gap-3 px-5 py-3 transition-colors hover:bg-base-850/60"
                      >
                        <SeverityBadge severity={f.severity} showLabel={false} />
                        <div className="min-w-0 flex-1">
                          <p className="truncate text-[13px] font-medium text-slate-200">{f.title}</p>
                          <p className="truncate font-mono text-[11px] text-slate-500">
                            {f.filePath === 'submission.txt' ? latestScan.fileName : f.filePath}
                            {f.line ? `:${f.line}` : ''}
                          </p>
                        </div>
                        <span className="shrink-0 text-[11px] tabular-nums text-slate-500">{f.confidence}%</span>
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="p-5">
                  <EmptyState
                    icon={ShieldCheck}
                    tone="success"
                    compact
                    title="No actionable findings"
                    message="The latest scan passed the current security checks."
                    action={<Link to="/scans/new" className="btn-secondary"><ScanSearch size={14} /> Scan again</Link>}
                  />
                </div>
              )}
            </Card>
          </div>
        </div>
      ) : null}
    </Layout>
  );
}
