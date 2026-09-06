import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card, CardHeader } from '../components/ui/Card.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { StatusBadge } from '../components/ui/StatusBadge.jsx';
import { SecurityScore } from '../components/security/SecurityScore.jsx';
import { RiskBar } from '../components/security/RiskBar.jsx';
import { formatDate, scoreColor, errorMessage, scoreLabelText } from '../utils/helpers.js';
import { Plus, ScanSearch, ArrowUpRight, FolderKanban, TrendingUp, TrendingDown } from 'lucide-react';

export default function ProjectDetailPage() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const { data } = await api.get(`/projects/${id}/overview`);
        if (mounted) setData(data);
      } catch (err) {
        if (mounted) setError(errorMessage(err));
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, [id]);

  if (loading) return <Layout><PageLoader label="Loading project…" /></Layout>;
  if (error) {
    return (
      <Layout>
        <ErrorState title="Could not load this project" message={error} onRetry={() => window.location.reload()} />
      </Layout>
    );
  }

  const project = data.project;
  const latest = data.latestScan;
  const history = data.scanHistory || [];
  const comparison = data.comparisonSummary;
  const sev = latest?.severityCounts || {};

  return (
    <Layout>
      <PageHeader
        eyebrow="Overview"
        title={project?.name || 'Project'}
        description={project?.description || 'Security history and posture for this project.'}
        backTo="/projects"
        backLabel="Projects"
        actions={<Link to="/scans/new" className="btn-primary"><Plus size={15} /> New Scan</Link>}
      />

      <div className="flex flex-col gap-5">
        <div className="grid gap-5 lg:grid-cols-3">
          <Card className="card-pad flex flex-col items-center justify-center gap-2">
            {latest ? (
              <>
                <SecurityScore score={latest.score} size={130} strokeWidth={11} />
                <p className="text-2xs text-slate-500">{scoreLabelText(latest.score)} · {formatDate(latest.createdAt)}</p>
              </>
            ) : (
              <div className="flex flex-col items-center gap-2 py-6 text-slate-500">
                <FolderKanban size={24} />
                <span className="text-xs">No scans yet</span>
              </div>
            )}
          </Card>

          <Card className="p-5">
            <p className="eyebrow">Latest severity</p>
            {latest ? (
              <>
                <RiskBar counts={sev} className="mt-4" />
                <p className="mt-3 text-xs text-slate-500">
                  {(latest.findings || []).length} findings · {sev.critical || 0} critical, {sev.high || 0} high
                </p>
              </>
            ) : (
              <p className="mt-2 text-xs text-slate-600">Run a scan to see the risk distribution here.</p>
            )}
          </Card>

          <Card className="p-5">
            <p className="eyebrow">Verification</p>
            {comparison ? (
              <>
                <div className="mt-2 flex items-center gap-2">
                  <span className={comparison.delta >= 0 ? 'text-emerald-400' : 'text-critical'}>
                    {comparison.delta >= 0 ? <TrendingUp size={20} /> : <TrendingDown size={20} />}
                  </span>
                  <span className={`text-xl font-bold tabular-nums ${comparison.delta >= 0 ? 'text-emerald-400' : 'text-critical'}`}>
                    {comparison.delta >= 0 ? '+' : ''}{comparison.delta}
                  </span>
                  <span className="text-xs text-slate-500">points vs previous scan</span>
                </div>
                <div className="mt-3 flex flex-wrap gap-2">
                  <StatusBadge tone="success" label={`${comparison.resolved} resolved`} />
                  <StatusBadge tone="slate" label={`${comparison.remaining} remaining`} />
                  {comparison.new > 0 ? <StatusBadge tone="critical" label={`${comparison.new} new`} /> : null}
                </div>
                <p className="mt-3 text-xs text-slate-500">
                  Score {comparison.previousScore} → <span style={{ color: scoreColor(comparison.currentScore) }}>{comparison.currentScore}</span>
                </p>
              </>
            ) : (
              <p className="mt-2 text-xs leading-relaxed text-slate-500">
                Run the scan again after fixes to verify resolved and remaining findings.
              </p>
            )}
          </Card>
        </div>

        <Card>
          <CardHeader title="Scan history" subtitle={`${history.length} analysis runs for this project`} />
          {history.length === 0 ? (
            <div className="p-5">
              <EmptyState
                icon={ScanSearch}
                title="No scans for this project"
                message="Run your first security scan to establish the project's security baseline."
                action={<Link to="/scans/new" className="btn-primary"><ScanSearch size={14} /> Run a Scan</Link>}
              />
            </div>
          ) : (
            <ul className="divide-y divide-edge">
              {[...history].reverse().map((s) => (
                <li key={s.id}>
                  <Link to={`/scans/${s.id}`} className="group flex items-center justify-between gap-4 px-5 py-3.5 transition-colors hover:bg-base-850/60">
                    <div className="min-w-0">
                      <p className="text-[13px] font-medium text-slate-200 group-hover:text-white">
                        Scan · {formatDate(s.createdAt)}
                      </p>
                      <p className="text-xs text-slate-500">
                        {s.findingCount} findings{s.fileCount ? ` · ${s.fileCount} files` : ''}
                        {s.hasComparison && s.comparison && typeof s.comparison.delta === 'number' ? (
                          <span className={s.comparison.delta >= 0 ? 'ml-2 text-emerald-400' : 'ml-2 text-critical'}>
                            {s.comparison.delta >= 0 ? '+' : ''}{s.comparison.delta} pts
                          </span>
                        ) : null}
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      <span className="font-mono text-base font-bold" style={{ color: scoreColor(s.score) }}>{s.score}</span>
                      <ArrowUpRight size={15} className="text-slate-600 transition-colors group-hover:text-slate-300" />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </Layout>
  );
}
