import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { Card, CardHeader } from '../components/ui/Card.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { Alert } from '../components/ui/Alert.jsx';
import { SecurityScore } from '../components/security/SecurityScore.jsx';
import { SeverityChart } from '../components/security/SeverityChart.jsx';
import { formatDate, scoreColor, errorMessage } from '../utils/helpers.js';
import { Plus, FileSearch, ArrowRight, TrendingUp, TrendingDown } from 'lucide-react';

export default function ProjectDetailPage() {
  const { id } = useParams();
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    async function load() {
      try {
        const { data } = await api.get(`/projects/${id}/overview`);
        setData(data);
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  if (loading) return <Layout><PageLoader label="Loading project..." /></Layout>;

  const overview = data;
  const latest = overview?.latestScan;
  const comparison = overview?.comparisonSummary;

  return (
    <Layout>
      <div className="mx-auto max-w-6xl">
        <div className="mb-6 flex items-start justify-between">
          <div>
            <Link to="/projects" className="text-xs text-sky-400 hover:text-sky-300">← Projects</Link>
            <h1 className="mt-1 text-xl font-bold text-slate-50">{overview?.project?.name || 'Project'}</h1>
            {overview?.project?.description ? (
              <p className="text-sm text-slate-400">{overview.project.description}</p>
            ) : null}
          </div>
          <Link to="/new-scan" className="btn-primary"><Plus size={16} /> New Scan</Link>
        </div>

        {error ? (
          <div className="card card-pad text-sm text-red-300">{error}</div>
        ) : (
          <div className="flex flex-col gap-5">
            <div className="grid gap-4 sm:grid-cols-3">
              <div className="card card-pad flex flex-col items-center justify-center gap-2">
                {latest ? (
                  <>
                    <SecurityScore score={latest.score} size={110} strokeWidth={10} />
                    <span className="text-[11px] text-slate-500">{formatDate(latest.createdAt)}</span>
                  </>
                ) : (
                  <div className="flex flex-col items-center gap-2 text-slate-500">
                    <FileSearch size={26} />
                    <span className="text-xs">No scans yet</span>
                  </div>
                )}
              </div>

              <div className="card card-pad">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Severity Distribution</span>
                {latest ? (
                  <SeverityChart counts={latest.severityCounts} className="mt-2" />
                ) : (
                  <p className="mt-2 text-xs text-slate-600">Once you scan this project, findings will appear here.</p>
                )}
              </div>

              <Card className="card-pad">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Scan History</span>
                <p className="mt-2 text-2xl font-bold text-slate-100">{overview?.scanHistory?.length ?? 0}</p>
                <p className="text-xs text-slate-500">runs on this project</p>
              </Card>
            </div>

            {comparison ? (
              <div className="card card-pad">
                <div className="mb-3 flex items-center gap-3">
                  <h3 className="text-sm font-semibold text-slate-100">Verification: Last Scan vs Previous</h3>
                  {comparison.delta !== undefined && (
                    <span className={`flex items-center gap-1 text-xs font-semibold ${comparison.delta >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                      {comparison.delta >= 0 ? <TrendingUp size={14} /> : <TrendingDown size={14} />}
                      {comparison.delta >= 0 ? '+' : ''}{comparison.delta} points
                    </span>
                  )}
                </div>
                <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
                  <div><p className="text-xs text-slate-500">Resolved</p><p className="text-lg font-bold text-emerald-400">{comparison.resolved}</p></div>
                  <div><p className="text-xs text-slate-500">Remaining</p><p className="text-lg font-bold text-slate-200">{comparison.remaining}</p></div>
                  <div><p className="text-xs text-slate-500">New</p><p className="text-lg font-bold text-red-400">{comparison.new}</p></div>
                  <div><p className="text-xs text-slate-500">Score Change</p><p className="text-lg font-bold" style={{ color: scoreColor(comparison.currentScore) }}>{comparison.previousScore} → {comparison.currentScore}</p></div>
                </div>
              </div>
            ) : null}


            <Card>
              <CardHeader title="All Scans" subtitle="History of security analyses for this project" />
              {overview?.scanHistory?.length ? (
                <ul className="divide-y divide-borderline">
                  {[...overview.scanHistory].reverse().map((s) => (
                    <li key={s.id}>
                      <Link to={`/scans/${s.id}`} className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 text-sm hover:bg-base-850">
                        <div className="flex items-center gap-3">
                          <span className="flex h-8 w-8 items-center justify-center rounded-md bg-base-800 text-slate-400"><FileSearch size={15} /></span>
                          <div>
                            <p className="font-medium text-slate-200">Scan · {formatDate(s.createdAt)}</p>
                            <p className="text-xs text-slate-500">{s.findingCount} findings</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-3">
                          {s.hasComparison && s.comparison && typeof s.comparison.delta === 'number' ? (
                            <span className={`text-xs ${s.comparison.delta >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                              {s.comparison.delta >= 0 ? '+' : ''}{s.comparison.delta}
                            </span>
                          ) : null}
                          <span className="text-base font-bold" style={{ color: scoreColor(s.score) }}>{s.score}</span>
                          <ArrowRight size={15} className="text-slate-600" />
                        </div>
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="p-5">
                  <EmptyState
                    icon={FileSearch}
                    title="No scans for this project"
                    message="Run your first security scan to get a security score and findings."
                    action={<Link to="/new-scan" className="btn-primary">Run a Scan</Link>}
                  />
                </div>
              )}
            </Card>
          </div>
        )}
      </div>
    </Layout>
  );
}

