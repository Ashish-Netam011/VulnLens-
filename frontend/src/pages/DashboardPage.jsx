import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { Card, CardHeader } from '../components/ui/Card.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { SecurityScore } from '../components/security/SecurityScore.jsx';
import { SeverityChart } from '../components/security/SeverityChart.jsx';
import { formatDate, scoreColor } from '../utils/helpers.js';
import { FolderKanban, ScanSearch, FileSearch } from 'lucide-react';

export default function DashboardPage() {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    async function load() {
      try {
        const { data } = await api.get('/dashboard');
        setData(data);
      } catch (err) {
        setError(err?.response?.data?.error || 'Failed to load dashboard');
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) {
    return <Layout><PageLoader label="Loading dashboard..." /></Layout>;
  }

  return (
    <Layout>
      <div className="mx-auto max-w-6xl">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-50">Security Overview</h1>
            <p className="text-sm text-slate-400">AI-assisted monitoring across all your projects</p>
          </div>
          <Link to="/new-scan" className="btn-primary">New Scan</Link>
        </div>

        {error ? (
          <div className="card card-pad text-sm text-red-300">{error}</div>
        ) : (
          <div className="flex flex-col gap-5">
            {/* Top metric cards */}
            <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
              <div className="card card-pad flex flex-col items-center justify-center gap-1">
                {data.overallScore !== null ? (
                  <>
                    <SecurityScore score={data.overallScore} size={96} strokeWidth={9} />
                    <span className="mt-1 text-[11px] text-slate-500">Average across projects</span>
                  </>
                ) : (
                  <div className="flex flex-col items-center gap-2 text-slate-500">
                    <ScanSearch size={28} />
                    <span className="text-xs">No scans yet</span>
                  </div>
                )}
              </div>

              <div className="card card-pad flex flex-col justify-center">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Projects</span>
                <span className="mt-1 text-2xl font-bold text-slate-100">{data.projectCount ?? 0}</span>
                <span className="mt-1 text-[11px] text-slate-500">
                  {data.latestProject ? `Latest: ${data.latestProject.name}` : 'No projects yet'}
                </span>
              </div>

              <div className="card card-pad flex flex-col justify-center">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Findings</span>
                <span className="mt-1 text-2xl font-bold text-slate-100">{data.totalFindings ?? 0}</span>
                <span className="mt-1 text-[11px] text-slate-500">{data.scanCount ?? 0} total scans</span>
              </div>

              <div className="card card-pad">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Severity Distribution</span>
                <SeverityChart counts={data.severityCounts} className="mt-2" />
              </div>
            </div>


            {/* Recent scans */}
            <Card>
              <CardHeader
                title="Recent Scans"
                subtitle="Latest security analysis results"
                actions={<Link to="/scans" className="text-xs text-sky-400 hover:text-sky-300">View all</Link>}
              />
              {data.recentScans && data.recentScans.length ? (
                <ul className="divide-y divide-borderline">
                  {data.recentScans.map((s) => (
                    <li key={s.id}>
                      <Link
                        to={`/scans/${s.id}`}
                        className="flex flex-wrap items-center justify-between gap-2 px-5 py-3 text-sm hover:bg-base-850"
                      >
                        <div className="flex items-center gap-3">
                          <span className="flex h-8 w-8 items-center justify-center rounded-md bg-base-800 text-slate-400">
                            <FileSearch size={15} />
                          </span>
                          <div>
                            <p className="font-medium text-slate-200">{s.fileName || 'Scan'}</p>
                            <p className="text-xs text-slate-500">{formatDate(s.createdAt)}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-4">
                          {s.severityCounts ? (
                            <div className="flex items-center gap-2 text-xs tabular-nums">
                              <span className="text-critical">{s.severityCounts.critical || 0}</span>
                              <span className="text-high">{s.severityCounts.high || 0}</span>
                              <span className="text-medium">{s.severityCounts.medium || 0}</span>
                              <span className="text-low">{s.severityCounts.low || 0}</span>
                            </div>
                          ) : null}
                          <span className="text-base font-bold" style={{ color: scoreColor(s.score) }}>{s.score}</span>
                        </div>
                      </Link>
                    </li>
                  ))}
                </ul>
              ) : (
                <div className="p-5">
                  <EmptyState
                    icon={FolderKanban}
                    title="No scans yet"
                    message="Create a project and run your first security scan to see results here."
                    action={<Link to="/new-scan" className="btn-primary">Start Scanning</Link>}
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

