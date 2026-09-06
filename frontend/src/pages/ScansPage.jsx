import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card } from '../components/ui/Card.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { formatDate, scoreColor, scoreLabelText, errorMessage, cx } from '../utils/helpers.js';
import { ScanSearch, ArrowUpRight } from 'lucide-react';

export default function ScansPage() {
  const [scans, setScans] = useState([]);
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const [s, p] = await Promise.all([
          api.get('/scans'),
          api.get('/projects').catch(() => ({ data: { projects: [] } })),
        ]);
        if (!mounted) return;
        setScans(s.data.scans || []);
        setProjects(p.data.projects || []);
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
  }, []);

  if (loading) return <Layout><PageLoader label="Loading scan history…" /></Layout>;
  const nameOf = (pid) => projects.find((p) => p.id === pid)?.name || 'Project';

  return (
    <Layout>
      <PageHeader
        eyebrow="Scans"
        title="Scan History"
        description="Every security analysis you have run — reopen results, comparisons and exports at any time."
        actions={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> New Scan</Link>}
      />

      {error && <ErrorState title="Could not load scans" message={error} onRetry={() => window.location.reload()} />}

      {!error && scans.length === 0 ? (
        <EmptyState
          icon={ScanSearch}
          title="No scans yet"
          message="Run your first security scan to establish your project's security baseline."
          action={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> Start a scan</Link>}
        />
      ) : null}

      {!error && scans.length > 0 ? (
        <Card className="overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[820px] text-left">
              <caption className="sr-only">Scan history</caption>
              <thead>
                <tr className="border-b border-edge text-2xs uppercase tracking-wider text-slate-500">
                  <th scope="col" className="px-5 py-3 font-semibold">Scan</th>
                  <th scope="col" className="px-4 py-3 font-semibold">Started</th>
                  <th scope="col" className="px-4 py-3 text-right font-semibold">Files</th>
                  <th scope="col" className="px-4 py-3 text-right font-semibold">Findings</th>
                  <th scope="col" className="px-4 py-3 text-right font-semibold">Trend</th>
                  <th scope="col" className="px-4 py-3 text-right font-semibold">Score</th>
                  <th scope="col" className="w-10 px-2 py-3" />
                </tr>
              </thead>
              <tbody className="divide-y divide-edge">
                {scans.map((s) => {
                  const delta = s.hasComparison && typeof s.comparison?.delta === 'number' ? s.comparison.delta : null;
                  const files = s.fileCount || 0;
                  const sc = s.severityCounts || {};
                  return (
                    <tr key={s.id} className="group">
                      <td className="px-5 py-3">
                        <div className="flex items-center gap-3">
                          <span className="flex h-8 w-8 shrink-0 items-center justify-center rounded-md border border-edge bg-base-850 text-slate-400">
                            <ScanSearch size={14} />
                          </span>
                          <div className="min-w-0">
                            <p className="truncate text-[13px] font-medium text-slate-100">{nameOf(s.project)}</p>
                            <p className="truncate font-mono text-[11px] text-slate-500">{s.fileName}</p>
                          </div>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-slate-400">{formatDate(s.createdAt)}</td>
                      <td className="px-4 py-3 text-right text-sm tabular-nums text-slate-300">{files}</td>
                      <td className="px-4 py-3 text-right">
                        <span className="text-sm font-semibold tabular-nums text-slate-200">{s.findingCount}</span>
                        {(sc.critical || sc.high) ? (
                          <span className="ml-2 inline-flex gap-1.5 text-[10px] font-semibold tabular-nums">
                            {sc.critical ? <span className="text-critical">{sc.critical}C</span> : null}
                            {sc.high ? <span className="text-high">{sc.high}H</span> : null}
                          </span>
                        ) : null}
                      </td>
                      <td className="px-4 py-3 text-right">
                        {delta === null ? (
                          <span className="text-xs text-slate-600">baseline</span>
                        ) : (
                          <span
                            className={cx('text-xs font-semibold tabular-nums', delta >= 0 ? 'text-emerald-400' : 'text-critical')}
                            title={`Score vs previous scan (${s.comparison.previousScore ?? '—'} → ${s.score})`}
                          >
                            {delta >= 0 ? '+' : ''}{delta}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className="font-mono text-sm font-bold" style={{ color: scoreColor(s.score) }}>{s.score}</span>
                        <span className="ml-2 hidden text-[10px] uppercase tracking-wide text-slate-500 lg:inline">{scoreLabelText(s.score)}</span>
                      </td>
                      <td className="px-2 py-3">
                        <Link to={`/scans/${s.id}`} className="inline-flex items-center justify-center rounded p-1.5 text-slate-600 transition-colors hover:bg-base-850 hover:text-slate-200" aria-label={`Open scan of ${nameOf(s.project)}`}>
                          <ArrowUpRight size={15} />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </Card>
      ) : null}
    </Layout>
  );
}
