import { useEffect, useMemo, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card, CardHeader } from '../components/ui/Card.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { SeverityBadge } from '../components/ui/SeverityBadge.jsx';
import { FindingTable } from '../components/security/FindingTable.jsx';
import { formatDate, rescanStatus, cx } from '../utils/helpers.js';
import { ScanSearch, ShieldCheck, Search } from 'lucide-react';

export default function FindingsPage() {
  const navigate = useNavigate();
  const [scans, setScans] = useState([]);
  const [projects, setProjects] = useState([]);
  const [scanId, setScanId] = useState('');
  const [scan, setScan] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [query, setQuery] = useState('');

  // Load scan list (pick the newest scan that has findings by default).
  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const [{ data: s }, p] = await Promise.all([
          api.get('/scans'),
          api.get('/projects').catch(() => ({ data: { projects: [] } })),
        ]);
        if (!mounted) return;
        setScans(s.scans || []);
        setProjects(p.data.projects || []);
        const preferred = (s.scans || []).find((x) => x.findingCount > 0) || s.scans?.[0];
        setScanId((prev) => prev || preferred?.id || '');
      } catch (err) {
        if (mounted) setError(err?.response?.data?.error || 'Failed to load scans');
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, []);

  // Load the selected scan's full findings + comparison.
  useEffect(() => {
    if (!scanId) return;
    let mounted = true;
    setScanLoading(true);
    setScan(null);
    Promise.all([
      api.get(`/scans/${scanId}`),
      api.get(`/scans/${scanId}/comparison`).catch(() => null),
    ])
      .then(([s, c]) => {
        if (!mounted) return;
        setScan(s.data.scan);
        if (c) setComparison(c.data);
      })
      .catch((err) => mounted && setError(err?.response?.data?.error || 'Failed to load findings'))
      .finally(() => mounted && setScanLoading(false));
    return () => {
      mounted = false;
    };
  }, [scanId]);

  const findings = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (scan?.findings || [])
      .filter((f) => filter === 'all' || f.severity === filter)
      .filter((f) => !q || `${f.title} ${f.category || ''} ${f.filePath || ''} ${f.affectedCode || ''} ${f.ruleId}`.toLowerCase().includes(q));
  }, [scan, filter, query]);

  if (loading) return <Layout><PageLoader label="Loading findings…" /></Layout>;

  const nameOf = (pid) => projects.find((p) => p.id === pid)?.name || 'Project';
  const total = scan?.findings?.length || 0;

  return (
    <Layout>
      <PageHeader
        eyebrow="Investigate"
        title="Findings"
        description="Every vulnerability VulnLens detected, filterable by severity, type, confidence and regression status."
        actions={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> New Scan</Link>}
      />

      {error && <div className="mb-4"><ErrorState title="Could not load findings" message={error} onRetry={() => window.location.reload()} /></div>}

      {!error && scans.length === 0 ? (
        <EmptyState
          icon={ScanSearch}
          title="No scans yet"
          message="Findings appear here after you run a security scan."
          action={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> Start a scan</Link>}
        />
      ) : null}

      {!error && scans.length > 0 && (
        <div className="flex flex-col gap-4">
          <Card className="p-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="min-w-[220px] flex-1 sm:max-w-sm">
                <label htmlFor="scan-picker" className="sr-only">Select a scan</label>
                <select
                  id="scan-picker"
                  className="input"
                  value={scanId}
                  onChange={(e) => { setScanId(e.target.value); setFilter('all'); setQuery(''); }}
                >
                  {scans.map((s) => (
                    <option key={s.id} value={s.id}>
                      {nameOf(s.project)} · {s.findingCount} findings · {formatDate(s.createdAt)}
                    </option>
                  ))}
                </select>
              </div>
              {scan && (
                <Link to={`/scans/${scan.id}`} className="text-xs font-medium text-accent-300 hover:text-accent-200">
                  Open full scan →
                </Link>
              )}
              <div className="ml-auto flex flex-wrap items-center gap-2">
                <div className="relative">
                  <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                  <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search…" className="input w-40 pl-8 text-xs" aria-label="Search findings" />
                </div>
                <div className="flex items-center gap-1">
                  {[{ k: 'all', label: 'All' }, ...['critical', 'high', 'medium', 'low', 'informational'].map((s) => ({ k: s, label: s }))].map((t) => (
                    <button key={t.k} onClick={() => setFilter(t.k)} aria-pressed={filter === t.k} className={cx('rounded px-2 py-1 text-[11px] font-medium capitalize transition-colors', filter === t.k ? 'bg-accent-600/25 text-accent-200' : 'text-slate-500 hover:bg-base-800 hover:text-slate-300')}>
                      {t.label}
                    </button>
                  ))}
                </div>
              </div>
            </div>
          </Card>

          {scanLoading ? <PageLoader label="Loading scan findings…" /> : null}

          {!scanLoading && scan ? (
            <>
              {total === 0 ? (
                <EmptyState
                  icon={ShieldCheck}
                  tone="success"
                  title="No vulnerabilities detected"
                  message="This scan found no actionable security findings."
                  action={<Link to="/scans/new" className="btn-primary"><ScanSearch size={14} /> Scan more code</Link>}
                />
              ) : findings.length === 0 ? (
                <EmptyState icon={ShieldCheck} title="Nothing matches" message="No findings match the current filter or search." />
              ) : (
                <Card>
                  <CardHeader
                    title={`${total} findings`}
                    subtitle={`${nameOf(scan.project)} · ${scan.fileCount} files · ${formatDate(scan.createdAt)}`}
                    actions={
                      <span className="text-xs text-slate-500">
                        {(['critical', 'high']).filter((s) => (scan.severityCounts || {})[s]).map((s) => (
                          <SeverityBadge key={s} severity={s} className="ml-1" />
                        ))}
                      </span>
                    }
                  />
                  <FindingTable
                    findings={findings}
                    statusOf={(f) => rescanStatus(f, comparison)}
                    onOpen={(f) => navigate(`/findings/${scan.id}/${encodeURIComponent(f.comparisonKey)}`)}
                  />
                </Card>
              )}
            </>
          ) : null}
        </div>
      )}
    </Layout>
  );
}
