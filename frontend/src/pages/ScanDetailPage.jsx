import { useEffect, useMemo, useState } from 'react';
import { useParams, useNavigate, Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card, CardHeader } from '../components/ui/Card.jsx';
import { Button } from '../components/ui/Button.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { SeverityBadge } from '../components/ui/SeverityBadge.jsx';
import { StatusBadge } from '../components/ui/StatusBadge.jsx';
import { SecurityScore } from '../components/security/SecurityScore.jsx';
import { RiskBar } from '../components/security/RiskBar.jsx';
import { FindingTable } from '../components/security/FindingTable.jsx';
import {
  formatDate, scoreLabelText, errorMessage, rescanStatus, isDependency, sumCounts, cx,
} from '../utils/helpers.js';
import { Repeat, Download, ShieldCheck, TrendingUp, TrendingDown, Search } from 'lucide-react';

export default function ScanDetailPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [scan, setScan] = useState(null);
  const [project, setProject] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [filter, setFilter] = useState('all');
  const [kindFilter, setKindFilter] = useState('all');
  const [statusFilter, setStatusFilter] = useState('all');
  const [query, setQuery] = useState('');

  useEffect(() => {
    let mounted = true;
    async function load() {
      try {
        const [{ data: s }, comp, proj] = await Promise.all([
          api.get(`/scans/${id}`),
          api.get(`/scans/${id}/comparison`).catch(() => null),
          api.get('/projects').catch(() => ({ data: { projects: [] } })),
        ]);
        if (!mounted) return;
        setScan(s.scan);
        if (comp) setComparison(comp.data);
        setProject((proj.data.projects || []).find((p) => p.id === s.scan.project) || null);
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

  // Preserve legacy deep links (#finding=<key>) by forwarding to the finding page.
  useEffect(() => {
    if (!scan) return;
    const hash = window.location.hash;
    if (!hash.startsWith('#finding=')) return;
    const key = decodeURIComponent(hash.slice('#finding='.length));
    const f = (scan.findings || []).find((x) => x.comparisonKey === key);
    if (f) navigate(`/findings/${scan.id}/${encodeURIComponent(key)}`, { replace: true });
  }, [scan, navigate]);

  const findings = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (scan?.findings || [])
      .filter((f) => kindFilter === 'all' || (kindFilter === 'dependency' ? isDependency(f) : !isDependency(f)))
      .filter((f) => filter === 'all' || f.severity === filter)
      .filter((f) => {
        if (statusFilter === 'all') return true;
        const st = rescanStatus(f, comparison);
        if (statusFilter === 'new') return st?.label === 'New';
        if (statusFilter === 'remaining') return st?.label === 'Pre-existing';
        if (statusFilter === 'unclassified') return !st;
        return false;
      })
      .filter((f) => !q || `${f.title} ${f.category || ''} ${f.filePath || ''} ${f.affectedCode || ''} ${f.reason || ''}`.toLowerCase().includes(q));
  }, [scan, kindFilter, filter, statusFilter, query, comparison]);

  if (loading) return <Layout><PageLoader label="Loading scan results…" detail="Gathering findings, evidence and comparison data." /></Layout>;

  if (error) {
    return (
      <Layout>
        <ErrorState title="Could not load this scan" message={error} onRetry={() => window.location.reload()} />
      </Layout>
    );
  }

  const sev = scan?.severityCounts || {};
  const depSev = scan?.dependencySeverityCounts || {};
  const hasDeps = (scan?.dependencySummary?.total || 0) > 0;
  const comparisonData = comparison?.comparison;
  const all = scan?.findings || [];
  const confirmed = all.filter((f) => f.verdict === 'CONFIRMED').length;
  const potential = all.filter((f) => f.verdict === 'POTENTIAL').length;
  const resolvedCount = comparison?.detail?.counts?.resolved || 0;
  const newCount = comparison?.detail?.counts?.new || 0;
  const delta = comparisonData && typeof comparisonData.delta === 'number' ? comparisonData.delta : null;

  function download(kind) {
    const path = kind === 'sarif' ? `/reports/${scan.id}/sarif` : `/reports/${scan.id}/download`;
    const name = kind === 'sarif' ? `vulnlens-scan-${scan.id}.sarif` : `vulnlens-report-${scan.id}.json`;
    api.get(path, { responseType: 'blob' })
      .then((res) => {
        const url = window.URL.createObjectURL(new Blob([res.data]));
        const a = document.createElement('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      })
      .catch((err) => setError(errorMessage(err)));
  }

  return (
    <Layout>
      <PageHeader
        eyebrow="Scans"
        title={project?.name || 'Scan Results'}
        description={
          <>
            {scan.fileName} · {formatDate(scan.createdAt)} · <span className="tabular-nums">{scan.fileCount} files</span> analyzed
          </>
        }
        backTo="/scans"
        backLabel="Scan history"
        actions={
          <>
            <Link to="/scans/new" className="btn-secondary"><Repeat size={14} /> Rescan</Link>
            <Button variant="secondary" onClick={() => download('json')}><Download size={14} /> JSON report</Button>
            <Button variant="secondary" onClick={() => download('sarif')}><Download size={14} /> SARIF</Button>
          </>
        }
      />

      {/* Headline cards */}
      <div className="grid gap-5 lg:grid-cols-3">
        <Card className="card-pad flex flex-col items-center justify-center gap-1">
          <SecurityScore score={scan.score} size={140} strokeWidth={11} />
          <p className="mt-1 text-2xs text-slate-500">{scoreLabelText(scan.score)} posture</p>
        </Card>

        <Card className="flex flex-col p-5">
          <p className="eyebrow">Findings</p>
          <div className="mt-2 flex flex-wrap gap-2">
            {(['critical', 'high', 'medium', 'low', 'informational']).map((s) =>
              (sev[s] || 0) > 0 ? (
                <span key={s} className="inline-flex items-center gap-1.5 rounded border border-edge bg-base-850 px-2 py-1">
                  <SeverityBadge severity={s} />
                  <span className="font-mono text-sm font-bold tabular-nums text-slate-100">{sev[s]}</span>
                </span>
              ) : null
            )}
            {sumCounts(sev) === 0 ? <span className="text-sm text-slate-500">No issues detected.</span> : null}
          </div>
          <div className="mt-4">
            <RiskBar counts={sev} showLegend={false} />
          </div>
          <div className="mt-4 flex flex-wrap gap-x-5 gap-y-1.5 text-xs text-slate-500">
            <span className="text-slate-400">{all.length} total</span>
            <span className="text-critical">{confirmed} confirmed</span>
            <span className="text-amber-300/80">{potential} potential</span>
          </div>
        </Card>

        <Card className="flex flex-col p-5">
          <p className="eyebrow">Regression check</p>
          {comparisonData && delta !== null ? (
            <>
              <div className="mt-2 flex items-center gap-2">
                <span className={cx('text-2xl font-bold tabular-nums', delta >= 0 ? 'text-emerald-400' : 'text-critical')}>
                  {delta >= 0 ? '+' : ''}{delta}
                </span>
                <span className="text-xs text-slate-500">score vs previous scan</span>
              </div>
              <div className="mt-3 flex flex-wrap items-center gap-2">
                <StatusBadge tone="success" label={`${resolvedCount} resolved`} />
                {newCount > 0 ? <StatusBadge tone="critical" label={`${newCount} new`} /> : null}
                {delta >= 0 ? <TrendingUp size={15} className="text-emerald-400" /> : <TrendingDown size={15} className="text-critical" />}
              </div>
              <p className="mt-3 text-xs leading-relaxed text-slate-500">
                Comparison against the previous scan of this project
                {comparisonData.previousScore !== undefined ? ` (score ${comparisonData.previousScore} → ${scan.score})` : ''}.
              </p>
            </>
          ) : (
            <p className="mt-2 text-[13px] leading-relaxed text-slate-500">
              This is the first scan for this project. Scan the same code again after fixes to see
              resolved / remaining / new findings here.
            </p>
          )}
        </Card>
      </div>

      {/* Dependency strip */}
      {hasDeps ? (
        <Card className="card-pad">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div className="flex items-center gap-2">
              <ShieldCheck size={15} className="text-amber-300" />
              <p className="text-sm font-semibold text-slate-100">Dependencies</p>
              <span className="text-xs text-slate-500">
                {scan.dependencySummary.total} packages · {scan.dependencySummary.vulnerable} vulnerable
              </span>
            </div>
            <div className="w-48"><RiskBar counts={depSev} showLegend={false} /></div>
          </div>
        </Card>
      ) : null}

      {/* Findings list */}
      <Card className="mt-5">
        <CardHeader
          title="Findings"
          subtitle={`${all.length} total · ${findings.length} shown`}
          actions={
            <div className="flex flex-wrap items-center justify-end gap-2">
              <div className="relative">
                <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                <input value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search findings…" className="input w-40 pl-8 text-xs" aria-label="Search findings" />
              </div>
              <div className="flex items-center gap-1">
                {[{ k: 'all', label: 'All' }, { k: 'code', label: 'Code' }, { k: 'dependency', label: 'Dependencies' }].map((t) => (
                  <button key={t.k} onClick={() => setKindFilter(t.k)} aria-pressed={kindFilter === t.k} className={cx('rounded px-2 py-1 text-[11px] font-medium transition-colors', kindFilter === t.k ? 'bg-accent-600/25 text-accent-200' : 'text-slate-500 hover:bg-base-800 hover:text-slate-300')}>
                    {t.label}
                  </button>
                ))}
              </div>
              <div className="flex items-center gap-1">
                {[{ k: 'all', label: 'All' }, ...['critical', 'high', 'medium', 'low', 'informational'].map((s) => ({ k: s, label: s }))].map((t) => (
                  <button key={t.k} onClick={() => setFilter(t.k)} aria-pressed={filter === t.k} className={cx('rounded px-2 py-1 text-[11px] font-medium capitalize transition-colors', filter === t.k ? 'bg-accent-600/25 text-accent-200' : 'text-slate-500 hover:bg-base-800 hover:text-slate-300')}>
                    {t.label}
                  </button>
                ))}
              </div>
              {comparison?.detail ? (
                <div className="flex items-center gap-1">
                  {[{ k: 'all', label: 'All' }, { k: 'new', label: 'New' }, { k: 'remaining', label: 'Pre-existing' }].map((t) => (
                    <button key={t.k} onClick={() => setStatusFilter(t.k)} aria-pressed={statusFilter === t.k} className={cx('rounded px-2 py-1 text-[11px] font-medium capitalize transition-colors', statusFilter === t.k ? 'bg-accent-600/25 text-accent-200' : 'text-slate-500 hover:bg-base-800 hover:text-slate-300')}>
                      {t.label}
                    </button>
                  ))}
                </div>
              ) : null}
            </div>
          }
        />
        {findings.length === 0 ? (
          <div className="p-5">
            <EmptyState
              icon={ShieldCheck}
              tone={all.length ? 'default' : 'success'}
              title={all.length ? 'No findings match the current filters' : 'No vulnerabilities detected'}
              message={all.length ? 'Try clearing filters or your search term.' : 'This code passed deterministic static analysis with no detected issues.'}
            />
          </div>
        ) : (
          <FindingTable
            findings={findings}
            statusOf={(f) => rescanStatus(f, comparison)}
            onOpen={(f) => navigate(`/findings/${scan.id}/${encodeURIComponent(f.comparisonKey)}`)}
          />
        )}
      </Card>
    </Layout>
  );
}
