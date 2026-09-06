import { useEffect, useState } from 'react';
import { useParams, Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { Card, CardHeader } from '../components/ui/Card.jsx';
import { Button } from '../components/ui/Button.jsx';
import { Modal } from '../components/ui/Modal.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { Alert } from '../components/ui/Alert.jsx';
import { SecurityScore } from '../components/security/SecurityScore.jsx';
import { SeverityChart } from '../components/security/SeverityChart.jsx';
import { FindingCard } from '../components/security/FindingCard.jsx';
import { FindingDetails } from '../components/security/FindingDetails.jsx';
import { DependencyDetails } from '../components/security/DependencyDetails.jsx';
import { formatDate, scoreColor, errorMessage, pluralize } from '../utils/helpers.js';
import { TrendingUp, TrendingDown, Download, FileSearch, Repeat, Search } from 'lucide-react';

export default function ScanDetailPage() {
  const { id } = useParams();
  const [scan, setScan] = useState(null);
  const [comparison, setComparison] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [selected, setSelected] = useState(null);
  const [filter, setFilter] = useState('all');
  const [kindFilter, setKindFilter] = useState('all'); // 'all' | 'code' | 'dependency'
  const [query, setQuery] = useState('');
  const [statusFilter, setStatusFilter] = useState('all'); // 'all' | 'resolved' | 'remaining' | 'new'
  const [activeIndex, setActiveIndex] = useState(0);

  const allFindings = scan?.findings || [];
  const q = query.trim().toLowerCase();
  const comparisonDetail = comparison?.detail?.counts;
  const resolvedByKey = comparisonDetail
    ? new Set(comparison.detail?.resolved?.map((r) => r.finding.comparisonKey) || [])
    : null;
  const newByKey = comparisonDetail
    ? new Set(comparison.detail?.new?.map((r) => r.finding.comparisonKey) || [])
    : null;
  const fKind = (f) => (f.kind === 'dependency' ? 'dependency' : 'code');
  const findings = allFindings
    .filter((f) => kindFilter === 'all' || fKind(f) === kindFilter)
    .filter((f) => filter === 'all' || f.severity === filter)
    .filter((f) => {
      if (statusFilter === 'resolved') return resolvedByKey && resolvedByKey.has(f.comparisonKey);
      if (statusFilter === 'new') return newByKey && newByKey.has(f.comparisonKey);
      if (statusFilter === 'remaining') {
        if (!resolvedByKey) return true;
        return !resolvedByKey.has(f.comparisonKey) && !(newByKey && newByKey.has(f.comparisonKey));
      }
      return true;
    })
    .filter((f) => !q || `${f.title} ${f.category || ''} ${f.filePath || ''} ${f.affectedCode || ''} ${f.reason || ''}`.toLowerCase().includes(q));
  const safeIndex = findings.length ? Math.min(activeIndex, findings.length - 1) : -1;
  const severityCounts = scan?.severityCounts;
  const comparisonData = comparison?.comparison;
  const depSummary = scan?.dependencySummary || { total: 0, vulnerable: 0, direct: 0, transitive: 0 };
  const hasDeps = (scan?.dependencySummary?.total || 0) > 0;

  useEffect(() => {
    async function load() {
      try {
        const [{ data: scanRes }, compRes] = await Promise.all([
          api.get(`/scans/${id}`),
          api.get(`/scans/${id}/comparison`).catch(() => null),
        ]);
        setScan(scanRes.scan);
        if (compRes) setComparison(compRes.data);
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  function openFinding(f) {
    setSelected(f);
    try {
      window.history.replaceState(null, '', `#finding=${encodeURIComponent(f.comparisonKey)}`);
    } catch {
      /* ignore history API failures */
    }
  }

  function closeFinding() {
    setSelected(null);
    try {
      window.history.replaceState(null, '', window.location.pathname);
    } catch {
      /* ignore history API failures */
    }
  }

  // Deep-link support: #finding=<comparisonKey> auto-opens the detail modal.
  useEffect(() => {
    const hash = window.location.hash;
    if (!hash.startsWith('#finding=') || !scan) return;
    const key = decodeURIComponent(hash.slice('#finding='.length));
    const f = (scan.findings || []).find((x) => x.comparisonKey === key);
    if (f) setSelected(f);
  }, [scan]);

  // Keyboard navigation across the findings list (↑/↓ move, Enter opens).
  useEffect(() => {
    function onKey(e) {
      const tag = (e.target?.tagName || '').toLowerCase();
      if (tag === 'input' || tag === 'textarea' || e.target?.isContentEditable) return;
      if (selected || findings.length === 0) return;
      if (e.key === 'ArrowDown' || e.key === 'ArrowRight') {
        e.preventDefault();
        setActiveIndex((i) => Math.min(i + 1, findings.length - 1));
      } else if (e.key === 'ArrowUp' || e.key === 'ArrowLeft') {
        e.preventDefault();
        setActiveIndex((i) => Math.max(i - 1, 0));
      } else if (e.key === 'Enter') {
        const f = findings[safeIndex];
        if (f) {
          e.preventDefault();
          openFinding(f);
        }
      }
    }
    document.addEventListener('keydown', onKey);
    return () => document.removeEventListener('keydown', onKey);
  }, [selected, findings, safeIndex]);

  // Keep the active card in view while navigating and reset on filter changes.
  useEffect(() => {
    if (safeIndex < 0) return;
    const el = document.querySelector(`[data-fidx="${safeIndex}"]`);
    el?.scrollIntoView({ block: 'nearest', behavior: 'smooth' });
  }, [safeIndex]);

  useEffect(() => {
    setActiveIndex(0);
  }, [id, filter, statusFilter, q, kindFilter]);

  if (loading) return <Layout><PageLoader label="Loading scan results..." /></Layout>;

  function downloadReport() {
    // Authenticated blob download so the Bearer token is sent (fixes the
    // window.open 401 noted in the security hardening report).
    api.get(`/reports/${scan.id}/download`, { responseType: 'blob' })
      .then((res) => {
        const url = window.URL.createObjectURL(new Blob([res.data]));
        const a = document.createElement('a');
        a.href = url;
        a.download = `vulnlens-report-${scan.id}.json`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      })
      .catch((err) => setError(errorMessage(err)));
  }

  function downloadSarif() {
    // Authenticated, ownership-checked SARIF 2.1.0 download.
    api.get(`/reports/${scan.id}/sarif`, { responseType: 'blob' })
      .then((res) => {
        const url = window.URL.createObjectURL(new Blob([res.data]));
        const a = document.createElement('a');
        a.href = url;
        a.download = `vulnlens-scan-${scan.id}.sarif`;
        document.body.appendChild(a);
        a.click();
        a.remove();
        window.URL.revokeObjectURL(url);
      })
      .catch((err) => setError(errorMessage(err)));
  }


  return (
    <Layout>
      <div className="mx-auto max-w-6xl">
        <div className="mb-6 flex flex-wrap items-start justify-between gap-3">
          <div>
            <Link to="/scans" className="text-xs text-sky-400 hover:text-sky-300">← Scans</Link>
            <h1 className="mt-1 text-xl font-bold text-slate-50">Scan Results</h1>
            <p className="text-sm text-slate-400">
              {scan?.fileCount > 0 ? `${scan.fileCount} files · ` : ''}{scan?.fileName || 'Scan'} · {formatDate(scan?.createdAt)}
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Link to="/new-scan" className="btn-secondary"><Repeat size={15} /> Rescan</Link>
            <Button variant="secondary" onClick={downloadReport}><Download size={15} /> Download Report</Button>
            <Button variant="secondary" onClick={downloadSarif}>
              <Download size={15} /> Download SARIF
            </Button>
          </div>
        </div>

        {error && <Alert variant="error">{error}</Alert>}

        {scan && (
          <div className="flex flex-col gap-5">
            {/* Score + severity */}
            <div className="grid gap-4 sm:grid-cols-3">
              <Card className="card-pad flex flex-col items-center justify-center gap-2">
                <SecurityScore score={scan.score} size={120} strokeWidth={11} />
                <span className="text-[11px] text-slate-500">{pluralize(findings.length, 'finding')} detected</span>
              </Card>
              <div className="card card-pad">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Severity Distribution</span>
                <SeverityChart counts={severityCounts} className="mt-2" />
              </div>
              <Card className="card-pad flex flex-col justify-center gap-3">
                <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Comparison</span>
                {comparisonData && typeof comparisonData.delta === 'number' ? (
                  <>
                    <div className="flex items-center gap-2">
                      <span className={`flex items-center gap-1 text-xl font-bold ${comparisonData.delta >= 0 ? 'text-emerald-400' : 'text-red-400'}`}>
                        {comparisonData.delta >= 0 ? <TrendingUp size={18} /> : <TrendingDown size={18} />}
                        {comparisonData.delta >= 0 ? '+' : ''}{comparisonData.delta}
                      </span>
                      <span className="text-xs text-slate-500">vs previous ({comparisonData.previousScore})</span>
                    </div>
                    <div className="flex gap-4 text-xs">
                      <span className="text-emerald-400">{pluralize(comparisonData.resolved, 'resolved')}</span>
                      <span className="text-slate-300">{pluralize(comparisonData.remaining, 'remaining')}</span>
                      <span className="text-red-400">{pluralize(comparisonData.new, 'new')}</span>
                    </div>
                  </>
                ) : (
                  <p className="text-xs text-slate-500">This is the first scan. Run it again after fixing code to see verification.</p>
                )}
              </Card>
            </div>

            {/* Dependencies overview (Phase 2) */}
            {hasDeps ? (
              <div className="card card-pad">
                <div className="grid gap-5 lg:grid-cols-2">
                  <div>
                    <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Dependencies</span>
                    <div className="mt-3 flex flex-wrap gap-x-8 gap-y-2 text-sm">
                      <div>
                        <div className="text-lg font-bold text-slate-100">{depSummary.total}</div>
                        <div className="text-[11px] text-slate-500">packages</div>
                      </div>
                      <div>
                        <div className="text-lg font-bold text-slate-100">{depSummary.direct}</div>
                        <div className="text-[11px] text-slate-500">direct</div>
                      </div>
                      <div>
                        <div className="text-lg font-bold text-slate-100">{depSummary.transitive}</div>
                        <div className="text-[11px] text-slate-500">transitive</div>
                      </div>
                      <div>
                        <div className={`text-lg font-bold ${depSummary.vulnerable ? 'text-amber-400' : 'text-emerald-400'}`}>{depSummary.vulnerable}</div>
                        <div className="text-[11px] text-slate-500">vulnerable</div>
                      </div>
                    </div>
                  </div>
                  <div>
                    <span className="text-[11px] font-medium uppercase tracking-wider text-slate-500">Dependency Severity</span>
                    <SeverityChart counts={scan?.dependencySeverityCounts} className="mt-2" />
                  </div>
                </div>
              </div>
            ) : null}

            {/* Findings list */}
            <Card>
              <CardHeader
                title="Findings"
                subtitle={`${(scan.findings || []).length} total · showing ${findings.length}`}
                actions={
                  <div className="flex flex-wrap items-center justify-end gap-2">
                    <div className="relative">
                      <Search size={13} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                      <input
                        value={query}
                        onChange={(e) => setQuery(e.target.value)}
                        placeholder="Search findings..."
                        className="input w-44 pl-8 text-xs"
                        aria-label="Search findings"
                      />
                    </div>
                    <div className="flex items-center gap-1">
                      {[
                        { key: 'all', label: 'All' },
                        { key: 'code', label: 'Code' },
                        { key: 'dependency', label: 'Dependencies' },
                      ].map((k) => (
                        <button
                          key={k.key}
                          onClick={() => setKindFilter(k.key)}
                          className={`rounded px-2 py-1 text-[11px] font-medium capitalize transition-colors ${
                            kindFilter === k.key ? 'bg-sky-600/20 text-sky-300' : 'text-slate-500 hover:bg-base-800 hover:text-slate-300'
                          }`}
                        >
                          {k.label}
                        </button>
                      ))}
                    </div>
                    <div className="flex items-center gap-1">
                      {['all', 'critical', 'high', 'medium', 'low', 'informational'].map((s) => (
                        <button
                          key={s}
                          onClick={() => setFilter(s)}
                          className={`rounded px-2 py-1 text-[11px] font-medium capitalize transition-colors ${
                            filter === s ? 'bg-sky-600/20 text-sky-300' : 'text-slate-500 hover:bg-base-800 hover:text-slate-300'
                          }`}
                        >
                          {s}
                        </button>
                      ))}
                    </div>
                  </div>
                }
              />
              {comparisonDetail && findings.length > 0 && (
                <div className="flex flex-wrap items-center gap-1.5 border-b border-borderline px-4 py-2">
                  <span className="mr-1 text-[11px] font-medium uppercase tracking-wider text-slate-500">Status</span>
                  {[
                    { key: 'all', label: 'All' },
                    { key: 'remaining', label: 'Remaining' },
                    { key: 'resolved', label: 'Resolved' },
                    { key: 'new', label: 'New' },
                  ].map((s) => (
                    <button
                      key={s.key}
                      onClick={() => setStatusFilter(s.key)}
                      className={`rounded px-2 py-1 text-[11px] font-medium capitalize transition-colors ${
                        statusFilter === s.key ? 'bg-sky-600/20 text-sky-300' : 'text-slate-500 hover:bg-base-800 hover:text-slate-300'
                      }`}
                    >
                      {s.label}
                    </button>
                  ))}
                  <span className="ml-auto text-[11px] tabular-nums text-slate-600">
                    {findings.length} shown · ↑/↓ to navigate · Enter to open
                  </span>
                </div>
              )}
              {findings.length === 0 ? (
                <div className="p-5">
                  <EmptyState icon={FileSearch} title="No findings" message={scan.findings && scan.findings.length ? 'No findings match the current filters or search.' : 'This code passed static analysis with no detected issues.'} />
                </div>
              ) : (
                <div className="grid gap-2 p-4 sm:grid-cols-2">
                  {findings.map((f, i) => (
                    <div key={f.comparisonKey} className="relative" data-fidx={i}>
                      <FindingCard
                        finding={f}
                        onClick={() => openFinding(f)}
                        className={i === safeIndex ? 'ring-2 ring-sky-500/40 border-sky-500/60' : ''}
                      />
                      {resolvedByKey && resolvedByKey.has(f.comparisonKey) && (
                        <span className="absolute right-2 top-2 rounded bg-emerald-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-emerald-300">Resolved</span>
                      )}
                      {newByKey && newByKey.has(f.comparisonKey) && (
                        <span className="absolute right-2 top-2 rounded bg-red-500/20 px-1.5 py-0.5 text-[10px] font-semibold text-red-300">New</span>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </Card>
          </div>
        )}
      </div>

      <Modal open={!!selected} onClose={closeFinding} title={selected?.kind === 'dependency' ? 'Dependency Details' : 'Finding Details'} maxWidth="max-w-3xl">
        {selected ? (
          selected.kind === 'dependency' ? <DependencyDetails finding={selected} /> : <FindingDetails finding={selected} />
        ) : null}
      </Modal>
    </Layout>
  );
}
