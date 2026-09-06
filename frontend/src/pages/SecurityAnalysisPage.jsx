import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card } from '../components/ui/Card.jsx';
import { SeverityBadge } from '../components/ui/SeverityBadge.jsx';
import { StatusBadge } from '../components/ui/StatusBadge.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { CodeWindow } from '../components/security/CodeWindow.jsx';
import { DataFlowGraph } from '../components/security/DataFlowGraph.jsx';
import { useSourceWindow } from '../hooks/useSourceWindow.js';
import { extractFlows, flowFlags } from '../utils/flow.js';
import { formatDate, isDependency, sortFindings, cx } from '../utils/helpers.js';
import { Radar, ScanSearch, ArrowUpRight, ShieldCheck } from 'lucide-react';

export default function SecurityAnalysisPage() {
  const [scans, setScans] = useState([]);
  const [projects, setProjects] = useState([]);
  const [scanId, setScanId] = useState('');
  const [scan, setScan] = useState(null);
  const [selected, setSelected] = useState(null);
  const [loading, setLoading] = useState(true);
  const [scanLoading, setScanLoading] = useState(false);
  const [error, setError] = useState('');

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
        setScanId((prev) => prev || s.scans?.[0]?.id || '');
      } catch (err) {
        if (mounted) setError(err?.response?.data?.error || 'Failed to load analyses');
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, []);

  useEffect(() => {
    if (!scanId) return;
    let mounted = true;
    setScanLoading(true);
    setScan(null);
    setSelected(null);
    api
      .get(`/scans/${scanId}`)
      .then((res) => mounted && setScan(res.data.scan))
      .catch((err) => mounted && setError(err?.response?.data?.error || 'Failed to load scan'))
      .finally(() => mounted && setScanLoading(false));
    return () => {
      mounted = false;
    };
  }, [scanId]);

  // Code findings that carry a traced or shape-level flow.
  const flowFindings = useMemo(() => {
    if (!scan) return [];
    return sortFindings(
      (scan.findings || []).filter((f) => !isDependency(f) && (extractFlows(f).length > 0 || flowFlags(f).sources.length > 0))
    );
  }, [scan]);

  const nameOf = (pid) => projects.find((p) => p.id === pid)?.name || 'Project';
  const active = selected || flowFindings[0] || null;

  const { window: srcWin, loading: srcLoading } = useSourceWindow({
    scanId,
    file: active?.filePath,
    line: active?.line,
    enabled: !!active && !!active.filePath && !!active.line && scanId === (scan?.id),
  });

  if (loading) return <Layout><PageLoader label="Loading security analysis…" /></Layout>;

  return (
    <Layout>
      <PageHeader
        eyebrow="Investigate"
        title="Security Analysis · Data Flow"
        description="See how untrusted input travels through your code: source → propagation → sink, exactly as the deterministic scanner traced it."
        actions={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> New Scan</Link>}
      />

      {error && <div className="mb-4"><ErrorState title="Could not load analysis" message={error} onRetry={() => window.location.reload()} /></div>}

      {!error && scans.length === 0 ? (
        <EmptyState
          icon={Radar}
          title="No scans to analyze"
          message="Run a security scan first — traced data flows appear here."
          action={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> Start a scan</Link>}
        />
      ) : null}

      {!error && scans.length > 0 && (
        <div className="flex flex-col gap-4">
          <Card className="p-4">
            <label htmlFor="flow-scan" className="sr-only">Select a scan</label>
            <select id="flow-scan" className="input max-w-sm" value={scanId} onChange={(e) => setScanId(e.target.value)}>
              {scans.map((s) => (
                <option key={s.id} value={s.id}>
                  {nameOf(s.project)} · {s.findingCount} findings · {formatDate(s.createdAt)}
                </option>
              ))}
            </select>
          </Card>

          {scanLoading ? <PageLoader label="Analyzing data flows…" /> : null}

          {!scanLoading && scan ? (
            flowFindings.length === 0 ? (
              <EmptyState
                icon={ShieldCheck}
                tone="success"
                title="No traced data flows in this scan"
                message="No findings in this scan carried source→sink flow evidence. Flows appear for injection, XSS, command, and file-handling patterns."
              />
            ) : (
              <div className="grid gap-5 lg:grid-cols-[320px_minmax(0,1fr)]">
                {/* Flow list */}
                <Card className="overflow-hidden">
                  <div className="border-b border-edge px-4 py-3">
                    <p className="text-[13px] font-semibold text-slate-100">{flowFindings.length} flows traced</p>
                    <p className="text-xs text-slate-500">{scan.fileCount} files analyzed</p>
                  </div>
                  <ul className="max-h-[560px] divide-y divide-edge overflow-y-auto">
                    {flowFindings.map((f) => {
                      const f2 = flowFlags(f);
                      const count = extractFlows(f).length;
                      const isActive = active?.comparisonKey === f.comparisonKey;
                      return (
                        <li key={f.comparisonKey}>
                          <button
                            type="button"
                            onClick={() => setSelected(f)}
                            aria-pressed={isActive}
                            className={cx('w-full px-4 py-3 text-left transition-colors', isActive ? 'bg-accent-500/[0.07]' : 'hover:bg-base-850/70')}
                          >
                            <div className="flex items-center justify-between gap-2">
                              <SeverityBadge severity={f.severity} />
                              <span className="text-[10px] font-semibold uppercase tracking-wide text-cyan-300">{count} path{count === 1 ? '' : 's'}</span>
                            </div>
                            <p className="mt-1.5 truncate text-[13px] font-medium text-slate-100">{f.title}</p>
                            <p className="truncate font-mono text-[10.5px] text-slate-500">
                              {f.filePath || scan.fileName}{f.line ? `:${f.line}` : ''}
                            </p>
                            <div className="mt-1.5 flex flex-wrap gap-1.5">
                              {f2.direct ? <StatusBadge tone="flow" label="direct" dot={false} /> : null}
                              {f2.parameterized ? <StatusBadge tone="success" label="parameterized" dot={false} /> : null}
                              {f2.sanitized ? <StatusBadge tone="info" label="sanitized" dot={false} /> : null}
                            </div>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                </Card>

                {/* Selected flow */}
                <div className="flex min-w-0 flex-col gap-4">
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <p className="text-sm font-semibold text-slate-100">{active.title}</p>
                    <Link to={`/findings/${scan.id}/${encodeURIComponent(active.comparisonKey)}`} className="inline-flex items-center gap-1 text-xs font-medium text-accent-300 hover:text-accent-200">
                      Open full finding <ArrowUpRight size={13} />
                    </Link>
                  </div>
                  <DataFlowGraph finding={active} />
                  <div>
                    <p className="eyebrow mb-2">Source context</p>
                    {srcLoading ? (
                      <p className="text-sm text-slate-500">Loading source…</p>
                    ) : srcWin ? (
                      <CodeWindow file={srcWin.file} window={srcWin} highlights={{ [active.line]: 'primary' }} maxHeight="max-h-80" />
                    ) : (
                      <CodeWindow code={active.affectedCode} highlights={{ 1: 'primary' }} maxHeight="max-h-40" />
                    )}
                  </div>
                </div>
              </div>
            )
          ) : null}
        </div>
      )}
    </Layout>
  );
}
