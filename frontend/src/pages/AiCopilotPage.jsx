import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card } from '../components/ui/Card.jsx';
import { SeverityBadge } from '../components/ui/SeverityBadge.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { CopilotPanel } from '../components/ai/CopilotPanel.jsx';
import { useSourceWindow } from '../hooks/useSourceWindow.js';
import { formatDate, isDependency, sortFindings, cx } from '../utils/helpers.js';
import { Sparkles, ScanSearch, ArrowUpRight, ShieldCheck } from 'lucide-react';

export default function AiCopilotPage() {
  const [scans, setScans] = useState([]);
  const [projects, setProjects] = useState([]);
  const [scanId, setScanId] = useState('');
  const [scan, setScan] = useState(null);
  const [selectedKey, setSelectedKey] = useState('');
  const [loading, setLoading] = useState(true);
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
        if (mounted) setError(err?.response?.data?.error || 'Failed to load findings');
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
    api
      .get(`/scans/${scanId}`)
      .then((res) => {
        if (!mounted) return;
        setScan(res.data.scan);
        setSelectedKey((prev) => prev || res.data.scan.findings?.[0]?.comparisonKey || '');
      })
      .catch((err) => mounted && setError(err?.response?.data?.error || 'Failed to load scan'))
      .finally(() => mounted && setLoading(false));
    return () => {
      mounted = false;
    };
  }, [scanId]);

  const findings = useMemo(() => (scan ? sortFindings((scan.findings || []).filter((f) => !isDependency(f))) : []), [scan]);
  const finding = findings.find((f) => f.comparisonKey === selectedKey) || findings[0] || null;
  const nameOf = (pid) => projects.find((p) => p.id === pid)?.name || 'Project';

  const { window: srcWin, loading: srcLoading } = useSourceWindow({
    scanId,
    file: finding?.filePath,
    line: finding?.line,
    enabled: !!finding && !!finding.filePath && !!finding.line,
  });
  const contextCode = srcWin ? srcWin.lines.map((l) => l.code).join('\n') : undefined;

  if (loading) return <Layout><PageLoader label="Loading AI Copilot…" /></Layout>;

  return (
    <Layout>
      <PageHeader
        eyebrow="Investigate"
        title="AI Security Copilot"
        description="Select a deterministic finding and get a structured security explanation: why it matters, real impact, an attack scenario, remediation, and a secure code example."
      />

      {error && <div className="mb-4"><ErrorState title="Could not load Copilot data" message={error} onRetry={() => window.location.reload()} /></div>}

      {!error && scans.length === 0 ? (
        <EmptyState
          icon={Sparkles}
          title="No findings to explain yet"
          message="Run a security scan first — then explain any finding the deterministic scanner reports."
          action={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> Start a scan</Link>}
        />
      ) : null}

      {!error && scans.length > 0 && (
        <div className="flex flex-col gap-4">
          <Card className="p-4">
            <div className="flex flex-wrap items-center gap-3">
              <label htmlFor="copilot-scan" className="sr-only">Select a scan</label>
              <select id="copilot-scan" className="input max-w-xs" value={scanId} onChange={(e) => { setScanId(e.target.value); setSelectedKey(''); }}>
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {nameOf(s.project)} · {formatDate(s.createdAt)}
                  </option>
                ))}
              </select>
              <label htmlFor="copilot-finding" className="sr-only">Select a finding</label>
              <select id="copilot-finding" className="input min-w-[200px] flex-1 sm:max-w-sm" value={finding?.comparisonKey || ''} onChange={(e) => setSelectedKey(e.target.value)}>
                {findings.length === 0 ? <option value="">No code findings in this scan</option> : null}
                {findings.map((f) => (
                  <option key={f.comparisonKey} value={f.comparisonKey}>
                    [{f.severity}] {f.title} · {f.filePath?.split('/').pop() || scan.fileName}:{f.line || '?'}
                  </option>
                ))}
              </select>
            </div>
          </Card>

          {finding ? (
            <>
              <div className="flex flex-wrap items-center justify-between gap-2">
                <div className="flex items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <p className="text-[13px] text-slate-300">
                    <span className="font-medium text-slate-100">{finding.title}</span>
                    <span className="mx-2 text-slate-600">·</span>
                    <span className="font-mono">{finding.filePath || scan.fileName}:{finding.line || '?'}</span>
                  </p>
                </div>
                {srcLoading ? <span className="text-xs text-slate-500">Loading source context…</span> : null}
                <Link to={`/findings/${scan.id}/${encodeURIComponent(finding.comparisonKey)}`} className="inline-flex items-center gap-1 text-xs font-medium text-accent-300 hover:text-accent-200">
                  Full finding <ArrowUpRight size={13} />
                </Link>
              </div>
              <CopilotPanel scanId={scanId} finding={finding} code={contextCode} auto />
              <div className="rounded-lg border border-edge bg-base-925/40 p-4 text-[12.5px] leading-relaxed text-slate-500">
                <p className="mb-1 flex items-center gap-1.5 font-semibold text-slate-300">
                  <ShieldCheck size={13} className="text-accent-300" /> How this works
                </p>
                The deterministic scanner decides what is vulnerable. The Copilot only explains that finding —
                it can never create, suppress, or change severity, confidence, baseline status, or the CI gate.
              </div>
            </>
          ) : (
            <EmptyState
              icon={ShieldCheck}
              title="No code findings in this scan"
              message="Switch scans or run a new one — only deterministic findings can be explained."
              action={<Link to="/scans/new" className="btn-primary"><ScanSearch size={14} /> New Scan</Link>}
            />
          )}
        </div>
      )}
    </Layout>
  );
}
