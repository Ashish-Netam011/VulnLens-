import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card } from '../components/ui/Card.jsx';
import { Button } from '../components/ui/Button.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { formatDate, scoreColor } from '../utils/helpers.js';
import { FileCode2, FileJson, ScanSearch, ExternalLink, Download } from 'lucide-react';

export default function ReportsPage() {
  const [scans, setScans] = useState([]);
  const [projects, setProjects] = useState([]);
  const [scanId, setScanId] = useState('');
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
        if (mounted) setError(err?.response?.data?.error || 'Failed to load reports');
      } finally {
        if (mounted) setLoading(false);
      }
    }
    load();
    return () => {
      mounted = false;
    };
  }, []);

  if (loading) return <Layout><PageLoader label="Loading reports…" /></Layout>;
  const nameOf = (pid) => projects.find((p) => p.id === pid)?.name || 'Project';
  const active = scans.find((s) => s.id === scanId) || scans[0] || null;
  const scanIdToUse = active?.id;

  function download(kind) {
    if (!scanIdToUse) return;
    const path = kind === 'sarif' ? `/reports/${scanIdToUse}/sarif` : `/reports/${scanIdToUse}/download`;
    const name = kind === 'sarif' ? `vulnlens-scan-${scanIdToUse}.sarif` : `vulnlens-report-${scanIdToUse}.json`;
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
      .catch((err) => setError(err?.response?.data?.error || 'Download failed'));
  }

  const FORMATS = [
    {
      key: 'sarif',
      icon: FileCode2,
      accent: 'text-accent-300',
      ring: 'hover:border-accent-500/50',
      title: 'SARIF 2.1.0',
      for: 'CI/CD integration & GitHub Code Scanning',
      body: 'The standard SARIF format uploads directly to GitHub Advanced Security and other code-scanning tools. Every result carries a deterministic comparisonKey-based fingerprint.',
    },
    {
      key: 'json',
      icon: FileJson,
      accent: 'text-amber-300',
      ring: 'hover:border-amber-500/40',
      title: 'JSON report',
      for: 'Archiving, tooling & audits',
      body: 'The full machine-readable report: every finding with rule, evidence, severity, confidence and dependency data, plus the per-file breakdown for folder scans.',
    },
    {
      key: 'app',
      icon: ExternalLink,
      accent: 'text-cyan-300',
      ring: 'hover:border-cyan-500/40',
      title: 'Security summary',
      for: 'Human review in VulnLens',
      body: 'Open the scan in the app to review findings, data flows, AI explanations and remediation side by side before exporting.',
    },
  ];

  return (
    <Layout>
      <PageHeader
        eyebrow="Output"
        title="Reports & Exports"
        description="Share scan results with your CI pipeline, reviewers, or compliance process. Every export is generated from the real scan data."
      />

      {error && <div className="mb-4"><ErrorState title="Reports unavailable" message={error} /></div>}

      {!error && scans.length === 0 ? (
        <EmptyState
          icon={FileCode2}
          title="No scans to export"
          message="Run a security scan first — then export it as SARIF or JSON."
          action={<Link to="/scans/new" className="btn-primary"><ScanSearch size={15} /> Start a scan</Link>}
        />
      ) : null}

      {!error && active ? (
        <div className="flex flex-col gap-5">
          <Card className="p-4">
            <div className="flex flex-wrap items-center gap-3">
              <label htmlFor="report-scan" className="sr-only">Select a scan</label>
              <select id="report-scan" className="input max-w-md" value={scanIdToUse} onChange={(e) => setScanId(e.target.value)}>
                {scans.map((s) => (
                  <option key={s.id} value={s.id}>
                    {nameOf(s.project)} · {formatDate(s.createdAt)} · {s.findingCount} findings
                  </option>
                ))}
              </select>
              <span className="text-sm text-slate-500">
                Score <span className="font-mono font-bold" style={{ color: scoreColor(active.score) }}>{active.score}</span>
                {active.severityCounts?.critical ? <span className="ml-3 text-critical">{active.severityCounts.critical} critical</span> : null}
                {active.severityCounts?.high ? <span className="ml-2 text-high">{active.severityCounts.high} high</span> : null}
              </span>
            </div>
          </Card>

          <div className="grid gap-4 md:grid-cols-3">
            {FORMATS.map((f) => {
              const Icon = f.icon;
              const isApp = f.key === 'app';
              return (
                <Card key={f.key} className={`flex flex-col p-5 transition-colors ${f.ring}`}>
                  <div className="flex items-center justify-between">
                    <span className={`flex h-10 w-10 items-center justify-center rounded-lg border border-edge bg-base-850 ${f.accent}`}>
                      <Icon size={18} aria-hidden="true" />
                    </span>
                    {!isApp ? <span className="text-[10px] font-semibold uppercase tracking-wider text-slate-600">Export</span> : null}
                  </div>
                  <h3 className="mt-3 text-[14px] font-semibold text-slate-100">{f.title}</h3>
                  <p className="mt-0.5 text-xs font-medium text-accent-300/80">{f.for}</p>
                  <p className="mt-2 flex-1 text-[12.5px] leading-relaxed text-slate-500">{f.body}</p>
                  <div className="mt-4">
                    {isApp ? (
                      <Link to={`/scans/${scanIdToUse}`} className="btn-secondary w-full"><ExternalLink size={14} /> Open scan</Link>
                    ) : (
                      <Button variant="secondary" className="w-full" onClick={() => download(f.key)}>
                        <Download size={14} /> Download {f.key === 'sarif' ? 'SARIF' : 'JSON'}
                      </Button>
                    )}
                  </div>
                </Card>
              );
            })}
          </div>

          <p className="text-xs leading-relaxed text-slate-600">
            Downloads are authenticated, ownership-checked exports of the selected scan — identical to what the CLI and CI produce.
          </p>
        </div>
      ) : null}
    </Layout>
  );
}
