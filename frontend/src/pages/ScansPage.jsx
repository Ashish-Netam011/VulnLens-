import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { Card } from '../components/ui/Card.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { Alert } from '../components/ui/Alert.jsx';
import { formatDate, scoreColor, errorMessage } from '../utils/helpers.js';
import { FileSearch, ArrowRight } from 'lucide-react';

export default function ScansPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');

  useEffect(() => {
    async function load() {
      try {
        const { data } = await api.get('/scans');
        setScans(data.scans || []);
      } catch (err) {
        setError(errorMessage(err));
      } finally {
        setLoading(false);
      }
    }
    load();
  }, []);

  if (loading) return <Layout><PageLoader label="Loading scans..." /></Layout>;

  return (
    <Layout>
      <div className="mx-auto max-w-5xl">
        <div className="mb-6">
          <h1 className="text-xl font-bold text-slate-50">Scans</h1>
          <p className="text-sm text-slate-400">All security analyses across your projects</p>
        </div>

        {error && <Alert variant="error">{error}</Alert>}

        {scans.length === 0 ? (
          <EmptyState
            icon={FileSearch}
            title="No scans yet"
            message="Run a security scan on your code to see results here."
            action={<Link to="/new-scan" className="btn-primary">New Scan</Link>}
          />
        ) : (
          <Card>
            <ul className="divide-y divide-borderline">
              {scans.map((s) => (
                <li key={s.id}>
                  <Link to={`/scans/${s.id}`} className="flex flex-wrap items-center justify-between gap-3 px-5 py-3.5 text-sm hover:bg-base-850">
                    <div className="flex items-center gap-3">
                      <span className="flex h-9 w-9 items-center justify-center rounded-md bg-base-800 text-slate-400"><FileSearch size={16} /></span>
                      <div>
                        <p className="font-medium text-slate-200">{s.fileName || 'Scan'}</p>
                        <p className="text-xs text-slate-500">{formatDate(s.createdAt)} · {s.findingCount} findings{s.fileCount > 0 ? ` · ${s.fileCount} files` : ''}</p>
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
                      <ArrowRight size={15} className="text-slate-600" />
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          </Card>
        )}
      </div>
    </Layout>
  );
}