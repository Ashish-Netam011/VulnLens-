import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card } from '../components/ui/Card.jsx';
import { Button } from '../components/ui/Button.jsx';
import { Modal } from '../components/ui/Modal.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { ErrorState } from '../components/ui/ErrorState.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { SeverityBadge } from '../components/ui/SeverityBadge.jsx';
import { formatDate, scoreColor, errorMessage } from '../utils/helpers.js';
import { FolderKanban, Plus, Trash2, ArrowUpRight, FolderPlus } from 'lucide-react';

export default function ProjectsPage() {
  const [projects, setProjects] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [showCreate, setShowCreate] = useState(false);
  const [form, setForm] = useState({ name: '', description: '' });
  const [creating, setCreating] = useState(false);

  async function load() {
    try {
      const { data } = await api.get('/projects');
      setProjects(data.projects || []);
      setError('');
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, []);

  async function createProject(e) {
    e.preventDefault();
    setCreating(true);
    try {
      await api.post('/projects', form);
      setShowCreate(false);
      setForm({ name: '', description: '' });
      await load();
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setCreating(false);
    }
  }

  async function deleteProject(id) {
    if (!window.confirm('Delete this project and all of its scans?')) return;
    try {
      await api.delete(`/projects/${id}`);
      setProjects((p) => p.filter((x) => x.id !== id));
    } catch (err) {
      setError(errorMessage(err));
    }
  }

  if (loading) return <Layout><PageLoader label="Loading projects…" /></Layout>;

  return (
    <Layout>
      <PageHeader
        eyebrow="Overview"
        title="Projects"
        description="Organize codebases and their scan history. Every scan belongs to a project."
        actions={<Button onClick={() => setShowCreate(true)}><Plus size={15} /> New Project</Button>}
      />

      {error && <div className="mb-4"><ErrorState title="Could not manage projects" message={error} /></div>}

      {projects.length === 0 ? (
        <EmptyState
          icon={FolderKanban}
          title="No projects yet"
          message="Create your first project to start running security scans on your code."
          action={<Button onClick={() => setShowCreate(true)}><FolderPlus size={15} /> Create Project</Button>}
        />
      ) : (
        <div className="grid gap-4 md:grid-cols-2 xl:grid-cols-3">
          {projects.map((p) => {
            const latest = p.latestScan;
            const sc = latest?.severityCounts || {};
            return (
              <Card key={p.id} className="group flex flex-col p-5 transition-colors hover:border-edge-strong">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex min-w-0 items-center gap-3">
                    <span className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg border border-edge bg-base-850 text-accent-300">
                      <FolderKanban size={17} aria-hidden="true" />
                    </span>
                    <div className="min-w-0">
                      <Link to={`/projects/${p.id}`} className="block truncate text-[14px] font-semibold text-slate-100 group-hover:text-white">{p.name}</Link>
                      <p className="text-2xs text-slate-500">{formatDate(p.createdAt)}</p>
                    </div>
                  </div>
                  <button onClick={() => deleteProject(p.id)} className="rounded p-1.5 text-slate-600 transition-colors hover:bg-critical/10 hover:text-critical" title="Delete project" aria-label={`Delete ${p.name}`}>
                    <Trash2 size={14} />
                  </button>
                </div>

                {p.description ? <p className="mt-3 line-clamp-2 text-xs leading-relaxed text-slate-500">{p.description}</p> : null}

                <div className="mt-4 flex items-end justify-between gap-3 border-t border-edge pt-3">
                  {latest ? (
                    <div className="min-w-0">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-base font-bold" style={{ color: scoreColor(latest.score) }}>{latest.score}</span>
                        <span className="text-[10px] uppercase tracking-wide text-slate-500">score</span>
                      </div>
                      <div className="mt-1.5 flex flex-wrap gap-1.5">
                        {(['critical', 'high']).map((s) =>
                          (sc[s] || 0) > 0 ? <SeverityBadge key={s} severity={s} size="sm" /> : null
                        )}
                        {(sc.medium || 0) > 0 ? (
                          <span className="inline-flex items-center rounded border border-medium/25 bg-medium/10 px-1.5 py-px font-mono text-[10px] font-semibold text-medium">{sc.medium} med</span>
                        ) : null}
                      </div>
                    </div>
                  ) : (
                    <p className="text-xs text-slate-600">No scans yet</p>
                  )}
                  <Link to={`/projects/${p.id}`} className="inline-flex items-center gap-1 rounded p-1.5 text-slate-500 transition-colors hover:bg-base-850 hover:text-accent-300" aria-label={`Open ${p.name}`}>
                    <ArrowUpRight size={16} />
                  </Link>
                </div>
              </Card>
            );
          })}
        </div>
      )}

      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Project" labelledBy="create-project-title">
        <form onSubmit={createProject} className="flex flex-col gap-4">
          <div>
            <label htmlFor="project-name" className="label">Project name</label>
            <input id="project-name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="input" placeholder="e.g. Payment Gateway API" autoFocus />
          </div>
          <div>
            <label htmlFor="project-desc" className="label">Description (optional)</label>
            <textarea id="project-desc" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="input min-h-[84px] resize-y" placeholder="What is this project about?" />
          </div>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button type="submit" disabled={creating}>{creating ? 'Creating…' : 'Create Project'}</Button>
          </div>
        </form>
      </Modal>
    </Layout>
  );
}
