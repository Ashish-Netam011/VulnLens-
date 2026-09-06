import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { Card } from '../components/ui/Card.jsx';
import { Button } from '../components/ui/Button.jsx';
import { Modal } from '../components/ui/Modal.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { EmptyState } from '../components/ui/EmptyState.jsx';
import { Alert } from '../components/ui/Alert.jsx';
import { formatDate, scoreColor, errorMessage } from '../utils/helpers.js';
import { FolderKanban, Plus, Trash2, ArrowRight } from 'lucide-react';

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
    } catch (err) { setError(errorMessage(err)); }
    finally { setLoading(false); }
  }

  useEffect(() => { load(); }, []);

  async function createProject(e) {
    e.preventDefault();
    setCreating(true);
    try {
      await api.post('/projects', form);
      setShowCreate(false);
      setForm({ name: '', description: '' });
      await load();
    } catch (err) { setError(errorMessage(err)); }
    finally { setCreating(false); }
  }

  async function deleteProject(id) {
    if (!window.confirm('Delete this project and all its scans?')) return;
    try { await api.delete(`/projects/${id}`); setProjects((p) => p.filter((x) => x.id !== id)); }
    catch (err) { setError(errorMessage(err)); }
  }

  if (loading) return <Layout><PageLoader label="Loading projects..." /></Layout>;

  return (
    <Layout>
      <div className="mx-auto max-w-5xl">
        <div className="mb-6 flex items-center justify-between">
          <div>
            <h1 className="text-xl font-bold text-slate-50">Projects</h1>
            <p className="text-sm text-slate-400">Organize your codebases and scans</p>
          </div>
          <Button onClick={() => setShowCreate(true)}><Plus size={16} /> New Project</Button>
        </div>
        {error && <div className="mb-4"><Alert variant="error">{error}</Alert></div>}
        {projects.length === 0 ? (
          <EmptyState icon={FolderKanban} title="No projects yet" message="Create your first project to start running security scans on your code." action={<Button onClick={() => setShowCreate(true)}><Plus size={16} /> Create Project</Button>} />
        ) : (
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {projects.map((p) => (
              <Card key={p.id} className="group flex flex-col p-5 hover:border-slate-600">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-3">
                    <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-base-800 text-sky-400"><FolderKanban size={18} /></div>
                    <div>
                      <Link to={`/projects/${p.id}`} className="text-sm font-semibold text-slate-100 group-hover:text-sky-300">{p.name}</Link>
                      <p className="text-xs text-slate-500">{formatDate(p.createdAt)}</p>
                    </div>
                  </div>
                  <button onClick={() => deleteProject(p.id)} className="text-slate-600 hover:text-red-400" title="Delete project" aria-label="Delete project"><Trash2 size={15} /></button>
                </div>
                {p.description ? <p className="mt-3 line-clamp-2 text-xs text-slate-400">{p.description}</p> : null}
                <div className="mt-4 flex items-center justify-between border-t border-borderline pt-3">
                  {p.latestScan ? (
                    <div className="flex items-center gap-2 text-xs text-slate-400">
                      <span>Score</span>
                      <span className="text-base font-bold" style={{ color: scoreColor(p.latestScan.score) }}>{p.latestScan.score}</span>
                      {p.latestScan.severityCounts && p.latestScan.severityCounts.critical > 0 && (<span className="text-critical">{p.latestScan.severityCounts.critical} critical</span>)}
                    </div>
                  ) : (<span className="text-xs text-slate-600">No scans yet</span>)}
                  <Link to={`/projects/${p.id}`} className="flex items-center gap-1 text-xs font-medium text-sky-400 hover:text-sky-300">Open <ArrowRight size={13} /></Link>
                </div>
              </Card>
            ))}
          </div>
        )}
      </div>
      <Modal open={showCreate} onClose={() => setShowCreate(false)} title="Create Project">
        <form onSubmit={createProject} className="flex flex-col gap-4">
          <div><label className="label">Project Name</label><input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} className="input" placeholder="e.g. Payment Gateway API" autoFocus /></div>
          <div><label className="label">Description (optional)</label><textarea value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} className="input min-h-[80px] resize-y" placeholder="What is this project about?" /></div>
          <div className="flex justify-end gap-2">
            <Button variant="ghost" type="button" onClick={() => setShowCreate(false)}>Cancel</Button>
            <Button type="submit" disabled={creating}>{creating ? 'Creating...' : 'Create Project'}</Button>
          </div>
        </form>
      </Modal>
    </Layout>
  );
}