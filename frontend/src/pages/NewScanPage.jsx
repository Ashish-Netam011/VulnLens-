import { useEffect, useRef, useState } from 'react';
import { useNavigate, Link } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { PageHeader } from '../components/layout/PageHeader.jsx';
import { Card, CardHeader } from '../components/ui/Card.jsx';
import { Button } from '../components/ui/Button.jsx';
import { Alert } from '../components/ui/Alert.jsx';
import { Spinner } from '../components/ui/Spinner.jsx';
import { SecurityScore } from '../components/security/SecurityScore.jsx';
import { SeverityBadge } from '../components/ui/SeverityBadge.jsx';
import { errorMessage, cx } from '../utils/helpers.js';
import { UploadCloud, FolderUp, FileCode2, ClipboardPaste, FileText, X, FolderOpen, Search, CheckCircle2, ArrowRight, Repeat } from 'lucide-react';

const SAMPLE = `const express = require('express');
const app = express();
const db = require('db');
const SECRET_KEY = "sk-live-super-secret-value-12345";

app.get('/users', (req, res) => {
  const id = req.query.id;
  const query = "SELECT * FROM users WHERE id = " + id;
  db.query(query, (err, rows) => {
    if (err) return res.status(500).send(err.message);
    res.send(rows);
  });
});

app.get('/profile', (req, res) => {
  const html = '<div>' + req.query.name + '</div>';
  res.send(html);
});

app.post('/login', (req, res) => {
  const hash = crypto.createHash('md5').update(req.body.password).digest('hex');
  res.json({ token: hash });
});
`;

const LANG_MAP = { js: 'javascript', jsx: 'javascript', ts: 'typescript', tsx: 'typescript', py: 'python', java: 'java', go: 'go', rb: 'ruby', php: 'php', html: 'html', sql: 'sql', css: 'css', json: 'json' };
const ALLOWED_EXTS = new Set(['.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.java', '.c', '.cpp', '.cs', '.go', '.rb', '.php', '.sh', '.bash', '.json', '.yaml', '.yml', '.html', '.css', '.sql', '.txt', '.md']);
const MAX_FOLDER_FILES = 100;
const MAX_FOLDER_CHARS = 5_000_000;

function inferLanguage(name) {
  const ext = (name.split('.').pop() || '').toLowerCase();
  return LANG_MAP[ext] || 'text';
}

function extensionOf(path) {
  const name = (path || '').split('/').pop() || '';
  const dot = name.lastIndexOf('.');
  return dot >= 0 ? name.slice(dot).toLowerCase() : '';
}

export default function NewScanPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState([]);
  const [projectsLoading, setProjectsLoading] = useState(true);
  const [projectId, setProjectId] = useState('');
  const [fileName, setFileName] = useState('submission.txt');
  const [code, setCode] = useState('');
  const [files, setFiles] = useState([]);
  const [sourceMode, setSourceMode] = useState('paste');
  const [inputError, setInputError] = useState('');
  const [running, setRunning] = useState(false);
  const [phase, setPhase] = useState('idle'); // idle | reading | scanning | done
  const [reading, setReading] = useState(0);
  const [readingTotal, setReadingTotal] = useState(0);
  const [dragActive, setDragActive] = useState(false);
  const [fileQuery, setFileQuery] = useState('');
  const [completed, setCompleted] = useState(null); // scan summary
  const fileRef = useRef(null);
  const folderRef = useRef(null);

  useEffect(() => {
    api
      .get('/projects')
      .then(({ data }) => setProjects(data.projects || []))
      .catch(() => setProjects([]))
      .finally(() => setProjectsLoading(false));
  }, []);

  function onFileSelect(e) {
    const file = e.target.files[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      setFiles([]);
      setSourceMode('paste');
      setCode(String(reader.result || ''));
      setCompleted(null);
    };
    reader.readAsText(file);
  }

  async function onFolderSelect(e) {
    const list = Array.from(e.target.files || []);
    e.target.value = '';
    if (list.length === 0) return;
    const candidates = list
      .map((file) => ({ path: (file.webkitRelativePath || file.name).replace(/\\/g, '/'), file }))
      .filter(({ path }) => ALLOWED_EXTS.has(extensionOf(path)));
    await onCandidates(candidates);
  }

  async function onCandidates(candidates) {
    setCompleted(null);
    if (candidates.length === 0) return setInputError('No supported code files found in this folder (.js, .py, .java, .go, etc.).');
    if (candidates.length > MAX_FOLDER_FILES) return setInputError(`Too many files (max ${MAX_FOLDER_FILES}). Exclude build output or vendor folders and try again.`);

    const items = [];
    let total = 0;
    setPhase('reading');
    setReadingTotal(candidates.length);
    for (let i = 0; i < candidates.length; i++) {
      const { path, file } = candidates[i];
      setReading(i + 1);
      let content = '';
      try {
        content = await file.text();
      } catch {
        content = '';
      }
      total += content.length;
      if (total > MAX_FOLDER_CHARS) {
        setPhase('idle');
        setReading(0);
        setReadingTotal(0);
        return setInputError('Total code size is too large (max 5,000,000 characters).');
      }
      if (content.trim()) items.push({ path, content });
    }
    setReading(0);
    setReadingTotal(0);
    setPhase('idle');
    if (items.length === 0) return setInputError('The selected folder contains no readable source text.');
    setFiles(items);
    setSourceMode('folder');
    setInputError('');
  }

  function onDrop(e) {
    e.preventDefault();
    setDragActive(false);
    const dt = e.dataTransfer;
    if (!dt) return;
    const items = dt.items ? Array.from(dt.items) : [];
    if (items.length === 0) return;
    const hasEntries = items.some((it) => typeof it.webkitGetAsEntry === 'function' && it.kind === 'file');
    if (hasEntries) {
      collectEntries(items, (entries) => {
        const candidates = entries
          .map(({ path, file }) => ({ path: path.replace(/\\/g, '/'), file }))
          .filter(({ path }) => ALLOWED_EXTS.has(extensionOf(path)));
        onCandidates(candidates);
      });
      return;
    }
    const file = dt.files && dt.files[0];
    if (!file) return;
    setFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      setFiles([]);
      setSourceMode('paste');
      setCode(String(reader.result || ''));
    };
    reader.readAsText(file);
  }

  function collectEntries(items, onDone) {
    const out = [];
    let pending = 0;
    let done = false;
    const finish = () => {
      if (done) return;
      done = true;
      onDone(out);
    };
    const pushFile = (entry, path) => {
      pending += 1;
      entry.file(
        (file) => {
          out.push({ path, file });
          if (--pending === 0) finish();
        },
        () => { if (--pending === 0) finish(); }
      );
    };
    const walkDir = (dirEntry, path) => {
      pending += 1;
      const reader = dirEntry.createReader();
      const readBatch = () => {
        reader.readEntries(
          (results) => {
            if (results.length === 0) {
              if (--pending === 0) finish();
              return;
            }
            results.forEach((entry) => {
              if (entry.isFile) pushFile(entry, `${path}/${entry.name}`);
              else if (entry.isDirectory) walkDir(entry, `${path}/${entry.name}`);
            });
            readBatch();
          },
          () => { if (--pending === 0) finish(); }
        );
      };
      readBatch();
    };
    items.forEach((it) => {
      const entry = it.webkitGetAsEntry && it.webkitGetAsEntry();
      if (!entry) return;
      if (entry.isFile) pushFile(entry, entry.name);
      else if (entry.isDirectory) walkDir(entry, entry.name);
    });
    if (pending === 0) finish();
  }

  function onDragOver(e) {
    e.preventDefault();
    if (!dragActive) setDragActive(true);
  }

  function onDragLeave(e) {
    e.preventDefault();
    if (e.currentTarget.contains(e.relatedTarget)) return;
    setDragActive(false);
  }

  function clearFolder() {
    setFiles([]);
    setSourceMode('paste');
    setInputError('');
    setCompleted(null);
  }

  async function runScan() {
    setInputError('');
    if (!projectId) return setInputError('Please select a project to scan.');

    setRunning(true);
    setCompleted(null);
    setPhase('scanning');
    try {
      let data;
      if (sourceMode === 'folder') {
        if (files.length === 0) {
          setInputError('Please choose a project folder to scan.');
          setRunning(false);
          setPhase('idle');
          return;
        }
        const form = new FormData();
        form.append('projectId', projectId);
        form.append('paths', JSON.stringify(files.map((f) => f.path)));
        for (const f of files) form.append('files', new Blob([f.content], { type: 'text/plain' }), f.path);
        data = (await api.post('/scans/upload', form)).data;
      } else {
        if (!code.trim()) {
          setInputError('Please paste code or upload a file.');
          setRunning(false);
          setPhase('idle');
          return;
        }
        data = (
          await api.post('/scans', {
            projectId,
            code,
            fileName,
            language: inferLanguage(fileName),
          })
        ).data;
      }
      setCompleted(data.scan);
      setPhase('done');
    } catch (err) {
      setInputError(errorMessage(err));
      setPhase('idle');
    } finally {
      setRunning(false);
    }
  }

  // ── Derived state ───────────────────────────────────────────
  const folderTotalChars = files.reduce((n, f) => n + f.content.length, 0);
  const folderRoot = files.length ? (files[0].path.split('/')[0] || 'project') : 'project';
  const q = fileQuery.trim().toLowerCase();
  const filteredFiles = q ? files.filter((f) => f.path.toLowerCase().includes(q)) : files;

  // ── Completed summary view ──────────────────────────────────
  if (completed) {
    const sc = completed.severityCounts || {};
    return (
      <Layout>
        <div className="mx-auto max-w-3xl">
          <Card className="card-pad fade-in">
            <div className="flex flex-col items-center gap-5 py-6 text-center">
              <CheckCircle2 size={34} className="text-emerald-400" aria-hidden="true" />
              <div>
                <p className="eyebrow">Scan complete</p>
                <h1 className="mt-1 text-2xl font-bold tracking-tight text-slate-50">{completed.fileName}</h1>
                <p className="mt-2 text-sm text-slate-400">
                  VulnLens analyzed <span className="tabular-nums text-slate-200">{completed.fileCount} files</span> and reported{' '}
                  <span className="tabular-nums text-slate-200">{(completed.findings || []).length} findings</span>.
                </p>
              </div>
              <SecurityScore score={completed.score} size={120} strokeWidth={10} />
              <div className="flex flex-wrap items-center justify-center gap-2">
                {(['critical', 'high', 'medium', 'low', 'informational']).map((s) =>
                  (sc[s] || 0) > 0 ? <SeverityBadge key={s} severity={s} /> : null
                )}
                {(['critical', 'high', 'medium', 'low', 'informational']).every((s) => !(sc[s] || 0)) ? (
                  <span className="text-sm text-slate-400">No vulnerabilities detected in this scan.</span>
                ) : null}
              </div>
              <div className="mt-2 flex flex-wrap justify-center gap-3">
                <Button onClick={() => navigate(`/scans/${completed.id}`)}>
                  <ArrowRight size={15} /> Review Findings
                </Button>
                <Button variant="secondary" onClick={() => { setCompleted(null); setCode(''); setFiles([]); setSourceMode('paste'); }}>
                  <Repeat size={15} /> New Scan
                </Button>
              </div>
            </div>
          </Card>
        </div>
      </Layout>
    );
  }

  return (
    <Layout>
      <PageHeader
        eyebrow="Scans"
        title="New Security Scan"
        description="Analyze your project for vulnerabilities, unsafe data flows, injection risks and insecure dependencies. Paste code, upload a file, or drop an entire folder."
      />

      {projectsLoading ? (
        <div className="flex justify-center py-16"><Spinner size="lg" /></div>
      ) : (
        <div className="mx-auto flex max-w-3xl flex-col gap-5">
          <Card className="card-pad">
            <label htmlFor="project" className="label">Project</label>
            {projects.length === 0 ? (
              <Alert variant="warning" title="Create a project first">
                Scans belong to a project. <Link to="/projects" className="font-medium text-accent-300 underline">Create a project</Link> to continue.
              </Alert>
            ) : (
              <select id="project" value={projectId} onChange={(e) => setProjectId(e.target.value)} className="input" disabled={running}>
                <option value="">Select a project…</option>
                {projects.map((p) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            )}
          </Card>

          <Card onDragEnter={onDragOver} onDragOver={onDragOver} onDragLeave={onDragLeave} onDrop={onDrop} className={dragActive ? 'ring-2 ring-accent-500/60' : ''}>
            <CardHeader
              title="Source code"
              subtitle={
                sourceMode === 'folder'
                  ? `${filteredFiles.length} / ${files.length} files · ${folderTotalChars.toLocaleString()} characters`
                  : 'Paste below, upload a single file, or drag-and-drop a project folder'
              }
              actions={
                <div className="flex items-center gap-2">
                  <input ref={folderRef} type="file" webkitdirectory="" directory="" multiple className="hidden" onChange={onFolderSelect} disabled={running} aria-label="Upload a project folder" />
                  <input ref={fileRef} type="file" accept={[...ALLOWED_EXTS].join(',')} className="hidden" onChange={onFileSelect} disabled={running} aria-label="Upload a source file" />
                  <Button variant="secondary" size="sm" onClick={() => folderRef.current?.click()} disabled={running}>
                    <FolderUp size={14} /> Folder
                  </Button>
                  <Button variant="secondary" size="sm" onClick={() => fileRef.current?.click()} disabled={running}>
                    <UploadCloud size={14} /> File
                  </Button>
                </div>
              }
            />
            {dragActive && (
              <div className="flex items-center justify-center gap-3 border-y border-dashed border-accent-500/60 bg-accent-500/[0.06] px-4 py-6 text-sm font-medium text-accent-300">
                <FolderOpen size={18} /> Drop files or a folder to add them
              </div>
            )}

            {phase === 'reading' && (
              <div className="flex items-center gap-3 border-b border-edge px-5 py-3">
                <Spinner size="sm" className="text-accent-400" />
                <span className="flex-1 text-xs text-slate-400">Reading source files… {reading}/{readingTotal}</span>
                <div className="h-1.5 w-32 overflow-hidden rounded-full bg-base-700">
                  <div className="h-full rounded-full bg-accent-500 transition-all" style={{ width: `${Math.round((reading / Math.max(readingTotal, 1)) * 100)}%` }} />
                </div>
              </div>
            )}

            {sourceMode === 'folder' ? (
              <div className="p-4">
                <div className="flex items-center justify-between rounded-md border border-accent-500/25 bg-accent-500/[0.05] px-3 py-2">
                  <div className="flex min-w-0 items-center gap-2 text-sm text-slate-200">
                    <FolderOpen size={15} className="shrink-0 text-accent-300" />
                    <span className="truncate font-medium">{folderRoot}/</span>
                    <span className="shrink-0 text-xs text-slate-500">{files.length} files · {folderTotalChars.toLocaleString()} chars</span>
                  </div>
                  <Button variant="ghost" size="sm" onClick={clearFolder} disabled={running}><X size={13} /> Remove</Button>
                </div>
                <div className="mt-3">
                  <input value={fileQuery} onChange={(e) => setFileQuery(e.target.value)} placeholder="Filter files…" className="input pl-3 text-xs" aria-label="Filter files" disabled={running} />
                </div>
                <ul className="mt-2 max-h-56 space-y-px overflow-y-auto rounded-md border border-edge bg-base-950 p-1.5">
                  {filteredFiles.length === 0 ? (
                    <li className="px-4 py-6 text-center text-xs text-slate-600">No files match the filter.</li>
                  ) : (
                    filteredFiles.map((f) => (
                      <li key={f.path} className="flex items-center gap-2 px-2 py-1 font-mono text-[11px] text-slate-400">
                        <FileText size={12} className="shrink-0 text-slate-600" />
                        <span className="truncate">{f.path}</span>
                        <span className="ml-auto shrink-0 tabular-nums text-slate-600">{f.content.length.toLocaleString()}</span>
                      </li>
                    ))
                  )}
                </ul>
              </div>
            ) : (
              <div className="p-4">
                <textarea
                  value={code}
                  onChange={(e) => { setCode(e.target.value); setCompleted(null); }}
                  placeholder="Paste your source code here…"
                  className="min-h-[300px] w-full resize-y rounded-md border border-edge bg-base-950 p-3 font-mono text-[12.5px] leading-relaxed text-slate-200 placeholder:text-slate-600 focus:border-accent-500 focus:outline-none"
                  disabled={running}
                  spellCheck="false"
                />
                <div className="mt-2 flex items-center justify-between text-xs text-slate-500">
                  <span>{fileName} · {code.length.toLocaleString()} characters</span>
                  <Button variant="ghost" size="sm" onClick={() => { setCode(SAMPLE); setCompleted(null); }}>
                    <ClipboardPaste size={13} /> Load sample
                  </Button>
                </div>
              </div>
            )}
          </Card>

          {running && (
            <Card className="card-pad">
              <div className="flex items-center gap-3">
                <Spinner className="text-accent-400" />
                <div>
                  <p className="text-sm font-medium text-slate-200">Analyzing your code…</p>
                  <p className="text-xs text-slate-500">
                    {sourceMode === 'folder' ? `Scanning ${files.length} source files` : `Scanning ${fileName}`} with the deterministic rule engine
                  </p>
                </div>
              </div>
            </Card>
          )}

          {inputError && <Alert variant="error">{inputError}</Alert>}

          <div className="flex items-center justify-between">
            <p className="text-xs text-slate-600">
              Deterministic static analysis — no code leaves your workspace except to the scanner.
            </p>
            <Button onClick={runScan} disabled={running || !projectId}>
              <FileCode2 size={15} /> {running ? 'Scanning…' : 'Start Scan'}
            </Button>
          </div>
        </div>
      )}
    </Layout>
  );
}
