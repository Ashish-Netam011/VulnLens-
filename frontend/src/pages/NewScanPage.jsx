import { useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import api from '../api/client.js';
import { Layout } from '../components/layout/Layout.jsx';
import { Card, CardHeader } from '../components/ui/Card.jsx';
import { Button } from '../components/ui/Button.jsx';
import { Alert } from '../components/ui/Alert.jsx';
import { PageLoader } from '../components/ui/Spinner.jsx';
import { ScanProgress } from '../components/security/ScanProgress.jsx';
import { errorMessage } from '../utils/helpers.js';
import { UploadCloud, FolderUp, FileCode2, ClipboardPaste, FileText, X, FolderOpen, Search } from 'lucide-react';
import { Spinner } from '../components/ui/Spinner.jsx';

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
  // Multi-file (project folder) mode: [{ path, content }, ...]
  const [files, setFiles] = useState([]);
  const [sourceMode, setSourceMode] = useState('paste'); // 'paste' | 'folder'
  const [inputError, setInputError] = useState('');
  const [running, setRunning] = useState(false);
  const [phase, setPhase] = useState('scanning');
  const fileRef = useRef(null);
  const folderRef = useRef(null);

  // Phase 4 folder-scan UX: file search, per-file read progress, drag & drop.
  const [fileQuery, setFileQuery] = useState('');
  const [reading, setReading] = useState(0);
  const [readingTotal, setReadingTotal] = useState(0);
  const [dragActive, setDragActive] = useState(false);

  useEffect(() => {
    api.get('/projects')
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
    };
    reader.readAsText(file);
  }

  // Folder picker: keep only supported source files, read them as text, and
  // remember each file's webkitRelativePath so the backend can group findings.
  async function onFolderSelect(e) {
    const list = Array.from(e.target.files || []);
    e.target.value = ''; // allow selecting the same folder again later
    if (list.length === 0) return;

    const candidates = list
      .map((file) => ({ path: (file.webkitRelativePath || file.name).replace(/\\/g, '/'), file }))
      .filter(({ path }) => ALLOWED_EXTS.has(extensionOf(path)));
    await onCandidates(candidates);
  }

  // Shared post-processing for the directory picker and drag-drop: validate
  // limits, read each file with a live progress counter, then load folder mode.
  async function onCandidates(candidates) {
    if (candidates.length === 0) {
      return setInputError('No supported code files found in this folder (.js, .py, .java, .go, etc.).');
    }
    if (candidates.length > MAX_FOLDER_FILES) {
      return setInputError(`Too many files (max ${MAX_FOLDER_FILES}). Exclude build output or vendor folders and try again.`);
    }

    const items = [];
    let total = 0;
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
        setReading(0);
        setReadingTotal(0);
        return setInputError('Total code size is too large (max 5,000,000 characters).');
      }
      if (content.trim()) items.push({ path, content });
    }
    setReading(0);
    setReadingTotal(0);

    if (items.length === 0) {
      return setInputError('The selected folder contains no readable source text.');
    }

    setFiles(items);
    setSourceMode('folder');
    setInputError('');
  }

  // Drag & drop: walk dropped FileSystemEntries (folders included) via
  // webkitGetAsEntry, falling back to plain files when entries are unavailable.
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

    // No directory metadata: treat the first dropped file as a single upload.
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

  // Recursively flattens dropped FileSystemEntries into { path, file } pairs
  // using createReader/readEntries — readEntries returns results in batches,
  // so it must be polled until it yields an empty array.
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
  }

  async function runScan() {
    setInputError('');
    if (!projectId) return setInputError('Please select a project to scan.');

    // Folder mode → multipart upload to /scans/upload.
    if (sourceMode === 'folder') {
      if (files.length === 0) return setInputError('Please choose a project folder to scan.');
      setRunning(true);
      setPhase('scanning');
      try {
        await new Promise((r) => setTimeout(r, 500));
        setPhase('ai');
        const form = new FormData();
        form.append('projectId', projectId);
        form.append('paths', JSON.stringify(files.map((f) => f.path)));
        for (const f of files) {
          form.append('files', new Blob([f.content], { type: 'text/plain' }), f.path);
        }
        const { data } = await api.post('/scans/upload', form);
        navigate(`/scans/${data.scan.id}`, { replace: true });
      } catch (err) {
        setInputError(errorMessage(err));
      } finally {
        setRunning(false);
      }
      return;
    }

    // Single-file / paste mode → JSON POST to /scans.
    if (!code.trim()) return setInputError('Please paste code or upload a file.');
    setRunning(true);
    setPhase('scanning');
    try {
      await new Promise((r) => setTimeout(r, 500));
      setPhase('ai');
      const { data } = await api.post('/scans', {
        projectId,
        code,
        fileName,
        language: inferLanguage(fileName),
      });
      navigate(`/scans/${data.scan.id}`, { replace: true });
    } catch (err) {
      setInputError(errorMessage(err));
    } finally {
      setRunning(false);
    }
  }

  const folderTotalChars = files.reduce((n, f) => n + f.content.length, 0);
  const folderRoot = files.length ? (files[0].path.split('/')[0] || 'project') : 'project';
  const q = fileQuery.trim().toLowerCase();
  const filteredFiles = q ? files.filter((f) => f.path.toLowerCase().includes(q)) : files;

  return (
    <Layout>
      <div className="mx-auto max-w-4xl">
        <div className="mb-6">
          <h1 className="text-xl font-bold text-slate-50">New Security Scan</h1>
          <p className="text-sm text-slate-400">Paste code, upload a file, or upload an entire project folder to analyze it with VulnLens AI</p>
        </div>

        {projectsLoading ? (
          <PageLoader label="Loading projects..." />
        ) : (
          <div className="flex flex-col gap-5">
            <Card className="card-pad">
              <label className="label">Project</label>
              {projects.length === 0 ? (
                <Alert variant="warning" title="Create a project first">
                  You need a project before scanning.{' '}
                  <button onClick={() => navigate('/projects')} className="text-sky-400 underline">Create one</button>
                </Alert>
              ) : (
                <select value={projectId} onChange={(e) => setProjectId(e.target.value)} className="input" disabled={running}>
                  <option value="">Select a project…</option>
                  {projects.map((p) => (
                    <option key={p.id} value={p.id}>{p.name}</option>
                  ))}
                </select>
              )}
            </Card>

            <Card
              onDragEnter={onDragOver}
              onDragOver={onDragOver}
              onDragLeave={onDragLeave}
              onDrop={onDrop}
              className={dragActive ? 'ring-2 ring-sky-500/50 ring-offset-0' : ''}
            >
              <CardHeader
                title="Source Code"
                subtitle={sourceMode === 'folder' ? `${filteredFiles.length} / ${files.length} files · ${folderTotalChars.toLocaleString()} chars` : 'Paste below, upload a single file, or drag-and-drop a project folder'}
                actions={
                  <div className="flex items-center gap-2">
                    <input ref={folderRef} type="file" webkitdirectory="" directory="" multiple className="hidden" onChange={onFolderSelect} disabled={running} />
                    <input ref={fileRef} type="file" accept=".js,.jsx,.ts,.tsx,.py,.java,.c,.cpp,.rb,.php,.go,.sh,.bash,.json,.yaml,.yml,.html,.css,.sql,.txt,.md" className="hidden" onChange={onFileSelect} disabled={running} />
                    <Button variant="secondary" onClick={() => folderRef.current?.click()} disabled={running}>
                      <FolderUp size={15} /> Upload Folder
                    </Button>
                    <Button variant="secondary" onClick={() => fileRef.current?.click()} disabled={running}>
                      <UploadCloud size={15} /> Upload File
                    </Button>
                  </div>
                }
              />
              {dragActive && (
                <div className="flex items-center justify-center gap-3 border-2 border-dashed border-sky-500/60 bg-sky-500/10 px-4 py-6 text-sm font-medium text-sky-300">
                  <FolderOpen size={18} className="text-sky-400" />
                  Drop files or a folder here to add them
                </div>
              )}
              {readingTotal > 0 && (
                <div className="flex items-center gap-3 border-b border-borderline px-5 py-3">
                  <Spinner size="sm" className="text-sky-500" />
                  <span className="flex-1 text-xs text-slate-400">
                    Reading files... {reading}/{readingTotal}
                  </span>
                  <div className="h-1.5 w-32 overflow-hidden rounded-full bg-base-700">
                    <div
                      className="h-full rounded-full bg-sky-500 transition-all"
                      style={{ width: `${Math.round((reading / Math.max(readingTotal, 1)) * 100)}%` }}
                    />
                  </div>
                </div>
              )}
              {sourceMode === 'folder' ? (
                <div className="p-4">
                  <div className="flex items-center justify-between rounded-md border border-sky-600/30 bg-sky-500/5 px-3 py-2">
                    <div className="flex items-center gap-2 text-sm text-slate-200">
                      <FolderOpen size={16} className="text-sky-400" />
                      <span className="font-medium">{folderRoot}/</span>
                      <span className="text-xs text-slate-500">{files.length} files · {folderTotalChars.toLocaleString()} chars</span>
                    </div>
                    <Button variant="ghost" onClick={clearFolder} disabled={running}>
                      <X size={14} /> Remove
                    </Button>
                  </div>
                  <div className="mt-3 flex items-center gap-2">
                    <div className="relative flex-1">
                      <Search size={14} className="pointer-events-none absolute left-2.5 top-1/2 -translate-y-1/2 text-slate-500" />
                      <input
                        value={fileQuery}
                        onChange={(e) => setFileQuery(e.target.value)}
                        placeholder="Filter files..."
                        className="input pl-8 text-xs"
                        aria-label="Filter files"
                        disabled={running}
                      />
                    </div>
                    {fileQuery && filteredFiles.length !== files.length && (
                      <span className="text-xs tabular-nums text-slate-500">{filteredFiles.length} / {files.length}</span>
                    )}
                  </div>
                  <ul className="mt-2 max-h-64 space-y-1 overflow-y-auto rounded-md border border-borderline bg-base-950 p-2">
                    {filteredFiles.length === 0 ? (
                      <li className="px-4 py-6 text-center text-xs text-slate-600">No files match the filter.</li>
                    ) : (
                      filteredFiles.map((f) => (
                        <li key={f.path} className="flex items-center gap-2 px-2 py-1 text-xs text-slate-400">
                          <FileText size={13} className="shrink-0 text-slate-600" />
                          <span className="truncate font-mono">{f.path}</span>
                          <span className="ml-auto shrink-0 tabular-nums text-[11px] text-slate-600">{f.content.length.toLocaleString()} chars</span>
                        </li>
                      ))
                    )}
                  </ul>
                  {filteredFiles.length > 0 && filteredFiles.length < files.length && (
                    <p className="mt-2 text-xs text-slate-500">Showing {filteredFiles.length} of {files.length} files · clear the filter to see all.</p>
                  )}
                </div>
              ) : (
                <div className="p-4">
                  <textarea
                    value={code}
                    onChange={(e) => setCode(e.target.value)}
                    placeholder="Paste your source code here…"
                    className="code-block min-h-[320px] w-full resize-y rounded-md border border-borderline bg-base-950 p-3 text-slate-200 placeholder:text-slate-600 focus:outline-none focus:border-sky-600"
                    disabled={running}
                  />
                  <div className="mt-2 flex items-center justify-between">
                    <span className="text-xs text-slate-500">{fileName} · {code.length.toLocaleString()} chars</span>
                    <Button variant="ghost" onClick={() => setCode(SAMPLE)} disabled={running}>
                      <ClipboardPaste size={14} /> Load Sample
                    </Button>
                  </div>
                </div>
              )}
            </Card>

            {running && (
              <Card className="card-pad"><ScanProgress phase={phase} /></Card>
            )}

            {inputError && <Alert variant="error">{inputError}</Alert>}

            <div className="flex justify-end">
              <Button onClick={runScan} disabled={running || !projectId}>
                <FileCode2 size={15} /> {running ? 'Scanning…' : 'Run Scan'}
              </Button>
            </div>
          </div>
        )}
      </div>
    </Layout>
  );
}