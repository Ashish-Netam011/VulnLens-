/**
 * Source-context endpoint integration tests (UI redesign Phase).
 *
 * Exercises GET /api/scans/:id/source — the read-only, owner-scoped, bounded
 * source window used by the Finding Detail code viewer and AI Copilot context.
 *
 * Coverage:
 *   - authorization (owner yes / other user no / nonexistent scan)
 *   - path safety (valid relative file, ../ traversal, encoded traversal,
 *     absolute paths, cross-scan file access)
 *   - bounds (≈40-line window, beginning/end clamping, invalid lines)
 *   - correctness (targetLine/startLine/endLine, original line numbers,
 *     nonexistent file)
 *
 * The deterministic scanner, baseline, SARIF, and CI gate are untouched by
 * this endpoint — nothing here imports or modifies them.
 */
import { test, before, after, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import {
  setupTestServer,
  teardownTestServer,
  createAuthUser,
  createProject,
  api,
  baseUrl,
} from './helpers.js';

let ready = false;
let auth;

before(async (t) => {
  try {
    await setupTestServer();
    ready = true;
  } catch (err) {
    t.diagnostic(`in-memory MongoDB unavailable: ${err.message}`);
    ready = false;
  }
});

after(async () => {
  await teardownTestServer();
});

beforeEach(async () => {
  if (!ready) return;
  auth = await createAuthUser();
});

function requireReady(t) {
  if (!ready) {
    t.skip('in-memory MongoDB unavailable');
    return false;
  }
  return true;
}

async function newProject() {
  return createProject(auth.userId);
}

/** Single-file (paste) scan. */
async function doScan(code, projectId, fileName = 'test.js') {
  return api(baseUrl, 'POST', '/api/scans', {
    token: auth.token,
    body: { projectId, code, language: 'javascript', fileName },
  });
}

/** Multi-file (folder) scan upload. */
async function doFolderScan(projectId, files, token = auth.token) {
  const form = new FormData();
  form.append('projectId', projectId);
  form.append('paths', JSON.stringify(files.map((f) => f.path)));
  for (const f of files) {
    form.append('files', new Blob([f.content], { type: 'text/plain' }), f.path);
  }
  const res = await fetch(`${baseUrl}/api/scans/upload`, {
    method: 'POST',
    headers: { Authorization: `Bearer ${token}` },
    body: form,
  });
  const text = await res.text();
  const body = text ? JSON.parse(text) : null;
  return { status: res.status, body };
}

function getSource(scanId, params, token = auth.token) {
  const qs = new URLSearchParams(params).toString();
  return api(baseUrl, 'GET', `/api/scans/${scanId}/source?${qs}`, { token });
}

// ── Single-file scan ────────────────────────────────────────────────────────

test('single-file: owner fetches a bounded window with correct lines', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const lines = Array.from({ length: 60 }, (_, i) => `const line${i + 1} = ${i + 1};`);
  const code = lines.join('\n');
  const { status, body } = await doScan(code, projectId, 'app.js');
  assert.equal(status, 201);
  const scanId = body.scan.id;

  const res = await getSource(scanId, { around: 30, file: 'app.js' });
  assert.equal(res.status, 200);
  assert.equal(res.body.success, true);
  assert.equal(res.body.file, 'app.js');
  assert.equal(res.body.targetLine, 30);
  assert.equal(res.body.startLine, 10); // 30 - 20
  assert.equal(res.body.endLine, 49); // 30 + 19
  assert.equal(res.body.lines.length, 40);
  // Original line numbers retained and content matches.
  assert.equal(res.body.lines[0].line, 10);
  assert.equal(res.body.lines[0].code, lines[9]);
  assert.equal(res.body.lines[res.body.lines.length - 1].line, 49);
  assert.equal(res.body.lines[res.body.lines.length - 1].code, lines[48]);
});

test('single-file: file param may be omitted (single stored source)', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const code = ['const a = 1;', 'const b = 2;', 'const c = 3;'].join('\n');
  const { status, body } = await doScan(code, projectId, 'solo.js');
  assert.equal(status, 201);

  const res = await getSource(body.scan.id, { around: 2 });
  assert.equal(res.status, 200);
  assert.equal(res.body.file, 'solo.js');
  assert.equal(res.body.lines.length, 3);
});

test('single-file: wrong file name is rejected (404)', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const { status, body } = await doScan('const a = 1;', projectId, 'app.js');
  assert.equal(status, 201);

  const res = await getSource(body.scan.id, { around: 1, file: 'other.js' });
  assert.equal(res.status, 404);
  assert.equal(res.body.success, undefined);
});

test('single-file: traversal / absolute file names are rejected (400)', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const { status, body } = await doScan('const a = 1;\nconst b = 2;', projectId, 'app.js');
  assert.equal(status, 201);
  const scanId = body.scan.id;

  for (const bad of ['../app.js', '..%2Fapp.js', '%2e%2e%2fapp.js', '%2Fetc%2Fpasswd', '/etc/passwd', 'C:\\app.js', 'a%00b.js']) {
    const res = await getSource(scanId, { around: 1, file: bad });
    assert.equal(res.status, 400, `expected 400 for file=${bad}, got ${res.status}`);
  }
});

// ── Multi-file (folder) scan ────────────────────────────────────────────────

test('folder scan: valid project-relative file resolves against stored sources', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const srcLines = Array.from({ length: 50 }, (_, i) => `// src line ${i + 1}`);
  const files = [
    { path: 'src/api.js', content: srcLines.join('\n') },
    { path: 'src/helper.js', content: 'const add = (a, b) => a + b;\nmodule.exports = { add };' },
  ];
  const up = await doFolderScan(projectId, files);
  assert.equal(up.status, 201);
  const scanId = up.body.scan.id;

  const res = await getSource(scanId, { around: 25, file: 'src/api.js' });
  assert.equal(res.status, 200);
  assert.equal(res.body.file, 'src/api.js');
  assert.equal(res.body.targetLine, 25);
  assert.equal(res.body.startLine, 5);
  assert.equal(res.body.endLine, 44);
  assert.equal(res.body.lines.length, 40);
  assert.equal(res.body.lines[0].code, srcLines[4]);
});

test('folder scan: file param is required', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const up = await doFolderScan(projectId, [{ path: 'src/a.js', content: 'const a = 1;' }]);
  assert.equal(up.status, 201);

  const res = await getSource(up.body.scan.id, { around: 1 });
  assert.equal(res.status, 400);
});

test('folder scan: nonexistent / traversal / absolute file rejected', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const up = await doFolderScan(projectId, [
    { path: 'src/a.js', content: 'const a = 1;\nconst b = 2;' },
    { path: 'lib/b.js', content: 'const c = 3;' },
  ]);
  assert.equal(up.status, 201);
  const scanId = up.body.scan.id;

  // Well-formed but absent from this scan → 404.
  for (const missing of ['src/missing.js', 'other-scan.js', 'lib']) {
    const res = await getSource(scanId, { around: 1, file: missing });
    assert.equal(res.status, 404, `expected 404 for file=${missing}, got ${res.status}`);
  }

  // Traversal / encoded / absolute attempts → 400 before resolution.
  for (const bad of ['../src/a.js', '..%2Fsrc%2Fa.js', '%2e%2e%2fsrc%2fa.js', '%2Fetc%2Fpasswd', 'lib/../src/a.js', 'src/a%00.js', 'C:\\x.js']) {
    const res = await getSource(scanId, { around: 1, file: bad });
    assert.equal(res.status, 400, `expected 400 for file=${bad}, got ${res.status}`);
  }
});

test('folder scan: beginning-of-file and end-of-file clamping', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const content = Array.from({ length: 60 }, (_, i) => `x${i + 1}`).join('\n');
  const up = await doFolderScan(projectId, [{ path: 'main.js', content }]);
  assert.equal(up.status, 201);
  const scanId = up.body.scan.id;

  // Beginning clamp.
  const head = await getSource(scanId, { around: 5, file: 'main.js' });
  assert.equal(head.status, 200);
  assert.equal(head.body.startLine, 1);
  assert.equal(head.body.lines.length, 24); // lines 1..24 (5 + 19 below)
  assert.equal(head.body.lines[0].line, 1);

  // End clamp.
  const tail = await getSource(scanId, { around: 60, file: 'main.js' });
  assert.equal(tail.status, 200);
  assert.equal(tail.body.endLine, 60);
  assert.equal(tail.body.startLine, 40); // 60 - 20
  assert.equal(tail.body.lines.length, 21);
  assert.equal(tail.body.lines[tail.body.lines.length - 1].line, 60);
});

// ── Authorization ───────────────────────────────────────────────────────────

test('authorization: another user cannot read source (404, no leak)', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const { status, body } = await doScan('const a = 1;', projectId, 'app.js');
  assert.equal(status, 201);

  const other = await createAuthUser();
  const res = await getSource(body.scan.id, { around: 1 }, other.token);
  assert.equal(res.status, 404);
  assert.equal(res.body.error, 'Scan not found');
});

test('authorization: nonexistent scan id → 404; malformed id → 404', async (t) => {
  if (!requireReady(t)) return;
  const res = await getSource('000000000000000000000000', { around: 1 });
  assert.equal(res.status, 404);

  const bad = await getSource('not-an-object-id', { around: 1 });
  assert.equal(bad.status, 404); // CastError mapped to 404 by the error handler
});

test('authorization: file from another scan of the same owner is rejected', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const s1 = await doFolderScan(projectId, [{ path: 'only-in-scan1.js', content: 'const a = 1;' }]);
  const s2 = await doFolderScan(projectId, [{ path: 'only-in-scan2.js', content: 'const b = 2;' }]);
  assert.equal(s1.status, 201);
  assert.equal(s2.status, 201);

  // Cross-scan: file exists in scan 2 but not scan 1.
  const res = await getSource(s1.body.scan.id, { around: 1, file: 'only-in-scan2.js' });
  assert.equal(res.status, 404);
});

// ── Validation / bounds ─────────────────────────────────────────────────────

test('validation: around must be a positive integer', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const { status, body } = await doScan('const a = 1;\nconst b = 2;\nconst c = 3;', projectId);
  assert.equal(status, 201);
  const scanId = body.scan.id;

  for (const bad of [undefined, '', '0', '-1', '1.5', 'abc']) {
    const params = bad === undefined ? {} : { around: bad };
    const res = await getSource(scanId, params);
    assert.equal(res.status, 400, `expected 400 for around=${bad}, got ${res.status}`);
  }
});

test('validation: around beyond the file length is rejected (400)', async (t) => {
  if (!requireReady(t)) return;
  const projectId = await newProject();
  const { status, body } = await doScan('const a = 1;\nconst b = 2;', projectId);
  assert.equal(status, 201);

  const res = await getSource(body.scan.id, { around: 999 });
  assert.equal(res.status, 400);
  assert.match(res.body.error, /out of range/i);
});
