/**
 * Rescan Integration Tests
 * Verifies score improvement/regression, single-file & folder rescan,
 * and file-path namespaced comparison keys.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScanner } from '../src/scanner/scanner.js';
import { calculateScore } from '../src/scanner/score.js';
import { compareScans, buildComparisonDetail } from '../src/services/rescanService.js';

function scanFromCode(code, filePath = 'app.js') {
  const { findings, severityCounts } = runScanner(code, { filePath });
  return { findings, severityCounts, score: calculateScore(severityCounts, { findings }) };
}

function scanFromFiles(files) {
  const { findings, severityCounts } = runScanner(null, { files });
  return { findings, severityCounts, score: calculateScore(severityCounts, { findings }) };
}

// ── Score improvement / regression ───────────────────────────────────
test('fixing vulnerabilities improves the score', () => {
  const vulnerable = scanFromCode(
    'const API_KEY = "sk-live-abcdefghijklmnop";\ndb.query("SELECT * FROM users WHERE id=" + id);'
  );
  const fixed = scanFromCode(
    'const key = process.env.API_KEY;\ndb.query("SELECT * FROM users WHERE id = ?", [id]);'
  );
  assert.ok(fixed.score > vulnerable.score, `Expected improvement, got ${vulnerable.score} -> ${fixed.score}`);
  const cmp = compareScans(vulnerable, fixed);
  assert.ok(cmp.resolved > 0);
  assert.equal(cmp.new, 0);
});

test('introducing vulnerabilities regresses the score', () => {
  const clean = scanFromCode('const x = 42;');
  const vulnerable = scanFromCode('const API_KEY = "sk-live-abcdefghijklmnop";');
  assert.ok(vulnerable.score < clean.score);
  const cmp = compareScans(clean, vulnerable);
  assert.ok(cmp.new > 0);
  assert.equal(cmp.resolved, 0);
});

// ── Single-file rescan ──────────────────────────────────────────────
test('single-file rescan classifies resolved/remaining/new', () => {
  const prev = scanFromCode(
    'const API_KEY = "sk-live-abcdefghijklmnop";\ndb.query("SELECT * FROM users WHERE id=" + id);'
  );
  const curr = scanFromCode(
    'const API_KEY = "sk-live-abcdefghijklmnop";\ndb.query("SELECT * FROM users WHERE id = ?", [id]);'
  );
  const cmp = compareScans(prev, curr);
  // The secret remains (remaining), the SQL injection is fixed (resolved).
  assert.ok(cmp.resolved >= 1);
  assert.ok(cmp.remaining >= 1);
  assert.equal(cmp.new, 0);
});

// ── Folder rescan ───────────────────────────────────────────────────
test('folder rescan resolves findings only in the changed file', () => {
  const prev = scanFromFiles([
    { path: 'src/api.js', content: 'db.query("SELECT * FROM users WHERE id=" + id);' },
    { path: 'src/helper.js', content: 'const SECRET = "superSecretValue123";' },
  ]);
  const curr = scanFromFiles([
    { path: 'src/api.js', content: 'db.query("SELECT * FROM users WHERE id = ?", [id]);' },
    { path: 'src/helper.js', content: 'const SECRET = "superSecretValue123";' },
  ]);
  const cmp = compareScans(prev, curr);
  // api.js injection fixed (resolved), helper.js secret remains (remaining).
  assert.ok(cmp.resolved >= 1, `Expected >=1 resolved, got ${cmp.resolved}`);
  assert.ok(cmp.remaining >= 1, `Expected >=1 remaining, got ${cmp.remaining}`);
  assert.equal(cmp.new, 0);
});

test('folder rescan detects newly introduced finding', () => {
  const prev = scanFromFiles([{ path: 'src/api.js', content: 'const x = 1;' }]);
  const curr = scanFromFiles([
    { path: 'src/api.js', content: 'const x = 1;' },
    { path: 'src/new.js', content: 'eval(userInput);' },
  ]);
  const cmp = compareScans(prev, curr);
  assert.ok(cmp.new >= 1);
});

// ── Details include per-finding status ──────────────────────────────
test('buildComparisonDetail reports status for each finding', () => {
  const prev = scanFromCode('const API_KEY = "sk-live-abcdefghijklmnop";');
  const curr = scanFromCode('let key = process.env.API_KEY;');
  const detail = buildComparisonDetail(prev, curr);
  assert.ok(detail.resolved.length >= 1);
  assert.equal(detail.counts.resolved, detail.resolved.length);
  assert.equal(detail.newlyIntroduced.length, 0);
  for (const r of detail.resolved) {
    assert.equal(r.status, 'resolved');
    assert.ok(r.finding.comparisonKey);
  }
});

test('same vulnerability in different files stays distinct', () => {
  const prev = scanFromFiles([
    { path: 'a.js', content: 'const API_KEY = "sk-live-abcdefghijklmnop";' },
    { path: 'b.js', content: 'const API_KEY = "sk-live-abcdefghijklmnop";' },
  ]);
  const curr = scanFromFiles([
    { path: 'a.js', content: 'const API_KEY = "sk-live-abcdefghijklmnop";' },
    { path: 'b.js', content: 'const key = process.env.API_KEY;' },
  ]);
  // a.js stays, b.js resolved.
  const cmp = compareScans(prev, curr);
  assert.equal(cmp.resolved, 1);
  assert.equal(cmp.remaining, 1);
});
