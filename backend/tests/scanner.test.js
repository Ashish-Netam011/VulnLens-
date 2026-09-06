import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScanner } from '../src/scanner/scanner.js';
import { calculateScore } from '../src/scanner/score.js';

const VULNERABLE_CODE = `
const http = require('http');
const db = require('db');

const API_KEY = "sk-live-abcdefghijklmnop";
const SECRET = "superSecretValue123";

function getUser(id) {
  const query = "SELECT * FROM users WHERE id=" + id;
  return db.query(query);
}

function render(html) {
  document.getElementById("app").innerHTML = html;
}

function run(input) {
  eval(input);
}
`;

test('scanner detects multiple vulnerability categories', () => {
  const { findings, severityCounts } = runScanner(VULNERABLE_CODE, { filePath: 'app.js' });
  assert.ok(findings.length >= 4, `expected >=4 findings, got ${findings.length}`);
  const types = new Set(findings.map((f) => f.category));
  assert.ok(types.has('Hardcoded Credentials and Secrets'));
  assert.ok(types.has('Injection Vulnerabilities'));
  assert.ok(types.has('Cross-Site Scripting (XSS)'));
  assert.ok(types.has('Dangerous Function Usage'));
});

test('findings have a consistent schema', () => {
  const { findings } = runScanner('const pwd = "12345678";', { filePath: 'x.js' });
  const f = findings[0];
  assert.ok(f.ruleId);
  assert.ok(f.title);
  assert.ok(f.severity);
  assert.ok(f.confidence >= 0 && f.confidence <= 100);
  assert.ok(f.comparisonKey);
  assert.ok(f.line >= 1);
});

test('severity counts sum correctly', () => {
  const { severityCounts } = runScanner(VULNERABLE_CODE);
  const total = Object.values(severityCounts).reduce((a, b) => a + b, 0);
  assert.ok(total >= 4);
});

test('score is reproducible and in range', () => {
  const { severityCounts } = runScanner(VULNERABLE_CODE);
  const score = calculateScore(severityCounts);
  assert.ok(score >= 0 && score <= 100);
  // Reproducible
  const score2 = calculateScore(severityCounts);
  assert.equal(score, score2);
});

test('clean code scores high', () => {
  const code = 'const db = require("db");\nmodule.exports = function (id) { return db.query("SELECT * FROM users WHERE id = ?", [id]); };';
  const { severityCounts, findings } = runScanner(code);
  assert.equal(findings.length, 0);
  assert.equal(calculateScore(severityCounts), 100);
});

test('declining severity weights affect score', () => {
  const criticalScore = calculateScore({ critical: 1, high: 0, medium: 0, low: 0, informational: 0 });
  const lowScore = calculateScore({ critical: 0, high: 0, medium: 0, low: 1, informational: 0 });
  assert.ok(criticalScore < lowScore);
});

test('multi-file scan attributes findings to the correct files', () => {
  const { findings, severityCounts } = runScanner(null, {
    files: [
      { path: 'app/server.js', content: 'const API_KEY = "sk-live-abcdefghijklmnop";' },
      { path: 'lib/auth.py', content: 'password = "hunter2"\nev = input()\n' },
      { path: 'utils/clean.js', content: 'module.exports = function (id) { return db.query("SELECT * FROM users WHERE id = ?", [id]); };' },
      { path: '../crafted/evil.txt', content: 'const pwd = "12345678";' },
    ],
  });

  assert.ok(findings.length >= 3, `expected >=3 findings, got ${findings.length}`);
  const paths = new Set(findings.map((f) => f.filePath));
  assert.ok(paths.has('app/server.js'), 'missing finding for app/server.js');
  assert.ok(paths.has('lib/auth.py'), 'missing finding for lib/auth.py');
  assert.ok(!paths.has('../crafted/evil.txt'), 'path traversal must be normalized');

  // Comparison keys embed the file path so identical snippets in different
  // files remain distinct findings during rescan diffing.
  for (const f of findings) {
    assert.ok(f.comparisonKey.startsWith(`${f.filePath}:`), `comparisonKey should be namespaced by file (${f.comparisonKey})`);
  }
  assert.ok(!new Set(findings.map((f) => f.comparisonKey)).has(''));

  const total = Object.values(severityCounts).reduce((a, b) => a + b, 0);
  assert.equal(total, findings.length);
});


// ── Phase 4D: persistence / serialization invariants ──────────────────────────

test('serialization: findings (with evidence + verdict) survive a JSON round-trip', () => {
  const code =
    'const id = req.query.id;\nconst q = "SELECT * FROM users WHERE id=" + id;\ndb.query(q);\n' +
    'el.innerHTML = req.query.q;';
  const { findings } = runScanner(code, { filePath: 'persist.js' });
  assert.ok(findings.length >= 2, `expected >=2 findings, got ${findings.length}`);
  for (const f of findings) {
    const round = JSON.parse(JSON.stringify(f));
    assert.equal(round.comparisonKey, f.comparisonKey, 'comparisonKey must survive serialization');
    assert.equal(typeof round.verdict, 'string', 'verdict must be present and serializable');
    assert.ok(round.evidence && typeof round.evidence === 'object', 'evidence must be serializable');
    assert.equal(round.confidence, f.confidence, 'confidence must survive serialization');
  }
});

test('serialization: evidence round-trips nested structure faithfully', () => {
  const { findings } = runScanner('db.query("SELECT * FROM users WHERE id=" + req.query.id);', {
    filePath: 'p2.js',
  });
  const f = findings.find((x) => x.ruleId === 'sql-concat');
  const round = JSON.parse(JSON.stringify(f));
  assert.equal(round.evidence.flow.established, true);
  assert.equal(round.evidence.flow.direct, false);
  assert.ok(Array.isArray(round.evidence.flow.sources));
  assert.equal(round.evidence.flow.sources[0], 'req.query.id');
  assert.equal(typeof round.evidence.explanation, 'string');
});

test('serialization: no raw secret value leaks into any serialized field', () => {
  const { findings } = runScanner('const API_KEY = "sk-live-abcdefghijklmnop";', { filePath: 'p3.js' });
  const f = findings[0];
  const round = JSON.parse(JSON.stringify(f));
  const blob = JSON.stringify(round);
  assert.ok(!blob.includes('sk-live-abcdefghijklmnop'), 'raw secret must not serialize');
});


// ── Phase 4E: error isolation + pipeline determinism ─────────────────────────

// ERROR ISOLATION — a parser failure in one file must never abort a multi-file
// scan, and malformed single-file input must never throw out of the scanner.
test('EO: multi-file scan isolates parser failure in one file', () => {
  const files = [
    { path: 'good.js', content: 'db.query("SELECT * FROM users WHERE id=" + req.query.id);' },
    { path: 'broken.js', content: 'function((( {; const x = ;\n' },
    { path: 'clean.js', content: 'const add = (a, b) => a + b;' },
  ];
  let result;
  assert.doesNotThrow(() => {
    result = runScanner(null, { files });
  });
  // The vulnerable file still yields its CONFIRMED finding.
  const good = result.findings.find((f) => f.filePath === 'good.js');
  assert.ok(good, 'good.js finding expected');
  assert.equal(good.verdict, 'CONFIRMED');
  // The broken file never manufactures a finding that is false-confirmed.
  for (const f of result.findings) {
    if (f.filePath === 'broken.js') assert.notEqual(f.verdict, 'CONFIRMED');
  }
});

// ERROR ISOLATION — an individual throwing rule must not break the scan (the
// scanner already guards each rule.check with try/catch).
test('EO: a rule that throws is contained and the scan still completes', () => {
  // Craft input that is structurally hostile but must not crash the scanner.
  const hostile = [
    'const s = "\\u0000\\u0001\\u0002";',
    'const q = `SELECT * FROM users WHERE id=${req.query.id} ${' + '"x".repeat(50)}`;',
    'db.query(q);',
  ].join('\n');
  let result;
  assert.doesNotThrow(() => {
    result = runScanner(hostile, { filePath: 'hostile.js' });
  });
  assert.ok(Array.isArray(result.findings));
});

// PIPELINE DETERMINISM — severity counts + score are a pure function of the
// findings and stable across repeated runs (rescan/regression depend on this).
test('DET: severity counts and score are deterministic across runs', () => {
  const code = [
    'db.query("SELECT * FROM users WHERE id=" + req.query.id);',
    'const fs = require("fs");',
    'fs.readFile(req.query.path, () => {});',
    'const API_KEY = "sk-live-abcdefghijklmnop";',
  ].join('\n');
  const runs = [];
  for (let i = 0; i < 3; i++) {
    const r = runScanner(code, { filePath: 'det.js' });
    runs.push({ findings: r.findings, severityCounts: r.severityCounts, score: calculateScore(r.severityCounts, { findings: r.findings }) });
  }
  assert.deepEqual(runs[0], runs[1]);
  assert.deepEqual(runs[1], runs[2]);
  // A confirmed SQLi + path traversal + secret should never be an empty/zero finding set.
  assert.ok(runs[0].findings.length >= 3, `expected ≥3 findings, got ${runs[0].findings.length}`);
});

// PIPELINE — every finding carries verdict + evidence + normalized severity in
// the single-file path (same contract the multi-file and API paths rely on).
test('DET: single-file runScanner returns verdict/evidence/normalized severity', () => {
  const { findings } = runScanner(
    'db.query("SELECT * FROM users WHERE id=" + req.query.id);',
    { filePath: 'one.js' }
  );
  const f = findings[0];
  assert.equal(f.verdict, 'CONFIRMED');
  assert.ok(f.evidence, 'evidence present');
  assert.equal(f.evidence.flow.established, true);
  assert.ok(['critical', 'high', 'medium', 'low', 'informational'].includes(f.severity));
  assert.ok(typeof f.confidence === 'number' && f.confidence >= 0 && f.confidence <= 100);
});

