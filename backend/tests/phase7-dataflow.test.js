/**
 * Phase 7 — Targeted data-flow analysis (request-source → dangerous-sink).
 *
 * Verifies the request-taint detection added on top of the existing engine:
 *   - request sources reach fs path arguments through aliases and *Sync forms
 *   - request sources reach NoSQL document-query arguments (object literals,
 *     operator objects, whole-request values, db.<collection> chains)
 *   - constants, unrelated variables, sanitized values, parameterized queries,
 *     and findById-style id lookups never report
 *   - deterministic output, stable ruleIds, and comparisonKey determinism.
 *
 * These tests complement the existing evidence/verdict/dataFlowAnalysis tests;
 * they must never mutate severity/confidence/evidence semantics of other rules.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScanner } from '../src/scanner/scanner.js';

function scan(code, filePath = 't.js') {
  return runScanner(code, { filePath }).findings;
}

// ── File-access flows (fs.readFileSync / writeFileSync + aliases) ───────────

test('p7 file: request path via alias reaches fs.readFileSync → CONFIRMED', () => {
  const [f] = scan("const fs = require('fs'); const p = req.query.path; fs.readFileSync(p, 'utf8', cb);");
  assert.equal(f.ruleId, 'unchecked-file-read');
  assert.equal(f.verdict, 'CONFIRMED');
  assert.equal(f.evidence.flow.established, true);
  assert.ok(f.evidence.source.names.includes('req.query.path'), 'source recorded');
  assert.equal(f.severity, 'medium'); // rule severity preserved by CONFIRMED
});

test('p7 file: readFileSync is detected while plain readFile regex path stays intact', () => {
  // Sync variant must fire through the alias pass; the inline-request readFile
  // shape must still work through the existing regex rule.
  const sync = scan("const fs = require('fs'); const p = req.query.path; fs.readFileSync(p, cb);");
  const direct = scan("const fs = require('fs'); fs.readFile(req.query.path, cb);");
  assert.equal(sync.length, 1, 'sync alias shape yields exactly one finding');
  assert.equal(sync[0].ruleId, 'unchecked-file-read');
  assert.equal(sync[0].verdict, 'CONFIRMED');
  const directRead = direct.find((f) => f.ruleId === 'unchecked-file-read');
  assert.ok(directRead, 'direct readFile still reported as unchecked-file-read');
  assert.equal(directRead.verdict, 'CONFIRMED');
});

test('p7 file: request path via alias reaches fs.writeFileSync → CONFIRMED high', () => {
  const [f] = scan("const fs = require('fs'); const dest = req.query.file; fs.writeFileSync(dest, 'x');");
  assert.equal(f.ruleId, 'file-write-user');
  assert.equal(f.verdict, 'CONFIRMED');
  assert.equal(f.severity, 'high');
});

test('p7 file: multi-hop alias propagation (a → b → sink)', () => {
  const [f] = scan(
    "const fs = require('fs');\n" +
    'const a = req.query.path;\n' +
    'const b = a;\n' +
    'const p = b;\n' +
    "fs.readFileSync(p, 'utf8', cb);"
  );
  assert.equal(f.ruleId, 'unchecked-file-read');
  assert.equal(f.verdict, 'CONFIRMED');
});

test('p7 file: destructured request member reaches fs path sink', () => {
  const [f] = scan("const fs = require('fs'); const { path } = req.query; fs.readFileSync(path, cb);");
  assert.equal(f.ruleId, 'unchecked-file-read');
  assert.equal(f.verdict, 'CONFIRMED');
});

test('p7 file: constant path never triggers (TN)', () => {
  const findings = scan("const fs = require('fs'); fs.readFileSync('/opt/config/app.json', 'utf8', cb);");
  assert.equal(findings.length, 0);
});

test('p7 file: unrelated (non-request) variable never triggers (TN)', () => {
  const findings = scan("const fs = require('fs'); const p = process.env.CONFIG_DIR + '/x'; fs.readFileSync(p, 'utf8', cb);");
  assert.equal(findings.length, 0);
});

test('p7 file: request value not reaching the path argument is not reported', () => {
  // Tainted CONTENT (arg 1) on a constant path is not a traversal flow.
  const findings = scan("const fs = require('fs'); fs.writeFileSync('/var/log/app.log', req.body.data);");
  assert.equal(findings.length, 0);
});

// ── NoSQL document-query flows ──────────────────────────────────────────────

test('p7 nosql: request value inside a model object query → CONFIRMED', () => {
  const [f] = scan("const User = require('./user'); User.find({ name: req.query.name }, cb);");
  assert.equal(f.ruleId, 'nosql-object-query');
  assert.equal(f.verdict, 'CONFIRMED');
  assert.equal(f.severity, 'high');
  assert.equal(f.evidence.flow.established, true);
  assert.ok(f.affectedCode.includes('User.find'), 'evidence carries the call');
});

test('p7 nosql: request-built operator object → CONFIRMED', () => {
  const [f] = scan("const User = require('./user'); User.find({ age: { $gt: req.query.minAge } }, cb);");
  assert.equal(f.ruleId, 'nosql-object-query');
  assert.equal(f.verdict, 'CONFIRMED');
});

test('p7 nosql: whole request body as query → CONFIRMED', () => {
  const [f] = scan("const Item = require('./item'); Item.find(req.body, cb);");
  assert.equal(f.ruleId, 'nosql-object-query');
  assert.equal(f.verdict, 'CONFIRMED');
});

test('p7 nosql: db.<collection> object query with request value → CONFIRMED', () => {
  const [f] = scan('db.users.find({ name: req.query.name }, cb);');
  assert.equal(f.ruleId, 'nosql-object-query');
  assert.equal(f.verdict, 'CONFIRMED');
});

test('p7 nosql: request alias chain into document query → CONFIRMED', () => {
  const [f] = scan("const User = require('./user'); const q = req.query; User.find(q, cb);");
  assert.equal(f.ruleId, 'nosql-object-query');
  assert.equal(f.verdict, 'CONFIRMED');
});

test('p7 nosql: findById(id from request) is deliberately NOT flagged (TN)', () => {
  const findings = scan("const User = require('./user'); User.findById(req.params.id, cb);");
  assert.equal(findings.length, 0);
});

test('p7 nosql: constant filter object is NOT flagged (TN)', () => {
  const findings = scan("const User = require('./user'); User.find({ status: 'active' }, cb);");
  assert.equal(findings.length, 0);
});

test('p7 nosql: trusted session identity filter is NOT flagged (TN)', () => {
  const findings = scan("const User = require('./user'); User.findOne({ _id: req.user.id }, cb);");
  assert.equal(findings.length, 0);
});

test('p7 nosql: unrelated variable object query is NOT flagged (TN)', () => {
  const findings = scan("const User = require('./user'); const filter = buildFilter(); User.find(filter, cb);");
  assert.equal(findings.length, 0);
});

// ── Interaction with existing behavior (no regressions) ─────────────────────

test('p7 regression: parameterized SQL is clean; sanitized values stay demoted', () => {
  // Parameterized queries are provably safe → dropped entirely.
  const param = scan("db.query('SELECT * FROM users WHERE id = ?', [req.query.id]);");
  assert.equal(param.length, 0);
  // Sanitizer convention: the rule fires but the value is not CONFIRMED — the
  // finding is demoted to a low POTENTIAL lead (mirrors safe-sanitized-query.js).
  const sanitized = scan('const id = req.query.id; db.query("SELECT * FROM users WHERE id=" + encodeURIComponent(id));');
  assert.ok(sanitized.length >= 1, 'sanitized sink still reported as a lead');
  assert.equal(sanitized[0].verdict, 'POTENTIAL');
  assert.equal(sanitized[0].severity, 'low');
  assert.notEqual(sanitized[0].ruleId, 'nosql-object-query');
});

test('p7 regression: direct SQL concat/template still CONFIRMED with same ruleIds', () => {
  const concat = scan("const id = req.query.id; db.query('SELECT * FROM users WHERE id = ' + id);");
  const template = scan('const id = req.query.id; db.query(`SELECT * FROM users WHERE id = ${id}`);');
  assert.equal(concat[0].ruleId, 'sql-concat');
  assert.equal(concat[0].verdict, 'CONFIRMED');
  assert.equal(template[0].ruleId, 'sql-template');
  assert.equal(template[0].verdict, 'CONFIRMED');
});

test('p7 regression: benign constant exec still reported only as the existing child-process low', () => {
  const findings = scan("const { exec } = require('child_process'); exec('ls -la');");
  assert.equal(findings.length, 1);
  assert.equal(findings[0].ruleId, 'child-process');
  assert.notEqual(findings[0].severity, 'critical'); // never inflated without confirmed flow
});

// ── Determinism & identity ──────────────────────────────────────────────────

test('p7 determinism: identical output across repeated scans', () => {
  const code = "const User = require('./user');\nconst fs = require('fs');\nconst p = req.query.file;\nfs.readFileSync(p, 'utf8', cb);\nUser.find({ name: req.query.name }, cb);";
  const a = scan(code, 'det.js').map((f) => ({ ruleId: f.ruleId, line: f.line, comparisonKey: f.comparisonKey, verdict: f.verdict }));
  const b = scan(code, 'det.js').map((f) => ({ ruleId: f.ruleId, line: f.line, comparisonKey: f.comparisonKey, verdict: f.verdict }));
  assert.deepEqual(b, a);
});

test('p7 identity: new rules use stable kebab-case ids that do not collide', () => {
  const code = "const fs = require('fs');\nconst p = req.query.path;\nfs.readFileSync(p, cb);\nconst User = require('./user');\nUser.find({ name: req.query.name }, cb);";
  const ids = scan(code).map((f) => f.ruleId);
  assert.deepEqual([...new Set(ids)].sort(), ['nosql-object-query', 'unchecked-file-read']);
  for (const id of ids) assert.match(id, /^[a-z0-9-]+$/);
});
