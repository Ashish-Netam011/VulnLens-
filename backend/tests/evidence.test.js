/**
 * Evidence Engine Unit Tests (Phase 4C).
 *
 * Covers every evidence-state branch and re-locks the three target over-claims
 * the engine must eliminate:
 *   - tricky-no-source-internal  (was CRITICAL@92  -> POTENTIAL / low)
 *   - tricky-template-no-source  (was CRITICAL@88  -> POTENTIAL / low)
 *   - tricky-innerhtml-constant  (was HIGH@85 FP   -> dropped / FALSE_POSITIVE)
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScanner, applyEvidenceEngine } from '../src/scanner/scanner.js';
import { buildEvidence, sanitizeEvidence } from '../src/scanner/evidence.js';
import { determineVerdict } from '../src/scanner/verdictEngine.js';
import { computeConfidence } from '../src/scanner/confidenceEngine.js';

const sqlInj = (code) =>
  runScanner(code, { filePath: 'x.js' }).findings.filter((f) => f.category === 'Injection Vulnerabilities');

// ── Confirmed source→sink paths ────────────────────────────────────────────

test('sql: user source reaching sink is CONFIRMED (direct + indirect)', () => {
  const d = runScanner('db.query("SELECT * FROM users WHERE id=" + req.query.id);', { filePath: 'a.js' }).findings[0];
  assert.equal(d.verdict, 'CONFIRMED');
  assert.equal(d.severity, 'critical');
  assert.equal(d.evidence.flow.established, true);
  assert.deepEqual(d.evidence.flow.sources, ['req.query.id']);
  assert.equal(d.confidence, 90); // indirect (concat) flow

  const viaVar = runScanner(
    'const id = req.query.id;\nconst q = "SELECT * FROM users WHERE id=" + id;\ndb.query(q);',
    { filePath: 'b.js' }
  ).findings;
  assert.equal(viaVar[0].verdict, 'CONFIRMED');
  assert.equal(viaVar[0].confidence, 90);
});

test('sql/xss: direct flow scores higher confidence', () => {
  const f = runScanner('el.innerHTML = req.query.q;', { filePath: 'dom.js' }).findings.find(
    (x) => x.category === 'Cross-Site Scripting (XSS)'
  );
  assert.equal(f.verdict, 'CONFIRMED');
  assert.equal(f.evidence.flow.direct, true);
  assert.equal(f.confidence, 95);
});

test('command injection: exec with source is CONFIRMED', () => {
  const { findings } = runScanner('const cp = require("child_process");\ncp.exec("ls " + req.query.dir);', {
    filePath: 'cp.js',
  });
  const exec = findings.find((x) => x.ruleId === 'child-process');
  assert.ok(exec, 'child-process finding expected');
  assert.equal(exec.verdict, 'CONFIRMED');
  assert.ok(exec.evidence.flow.established);
});

test('path traversal: readFile with source is CONFIRMED', () => {
  const { findings } = runScanner('const fs = require("fs");\nfs.readFile(req.query.path, () => {});', {
    filePath: 'fs.js',
  });
  const f = findings.find((x) => x.ruleId === 'unchecked-file-read' || x.ruleId === 'path-traversal');
  assert.ok(f, 'file read finding expected');
  assert.equal(f.verdict, 'CONFIRMED');
});

// ── Static-confirmed categories ─────────────────────────────────────────────

test('hardcoded secret is static-confirmed (constant data IS the vuln)', () => {
  const f = runScanner('const API_KEY = "sk-live-abcdefghijklmnop";', { filePath: 'sec.js' }).findings.find(
    (x) => x.category === 'Hardcoded Credentials and Secrets'
  );
  assert.equal(f.verdict, 'CONFIRMED');
  assert.equal(f.evidence.staticConfirmed, true);
  assert.ok(f.confidence >= 80);
  assert.ok(['high', 'critical'].includes(f.severity));
});

test('weak crypto (md5) and misconfig are static-confirmed', () => {
  const md5 = runScanner('crypto.createHash("md5").update(data).digest("hex");', { filePath: 'c.js' }).findings.find(
    (x) => x.ruleId === 'md5'
  );
  assert.equal(md5.verdict, 'CONFIRMED');
  const cors = runScanner('app.use(cors({ origin: "*" }));', { filePath: 'm.js' }).findings.find(
    (x) => x.ruleId === 'cors-wildcard'
  );
  assert.equal(cors.verdict, 'CONFIRMED');
});

// ── Target over-claims (must now be demoted / dropped) ──────────────────────

test('TRICKY: no-source internal SQL is POTENTIAL (was CRITICAL@92)', () => {
  const f = sqlInj('function getUserById(db, id) {\n  return db.query("SELECT * FROM users WHERE id=" + id);\n}')[0];
  assert.ok(f, 'no-source internal SQL should still be reported (POTENTIAL)');
  assert.equal(f.verdict, 'POTENTIAL');
  assert.equal(f.severity, 'low');
  assert.ok(f.confidence <= 35, `confidence ${f.confidence} should be <=35`);
  assert.equal(f.evidence.flow.established, false);
});

test('TRICKY: template-only SQL is POTENTIAL (was CRITICAL@88)', () => {
  const f = sqlInj('const q = `SELECT * FROM users WHERE id=${id}`;')[0];
  assert.ok(f, 'template-only SQL should still be reported (POTENTIAL)');
  assert.equal(f.verdict, 'POTENTIAL');
  assert.equal(f.severity, 'low');
  assert.ok(f.confidence <= 35, `confidence ${f.confidence} should be <=35`);
  assert.equal(f.evidence.templateOnly, true);
});

test('TRICKY: constant innerHTML is FALSE_POSITIVE and dropped (was HIGH@85)', () => {
  const xss = runScanner('el.innerHTML = "<b>Static header</b>";', { filePath: 'ui.js' }).findings.filter(
    (x) => x.category === 'Cross-Site Scripting (XSS)'
  );
  assert.equal(xss.length, 0, 'constant innerHTML should be dropped');
});

// ── FALSE_POSITIVE branches ────────────────────────────────────────────────

test('parameterized query is never flagged', () => {
  assert.equal(sqlInj('db.query("SELECT * FROM users WHERE id = ?", [req.query.id]);').length, 0);
});

test('safe sibling (textContent) is never flagged', () => {
  const { findings } = runScanner('el.textContent = req.query.q;', { filePath: 's.js' });
  assert.equal(findings.length, 0);
});

// ── applyEvidenceEngine drops FALSE_POSITIVE ───────────────────────────────

test('applyEvidenceEngine removes FALSE_POSITIVE and normalizes severity', () => {
  const findings = [
    { ruleId: 'innerhtml', category: 'Cross-Site Scripting (XSS)', severity: 'high', confidence: 85, line: 0 },
    { ruleId: 'sql-template', category: 'Injection Vulnerabilities', severity: 'critical', confidence: 88, line: 0 },
    { ruleId: 'sql-concat', category: 'Injection Vulnerabilities', severity: 'critical', confidence: 92, line: 0 },
  ];
  const out = applyEvidenceEngine('el.innerHTML = "<b>x</b>";', findings);
  assert.ok(!out.some((f) => f.ruleId === 'innerhtml'), 'constant innerHTML must be dropped');
  for (const f of out) {
    assert.equal(f.verdict, 'POTENTIAL');
    assert.equal(f.severity, 'low');
    assert.ok(f.confidence <= 35);
  }
});

// ── Deterministic verdict / confidence engines ─────────────────────────────

test('determineVerdict is a pure function of evidence', () => {
  const flow = { flow: { established: true, direct: false }, constantData: false, parameterized: false, sanitized: false };
  assert.equal(determineVerdict(flow, { category: 'Injection Vulnerabilities', ruleId: 'sql-concat' }), 'CONFIRMED');

  const noSource = { flow: { established: false }, constantData: false, parameterized: false };
  assert.equal(determineVerdict(noSource, { category: 'Injection Vulnerabilities', ruleId: 'sql-concat' }), 'POTENTIAL');

  const param = { flow: { established: true }, constantData: false, parameterized: true };
  assert.equal(determineVerdict(param, { category: 'Injection Vulnerabilities', ruleId: 'sql-concat' }), 'FALSE_POSITIVE');

  const xssConst = { flow: { established: false }, constantData: true, parameterized: false };
  assert.equal(determineVerdict(xssConst, { category: 'Cross-Site Scripting (XSS)', ruleId: 'innerhtml' }), 'FALSE_POSITIVE');

  const staticEv = { staticConfirmed: true, flow: { established: null } };
  assert.equal(determineVerdict(staticEv, { category: 'Weak Cryptographic Practices', ruleId: 'md5' }), 'CONFIRMED');
});

test('computeConfidence maps verdicts deterministically', () => {
  assert.equal(computeConfidence({ flow: { established: true, direct: true } }, 'CONFIRMED', 0), 95);
  assert.equal(computeConfidence({ flow: { established: true, direct: false } }, 'CONFIRMED', 0), 90);
  assert.equal(computeConfidence({ staticConfirmed: true }, 'CONFIRMED', 90), 90);
  assert.equal(computeConfidence({}, 'POTENTIAL', 92), 35);
  assert.equal(computeConfidence({}, 'FALSE_POSITIVE', 99), 0);
});

test('buildEvidence produces a machine-readable evidence object', () => {
  const ev = buildEvidence('db.query("SELECT * FROM users WHERE id=" + req.query.id);', {
    ruleId: 'sql-concat',
    category: 'Injection Vulnerabilities',
    line: 1,
    severity: 'critical',
    confidence: 92,
  });
  const keys = ['source', 'sink', 'flow', 'constantData', 'parameterized', 'sanitized', 'templateOnly', 'techContext', 'explanation'];
  for (const k of keys) assert.ok(k in ev, `evidence should contain ${k}`);
  assert.equal(ev.flow.established, true);
  assert.equal(ev.source.found, true);
  assert.equal(ev.parameterized, false);
  assert.equal(ev.staticConfirmed, false);
});

// ── Phase 4D: adversarial taint-analyzer coverage ─────────────────────────────

test('FAIL(ast): malformed / incomplete source never crashes the scanner', () => {
  const broken = ['function incomplete(', 'const x = ;', 'el.innerHTML = ', '(() => {', 'db.query("unterminated'];
  for (const b of broken) {
    let out;
    assert.doesNotThrow(() => {
      out = runScanner(b, { filePath: 'b.js' });
    }, b);
    assert.ok(Array.isArray(out.findings) && out.findings.length >= 0, `${b}: findings array expected`);
  }
});

test('FAIL(ast): destructuring from user source is CONFIRMED', () => {
  const f = runScanner('const { id } = req.query;\ndb.query("SELECT * FROM users WHERE id=" + id);', {
    filePath: 'd.js',
  }).findings[0];
  assert.equal(f.verdict, 'CONFIRMED');
  assert.equal(f.severity, 'critical');
  assert.ok(
    f.evidence.flow.sources.includes('req.query'),
    `expected source to reference req.query, got ${JSON.stringify(f.evidence.flow.sources)}`
  );
});

test('FAIL(ast): array-pattern destructuring propagates the same taint', () => {
  const f = runScanner('const [a, b] = req.query.args;\ndb.query("SELECT * FROM users WHERE id=" + b);', {
    filePath: 'arr.js',
  }).findings[0];
  assert.equal(f.verdict, 'CONFIRMED');
});

test('FAIL(ast): arrow-function callback body is walked (sink CONFIRMED)', () => {
  const code = 'const q = req.query.q;\ndata.forEach((item) => {\n  document.getElementById("app").innerHTML = q;\n});';
  const f = runScanner(code, { filePath: 'ar.js' }).findings.find((x) => x.category === 'Cross-Site Scripting (XSS)');
  assert.ok(f, 'xss finding expected');
  assert.equal(f.verdict, 'CONFIRMED');
});


test('FAIL(ast): function-expression callback body is walked (sink CONFIRMED)', () => {
  const code = 'const q = req.query.q;\ncb(function () {\n  db.query("SELECT * FROM users WHERE id=" + q);\n});';
  const f = runScanner(code, { filePath: 'fn.js' }).findings[0];
  assert.equal(f.verdict, 'CONFIRMED');
});

test('FAIL(ast): for-of loop body is walked (sink CONFIRMED)', () => {
  const code = 'const fs = require("fs");\nfor (const p of req.query.files) {\n  fs.readFile(req.query.path, () => {});\n}';
  const f = runScanner(code, { filePath: 'fo.js' }).findings.find(
    (x) => x.ruleId === 'unchecked-file-read' || x.ruleId === 'path-traversal'
  );
  assert.ok(f, 'file-read finding expected');
  assert.equal(f.verdict, 'CONFIRMED');
});

test('FAIL(ast): recognized sanitizer blocks taint confirmation (not CONFIRMED)', () => {
  const sql = runScanner('db.query("SELECT * FROM users WHERE id=" + encodeURIComponent(req.query.id));', {
    filePath: 's1.js',
  }).findings[0];
  assert.equal(sql.verdict, 'POTENTIAL');
  assert.ok(sql.confidence <= 35);
  assert.equal(sql.severity, 'low');

  const xss = runScanner('el.innerHTML = escapeHtml(req.query.q);', { filePath: 's2.js' }).findings.find(
    (x) => x.category === 'Cross-Site Scripting (XSS)'
  );
  assert.equal(xss.verdict, 'POTENTIAL');
  assert.equal(xss.evidence.sanitized, true);
});

test('FAIL(ast): optional chaining on a source still yields taint', () => {
  const f = runScanner('db.query("SELECT * FROM users WHERE id=" + req?.query?.id);', { filePath: 'oc.js' }).findings[0];
  assert.equal(f.verdict, 'CONFIRMED');
});

test('FAIL(ast): nested template literal interpolation is CONFIRMED', () => {
  const code = "const name = req.query.name;\nconst q = `SELECT * FROM users WHERE name='${`hello ${name}`}'`;\ndb.query(q);";
  const f = runScanner(code, { filePath: 'nt.js' }).findings[0];
  assert.equal(f.verdict, 'CONFIRMED');
});


// ── Phase 4D: determinism / serialization invariants ──────────────────────────

test('INVARIANT: scanning the same source is deterministic across runs', () => {
  const code = 'const id = req.query.id;\ndb.query("SELECT * FROM users WHERE id=" + id);';
  const a = runScanner(code, { filePath: 'det.js' }).findings;
  const b = runScanner(code, { filePath: 'det.js' }).findings;
  assert.deepEqual(a, b, 'two identical scans must produce identical findings');
});

test('INVARIANT: evidence objects are JSON-serializable (no cycles, no functions)', () => {
  const f = runScanner('el.innerHTML = req.query.q;', { filePath: 'ser.js' }).findings.find(
    (x) => x.category === 'Cross-Site Scripting (XSS)'
  );
  const round = JSON.parse(JSON.stringify(f.evidence));
  assert.equal(round.flow.established, true);
  assert.equal(round.source.found, true);
  assert.equal(round.sink.type, 'dom-assign');
});

test('INVARIANT: verdict+confidence is a pure function of evidence (no hidden state)', () => {
  const ev = { flow: { established: true, direct: true }, staticConfirmed: false, parameterized: false };
  const ctx = { category: 'Injection Vulnerabilities', ruleId: 'sql-concat' };
  const once = [determineVerdict(ev, ctx), computeConfidence(ev, 'CONFIRMED', 0)];
  const twice = [determineVerdict(ev, ctx), computeConfidence(ev, 'CONFIRMED', 0)];
  const thrice = [determineVerdict(ev, ctx), computeConfidence(ev, 'CONFIRMED', 0)];
  assert.deepEqual(once, twice);
  assert.deepEqual(twice, thrice);
});

test('INVARIANT: an untainted-but-suspect sink is POTENTIAL, never CONFIRMED', () => {
  // Parameters are never treated as attacker-controlled (Phase 5 scope).
  const f = runScanner('function q(db, id) { return db.query("SELECT * FROM users WHERE id=" + id); }', {
    filePath: 'un.js',
  }).findings[0];
  assert.equal(f.verdict, 'POTENTIAL');
  assert.ok(f.confidence <= 35);
  assert.equal(f.severity, 'low');
});

// ── Phase 4E: security audit, size limits, determinism ─────────────────────────

// SECURITY AUDIT — evidence must never carry a raw secret value. It may carry
// source/sink *shapes* and flag names, but never the secret's payload.
test('SECURITY: hardcoded secret value never leaks into evidence or affectedCode', () => {
  const secretValue = 'sk-live-abcdefghijklmnop';
  const { findings } = runScanner(`const API_KEY = "${secretValue}";`, {
    filePath: 'sec-audit.js',
  });
  const secret = findings.find((f) => f.category === 'Hardcoded Credentials and Secrets');
  assert.ok(secret, 'hardcoded secret finding expected');
  assert.equal(secret.verdict, 'CONFIRMED');

  const json = JSON.stringify({ finding: secret, evidence: secret.evidence });
  assert.ok(!json.includes(secretValue), 'raw secret must not appear in serialized output');
  assert.ok(!json.includes('abcdefghijklmnop'), 'secret fragment must not appear');

  // Evidence object itself contains no raw secret payload.
  const asString = JSON.stringify(secret.evidence);
  assert.ok(!asString.includes(secretValue));
});

// SIZE LIMIT — exactly-at-boundary inputs remain untouched; only oversize are cut.
test('SIZE: sanitizeEvidence leaves boundary values intact and flags nothing', () => {
  const boundary = {
    source: { found: true, names: Array.from({ length: 8 }, (_, i) => 'n'.repeat(120)) },
    sink: { found: true, matched: true, type: 'sql', line: 1 },
    flow: { established: true, direct: false, sources: Array.from({ length: 8 }, () => 's'.repeat(120)) },
    constantData: false,
    parameterized: false,
    sanitized: false,
    templateOnly: false,
    techContext: { framework: 'express', db: 'sql', libs: ['a', 'b', 'c', 'd', 'e'] },
    staticConfirmed: false,
    explanation: 'e'.repeat(500),
  };
  const out = sanitizeEvidence(boundary);
  assert.equal(out.flow.sources.length, 8);
  assert.equal(out.source.names.length, 8);
  assert.equal(out.techContext.libs.length, 5);
  assert.equal(out.explanation.length, 500);
  assert.equal(out.truncated, undefined, 'no truncation at exact boundary');
  assert.equal(out.flow.sources[0].length, 120, '120-char source kept whole');
});

// SECURITY — a hostile source whose name is itself a huge secret-like blob is
// truncated to a fixed bound in evidence, so DB payload size is deterministic.
test('SIZE: pathological source expression is always truncated to ≤120 chars', () => {
  const blob = 'sk-live-' + 'x'.repeat(4000);
  const ev = {
    source: { found: true, names: [blob] },
    sink: { found: true, matched: true, type: 'sql', line: 1 },
    flow: { established: true, direct: false, sources: [blob] },
    constantData: false,
    parameterized: false,
    sanitized: false,
    templateOnly: false,
    techContext: { framework: 'express', db: 'sql', libs: ['zzzz'] },
    staticConfirmed: false,
    explanation: 'e',
  };
  const out = sanitizeEvidence(ev);
  assert.ok(out.flow.sources[0].length <= 120, `source truncated, got ${out.flow.sources[0].length}`);
  assert.ok(out.source.names[0].length <= 120, `name truncated, got ${out.source.names[0].length}`);
  // Truncated source no longer leaks the full blob.
  assert.ok(!out.flow.sources[0].includes('x'.repeat(4000)));
  assert.equal(out.truncated, true);
});

// SECURITY — evidence produced by the real pipeline is always JSON-serializable
// and free of secrets even when scanning secret-bearing and variable code.
test('SECURITY: full-scan evidence round-trips with no secret leak', () => {
  const code = [
    'const API_KEY = "ghp_1234567890abcdef";',
    'const token = "xoxb-secret-token-here";',
    'const id = req.query.id;',
    'db.query("SELECT * FROM users WHERE id=" + id);',
  ].join('\n');
  const { findings } = runScanner(code, { filePath: 'full-sec.js' });
  for (const f of findings) {
    const roundTripped = JSON.parse(JSON.stringify({ verdict: f.verdict, evidence: f.evidence }));
    assert.ok(roundTripped, 'evidence round-trips without throwing');
    const s = JSON.stringify(roundTripped);
    assert.ok(!s.includes('ghp_1234567890abcdef'), 'no GitHub PAT leak');
    assert.ok(!s.includes('xoxb-secret-token-here'), 'no Slack token leak');
    assert.ok(!s.includes('1234567890abcdef'), 'no secret fragment leak');
  }
});

// DETERMINISM — sanitizeEvidence is idempotent and stable (re-applying it never
// further mutates state, and identical inputs give identical outputs).
test('DETERMINISM: sanitizeEvidence is idempotent and deterministic', () => {
  const input = {
    source: { found: true, names: ['x'.repeat(500), 'y'] },
    sink: { found: true, matched: true, type: 'sql', line: 1 },
    flow: { established: true, direct: false, sources: ['a'.repeat(300), 'b'] },
    constantData: false,
    parameterized: false,
    sanitized: false,
    templateOnly: false,
    techContext: { framework: 'express', db: 'sql', libs: ['a', 'b', 'c', 'd', 'e', 'f'] },
    staticConfirmed: false,
    explanation: 'z'.repeat(900),
  };
  const first = sanitizeEvidence(structuredClone(input));
  const second = sanitizeEvidence(structuredClone(input));
  assert.deepEqual(JSON.parse(JSON.stringify(first)), JSON.parse(JSON.stringify(second)));

  // Idempotent: applying sanitizeEvidence again to an already-truncated object
  // produces an identical object (no drift, no repeated truncation).
  const again = sanitizeEvidence(structuredClone(first));
  assert.deepEqual(JSON.parse(JSON.stringify(again)), JSON.parse(JSON.stringify(first)));
});

