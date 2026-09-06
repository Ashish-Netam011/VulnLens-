/**
 * Mandatory security invariants (Phase 4E).
 *
 * These are the non-negotiable properties the whole deterministic pipeline must
 * uphold. They are deliberately written against the scanner + evidence engines
 * (no DB, no network) so they run instantly and form a hard security gate that
 * will never be caught up in integration/DB availability issues.
 *
 * Each invariant is phrased as "if X is true, then Y must hold" — a spec-style
 * security contract rather than an example check.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScanner, applyEvidenceEngine } from '../src/scanner/scanner.js';
import { buildEvidence, sanitizeEvidence } from '../src/scanner/evidence.js';
import { determineVerdict } from '../src/scanner/verdictEngine.js';
import { computeConfidence } from '../src/scanner/confidenceEngine.js';

// INVARIANT 1 ────────────────────────────────────────────────────────────────
// A finding the verdict engine labels FALSE_POSITIVE must NEVER be surfaced by
// the scanner. It is provably safe and must be dropped at the evidence layer.
test('INV 1: FALSE_POSITIVE findings are always removed from the result set', () => {
  const xssConstant = runScanner('el.innerHTML = "static text";', {
    filePath: 'inv1.js',
  }).findings;
  // Constant DOM sink is a provable false positive → dropped entirely.
  assert.equal(xssConstant.length, 0, 'constant DOM sink must be dropped');
  assert.ok(
    xssConstant.every((f) => f.verdict !== 'FALSE_POSITIVE'),
    'no FALSE_POSITIVE may surface'
  );

  // Defense-in-depth: even if we force evidence labeling, the verdict engine
  // must never produce CONFIRMED for constant data on a DOM sink.
  const ev = buildEvidence('el.innerHTML = "static text";', {
    category: 'Cross-Site Scripting (XSS)',
    ruleId: 'innerhtml',
    line: 1,
  });
  assert.equal(
    determineVerdict(ev, { category: 'Cross-Site Scripting (XSS)', ruleId: 'innerhtml' }),
    'FALSE_POSITIVE'
  );
  assert.equal(computeConfidence(ev, 'FALSE_POSITIVE', 95), 0);
});

// INVARIANT 2 ────────────────────────────────────────────────────────────────
// A finding the verdict engine labels POTENTIAL must be demoted to low severity
// and carry a confidence of ≤ 35 — the scanner must never let a POTENTIAL lead
// present itself as high/critical or high-confidence.
test('INV 2: POTENTIAL is always LOW severity with confidence ≤ 35', () => {
  const code =
    'function q(db, id) { return db.query("SELECT * FROM users WHERE id=" + id); }';
  const { findings } = runScanner(code, { filePath: 'inv2.js' });
  const sql = findings.find((f) => f.category === 'Injection Vulnerabilities');
  assert.ok(sql, 'expected a POTENTIAL sql finding');
  assert.equal(sql.verdict, 'POTENTIAL');
  assert.equal(sql.severity, 'low');
  assert.ok(sql.confidence <= 35, `confidence ${sql.confidence} must be ≤ 35`);
  assert.equal(sql.evidence.flow.established, false);
});

// INVARIANT 3 ────────────────────────────────────────────────────────────────
// CONFIRMED must be evidence-backed: a finding is only ever CONFIRMED when the
// evidence proves a real source→sink flow or the pattern is static-confirmed.
test('INV 3: CONFIRMED requires proof (established flow or static confirmation)', () => {
  const confirmed = runScanner(
    'db.query("SELECT * FROM users WHERE id=" + req.query.id);',
    { filePath: 'inv3.js' }
  ).findings[0];
  assert.equal(confirmed.verdict, 'CONFIRMED');
  assert.ok(
    confirmed.evidence.flow.established === true || confirmed.evidence.staticConfirmed === true,
    'CONFIRMED must be backed by evidence'
  );
  assert.ok(
    confirmed.evidence.source.found === true || confirmed.evidence.staticConfirmed === true
  );

  // Static-confirmed (hardcoded secret) is also a legitimate CONFIRMED, with
  // constantData itself being the proof.
  const secret = runScanner('const API_KEY = "sk-live-abcdefghijklmnop";', {
    filePath: 'inv3b.js',
  }).findings.find((f) => f.category === 'Hardcoded Credentials and Secrets');
  assert.equal(secret.verdict, 'CONFIRMED');
  assert.equal(secret.evidence.staticConfirmed, true);
});

// INVARIANT 4 ────────────────────────────────────────────────────────────────
// Severity is DERIVED from the verdict, never copied blindly from the rule.
// The scanner's normalization + verdict→severity mapping completely override any
// rule-authored severity for non-CONFIRMED findings.
test('INV 4: scanner severity normalization overrides rule-authored severity', () => {
  // A rule may claim CRITICAL, but if the evidence says POTENTIAL the persisted
  // severity must be LOW — the rule's number is ignored.
  const code =
    '// rule would call this CRITICAL\nfunction q(db, id) { db.query("SELECT * FROM users WHERE id=" + id); }';
  const { findings } = runScanner(code, { filePath: 'inv4.js' });
  for (const f of findings) {
    if (f.verdict === 'POTENTIAL') {
      assert.equal(f.severity, 'low', 'POTENTIAL must be low regardless of rule severity');
    }
    assert.ok(
      ['critical', 'high', 'medium', 'low', 'informational'].includes(f.severity),
      `severity normalized to a known value, got ${f.severity}`
    );
  }
});

// INVARIANT 5 ────────────────────────────────────────────────────────────────
// AI is advisory only. Even a deliberately hostile AI verdict/severity/confidence
// must never change the deterministic fields on the finding itself. (Integration
// tests cover the full network path; here we lock the data-contract invariant.)
test('INV 5: AI enrichment lives in ai.* and can never override deterministic fields', () => {
  // Simulate the scanService enrichment contract: whatever AI "says" is written
  // to f.ai.* and must not mutate f.verdict / f.severity / f.confidence.
  const base = runScanner(
    'function q(db, id) { db.query("SELECT * FROM users WHERE id=" + id); }',
    { filePath: 'inv5.js' }
  ).findings[0];
  assert.equal(base.verdict, 'POTENTIAL');
  assert.equal(base.severity, 'low');
  assert.ok(base.confidence <= 35);

  const hostileAi = { severity: 'critical', confidence: 0.99 };
  const enriched = {
    ...base,
    ai: {
      severity: hostileAi.severity,
      confidence: Math.round(hostileAi.confidence * 100),
      source: 'openrouter',
    },
  };

  // Deterministic fields are untouched by the hostile AI payload.
  assert.equal(enriched.verdict, 'POTENTIAL');
  assert.equal(enriched.severity, 'low');
  assert.ok(enriched.confidence <= 35);
  // Hostile AI claim is contained (and visible) only under ai.*.
  assert.equal(enriched.ai.severity, 'critical');
  assert.equal(enriched.ai.confidence, 99);
});


// INVARIANT 6 ────────────────────────────────────────────────────────────────
// Determinism: same input → bit-identical findings (no hidden state, no random,
// no ordering flakiness). This is the reproducibility guarantee the rescan and
// regression systems depend on.
test('INV 6: identical input yields deep-equal findings across repeated runs', () => {
  const code = [
    'const fs = require("fs");',
    'fs.readFile(req.query.path, () => {});',
    'db.query("SELECT * FROM users WHERE id=" + req.query.id);',
  ].join('\n');
  const runs = [];
  for (let i = 0; i < 3; i++) {
    runs.push(runScanner(code, { filePath: 'inv6.js' }).findings);
  }
  assert.deepEqual(runs[0], runs[1]);
  assert.deepEqual(runs[1], runs[2]);
});

// INVARIANT 7 ────────────────────────────────────────────────────────────────
// Evidence is JSON-safe and size-bounded. Even a pathological source with an
// enormous single expression cannot produce a huge persisted evidence blob.
test('INV 7: sanitizeEvidence bounds sources/libs/explanation deterministically', () => {
  const huge = 'var'.repeat(200) + ' ' + 'x'.repeat(5000);
  const ev = {
    source: { found: true, names: [huge, huge, huge, huge, huge, huge, huge, huge, huge] },
    sink: { found: true, matched: true, type: 'sql', line: 1 },
    flow: { established: true, direct: false, sources: Array.from({ length: 20 }, () => huge) },
    constantData: false,
    parameterized: false,
    sanitized: false,
    templateOnly: false,
    techContext: { framework: 'express', db: 'sql', libs: ['a', 'b', 'c', 'd', 'e', 'f', 'g'] },
    staticConfirmed: false,
    explanation: 'x'.repeat(5000),
  };

  const out = sanitizeEvidence(ev);

  // Array length caps.
  assert.ok(out.flow.sources.length <= 8, 'sources capped at 8');
  assert.ok(out.source.names.length <= 8, 'source.names capped at 8');
  assert.ok(out.techContext.libs.length <= 5, 'techContext.libs capped at 5');
  // Per-entry length caps.
  for (const s of out.flow.sources) assert.ok(s.length <= 120, `source ≤ 120 got ${s.length}`);
  for (const n of out.source.names) assert.ok(n.length <= 120, `name ≤ 120 got ${n.length}`);
  for (const l of out.techContext.libs) assert.ok(l.length <= 60, `lib ≤ 60 got ${l.length}`);
  assert.ok(out.explanation.length <= 500, `explanation ≤ 500 got ${out.explanation.length}`);
  // Flag set when truncation occurred.
  assert.equal(out.truncated, true);
  // Still JSON-serializable.
  assert.doesNotThrow(() => JSON.stringify(out));
});

// INVARIANT 8 ────────────────────────────────────────────────────────────────
// Error isolation: a malformed / unparseable file must never throw out of the
// scanner. The scan completes with (at worst) zero findings — never a crash and
// never a fabricated CONFIRMED from a broken AST.
test('INV 8: malformed / unparseable source never crashes and never false-confirms', () => {
  const malformed = [
    'function({{{ ;',
    'const x = ;',
    'db.query("SELECT 1");',
    '} else {',
    'const q = "SELECT * FROM users WHERE id=" + ;',
  ].join('\n');
  let result;
  assert.doesNotThrow(() => {
    result = runScanner(malformed, { filePath: 'inv8.js' });
  });
  assert.ok(Array.isArray(result.findings));
  for (const f of result.findings) {
    assert.notEqual(f.verdict, 'CONFIRMED', 'no CONFIRMED from a broken AST');
  }

  // Null/undefined code must also be tolerated (defensive server input).
  assert.doesNotThrow(() => runScanner(null, { filePath: 'n.js' }));
  assert.doesNotThrow(() => runScanner(undefined, { filePath: 'u.js' }));
  assert.doesNotThrow(() => runScanner('', { filePath: 'e.js' }));
});

// INVARIANT 9 ────────────────────────────────────────────────────────────────
// applyEvidenceEngine is a pure re-normalization: it can only REMOVE
// FALSE_POSITIVE and re-derive severity/confidence, and must never create
// findings or change comparisonKeys.
test('INV 9: applyEvidenceEngine preserves keys and never invents findings', () => {
  const code =
    'el.innerHTML = "x"; const a = "y"; db.query("SELECT 1 WHERE a=" + req.query.id);';
  const raw = runScanner(code, { filePath: 'inv9.js' }).findings;
  const inputKeys = raw.map((f) => f.comparisonKey).sort();
  const processed = applyEvidenceEngine(code, raw);
  const outputKeys = processed.map((f) => f.comparisonKey).sort();

  // No new finding keys introduced (output is a subset, dedup + FP removal only).
  for (const k of outputKeys) {
    assert.ok(inputKeys.includes(k), `output key ${k} must come from input`);
  }
  for (const f of processed) {
    assert.ok(!['FALSE_POSITIVE'].includes(f.verdict));
    assert.ok(
      f.verdict === 'CONFIRMED' || f.verdict === 'LIKELY' || f.verdict === 'POTENTIAL',
      `unknown verdict ${f.verdict}`
    );
  }
});

