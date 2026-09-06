/**
 * Interprocedural Evidence Correlation (Phase 5B) — unit tests.
 *
 * Verifies that Phase 5B only APPENDS `evidence.interprocedural.correlation`
 * metadata and never alters verdict / confidence / severity / risk score /
 * comparisonKey, while remaining deterministic, bounded, JSON-safe and
 * conservative about unresolved calls.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { analyzeFile } from '../src/scanner/functionAnalysis.js';
import {
  correlateFindingWithFunctionAnalysis,
  buildAnalysisSafe,
  serializeAnalysis,
  INTERPROCEDURAL_EVIDENCE_VERSION,
  MAX_PATHS,
  MAX_PATH_LENGTH,
  MAX_SOURCES,
  MAX_SINKS,
} from '../src/scanner/interproceduralEvidence.js';
import { DATAFLOW_VERSION } from '../src/scanner/dataFlowAnalysis.js';
import { runScanner } from '../src/scanner/scanner.js';

/** Build a correlation for a finding inside `code`. */
function corrFor(code, finding, filePath = 'app.js', opts = {}) {
  const analysis = analyzeFile(code, { filePath });
  return correlateFindingWithFunctionAnalysis(finding, analysis, { code, ...opts });
}

// ── 1. Source-shaped request input ──────────────────────────────────────────
test('correlates a finding in a function reachable from a req.* source shape', () => {
  const code = `
function handler() {
  const id = req.query.id;
  return process(id);
}
function process(input) {
  return input;
}
`;
  const corr = corrFor(code, { line: 3, ruleId: 'x', category: 'General' }, 'req.js');
  assert.equal(corr.affectedFunction.name, 'handler');
  assert.equal(corr.sourceEvidence.present, true);
  assert.ok(
    corr.sourceEvidence.sources.some((s) => s.expression === 'req.query.id'),
    'expected req.query.id source shape',
  );
  assert.match(corr.sourceEvidence.note, /Request-derived source shape/);
  assert.ok(!/user-controlled/i.test(corr.summary), 'must not claim user-controlled input');
});

// ── 2. Structural sink correlation ──────────────────────────────────────────
test('correlates a finding in a function that reaches a structural sink', () => {
  const code = `
function handle() {
  const data = req.body.val;
  run(data);
}
function run(v) {
  eval(v);
}
`;
  const corr = corrFor(code, { line: 3, ruleId: 'eval', category: 'Dangerous Functions' }, 'sink.js');
  assert.equal(corr.sinkEvidence.present, true);
  assert.ok(corr.sinkEvidence.sinks.some((s) => s.sinkType === 'eval'));
  assert.match(corr.sinkEvidence.note, /Structural sink shape/);
});

// ── 3. Caller → callee relationship ─────────────────────────────────────────
test('reports caller-callee relationships for resolved calls', () => {
  const code = `
function validateInput(v) { return v; }
function handler() {
  return validateInput(req.query.q);
}
`;
  const corr = corrFor(code, { line: 4, ruleId: 'x', category: 'General' }, 'caller.js');
  assert.equal(corr.affectedFunction.name, 'handler');
  assert.ok(
    corr.callRelationships.callees.some((c) => c.name === 'validateInput'),
    'expected validateInput in callees',
  );
});

// ── 4. Reachable path A → B → C ────────────────────────────────────────────
test('produces a caller-callee path when A → B → C is reachable', () => {
  const code = `
function executeQuery(q) { db.query(q); }
function processInput(v) { executeQuery(v); }
function handler() {
  processInput(req.query.id);
}
`;
  const corr = corrFor(code, { line: 5, ruleId: 'x', category: 'General' }, 'path.js');
  assert.equal(corr.affectedFunction.name, 'handler');
  assert.ok(corr.reachability.paths.length >= 1, 'expected at least one path');
  const bestPath = corr.reachability.paths[0].path.map((n) => n.name);
  assert.deepEqual(bestPath, ['handler', 'processInput', 'executeQuery']);
  assert.equal(corr.reachability.paths[0].relationship, 'caller-callee');
  assert.equal(corr.reachability.paths[0].confidence, 'structural');
});

// ── 5. Recursion ───────────────────────────────────────────────────────────
test('handles recursion without hanging and excludes self from reachable set', () => {
  const code = `
function count(n) {
  if (n <= 0) return 0;
  return count(n - 1);
}
`;
  const corr = corrFor(code, { line: 4, ruleId: 'x', category: 'General' }, 'recurse.js');
  assert.equal(corr.affectedFunction.name, 'count');
  assert.ok(
    corr.reachability.reachableFunctions.every((f) => f.name !== 'count'),
    'recursive call target must not appear in reachableFunctions',
  );
});

// ── 6. Cycles ──────────────────────────────────────────────────────────────
test('handles cycles (A→B→C→A) without hanging', () => {
  const code = `
function a() { return b(); }
function b() { return c(); }
function c() { return a(); }
`;
  const corr = corrFor(code, { line: 2, ruleId: 'x', category: 'General' }, 'cycle.js');
  const names = corr.reachability.reachableFunctions.map((f) => f.name).sort();
  assert.deepEqual(names, ['b', 'c']);
  assert.equal(corr.reachability.paths.length, 0, 'no sinks in cycle → no paths');
});

// ── 7. Unresolved calls ────────────────────────────────────────────────────
test('does not bind calls to undefined local functions (external)', () => {
  const code = `
function handler() {
  return transform(req.query.id);
}
`;
  const corr = corrFor(code, { line: 3, ruleId: 'x', category: 'General' }, 'ext.js');
  assert.equal(corr.callRelationships.callees.length, 0, 'external callee not bound');
  assert.equal(corr.reachability.reachableFunctions.length, 0, 'external not in reachable');
  assert.equal(corr.sourceEvidence.present, true, 'handler has req source');
});
// ── 8. Member calls ─────────────────────────────────────────────────────────
test('member calls are unresolved and not bound to local functions', () => {
  const code = `
function handler() {
  obj.execute(req.query.id);
}
`;
  const corr = corrFor(code, { line: 3, ruleId: 'x', category: 'General' }, 'member.js');
  assert.equal(corr.reachability.reachableFunctions.length, 0);
  assert.equal(corr.callRelationships.callees.length, 0);
  assert.equal(corr.sourceEvidence.present, true, 'req source still detected');
});

// ── 9. this calls ──────────────────────────────────────────────────────────
test('this.xxx() calls are unresolved and not bound', () => {
  const code = `
function handler() {
  this.execute(req.query.id);
}
`;
  const corr = corrFor(code, { line: 3, ruleId: 'x', category: 'General' }, 'this.js');
  assert.equal(corr.reachability.reachableFunctions.length, 0);
  assert.equal(corr.callRelationships.callees.length, 0);
});

// ── 10. Dynamic calls ──────────────────────────────────────────────────────
test('calls to locally-assigned variables are unresolved', () => {
  const code = `
function handler() {
  const fn = req.query.choice;
  fn(req.query.id);
}
`;
  const corr = corrFor(code, { line: 4, ruleId: 'x', category: 'General' }, 'dynamic.js');
  assert.equal(corr.reachability.reachableFunctions.length, 0);
  assert.equal(corr.callRelationships.callees.length, 0);
});

// ── 11. Nested functions ───────────────────────────────────────────────────
test('anchor is innermost function containing the finding line', () => {
  const code = `
function outer() {
  function inner() {
    return req.query.x;
  }
  return inner();
}
`;
  const corr = corrFor(code, { line: 2, ruleId: 'x', category: 'General' }, 'nest.js');
  assert.equal(corr.affectedFunction.name, 'outer');
  const reachableNames = corr.reachability.reachableFunctions.map((f) => f.name);
  assert.ok(reachableNames.includes('inner'), 'inner reachable from outer');
  assert.equal(corr.sourceEvidence.present, true, 'req.source in reachable inner');
});

// ── 12. Callbacks ──────────────────────────────────────────────────────────
test('callback function targets are not resolved by name', () => {
  const code = `
function run(cb) { return cb(); }
function handler() {
  run(() => req.query.id);
}
`;
  const corr = corrFor(code, { line: 4, ruleId: 'x', category: 'General' }, 'cb.js');
  // The arrow function is the innermost function at line 4, so it IS the
  // affected function (not the callback target).  Verify that handler's
  // callees do NOT include the arrow function as a resolved target.
  assert.ok(
    corr.callRelationships.callees.every((c) => c.name !== '_anonymous'),
    'anonymous callback must not appear in callees',
  );
  assert.equal(corr.affectedFunction.name, '_anonymous', 'arrow is innermost');
  // Arrow has req.query.id source, so sourceEvidence present is expected
  assert.equal(corr.sourceEvidence.present, true, 'arrow itself has req source');
});

// ── 13. Shadowing ──────────────────────────────────────────────────────────
test('parameter that shadows a local function is treated as unresolved', () => {
  const code = `
function db() {}
function handler(db) {
  return db(req.query.id);
}
`;
  const analysis = analyzeFile(code, { filePath: 'shadow.js' });
  const corr = correlateFindingWithFunctionAnalysis(
    { line: 4, ruleId: 'x', category: 'General' },
    analysis,
  );
  assert.ok(
    corr.callRelationships.callees.every((c) => c.name !== 'db'),
    'param-shadowed db must not resolve to local db()',
  );
  assert.ok(
    corr.reachability.reachableFunctions.every((f) => f.name !== 'db'),
    'shadowed function not in reachable set',
  );
});

// ── 14. Multiple paths ─────────────────────────────────────────────────────
test('records separate paths when multiple callees have structural sinks', () => {
  const code = `
function s1(v) { db.query(v); }
function s2(v) { db.query(v); }
function handler() {
  const a = req.query.a;
  s1(a);
  s2(a);
}
`;
  const corr = corrFor(code, { line: 5, ruleId: 'x', category: 'General' }, 'multi.js');
  assert.ok(
    corr.reachability.paths.length >= 2,
    `expected >=2 paths, got ${corr.reachability.paths.length}`,
  );
  const endNames = corr.reachability.paths
    .map((p) => p.path[p.path.length - 1].name)
    .sort();
  assert.deepEqual(endNames, ['s1', 's2']);
});
// ── 15. Path bounding ───────────────────────────────────────────────────────
test('paths are bounded at MAX_PATHS and path lengths at MAX_PATH_LENGTH', () => {
  // Build 25 targets each with a sql-query sink; all called directly by handler
  const lines = [];
  for (let i = 0; i < 25; i++) {
    lines.push(`function s${i}(v) { db.query(req.query.a); }`);
  }
  lines.push('function handler() {');
  for (let i = 0; i < 25; i++) lines.push(`  s${i}(1);`);
  lines.push('}');
  const code = lines.join('\n');
  const corr = corrFor(code, { line: lines.indexOf('function handler() {') + 1, ruleId: 'x', category: 'General' }, 'bound.js');
  assert.ok(corr.reachability.paths.length <= MAX_PATHS, `paths ${corr.reachability.paths.length} must be <= ${MAX_PATHS}`);
  for (const p of corr.reachability.paths) {
    assert.ok(p.path.length <= MAX_PATH_LENGTH, `path length ${p.path.length} must be <= ${MAX_PATH_LENGTH}`);
  }
});

// ── 16. Source bounding ─────────────────────────────────────────────────────
test('source list is bounded at MAX_SOURCES', () => {
  // 25 reachable functions each with a unique req.* shape, no sink
  const lines = [];
  for (let i = 0; i < 25; i++) {
    lines.push(`function t${i}() { return req.query.p${i}; }`);
  }
  lines.push('function handler() {');
  for (let i = 0; i < 25; i++) lines.push(`  t${i}();`);
  lines.push('}');
  const code = lines.join('\n');
  const corr = corrFor(code, { line: lines.indexOf('function handler() {') + 1, ruleId: 'x', category: 'General' }, 'sbound.js');
  assert.ok(corr.sourceEvidence.sources.length <= MAX_SOURCES, `sources ${corr.sourceEvidence.sources.length} must be <= ${MAX_SOURCES}`);
});

// ── 17. Sink bounding ──────────────────────────────────────────────────────
test('sink list is bounded at MAX_SINKS', () => {
  const lines = [];
  for (let i = 0; i < 25; i++) {
    lines.push(`function e${i}(v) { eval(v); }`);
  }
  lines.push('function handler() {');
  for (let i = 0; i < 25; i++) lines.push(`  e${i}(1);`);
  lines.push('}');
  const code = lines.join('\n');
  const corr = corrFor(code, { line: lines.indexOf('function handler() {') + 1, ruleId: 'x', category: 'Dangerous Functions' }, 'kbound.js');
  assert.ok(corr.sinkEvidence.sinks.length <= MAX_SINKS, `sinks ${corr.sinkEvidence.sinks.length} must be <= ${MAX_SINKS}`);
});

// ── 18. Malformed input ────────────────────────────────────────────────────
test('does not throw on malformed source code', () => {
  assert.doesNotThrow(() => buildAnalysisSafe('function {', 'bad.js'));
  const analysis = buildAnalysisSafe('function {', 'bad.js');
  // analysis may be null (parser error) or empty; correlator must not throw
  assert.doesNotThrow(() => correlateFindingWithFunctionAnalysis({ line: 1, ruleId: 'x' }, analysis));
});

// ── 19. Empty analysis ─────────────────────────────────────────────────────
test('returns null when analysis is null; produces minimal object for empty code', () => {
  assert.equal(correlateFindingWithFunctionAnalysis({ line: 1, ruleId: 'x' }, null), null);
  const empty = analyzeFile('', { filePath: 'e.js' });
  const corr = correlateFindingWithFunctionAnalysis({ line: 1, ruleId: 'x' }, empty);
  assert.equal(corr.affectedFunction, null);
  assert.equal(corr.sourceEvidence.present, false);
  assert.equal(corr.sinkEvidence.present, false);
  assert.equal(corr.reachability.reachableFunctions.length, 0);
  assert.equal(corr.reachability.paths.length, 0);
});

// ── 20. Missing finding ────────────────────────────────────────────────────
test('returns null when finding is null', () => {
  const analysis = analyzeFile('function x() {}', { filePath: 'm.js' });
  assert.equal(correlateFindingWithFunctionAnalysis(null, analysis), null);
});

// ── 21. Finding without location ───────────────────────────────────────────
test('handles finding object without .line property', () => {
  const code = `function handler() { return req.query.id; }`;
  const corr = corrFor(code, { ruleId: 'x', category: 'General' }, 'noline.js');
  assert.equal(corr.affectedFunction, null);
  assert.equal(corr.sourceEvidence.present, false, 'no anchor → no reachable → no source evidence');
  assert.equal(typeof corr.summary, 'string');
});
// ── 22. Deterministic output ────────────────────────────────────────────────
test('produces identical JSON on repeated calls with the same input', () => {
  const code = `
function handler() { return req.query.id; }
`;
  const finding = { line: 2, ruleId: 'x', category: 'General' };
  const a1 = corrFor(code, finding, 'det.js');
  const a2 = corrFor(code, finding, 'det.js');
  assert.equal(JSON.stringify(a1), JSON.stringify(a2));
});

// ── 23. JSON serialization ──────────────────────────────────────────────────
test('output is JSON-safe (round-trips through parse/stringify)', () => {
  const code = `
function handler() { return req.query.id; }
`;
  const corr = corrFor(code, { line: 2, ruleId: 'x', category: 'General' }, 'json.js');
  const round = JSON.parse(JSON.stringify(corr));
  assert.deepEqual(round, corr);
});

// ── 24. No absolute path leakage ───────────────────────────────────────────
test('function IDs remain project-relative (no drive letters or absolute paths)', () => {
  const code = `function handler() { return req.query.id; }`;
  const corr = corrFor(code, { line: 1, ruleId: 'x', category: 'General' }, 'src/app/routes.js');
  const s = JSON.stringify(corr);
  assert.equal(s.includes('C:\\'), false, 'must not contain Windows drive letter');
  assert.equal(s.includes('/src/'), false, 'must not contain absolute leading slash');
  assert.ok(s.includes('src/app/routes.js'), 'relative filePath present');
});

// ── 25. Verdict unchanged ──────────────────────────────────────────────────
test('correlator never mutates the finding verdict', () => {
  const code = `function handler() { const u = req.query.u; db.query("SELECT * FROM t WHERE a=" + u); }`;
  const scan = runScanner(code, { filePath: 'v.js' });
  assert.ok(scan.findings.length >= 1, 'at least one finding produced');
  for (const f of scan.findings) {
    const beforeVerdict = f.verdict;
    const analysis = analyzeFile(code, { filePath: f.filePath });
    correlateFindingWithFunctionAnalysis(f, analysis);
    assert.equal(f.verdict, beforeVerdict, 'verdict must not be changed by correlator');
  }
});
// ── 26. Severity unchanged ─────────────────────────────────────────────────
test('correlator never mutates the finding severity', () => {
  const code = `function handler() { const u = req.query.u; db.query("SELECT * FROM t WHERE a=" + u); }`;
  const scan = runScanner(code, { filePath: 's.js' });
  for (const f of scan.findings) {
    const beforeSev = f.severity;
    const analysis = analyzeFile(code, { filePath: f.filePath });
    correlateFindingWithFunctionAnalysis(f, analysis);
    assert.equal(f.severity, beforeSev, 'severity must not be changed');
  }
});

// ── 27. Confidence unchanged ───────────────────────────────────────────────
test('correlator never mutates the finding confidence', () => {
  const code = `function handler() { const u = req.query.u; db.query("SELECT * FROM t WHERE a=" + u); }`;
  const scan = runScanner(code, { filePath: 'c.js' });
  for (const f of scan.findings) {
    const beforeConf = f.confidence;
    const analysis = analyzeFile(code, { filePath: f.filePath });
    correlateFindingWithFunctionAnalysis(f, analysis);
    assert.equal(f.confidence, beforeConf, 'confidence must not be changed');
  }
});

// ── 28. Risk score unchanged ───────────────────────────────────────────────
test('correlator never adds or modifies riskScore / score fields', () => {
  const code = `function handler() { const u = req.query.u; db.query("SELECT * FROM t WHERE a=" + u); }`;
  const scan = runScanner(code, { filePath: 'rs.js' });
  assert.ok(scan.findings.length >= 1);
  const f = scan.findings[0];
  const before = JSON.stringify(f);
  correlateFindingWithFunctionAnalysis(f, analyzeFile(code, { filePath: 'rs.js' }));
  assert.equal(JSON.stringify(f), before, 'entire finding must remain unchanged');
  assert.equal(f.riskScore, undefined, 'no riskScore added');
  assert.equal(f.score, undefined, 'no score added');
});

// ── 29. ComparisonKey unchanged ─────────────────────────────────────────────
test('correlator never mutates the finding comparisonKey', () => {
  const code = `function handler() { const u = req.query.u; db.query("SELECT * FROM t WHERE a=" + u); }`;
  const scan = runScanner(code, { filePath: 'ck.js' });
  assert.ok(scan.findings.length >= 1);
  const f = scan.findings[0];
  const beforeKey = f.comparisonKey;
  correlateFindingWithFunctionAnalysis(f, analyzeFile(code, { filePath: 'ck.js' }));
  assert.equal(f.comparisonKey, beforeKey, 'comparisonKey must not be changed');
});
// ── 30. Secret masking preserved ───────────────────────────────────────────
test('correlation on a hardcoded-secret finding does not leak the secret', () => {
  const code = `const API_KEY = 'sk-live-1234567890abcdef';`;
  const scan = runScanner(code, { filePath: 'sec.js' });
  assert.ok(scan.findings.length >= 1, 'secret finding expected');
  const f = scan.findings[0];
  assert.equal(f.verdict, 'CONFIRMED', 'hardcoded secret must remain CONFIRMED');
  const analysis = analyzeFile(code, { filePath: 'sec.js' });
  const corr = correlateFindingWithFunctionAnalysis(f, analysis);
  assert.ok(corr, 'correlation produced');
  const corrJson = JSON.stringify(corr);
  assert.equal(corrJson.includes('sk-live-1234567890abcdef'), false, 'secret must not appear in correlation');
  assert.equal(f.verdict, 'CONFIRMED', 'verdict unchanged after correlation');
});

// ── 31. Folder fixture integration ─────────────────────────────────────────
test('correlator handles all Phase 5A fixtures without hanging', async () => {
  const { readdirSync, readFileSync } = await import('node:fs');
  const { join } = await import('node:path');
  const dir = join(process.cwd(), 'tests', 'security-fixtures', 'interprocedural');
  const files = readdirSync(dir).filter((f) => f.endsWith('.js'));
  assert.ok(files.length >= 8, `expected at least 8 fixtures, found ${files.length}`);
  for (const fname of files) {
    const code = readFileSync(join(dir, fname), 'utf8');
    const analysis = analyzeFile(code, { filePath: fname });
    const probe = { line: 1, ruleId: 'probe', category: 'General' };
    const corr = correlateFindingWithFunctionAnalysis(probe, analysis);
    assert.ok(corr, `correlation produced for ${fname}`);
    assert.equal(corr.version, INTERPROCEDURAL_EVIDENCE_VERSION);
  }
});

// ── Integration: correlation attached by runScanner ─────────────────────────
test('runScanner attaches interprocedural.correlation to findings', () => {
  const code = `function handler(){ const u = req.query.u; db.query("SELECT * FROM t WHERE a=" + u); }`;
  const scan = runScanner(code, { filePath: 'integ.js' });
  assert.ok(scan.findings.length >= 1, 'at least one finding');
  for (const f of scan.findings) {
    assert.ok(f.evidence, 'evidence present');
    assert.ok(f.evidence.interprocedural, 'interprocedural metadata present');
    assert.ok(f.evidence.interprocedural.correlation, '5B correlation attached');
    assert.equal(f.evidence.interprocedural.correlation.version, '5B.0');
    // Verify 5A fields are still present alongside correlation
    assert.equal(typeof f.evidence.interprocedural.functionCount, 'number');
    assert.equal(typeof f.evidence.interprocedural.callGraph, 'object');
  }
});

// ── 32. Phase 5C dataFlow key present ──────────────────────────────────────
test('correlation includes dataFlow key with version 5C.0 when code is provided', () => {
  const code = `function handler() { const id = req.query.id; db.query("SELECT * FROM t WHERE id=" + id); }`;
  const corr = corrFor(code, { line: 1, ruleId: 'x', category: 'General' }, 'df1.js');
  assert.ok(corr.dataFlow, 'dataFlow key present');
  assert.equal(corr.dataFlow.version, DATAFLOW_VERSION);
  assert.equal(typeof corr.dataFlow.paths, 'object');
  assert.equal(typeof corr.dataFlow.truncated, 'boolean');
  assert.equal(typeof corr.dataFlow.summary, 'string');
  assert.equal(typeof corr.dataFlow.facts, 'object');
});

// ── 33. Phase 5C dataFlow paths populated for source→sink ──────────────────
test('dataFlow traces source->sink paths when propagation exists', () => {
  const code = [
    'const express = require("express");',
    'const app = express();',
    'app.get("/x", (req, res) => {',
    '  const id = req.query.id;',
    '  const sql = "SELECT * FROM users WHERE id = " + id;',
    '  db.query(sql);',
    '  res.send(id);',
    '});',
  ].join('\n');
  const corr = corrFor(code, { line: 5, ruleId: 'sql-injection', category: 'Injection' }, 'df2.js');
  assert.ok(corr.dataFlow, 'dataFlow present');
  assert.ok(corr.dataFlow.paths.length > 0, 'at least one data-flow path traced');
  const path = corr.dataFlow.paths[0];
  assert.ok(path.source, 'path has source');
  assert.ok(path.sink, 'path has sink');
  assert.equal(path.confidence, 'structural-data-flow');
  assert.ok(path.steps.length >= 2, 'path has at least 2 steps');
});

// ── 34. Phase 5C dataFlow null without code ────────────────────────────────
test('dataFlow is null when opts.code is not provided', () => {
  const code = `function handler() { const id = req.query.id; db.query("SELECT * FROM t WHERE id=" + id); }`;
  const analysis = analyzeFile(code, { filePath: 'dfno.js' });
  const corr = correlateFindingWithFunctionAnalysis(
    { line: 1, ruleId: 'x', category: 'General' },
    analysis,
  );
  assert.ok(corr, 'correlation produced');
  assert.equal(corr.dataFlow, null, 'dataFlow is null when code not provided');
});

// ── 35. Phase 5C dataFlow empty when no sink ───────────────────────────────
test('dataFlow has empty paths when no sink is reachable', () => {
  const code = `function handler() { const id = req.query.id; console.log(id); }`;
  const corr = corrFor(code, { line: 1, ruleId: 'x', category: 'General' }, 'dfempty.js');
  assert.ok(corr.dataFlow, 'dataFlow key present');
  assert.equal(corr.dataFlow.paths.length, 0, 'no paths when no sink');
  assert.equal(corr.dataFlow.facts.sourceCount > 0, true, 'source detected');
  assert.equal(corr.dataFlow.facts.sinkCount, 0, 'no sinks');
});

// ── 36. Phase 5C summary includes dataFlow info ────────────────────────────
test('summary string includes data-flow path info when present', () => {
  const code = [
    'const express = require("express");',
    'const app = express();',
    'app.get("/x", (req, res) => {',
    '  const id = req.query.id;',
    '  const sql = "SELECT * FROM users WHERE id = " + id;',
    '  db.query(sql);',
    '});',
  ].join('\n');
  const corr = corrFor(code, { line: 5, ruleId: 'sql-injection', category: 'Injection' }, 'dfs.js');
  assert.ok(corr.summary.includes('Data-flow path(s)'), 'summary mentions data-flow paths');
});

// ── 37. Phase 5C determinism ───────────────────────────────────────────────
test('dataFlow output is deterministic across repeated calls', () => {
  const code = [
    'function handler() {',
    '  const id = req.query.id;',
    '  db.query("SELECT * FROM t WHERE id=" + id);',
    '}',
  ].join('\n');
  const finding = { line: 3, ruleId: 'x', category: 'General' };
  const a1 = corrFor(code, finding, 'determ_df.js');
  const a2 = corrFor(code, finding, 'determ_df.js');
  assert.equal(JSON.stringify(a1.dataFlow), JSON.stringify(a2.dataFlow), 'dataFlow is deterministic');
});

// ── 38. Phase 5C JSON-safe ─────────────────────────────────────────────────
test('dataFlow object round-trips through JSON serialization', () => {
  const code = [
    'function handler() {',
    '  const id = req.query.id;',
    '  db.query("SELECT * FROM t WHERE id=" + id);',
    '}',
  ].join('\n');
  const corr = corrFor(code, { line: 3, ruleId: 'x', category: 'General' }, 'dfjson.js');
  const round = JSON.parse(JSON.stringify(corr));
  assert.deepEqual(round.dataFlow, corr.dataFlow, 'dataFlow round-trips');
});

// ── 39. Phase 5C integration via runScanner ────────────────────────────────
test('runScanner findings include dataFlow in interprocedural.correlation', () => {
  const code = `function handler(){ const u = req.query.u; db.query("SELECT * FROM t WHERE a=" + u); }`;
  const scan = runScanner(code, { filePath: 'dfinteg.js' });
  assert.ok(scan.findings.length >= 1, 'at least one finding');
  const f = scan.findings[0];
  assert.ok(f.evidence.interprocedural, 'interprocedural metadata');
  assert.ok(f.evidence.interprocedural.correlation, 'correlation present');
  assert.ok(f.evidence.interprocedural.correlation.dataFlow, 'dataFlow in correlation');
  assert.equal(f.evidence.interprocedural.correlation.dataFlow.version, DATAFLOW_VERSION);
});

// ── 40. Phase 5C does not affect verdict/confidence/severity ───────────────
test('adding code to opts does not mutate the finding verdict/confidence/severity', () => {
  const code = `function handler() { const u = req.query.u; db.query("SELECT * FROM t WHERE a=" + u); }`;
  const analysis = analyzeFile(code, { filePath: 'dfimmut.js' });
  const finding = { line: 1, ruleId: 'x', category: 'General', verdict: 'POTENTIAL', confidence: 0.5, severity: 'low' };
  correlateFindingWithFunctionAnalysis(finding, analysis, { code });
  assert.equal(finding.verdict, 'POTENTIAL', 'verdict unchanged');
  assert.equal(finding.confidence, 0.5, 'confidence unchanged');
  assert.equal(finding.severity, 'low', 'severity unchanged');
});
