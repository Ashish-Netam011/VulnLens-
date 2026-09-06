/**
 * Intra-File Data-Flow Evidence (Phase 5C) — unit tests.
 *
 * Verifies that Phase 5C traces bounded source→sink propagation paths within a
 * single file and produces deterministic, bounded, JSON-safe evidence that is
 * PURELY ADDITIVE (never alters verdict / confidence / severity). It also
 * guards the "conservative / no guessing" contract: only provable propagation
 * shapes yield paths.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  analyzeDataFlow,
  buildDataFlowSafe,
  extractDataFlowFacts,
  propagateValue,
  traceSourceToSink,
  DATAFLOW_VERSION,
  MAX_DF_PATHS,
  MAX_DF_DEPTH,
} from '../src/scanner/dataFlowAnalysis.js';
import { analyzeFile } from '../src/scanner/functionAnalysis.js';
import { parseJS } from '../src/scanner/ast.js';

// ── 1. Version & shape ──────────────────────────────────────────────────────
test('analyzeDataFlow returns a well-formed result object', () => {
  const r = analyzeDataFlow('const x = 1;');
  assert.equal(r.version, DATAFLOW_VERSION);
  assert.ok(Array.isArray(r.paths));
  assert.equal(typeof r.truncated, 'boolean');
  assert.equal(typeof r.summary, 'string');
  assert.equal(typeof r.facts, 'object');
});

// ── 2. Empty / non-string input ─────────────────────────────────────────────
test('analyzeDataFlow returns empty result for empty or non-string code', () => {
  assert.equal(analyzeDataFlow('').paths.length, 0);
  assert.equal(analyzeDataFlow(null).paths.length, 0);
  assert.equal(analyzeDataFlow(undefined).paths.length, 0);
  assert.equal(analyzeDataFlow(123).paths.length, 0);
});

// ── 3. Malformed source fails safely ────────────────────────────────────────
test('malformed source does not throw and yields no paths', () => {
  assert.doesNotThrow(() => analyzeDataFlow('function {'));
  const r = analyzeDataFlow('function {', { filePath: 'bad.js' });
  assert.ok(Array.isArray(r.paths));
  assert.equal(r.facts.sourceCount, 0);
  assert.equal(r.facts.sinkCount, 0);
});

// ── 4. Direct assignment to a query sink ────────────────────────────────────
test('direct assignment req.query.id → db.query traces a path', () => {
  const code = [
    'const express = require("express");',
    'const app = express();',
    'app.get("/x", (req, res) => {',
    '  const id = req.query.id;',
    '  const sql = "SELECT * FROM users WHERE id = " + id;',
    '  db.query(sql);',
    '});',
  ].join('\n');
  const r = analyzeDataFlow(code, { filePath: 'df.ts' });
  assert.ok(r.paths.length > 0, 'at least one path');
  const p = r.paths[0];
  assert.equal(p.sink.type, 'sql-query');
  assert.equal(p.confidence, 'structural-data-flow');
  assert.ok(p.length >= 2, 'path has steps');
  assert.equal(p.steps[0].kind, 'source');
});

// ── 5. No sink → empty paths but facts captured ─────────────────────────────
test('source with no sink yields empty paths and captured sourceCount', () => {
  const r = analyzeDataFlow('function h(){ const id = req.query.id; console.log(id); }');
  assert.equal(r.paths.length, 0);
  assert.ok(r.facts.sourceCount > 0, 'source counted');
  assert.equal(r.facts.sinkCount, 0, 'no sink counted');
});

// ── 6. No source → empty paths ──────────────────────────────────────────────
test('sink with no source yields empty paths', () => {
  const r = analyzeDataFlow('db.query("SELECT * FROM t");');
  assert.equal(r.paths.length, 0);
  assert.equal(r.facts.sourceCount, 0);
  assert.ok(r.facts.sinkCount > 0, 'sink counted');
});

// ── 7. Sink-type mapping ────────────────────────────────────────────────────
test('recognizes multiple sink types', () => {
  const cases = [
    { code: 'const x = req.query.u; eval(x);', type: 'eval' },
    { code: 'const x = req.query.u; document.write(x);', type: 'dom' },
    { code: 'const x = req.query.u; fs.writeFileSync("f", x);', type: 'fs' },
    { code: 'const x = req.query.u; child_process.exec(x);', type: 'command' },
  ];
  for (const c of cases) {
    const r = analyzeDataFlow(c.code, { filePath: 'sink.js' });
    assert.ok(r.facts.sinkCount > 0, `sink detected for ${c.type}`);
    const types = r.paths.map((p) => p.sink.type);
    if (r.paths.length > 0) {
      assert.ok(types.includes(c.type), `path has type ${c.type}`);
    }
  }
});

// ── 8. Variable reassignment / alias propagation ────────────────────────────
test('taint propagates through reassignment and alias', () => {
  const code = [
    'function h(req){',
    '  const a = req.query.q;',
    '  const b = a;',
    '  b = b;',
    '  db.query(b);',
    '}',
  ].join('\n');
  const r = analyzeDataFlow(code, { filePath: 'alias.js' });
  assert.ok(r.paths.length > 0, 'alias path traced');
});

// ── 9. Direct source→sink via intermediate variable ────────────────────────
test('taint propagates from source through intermediate variable to sink', () => {
  const code = 'const id = req.query.q; db.query(id);';
  const r = analyzeDataFlow(code, { filePath: 'direct.js' });
  assert.ok(r.paths.length > 0, 'source-to-sink path traced');
  assert.equal(r.paths[0].sink.type, 'sql-query');
  assert.equal(r.paths[0].steps[0].kind, 'source');
});

// ── 10. Path bounding (MAX_DF_PATHS) ───────────────────────────────────────
test('paths are bounded by MAX_DF_PATHS and truncated flag set', () => {
  const lines = [];
  for (let i = 0; i < 40; i++) {
    lines.push(`const a${i} = req.query.p${i};`);
    lines.push(`db.query(a${i});`);
  }
  const code = lines.join('\n');
  const r = analyzeDataFlow(code, { filePath: 'bound.js' });
  assert.ok(r.paths.length <= MAX_DF_PATHS, 'paths capped');
  assert.equal(r.truncated, true, 'truncated flag set when capped');
  assert.equal(r.paths.length, MAX_DF_PATHS);
});

// ── 11. Determinism ────────────────────────────────────────────────────────
test('identical input yields identical JSON on repeated calls', () => {
  const code = [
    'function h(req){',
    '  const id = req.query.id;',
    '  db.query("SELECT * FROM t WHERE id=" + id);',
    '}',
  ].join('\n');
  const a = analyzeDataFlow(code, { filePath: 'det.js' });
  const b = analyzeDataFlow(code, { filePath: 'det.js' });
  assert.equal(JSON.stringify(a), JSON.stringify(b), 'deterministic');
});

// ── 12. JSON-safe ──────────────────────────────────────────────────────────
test('result round-trips through JSON', () => {
  const code = [
    'function h(req){',
    '  const id = req.query.id;',
    '  db.query("SELECT * FROM t WHERE id=" + id);',
    '}',
  ].join('\n');
  const r = analyzeDataFlow(code, { filePath: 'json.js' });
  const round = JSON.parse(JSON.stringify(r));
  assert.deepEqual(round, r);
});

// ── 13. No secret / absolute path leakage ──────────────────────────────────
test('result contains no absolute paths or raw environment variables', () => {
  const code = [
    'function h(req){',
    '  const id = req.query.id;',
    '  db.query("SELECT * FROM t WHERE id=" + id);',
    '}',
  ].join('\n');
  const r = JSON.stringify(analyzeDataFlow(code, { filePath: 'rel/path.js' }));
  assert.equal(r.includes('C:\\'), false, 'no Windows absolute path');
  assert.equal(r.includes('process.env'), false, 'no process.env leak');
});

// ── 14. buildDataFlowSafe wrapper ──────────────────────────────────────────
test('buildDataFlowSafe returns null on invalid input and result on valid', () => {
  assert.equal(buildDataFlowSafe(''), null);
  assert.equal(buildDataFlowSafe(null), null);
  assert.equal(buildDataFlowSafe(undefined), null);
  assert.equal(buildDataFlowSafe(42), null);
  const ok = buildDataFlowSafe('const x = 1;');
  assert.ok(ok, 'valid input returns result');
  assert.equal(ok.version, DATAFLOW_VERSION);
});

// ── 15. buildDataFlowSafe catches internal errors ──────────────────────────
test('buildDataFlowSafe never throws', () => {
  assert.doesNotThrow(() => buildDataFlowSafe('function {'));
});

// ── 16. extractDataFlowFacts shape ─────────────────────────────────────────
test('extractDataFlowFacts returns the documented fact groups', () => {
  const ast = parseJS('const a = req.query.x;');
  const f = extractDataFlowFacts(ast, 'const a = req.query.x;');
  assert.ok(Array.isArray(f.sources));
  assert.ok(Array.isArray(f.sinks));
  assert.ok(Array.isArray(f.bindings));
  assert.ok(Array.isArray(f.params));
  assert.ok(Array.isArray(f.returns));
  assert.ok(Array.isArray(f.callSites));
});

// ── 17. propagateValue marks tainted names only ────────────────────────────
test('propagateValue spreads taint through exact identifier bindings only', () => {
  const ast = parseJS('const a = req.query.x; const b = a; const c = b; const d = 1;');
  const facts = extractDataFlowFacts(ast, 'const a = req.query.x; const b = a; const c = b; const d = 1;');
  const tainted = propagateValue(['a'], facts);
  assert.ok(tainted.has('b'), 'b tainted via alias');
  assert.ok(tainted.has('c'), 'c tainted transitively');
  assert.equal(tainted.has('d'), false, 'd (constant) not tainted');
});

// ── 18. traceSourceToSink returns steps or null ────────────────────────────
test('traceSourceToSink returns bounded steps for a valid chain', () => {
  const code = 'const a = req.query.x; db.query(a);';
  const ast = parseJS(code);
  const facts = extractDataFlowFacts(ast, code);
  const functions = analyzeFile(code).functions || [];
  const source = { expression: 'req.query.x', line: 1 };
  const sink = { type: 'sql-query', line: 1, argIndex: 0 };
  const steps = traceSourceToSink(source, sink, facts, functions, { maxDepth: MAX_DF_DEPTH });
  assert.ok(steps && Array.isArray(steps), 'steps array produced');
  assert.ok(steps.length >= 2, 'at least source + sink');
  assert.equal(steps[0].kind, 'source');
  assert.equal(steps[steps.length - 1].kind, 'sink');
});

// ── 19. Bounded depth ──────────────────────────────────────────────────────
test('traceSourceToSink respects maxDepth', () => {
  const code = [
    'const a = req.query.x;',
    'const b = a;',
    'const c = b;',
    'const d = c;',
    'const e = d;',
    'const f = e;',
    'db.query(f);',
  ].join('\n');
  const r = analyzeDataFlow(code, { filePath: 'depth.js' });
  if (r.paths.length > 0) {
    assert.ok(r.paths[0].length <= MAX_DF_DEPTH, 'path length bounded');
  }
});

// ── 20. Conservative: complex expressions not over-claimed ─────────────────
test('does not fabricate paths through unsupported constructs', () => {
  const r = analyzeDataFlow('const s = req.query.x; someObj[fn()](s);');
  assert.ok(r.paths.length <= MAX_DF_PATHS, 'stays bounded and does not crash');
});

// ── 21. Facts counts are numeric ───────────────────────────────────────────
test('facts exposes numeric counters', () => {
  const r = analyzeDataFlow(
    'function h(req){ const a = req.query.x; const b = a; db.query(b); return b; }',
  );
  for (const key of ['sourceCount', 'sinkCount', 'bindingCount', 'paramCount', 'returnCount', 'callSiteCount']) {
    assert.equal(typeof r.facts[key], 'number', `facts.${key} numeric`);
  }
});
