/**
 * Function Analysis Engine Unit Tests (Phase 5A).
 *
 * This module provides the interprocedural-analysis FOUNDATION (function
 * extraction, summaries, call sites, and a deterministic intra-file call
 * graph). NONE of this produces or changes vulnerability verdicts — it is
 * structural metadata only.
 *
 * Coverage goals (25+ assertions):
 *   - Extraction of every function form (declaration, arrow, expression,
 *     object/class method, async, nested, IIFE).
 *   - Parameter handling (destructuring, defaults, rest).
 *   - Summary building (returns, calls, sinks, sources).
 *   - Call-site extraction and correct function attribution.
 *   - Conservative callee resolution (member/dynamic -> unresolved, not guessed).
 *   - Call graph nodes/edges, external edges, recursion/cycle termination.
 *   - Reachability with and without cycles.
 *   - Robustness: malformed/empty/null input never throws.
 *   - Determinism.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  extractFunctions,
  buildFunctionSummary,
  extractCalls,
  buildCallGraph,
  analyzeFile,
  resolveCallee,
  reachableFrom,
  FUNCTION_ANALYSIS_VERSION,
} from '../src/scanner/functionAnalysis.js';

const SHORT = { filePath: 'short.js' };
const nameOf = (arr) => arr.map((f) => f.name);

// ── 1. Function extraction ───────────────────────────────────────────────────

test('extracts named function declarations', () => {
  const fns = extractFunctions('function findUser(id){ return id; }\nfunction a(){}\nfunction b(){}', SHORT);
  assert.deepEqual(nameOf(fns), ['findUser', 'a', 'b']);
  const findUser = fns[0];
  assert.equal(findUser.type, 'declaration');
  assert.equal(findUser.isAsync, false);
  assert.deepEqual(findUser.paramNames, ['id']);
  assert.equal(findUser.location.startLine, 1);
  assert.equal(findUser.location.startCol, 0);
});

test('extracts arrow functions and const/let assigned expressions with names', () => {
  const fns = extractFunctions('const add = (a, b) => a + b;\nconst fetchData = async (url) => url;', SHORT);
  const names = fns.map((f) => `${f.name}:${f.type}:${f.isAsync}`);
  assert.deepEqual(names, ['add:arrow:false', 'fetchData:arrow:true']);
});

test('extracts anonymous function expressions assigned to variables', () => {
  const fns = extractFunctions('const cb = function (x) { return x; };', SHORT);
  assert.equal(fns.length, 1);
  assert.equal(fns[0].name, 'cb');
  assert.equal(fns[0].type, 'expression');
  assert.deepEqual(fns[0].paramNames, ['x']);
});

test('extracts object and class methods preserving names', () => {
  const fns = extractFunctions(
    'const o = { getUser(id){ return id; }, async del(id){ return id; } };\n' +
    'class C { find(x){ return x; } static create(){ return null; } }',
    SHORT
  );
  assert.deepEqual(nameOf(fns), ['getUser', 'del', 'find', 'create']);
});

test('extracts nested functions (inner included alongside outer)', () => {
  const fns = extractFunctions('function outer(){ function inner(){ return 1; } return inner; }', SHORT);
  assert.deepEqual(nameOf(fns), ['outer', 'inner']);
});

test('extracts IIFE and callback function expressions', () => {
  const fns = extractFunctions('(function(){ boot(); })();\nsetTimeout(function tick(){}, 100);', SHORT);
  const names = nameOf(fns).sort();
  assert.ok(names.includes('tick'), 'named callback function should be found');
});

test('handles zero-function and whitespace-only input', () => {
  assert.deepEqual(extractFunctions('const x = 5;'), []);
  assert.deepEqual(extractFunctions('   \n  '), []);
});

// ── 2. Parameter handling ────────────────────────────────────────────────────

test('captures destructuring, defaults, and rest parameters', () => {
  const fns = extractFunctions(
    'function a({ name, age = 0 }){}\nfunction b(...nums){}\nfunction c(x){}\nfunction d({ x: { y } }){}',
    SHORT
  );
  assert.ok(fns[0].paramNames.some((p) => p.startsWith('{')), 'object destructuring param');
  assert.ok(fns[1].paramNames.some((p) => p.startsWith('...')), 'rest param');
  assert.ok(fns[0].params.some((p) => p.type === 'object-destructure'));
  assert.ok(fns[1].params.some((p) => p.type === 'rest'));
});

// ── 3. Function summaries ────────────────────────────────────────────────────

test('summary captures returns, calls, and direct sinks', () => {
  const code = 'function route(id){ return db.query(id); }';
  const fns = extractFunctions(code, SHORT);
  const sum = buildFunctionSummary(fns[0], code);
  assert.ok(sum.returns.includes('call-return'));
  assert.ok(sum.calls.some((c) => c.calleeName === 'db.query'));
  assert.ok(sum.sinks.some((s) => s.type === 'sql-query'));
});

test('summary captures user-input sources structurally (no verdict)', () => {
  const code = 'function go(){ const id = req.query.id; return db.query(id); }';
  const fns = extractFunctions(code, SHORT);
  const sum = buildFunctionSummary(fns[0], code);
  assert.ok(sum.sources.length > 0, 'should record req.query source structurally');
});

test('summary excludes nested function bodies from outer summary', () => {
  const code = 'function outer(){ function inner(){ db.query(1); } return 1; }';
  const fns = extractFunctions(code, SHORT);
  assert.equal(fns.length, 2);
  const outer = buildFunctionSummary(fns[0], code);
  const inner = buildFunctionSummary(fns[1], code);
  assert.ok(!outer.calls.some((c) => c.calleeName.includes('query')), 'outer should not include inner call');
  assert.ok(inner.calls.some((c) => c.calleeName.includes('query')), 'inner should include its own call');
});

// ── 4. Call-site extraction ──────────────────────────────────────────────────

test('extracts call sites and attributes to correct caller function', () => {
  const code = 'function route(id){ return findUser(id); }\nfunction findUser(id){ return db.users.find({id}); }';
  const c = extractCalls(code, extractFunctions(code, SHORT), SHORT.filePath);
  const routeCall = c.find((x) => x.calleeName === 'findUser');
  assert.ok(routeCall, 'should find direct call findUser');
  assert.ok(routeCall.callerFunctionId.includes('route'));
  const dbCall = c.find((x) => x.calleeName === 'db.users.find');
  assert.ok(dbCall);
  assert.ok(dbCall.callerFunctionId.includes('findUser'));
});

test('marks top-level (non-function-scoped) calls with null caller', () => {
  const code = 'bootstrap();\nfunction setup(){ go(); }';
  const c = extractCalls(code, extractFunctions(code, SHORT), SHORT.filePath);
  const top = c.find((x) => x.calleeName === 'bootstrap');
  assert.equal(top.callerFunctionId, null);
  const inner = c.find((x) => x.calleeName === 'go');
  assert.ok(inner.callerFunctionId.includes('setup'));
});

test('resolves member-expression callee names to dotted form', () => {
  const code = 'function f(){ return obj.method(); }';
  const c = extractCalls(code, extractFunctions(code, SHORT), SHORT.filePath);
  assert.equal(c[0].calleeName, 'obj.method');
});

test('extractCalls safe on malformed input', () => {
  assert.deepEqual(extractCalls('function {{{'), []);
  assert.deepEqual(extractCalls(''), []);
  assert.deepEqual(extractCalls(null), []);
});

// ── 5. Conservative callee resolution ────────────────────────────────────────

test('resolveCallee resolves direct identifier calls to local functions', () => {
  const fns = extractFunctions('function findUser(){}\nfunction saveUser(){}', SHORT);
  const res = resolveCallee({ calleeName: 'findUser' }, fns);
  assert.equal(res && res.name, 'findUser');
});

test('resolveCallee does NOT resolve member/dotted calls (cannot confirm binding)', () => {
  const fns = extractFunctions('function findUser(){}', SHORT);
  assert.equal(resolveCallee({ calleeName: 'obj.findUser' }, fns), null);
  assert.equal(resolveCallee({ calleeName: 'this.run' }, fns), null);
});

test('resolveCallee returns null for unknown/external callees', () => {
  const fns = extractFunctions('function local(){}', SHORT);
  assert.equal(resolveCallee({ calleeName: 'fetch' }, fns), null);
  assert.equal(resolveCallee({ calleeName: 'unresolved' }, fns), null);
  assert.equal(resolveCallee({}, fns), null);
});

// ── 6. Call graph ────────────────────────────────────────────────────────────

test('builds deterministic intra-file call graph nodes and edges', () => {
  const code = 'function a(){ return b(); }\nfunction b(){ return c(); }\nfunction c(){ return 1; }';
  const r = analyzeFile(code, SHORT);
  assert.equal(r.callGraph.nodes.length, 3);
  const a2b = r.callGraph.edges.find((e) => e.from.includes('a') && e.to.includes('b'));
  const b2c = r.callGraph.edges.find((e) => e.from.includes('b') && e.to.includes('c'));
  assert.ok(a2b, 'edge a->b');
  assert.ok(b2c, 'edge b->c');
});

test('emits external edges for unresolved callees', () => {
  const code = 'function f(){ return fetch(url); }';
  const r = analyzeFile(code, SHORT);
  const ext = r.callGraph.edges.find((e) => e.to.startsWith('external:'));
  assert.ok(ext, 'should have an external edge');
  assert.equal(ext.to, 'external:fetch');
  assert.equal(ext.external, true);
});

test('recursion/cycles terminate and produce finite graphs', () => {
  const code = 'function fact(n){ return n <= 1 ? 1 : n * fact(n - 1); }\nfunction a(){ return b(); }\nfunction b(){ return a(); }';
  const r = analyzeFile(code, SHORT); // must not hang
  assert.ok(r.callGraph.edges.length >= 2);
});

test('call graph is deterministic across repeated runs', () => {
  const code = 'function a(){ return b(); }\nfunction b(){ return a(); }';
  const g1 = analyzeFile(code, SHORT).callGraph;
  const g2 = analyzeFile(code, SHORT).callGraph;
  assert.deepEqual(g1, g2);
});


// ── 7. Reachability ──────────────────────────────────────────────────────────

test('reachableFrom returns all transitively reachable nodes and stops cycles', () => {
  const graph = {
    nodes: [{ id: 'a' }, { id: 'b' }, { id: 'c' }],
    edges: [
      { from: 'a', to: 'b' },
      { from: 'b', to: 'c' },
      { from: 'c', to: 'a' }, // cycle back
    ],
  };
  const reached = reachableFrom('a', graph);
  assert.deepEqual(reached, ['b', 'c']);
});

test('reachableFrom handles unknown node and empty graph', () => {
  assert.deepEqual(reachableFrom('missing', { nodes: [], edges: [] }), []);
  assert.deepEqual(reachableFrom('x', { edges: [] }), []);
  assert.deepEqual(reachableFrom('x', null), []);
});

// ── 8. Robustness & safety ───────────────────────────────────────────────────

test('analyzeFile never throws on malformed / hostile input', () => {
  for (const bad of ['function {{{ {', '))))', 'const =', '', null, undefined, 42]) {
    assert.doesNotThrow(() => analyzeFile(bad, SHORT));
    const r = analyzeFile(bad, SHORT);
    assert.ok(r, 'analysis should return an object');
    assert.ok(Array.isArray(r.functions));
    assert.ok(Array.isArray(r.calls));
    assert.ok(r.callGraph && Array.isArray(r.callGraph.nodes));
    assert.ok(r.callGraph && Array.isArray(r.callGraph.edges));
  }
});

test('shadowing is handled conservatively (parameter shadows outer function)', () => {
  const code = 'function findUser(id){ return id; }\nfunction wrapper(findUser){ return findUser(1); }';
  const r = analyzeFile(code, SHORT);
  const wrapper = r.functions.find((f) => f.name === 'wrapper');
  const call = r.calls.find((c) => c.callerFunctionId === wrapper.id && c.calleeName === 'findUser');
  assert.ok(call);
  const edge = r.callGraph.edges.find((e) => e.from === wrapper.id);
  assert.ok(!edge || edge.to.startsWith('external:'), 'shadowed call must be unresolved/external');
});

test('extraction and analysis are deterministic (stable ordering)', () => {
  const code = 'const z = (a) => a;\nfunction b(){}\nconst m = { go(){} };';
  const first = extractFunctions(code, SHORT);
  const second = extractFunctions(code, SHORT);
  assert.deepEqual(first.map((f) => f.id), second.map((f) => f.id));
});

test('version constant is exported', () => {
  assert.equal(typeof FUNCTION_ANALYSIS_VERSION, 'string');
  assert.ok(FUNCTION_ANALYSIS_VERSION.length > 0);
});

// ── 9. Fixture integration (structural, not vulnerability proofs) ────────────

test('analyzes all interprocedural fixtures without throwing and identifies functions', async () => {
  const fs = await import('node:fs');
  const path = await import('node:path');
  const dir = path.join(process.cwd(), 'tests', 'security-fixtures', 'interprocedural');
  const files = fs.readdirSync(dir).filter((f) => f.endsWith('.js'));
  assert.ok(files.length >= 12, `expected >=12 fixtures, got ${files.length}`);
  for (const file of files) {
    const code = fs.readFileSync(path.join(dir, file), 'utf8');
    assert.doesNotThrow(() => analyzeFile(code, { filePath: file }));
  }
  const nonEmpty = files.filter((f) => !f.includes('malformed'));
  for (const file of nonEmpty) {
    const code = fs.readFileSync(path.join(dir, file), 'utf8');
    const r = analyzeFile(code, { filePath: file });
    assert.ok(r.functions.length > 0, `${file} should contain functions`);
  }
});

