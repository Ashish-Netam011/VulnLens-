/**
 * Phase 5C — Bounded Intra-File Data-Flow Evidence Enrichment.
 *
 * Traces source→sink propagation paths within a single source file, producing
 * additive metadata that describes HOW a user-controlled value could reach a
 * dangerous sink.  This module is:
 *
 *   - PURE: no I/O, no DB, no network, no LLM.
 *   - DETERMINISTIC: identical code + analysis → identical JSON.
 *   - BOUNDED: all arrays and depths are capped; recursion uses visited sets.
 *   - CONSERVATIVE: only six propagation shapes are supported; anything more
 *     complex (destructuring, spread, dynamic properties) is silently skipped.
 *   - ADDITIVE ONLY: never modifies verdict, confidence, severity, riskScore,
 *     score, ruleId, or comparisonKey.
 *
 * Supported propagation shapes:
 *   1. Direct assignment      const x = req.query.id
 *   2. Variable reassignment  x = y  (when y is tainted)
 *   3. Identifier alias       const alias = x  (when x is tainted)
 *   4. Function parameter     f(x) → inside f, param receives x's taint
 *   5. Return value           return x from callee → caller's target is tainted
 *   6. Direct argument        f(source) as a call-site fact (no callee body)
 */
import {
  parseJS, isUserInput, nodeText,
  isQuerySink, isDomSink, isCommandSink, isEvalSink, isFsSink, isDeserializationSink,
} from './ast.js';
import { analyzeFile } from './functionAnalysis.js';

// ── Version & Bounds ───────────────────────────────────────────────────────

export const DATAFLOW_VERSION   = '5C.0';
export const MAX_DF_PATHS       = 20;
export const MAX_DF_DEPTH       = 10;
export const MAX_DF_FACTS       = 500;
export const MAX_DF_VARIABLES   = 500;
export const MAX_DF_FUNCTIONS   = 500;
export const MAX_DF_STATES      = 5000;
export const MAX_DF_SUMMARY_LEN = 500;

// ── Sink Detectors ─────────────────────────────────────────────────────────

const SINK_DETECTORS = [
  { test: (n) => isQuerySink(n),            type: 'sql-query',       argIndex: 0 },
  { test: (n) => isDomSink(n),              type: 'dom',             argIndex: 0 },
  { test: (n) => isCommandSink(n),          type: 'command',         argIndex: 0 },
  { test: (n) => isEvalSink(n),             type: 'eval',            argIndex: 0 },
  { test: (n) => isFsSink(n),               type: 'fs',              argIndex: 0 },
  { test: (n) => isDeserializationSink(n),   type: 'deserialization', argIndex: 0 },
];

// ── AST Helpers ────────────────────────────────────────────────────────────

function walkAST(node, visitor) {
  if (!node || typeof node !== 'object') return;
  visitor(node);
  for (const key of Object.keys(node)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue;
    const child = node[key];
    if (Array.isArray(child)) {
      for (const item of child) {
        if (item && typeof item === 'object' && item.type) walkAST(item, visitor);
      }
    } else if (child && typeof child === 'object' && child.type) {
      walkAST(child, visitor);
    }
  }
}

function lineOf(node) {
  return node && node.loc ? node.loc.start.line : null;
}

function colOf(node) {
  return node && node.loc ? node.loc.start.column : 0;
}

function escapeRegExp(str) {
  return String(str).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function isSimpleIdentifier(node) {
  return node && node.type === 'Identifier' && typeof node.name === 'string';
}

function isFunctionNode(node) {
  return node && (
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression'
  );
}

function resolveCalleeName(node) {
  if (!node || !node.callee) return null;
  if (node.callee.type === 'Identifier') return node.callee.name;
  if (node.callee.type === 'MemberExpression') {
    const prop = node.callee.property;
    if (prop && prop.type === 'Identifier') return prop.name;
    if (prop && node.callee.computed && prop.type === 'Literal') return String(prop.value);
  }
  return null;
}

/** Return the enclosing function id for a given node using the Phase 5A analysis. */
function enclosingFunctionId(node, functions) {
  if (!node || !node.loc || !Array.isArray(functions)) return '';
  const line = node.loc.start.line;
  let best = null;
  let bestSpan = Infinity;
  for (const fn of functions) {
    const loc = fn.location;
    if (line >= loc.startLine && line <= loc.endLine) {
      const span = loc.endLine - loc.startLine;
      if (span < bestSpan) { bestSpan = span; best = fn; }
    }
  }
  return best ? best.id : '';
}

// ── Source & Sink Detection ────────────────────────────────────────────────

function findSources(ast, code) {
  const sources = [];
  const seen = new Set();
  walkAST(ast, (node) => {
    if (isUserInput(node)) {
      const expr = nodeText(node, code);
      const key = lineOf(node) + ':' + expr;
      if (seen.has(key)) return;
      seen.add(key);
      sources.push({ expression: expr, line: lineOf(node) });
    }
  });
  return sources;
}

function findSinks(ast, code) {
  const sinks = [];
  const seen = new Set();
  walkAST(ast, (node) => {
    let sinkType = null;
    let argIndex = 0;
    if (node.type === 'CallExpression') {
      for (const det of SINK_DETECTORS) {
        if (det.test(node)) { sinkType = det.type; argIndex = det.argIndex; break; }
      }
    } else if (node.type === 'AssignmentExpression' && isDomSink(node)) {
      sinkType = 'dom-assign'; argIndex = -1;
    }
    if (sinkType) {
      const key = lineOf(node) + ':' + sinkType;
      if (seen.has(key)) return;
      seen.add(key);
      sinks.push({ type: sinkType, line: lineOf(node), argIndex });
    }
  });
  return sinks;
}

// ── Fact Extraction ────────────────────────────────────────────────────────

/**
 * Extract all data-flow facts from the AST.
 * A "fact" describes: source expressions, sink calls, variable bindings,
 * function parameters, return statements, and call-site arguments.
 */
export function extractDataFlowFacts(ast, code) {
  if (!ast) return { sources: [], sinks: [], bindings: [], params: [], returns: [], callSites: [] };

  const sources  = findSources(ast, code);
  const sinks    = findSinks(ast, code);
  const bindings = [];
  const params   = [];
  const returns  = [];
  const callSites = [];

  const factsSeen = new Set();
  let factCount = 0;

  function addFact(arr, fact) {
    if (factCount >= MAX_DF_FACTS) return;
    const key = fact.kind + ':' + (fact.name || '') + ':' + (fact.line || '');
    if (factsSeen.has(key)) return;
    factsSeen.add(key);
    arr.push(fact);
    factCount++;
  }

  walkAST(ast, (node) => {
    if (factCount >= MAX_DF_FACTS) return;

    // Variable declarations: const/let/var x = expr
    if (node.type === 'VariableDeclaration') {
      for (const decl of node.declarations || []) {
        if (factCount >= MAX_DF_FACTS) break;
        if (decl.id && decl.id.type === 'Identifier' && decl.init) {
          addFact(bindings, {
            kind: 'binding', name: decl.id.name,
            expression: nodeText(decl.init, code),
            expressionType: decl.init.type,
            line: lineOf(decl), column: colOf(decl),
          });
        }
      }
    }

    // Assignment expressions: x = expr
    if (node.type === 'AssignmentExpression' && node.left && node.left.type === 'Identifier' && node.right) {
      addFact(bindings, {
        kind: 'binding', name: node.left.name,
        expression: nodeText(node.right, code),
        expressionType: node.right.type,
        line: lineOf(node), column: colOf(node),
      });
    }

    // Function parameters
    if (isFunctionNode(node) && node.params) {
      for (let i = 0; i < node.params.length; i++) {
        if (factCount >= MAX_DF_FACTS) break;
        const p = node.params[i];
        if (p && p.type === 'Identifier') {
          addFact(params, {
            kind: 'param', name: p.name, index: i,
            line: lineOf(p), column: colOf(p),
          });
        }
      }
    }

    // Return statements
    if (node.type === 'ReturnStatement' && node.argument) {
      addFact(returns, {
        kind: 'return',
        expression: nodeText(node.argument, code),
        expressionType: node.argument.type,
        name: isSimpleIdentifier(node.argument) ? node.argument.name : '',
        line: lineOf(node), column: colOf(node),
      });
    }

    // Call sites: capture arguments and callee
    if (node.type === 'CallExpression') {
      const calleeName = resolveCalleeName(node);
      const args = node.arguments || [];
      for (let i = 0; i < args.length; i++) {
        if (factCount >= MAX_DF_FACTS) break;
        const arg = args[i];
        if (!arg) continue;
        addFact(callSites, {
          kind: 'arg', calleeName: calleeName || '', argumentIndex: i,
          expression: nodeText(arg, code), expressionType: arg.type,
          name: isSimpleIdentifier(arg) ? arg.name : '',
          line: lineOf(arg), column: colOf(arg),
        });
      }
    }
  });

  return { sources, sinks, bindings, params, returns, callSites };
}

// ── Value Propagation ──────────────────────────────────────────────────────

/**
 * Check whether a binding's expression references any tainted variable.
 * Conservative: only exact identifier matches propagate.
 */
function taintedExpression(binding, tainted) {
  if (!binding || !binding.expression) return false;

  if (binding.expressionType === 'Identifier') {
    return tainted.has(binding.expression);
  }

  if (binding.expressionType === 'MemberExpression' || binding.expressionType === 'OptionalMemberExpression') {
    const root = binding.expression.split('.')[0].split('[')[0];
    return tainted.has(root);
  }

  // Template literal / binary expression: check if text contains a tainted name
  if (binding.expressionType === 'TemplateLiteral' || binding.expressionType === 'BinaryExpression') {
    for (const name of tainted) {
      if (binding.expression === name || binding.expression.includes(name + '.') ||
          binding.expression.includes(name + ' ') || binding.expression.startsWith(name + '+')) {
        return true;
      }
    }
    return false;
  }

  // Conservative: do NOT propagate through unknown function calls
  if (binding.expressionType === 'CallExpression') return false;

  return false;
}

/**
 * Given a set of initially-tainted variable names, propagate taint through
 * all bindings using a fixed-point iteration. Pure and bounded.
 */
export function propagateValue(initialNames, facts, opts = {}) {
  const maxStates = opts.maxStates || MAX_DF_STATES;
  const tainted = new Set(initialNames);
  let statesVisited = 0;

  let changed = true;
  while (changed) {
    if (statesVisited >= maxStates) break;
    changed = false;

    for (const b of (facts.bindings || [])) {
      if (statesVisited >= maxStates) break;
      statesVisited++;
      if (tainted.has(b.name)) continue;
      if (taintedExpression(b, tainted)) {
        tainted.add(b.name);
        changed = true;
      }
    }
  }

  return tainted;
}

// ── Source-to-Sink Path Tracing ────────────────────────────────────────────

function findSourceVariableNames(source, bindings) {
  if (!source || !source.expression) return [];
  const names = [];
  const seen = new Set();
  for (const b of bindings) {
    if (seen.has(b.name)) continue;
    if (b.expression === source.expression) {
      names.push(b.name);
      seen.add(b.name);
    } else if (source.expression.startsWith(b.expression + '.') && b.expressionType === 'Identifier') {
      names.push(b.name);
      seen.add(b.name);
    }
  }
  return names;
}

function findParamForArgIndex(argIndex, params) {
  for (const p of params) {
    if (p.index === argIndex) return p.name;
  }
  return null;
}

function findFunctionId(name, functions) {
  if (!name || !Array.isArray(functions)) return '';
  for (const fn of functions) {
    if (fn.name === name) return fn.id;
  }
  return '';
}

/**
 * Attempt to trace a path from a specific source expression to a specific
 * sink. Returns an array of step objects if a path exists, or null.
 */
export function traceSourceToSink(source, sink, facts, functions, opts = {}) {
  const maxDepth = opts.maxDepth || MAX_DF_DEPTH;
  const sourceVarNames = findSourceVariableNames(source, facts.bindings || []);
  const tainted = propagateValue(sourceVarNames, facts);

  const sinkLine = sink.line;
  const sinkArgIdx = sink.argIndex;
  let sinkReached = false;

  // Helper: does `text` contain a tainted variable as a standalone token?
  const containsTainted = (text) => {
    if (!text) return false;
    for (const t of tainted) {
      if (!t) continue;
      if (text === t) return true;
      if (text.startsWith(t + '.') || text.includes(t + '.') || text.includes(t + '[')) return true;
      // Word-boundary match inside a concatenation / template
      if (new RegExp('(^|[^A-Za-z0-9_$])' + escapeRegExp(t) + '($|[^A-Za-z0-9_$])').test(text)) return true;
    }
    return false;
  };

  for (const cs of (facts.callSites || [])) {
    if (cs.line !== sinkLine) continue;
    if (sinkArgIdx >= 0 && cs.argumentIndex !== sinkArgIdx) continue;
    if (cs.name && tainted.has(cs.name)) { sinkReached = true; break; }
    if (containsTainted(cs.expression)) { sinkReached = true; break; }
    if (sinkReached) break;
  }

  if (!sinkReached) {
    for (const cs of (facts.callSites || [])) {
      if (cs.line !== sinkLine) continue;
      if (sinkArgIdx >= 0 && cs.argumentIndex !== sinkArgIdx) continue;
      if (cs.expression && cs.expression.includes(source.expression)) {
        sinkReached = true;
        break;
      }
    }
  }

  if (!sinkReached) return null;

  const steps = [];
  const seen = new Set();

  steps.push({ kind: 'source', name: source.expression, line: source.line });
  seen.add('source:' + source.expression);

  for (const varName of sourceVarNames) {
    if (steps.length >= maxDepth) break;
    if (seen.has('var:' + varName)) continue;
    seen.add('var:' + varName);
    const binding = (facts.bindings || []).find((b) => b.name === varName && b.expression === source.expression);
    if (binding) {
      steps.push({
        kind: 'assignment', name: varName, expression: binding.expression,
        functionId: enclosingFunctionId(binding, functions),
        location: { line: binding.line, column: binding.column },
      });
    }
  }

  for (const b of (facts.bindings || [])) {
    if (steps.length >= maxDepth) break;
    if (!tainted.has(b.name)) continue;
    if (sourceVarNames.includes(b.name)) continue;
    if (seen.has('var:' + b.name)) continue;
    for (const prev of tainted) {
      if (prev === b.name) continue;
      if (b.expression === prev || b.expression.startsWith(prev + '.') || b.expression.includes(prev + '.')) {
        seen.add('var:' + b.name);
        steps.push({
          kind: 'assignment', name: b.name, expression: b.expression,
          functionId: enclosingFunctionId(b, functions),
          location: { line: b.line, column: b.column },
        });
        break;
      }
    }
  }

  for (const cs of (facts.callSites || [])) {
    if (steps.length >= maxDepth) break;
    if (!cs.name || !tainted.has(cs.name)) continue;
    const paramName = findParamForArgIndex(cs.argumentIndex, facts.params || []);
    if (paramName && !seen.has('param:' + paramName)) {
      seen.add('param:' + paramName);
      steps.push({
        kind: 'argument', name: cs.name, calleeName: cs.calleeName,
        argumentIndex: cs.argumentIndex, parameterName: paramName,
        functionId: '', location: { line: cs.line, column: cs.column },
      });
      steps.push({
        kind: 'parameter', name: paramName, calleeName: cs.calleeName,
        functionId: findFunctionId(cs.calleeName, functions),
        location: { line: cs.line, column: cs.column },
      });
    }
  }

  for (const ret of (facts.returns || [])) {
    if (steps.length >= maxDepth) break;
    if (!ret.name || !tainted.has(ret.name)) continue;
    if (seen.has('return:' + ret.name)) continue;
    seen.add('return:' + ret.name);
    steps.push({
      kind: 'return', name: ret.name, expression: ret.expression,
      functionId: enclosingFunctionId(ret, functions),
      location: { line: ret.line, column: ret.column },
    });
  }

  steps.push({ kind: 'sink', name: sink.type, line: sink.line });
  return steps.length >= 2 ? steps : null;
}

// ── Main Analysis ──────────────────────────────────────────────────────────

function extractFunctionsSafe(code, filePath) {
  try {
    const analysis = analyzeFile(code, { filePath: filePath || '' });
    return analysis ? analysis.functions || [] : [];
  } catch {
    return [];
  }
}

function emptyResult() {
  return {
    version: DATAFLOW_VERSION,
    paths: [],
    truncated: false,
    summary: '',
    facts: { sourceCount: 0, sinkCount: 0 },
  };
}

function buildDFSummary(paths) {
  if (paths.length === 0) return 'No data-flow paths detected.';
  const types = [...new Set(paths.map((p) => p.sink.type))];
  const txt = paths.length + ' path(s) from source to sink (' + types.join(', ') + ').';
  return txt.slice(0, MAX_DF_SUMMARY_LEN);
}

/**
 * Run the complete Phase 5C data-flow analysis on a single source file.
 * @param {string} code - source code
 * @param {object} [opts] - { filePath, analysis }
 * @returns {{ version, paths, truncated, summary, facts }}
 */
export function analyzeDataFlow(code, opts = {}) {
  const safeCode = typeof code === 'string' ? code : '';
  if (!safeCode) return emptyResult();

  const ast = parseJS(safeCode);
  if (!ast) return emptyResult();

  const functions = opts.analysis
    ? (opts.analysis.functions || [])
    : extractFunctionsSafe(safeCode, opts.filePath);

  const facts = extractDataFlowFacts(ast, safeCode);
  const { sources, sinks } = facts;

  if (sources.length === 0 || sinks.length === 0) {
    return {
      version: DATAFLOW_VERSION,
      paths: [],
      truncated: false,
      summary: buildDFSummary([]),
      facts: { sourceCount: sources.length, sinkCount: sinks.length },
    };
  }

  const paths = [];
  let truncated = false;

  for (const source of sources) {
    if (paths.length >= MAX_DF_PATHS) { truncated = true; break; }
    for (const sink of sinks) {
      if (paths.length >= MAX_DF_PATHS) { truncated = true; break; }
      const steps = traceSourceToSink(source, sink, facts, functions, { maxDepth: MAX_DF_DEPTH });
      if (steps && steps.length >= 2) {
        paths.push({
          source: { expression: source.expression, line: source.line },
          sink: { type: sink.type, line: sink.line, argIndex: sink.argIndex },
          steps,
          length: steps.length,
          confidence: 'structural-data-flow',
        });
      }
    }
  }

  paths.sort((a, b) => {
    if (a.source.line !== b.source.line) return (a.source.line || 0) - (b.source.line || 0);
    if (a.sink.line !== b.sink.line) return (a.sink.line || 0) - (b.sink.line || 0);
    return a.source.expression.localeCompare(b.source.expression);
  });

  return {
    version: DATAFLOW_VERSION,
    paths: paths.slice(0, MAX_DF_PATHS),
    truncated,
    summary: buildDFSummary(paths),
    facts: {
      sourceCount: sources.length,
      sinkCount: sinks.length,
      bindingCount: (facts.bindings || []).length,
      paramCount: (facts.params || []).length,
      returnCount: (facts.returns || []).length,
      callSiteCount: (facts.callSites || []).length,
    },
  };
}

// ── Safe Wrapper ───────────────────────────────────────────────────────────

/**
 * Safe wrapper around analyzeDataFlow. Returns null on bad input.
 * @param {string} code
 * @param {object} [opts]
 * @returns {object|null}
 */
export function buildDataFlowSafe(code, opts = {}) {
  if (typeof code !== 'string' || code.length === 0) return null;
  try {
    return analyzeDataFlow(code, opts);
  } catch {
    return null;
  }
}
