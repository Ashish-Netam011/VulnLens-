/**
 * Function Analysis Module (Phase 5A).
 *
 * Provides a deterministic, intra-file foundation for interprocedural analysis:
 *   1. Function extraction (declarations, expressions, arrows, methods, async)
 *   2. Function summaries (parameters, returns, sinks, calls — structural only)
 *   3. Call-site extraction (direct, member, nested, callback, conditional, loop)
 *   4. Deterministic intra-file call graph (nodes = functions, edges = caller -> callee)
 *
 * This module is PURE and DETERMINISTIC. It does NOT:
 *   - Treat function calls as proof of vulnerability
 *   - Perform taint propagation across function boundaries
 *   - Modify verdict engine semantics
 *   - Resolve cross-file imports
 *   - Make AI/LLM decisions
 *
 * Callee resolution is conservative: ambiguous or external calls are marked
 * "unresolved" rather than guessed. Recursion/cycles are handled via visited
 * sets and cannot hang analysis. Malformed source never crashes (returns []).
 */
import { parseJS } from './ast.js';

// ── Node helpers ─────────────────────────────────────────────────────────────

function isFunctionNode(node) {
  if (!node || !node.type) return false;
  return (
    node.type === 'FunctionDeclaration' ||
    node.type === 'FunctionExpression' ||
    node.type === 'ArrowFunctionExpression'
  );
}

function nodeTextSafe(node, code) {
  if (!node || typeof node.start !== 'number' || typeof node.end !== 'number') return '';
  return String(code || '').slice(node.start, node.end).slice(0, 200);
}

function propertyNameOfMember(node) {
  if (!node) return null;
  if (node.computed && node.property) {
    return node.property.type === 'Literal' ? String(node.property.value) : null;
  }
  return node.property && node.property.type === 'Identifier' ? node.property.name : null;
}

function nodeName(node) {
  if (!node) return '';
  if (node.type === 'Identifier') return node.name;
  if (node.type === 'Literal') return String(node.value);
  return '';
}

// ── Walk the whole tree, visiting every node depth-first once ────────────────
// Visits ALL nodes, including inside function bodies (so calls/sinks/returns are
// found), and keeps descending so nested functions are also reached.

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

// ── 1. Function extraction ───────────────────────────────────────────────────

function makeFunctionId(node, filePath) {
  let type;
  let name;
  if (node.type === 'FunctionDeclaration') {
    type = 'function';
    name = (node.id && node.id.name) || '_anonymous';
  } else if (node.type === 'FunctionExpression') {
    type = 'function-expr';
    name = (node.id && node.id.name) || '_anonymous';
  } else {
    type = 'arrow';
    name = '_anonymous';
  }
  const line = node.loc ? node.loc.start.line : 0;
  const col = node.loc ? node.loc.start.column : 0;
  const base = `${type}:${name}:${line}:${col}`;
  return filePath ? `${filePath}:${base}` : base;
}

function getFunctionType(node) {
  if (node.type === 'ArrowFunctionExpression') return 'arrow';
  if (node.type === 'FunctionDeclaration') return 'declaration';
  return 'expression';
}

function extractParameter(node, code) {
  if (!node) return { type: 'unknown', name: '' };
  switch (node.type) {
    case 'Identifier':
      return { type: 'identifier', name: node.name };
    case 'RestElement':
      return {
        type: 'rest',
        name: node.argument && node.argument.type === 'Identifier' ? node.argument.name : '',
        argument: extractParameter(node.argument, code),
      };
    case 'AssignmentPattern':
      return {
        type: 'default',
        name: node.left && node.left.type === 'Identifier' ? node.left.name : '',
        default: nodeTextSafe(node.right, code),
        left: extractParameter(node.left, code),
      };
    case 'ObjectPattern':
      return {
        type: 'object-destructure',
        properties: (node.properties || []).map((p) => ({
          key: p.value ? nodeName(p.key) : nodeName(p.argument),
          value: p.value ? extractParameter(p.value, code) : null,
        })),
      };
    case 'ArrayPattern':
      return {
        type: 'array-destructure',
        elements: (node.elements || []).map((el) =>
          el ? extractParameter(el, code) : null
        ),
      };
    case 'Property':
      return {
        type: 'property',
        key: nodeName(node.key),
        value: extractParameter(node.value, code),
      };
    default:
      return { type: 'unknown', name: '' };
  }
}

function paramDisplayName(p) {
  if (!p) return '';
  switch (p.type) {
    case 'identifier': return p.name;
    case 'rest': return `...${p.name}`;
    case 'default': return p.left ? paramDisplayName(p.left) : p.name;
    case 'object-destructure': return `{${(p.properties || []).map((x) => x.key).join(',')}}`;
    case 'array-destructure': return `[${(p.elements || []).map((e) => (e ? paramDisplayName(e) : '')).join(',')}]`;
    default: return p.name || '';
  }
}



function describeFunction(node, code, filePath) {
  let name = '_anonymous';
  if (node.id && node.id.name) {
    name = node.id.name;
  } else {
    // Anonymous: try to name it from the enclosing property/method context.
    const methodName = detectMethodName(node, code);
    if (methodName) name = methodName;
  }

  const params = (node.params || []).map((p) => extractParameter(p, code));
  const loc = node.loc || {};
  return {
    id: makeFunctionId(node, filePath),
    name,
    type: getFunctionType(node),
    params,
    paramNames: params.map(paramDisplayName),
    location: {
      startLine: loc.start ? loc.start.line : null,
      startCol: loc.start ? loc.start.column : null,
      endLine: loc.end ? loc.end.line : null,
      endCol: loc.end ? loc.end.column : null,
      start: node.start,
      end: node.end,
    },
    bodyRange: {
      start: node.body ? node.body.start : null,
      end: node.body ? node.body.end : null,
    },
    isAsync: !!node.async,
  };
}

/**
 * Find a human-meaningful name for an anonymous function by scanning the AST
 * for a Property / MethodDefinition whose value IS this function node.
 */
function detectMethodName(fnNode, code) {
  const ast = parseJS(code);
  if (!ast) return '';
  const s = fnNode.start;
  const e = fnNode.end;
  let result = '';
  walkAST(ast, (n) => {
    if (result) return;
    // Match by location identity (=== would fail because we re-parsed).
    const matches = (n.type === 'Property' || n.type === 'PropertyDefinition')
      && n.value && n.value.start === s && n.value.end === e && n.key;
    const methodMatch = n.type === 'MethodDefinition'
      && n.value && n.value.start === s && n.value.end === e && n.key;
    const varMatch = n.type === 'VariableDeclarator'
      && n.init && n.init.start === s && n.init.end === e && n.id;
    if (matches || methodMatch || varMatch) {
      result = nodeName(n.key || n.id);
    }
  });
  return result;
}

/**
 * Extract all functions from a source string. Deterministic, returns [] on
 * parse failure (never throws).
 *
 * @param {string} code
 * @param {{filePath?: string}} [opts]
 * @returns {Array<object>}
 */
export function extractFunctions(code, opts = {}) {
  const ast = parseJS(code);
  if (!ast || !ast.body) return [];
  const filePath = opts.filePath || '';
  const functions = [];
  walkAST(ast, (node) => {
    if (!isFunctionNode(node)) return;
    functions.push(describeFunction(node, code, filePath));
  });
  return functions;
}

// ── 2. Function summaries ───────────────────────────────────────────────────

/**
 * Build a deterministic structural summary of a function. Describes what
 * happens INSIDE the function (data-flow capability), never a vulnerability
 * verdict. No taint claims are made.
 */
export function buildFunctionSummary(fn, code) {
  if (!fn || typeof code !== 'string') return null;
  const ast = parseJS(code);
  if (!ast) return null;

  const summary = {
    functionId: fn.id,
    name: fn.name,
    parameters: fn.params.map((p) => ({ name: paramDisplayName(p), type: p.type })),
    returns: [],
    sinks: [],
    sources: [],
    calls: [],
  };

  // Locate this function's AST node, then walk ONLY its immediate body.
  let fnNode = null;
  walkAST(ast, (n) => {
    if (fnNode) return;
    if (isFunctionNode(n) && n.body && n.body.start === (fn.bodyRange || {}).start) {
      fnNode = n;
    }
  });
  if (fnNode && fnNode.body) {
    if (fnNode.body.type === 'BlockStatement') {
      walkStmts(fnNode.body.body || [], summary, code);
    } else {
      // Expression-bodied arrow: (id) => expr
      walkExpr(fnNode.body, summary, code);
    }
  }

  summary.returns = dedupe(summary.returns);
  summary.sinks = dedupeKeys(summary.sinks, 'type');
  summary.sources = dedupeKeys(summary.sources, 'expression');
  summary.calls = dedupeKeys(summary.calls, 'calleeExpression');
  return summary;
}

function walkStmts(stmts, summary, code) {
  for (const s of stmts || []) walkStmt(s, summary, code);
}

function walkStmt(s, summary, code) {
  if (!s || typeof s !== 'object') return;
  switch (s.type) {
    case 'ReturnStatement':
      summary.returns.push(describeReturn(s.argument, summary, code));
      walkExpr(s.argument, summary, code);
      break;
    case 'ExpressionStatement':
      walkExpr(s.expression, summary, code);
      break;
    case 'VariableDeclaration':
      for (const d of s.declarations || []) {
        if (isFunctionNode(d.init)) continue; // nested function, not in this summary
        walkExpr(d.init, summary, code);
      }
      break;
    case 'BlockStatement':
      walkStmts(s.body, summary, code);
      break;
    case 'IfStatement':
      if (s.test) walkExpr(s.test, summary, code);
      walkStmt(s.consequent, summary, code);
      walkStmt(s.alternate, summary, code);
      break;
    case 'ForStatement':
    case 'WhileStatement':
    case 'DoWhileStatement':
      if (s.test) walkExpr(s.test, summary, code);
      walkStmt(s.body, summary, code);
      break;
    case 'ForInStatement':
    case 'ForOfStatement':
      walkStmt(s.body, summary, code);
      break;
    case 'TryStatement':
      walkStmts(s.block ? s.block.body : [], summary, code);
      if (s.handler && s.handler.body) walkStmts(s.handler.body.body || [], summary, code);
      if (s.finalizer) walkStmts(s.finalizer.body || [], summary, code);
      break;
    case 'SwitchStatement':
      for (const c of s.cases || []) walkStmts(c.consequent || [], summary, code);
      break;
    default:
      break;
  }
}

function walkExpr(e, summary, code) {
  if (!e || typeof e !== 'object') return;
  if (isFunctionNode(e)) return; // nested function: excluded from this summary
  // Structural source detection at any expression depth (no taint claim).
  if (e.type === 'MemberExpression') {
    const src = userInputExpression(e);
    if (src) summary.sources.push({ expression: src });
  }
  if (e.type === 'CallExpression') {
    const call = describeCall(e, summary.functionId, code);
    if (call) summary.calls.push({ calleeName: call.calleeName, calleeExpression: call.calleeExpression });
    const st = identifySinkType(e);
    if (st) summary.sinks.push({ type: st, expression: call ? call.calleeExpression : '' });
    for (const a of e.arguments || []) {
      const source = userInputExpression(a);
      if (source) summary.sources.push({ expression: source });
    }
    for (const a of e.arguments || []) walkExpr(a, summary, code);
    walkExpr(e.callee, summary, code);
    return;
  }
  for (const key of Object.keys(e)) {
    if (key === 'type' || key === 'start' || key === 'end' || key === 'loc' || key === 'range') continue;
    const c = e[key];
    if (Array.isArray(c)) {
      for (const item of c) walkExpr(item, summary, code);
    } else if (c && typeof c === 'object' && c.type) {
      walkExpr(c, summary, code);
    }
  }
}

function describeReturn(arg, summary, code) {
  if (!arg) return 'void';
  const paramNames = new Set(summary.parameters.map((p) => p.name));
  switch (arg.type) {
    case 'Identifier':
      return paramNames.has(arg.name) ? `parameter:${arg.name}` : `variable:${arg.name}`;
    case 'Literal':
      return 'constant';
    case 'BinaryExpression':
      return 'transformed';
    case 'CallExpression':
      return 'call-return';
    case 'MemberExpression':
      return 'member-access';
    case 'TemplateLiteral':
      return 'transformed';
    default:
      return nodeTextSafe(arg, code).slice(0, 60) ? 'expression' : 'expression';
  }
}

function describeCall(node, callerId, code) {
  const calleeName = resolveCalleeName(node);
  const calleeExpression = nodeTextSafe(node.callee, code);
  return {
    calleeName,
    calleeExpression,
  };
}

function dedupe(arr) {
  return [...new Set(arr.filter((x) => x != null))];
}
function dedupeKeys(arr, key) {
  const seen = new Set();
  return arr.filter((x) => {
    const k = x ? x[key] : null;
    if (k == null || seen.has(k)) return false;
    seen.add(k);
    return true;
  });
}

// ── 3. Call-site extraction ──────────────────────────────────────────────────

/**
 * Extract all call sites in a source string, attributing each to its enclosing
 * function when one exists. Deterministic; [] on parse failure.
 *
 * @param {string} code
 * @param {Array<object>} [functions]  Optional function descriptors.
 * @param {string} [filePath]
 * @returns {Array<object>}
 */
export function extractCalls(code, functions = [], filePath = '') {
  const ast = parseJS(code);
  if (!ast || !ast.body) return [];

  // Build a location -> functionId index for attribution (deterministic).
  const calls = [];
  const fnById = new Map(functions.map((f) => [f.id, f]));
  const fnByRange = functions.filter((f) => f.bodyRange).map((f) => ({ f, start: f.bodyRange.start, end: f.bodyRange.end }));

  walkAST(ast, (node) => {
    if (node.type !== 'CallExpression') return;
    const callerId = attributeCall(node, fnByRange);
    const call = describeCall(node, callerId, code);
    const args = (node.arguments || []).map((a) => ({
      type: a ? a.type : 'unknown',
      text: nodeTextSafe(a, code),
    }));
    calls.push({
      callerFunctionId: callerId,
      calleeName: call.calleeName,
      calleeExpression: call.calleeExpression,
      arguments: args,
      location: {
        line: node.loc ? node.loc.start.line : null,
        col: node.loc ? node.loc.start.column : null,
      },
      filePath,
      optional: !!node.optional,
    });
  });

  // Deterministic ordering: sort by location, then calleeName.
  calls.sort((a, b) => {
    const la = a.location.line || 0;
    const lb = b.location.line || 0;
    if (la !== lb) return la - lb;
    return a.calleeName.localeCompare(b.calleeName);
  });
  return calls;
}

function attributeCall(node, byRange) {
  // The call's start must be inside a function's bodyRange; pick the smallest
  // containing function (innermost). Deterministic: prefers earlier start.
  let owner = null;
  let ownerStart = Infinity;
  for (const { f, start, end } of byRange) {
    if (start != null && end != null && node.start >= start && node.start <= end) {
      // A range with an earlier start is an outer function; we want innermost,
      // i.e. the smallest range (largest start) that contains the call.
      if (start > ownerStart || owner === null) {
        owner = f;
        ownerStart = start;
      }
    }
  }
  return owner ? owner.id : null;
}
// ── 4. Callee resolution ─────────────────────────────────────────────────────

/**
 * Resolve a call's callee to a local function descriptor, conservatively.
 * Direct identifier calls resolve to an exact-name local function.
 * Member/this/computed calls ALWAYS return null (we cannot confirm binding).
 * Unresolved is never returned by this function; it returns the function
 * descriptor or null.
 */
export function resolveCallee(call, functions) {
  const name = call && call.calleeName;
  if (!name || name === 'unresolved') return null;
  if (name.includes('.')) return null;  // member / this — cannot confirm binding

  const fnMap = new Map(functions.map((f) => [f.name, f]));
  return fnMap.get(name) || null;
}

/**
 * Reconstruct a full dotted path for a (possibly nested) member expression.
 * Returns null when any hop is computed/non-resolvable.
 */
function memberPath(node) {
  if (!node) return null;
  switch (node.type) {
    case 'Identifier':
      return node.name;
    case 'ThisExpression':
      return 'this';
    case 'Literal':
      return String(node.value);
    case 'MemberExpression': {
      const obj = memberPath(node.object);
      const prop = propertyNameOfMember(node);
      if (obj == null || prop == null) return null;
      return `${obj}.${prop}`;
    }
    default:
      return null;
  }
}

/**
 * Extract a callee name descriptor from a call node.
 * Returns 'unresolved' whenever the target cannot be identified deterministically.
 */
function resolveCalleeName(callNode) {
  if (!callNode || !callNode.callee) return 'unresolved';
  const c = callNode.callee;
  switch (c.type) {
    case 'Identifier':
      return c.name;
    case 'MemberExpression': {
      const p = memberPath(c);
      return p == null ? 'unresolved' : p;
    }
    default:
      return 'unresolved';
  }
}

// ── 5. User-input + sink recognition (structural only) ───────────────────────

function userInputExpression(node) {
  if (!node) return null;
  if (node.type === 'MemberExpression') {
    const prop = propertyNameOfMember(node);
    const obj = node.object;
    if (obj) {
      if (obj.type === 'Identifier' && obj.name === 'req' && ['query', 'params', 'body', 'headers', 'cookies'].includes(prop)) {
        return `req.${prop}`;
      }
      const inner = userInputExpression(obj);
      if (inner) return `${inner}.${prop}`;
    }
  }
  if (node.type === 'CallExpression') {
    // e.g. req.query.id — the object may itself be covered above; keep simple.
    return null;
  }
  return null;
}

function identifySinkType(expr) {
  if (!expr || expr.type !== 'CallExpression') return null;
  const base = resolveCalleeName(expr);
  const last = base.includes('.') ? base.slice(base.lastIndexOf('.') + 1) : base;
  const lower = String(base).toLowerCase();

  if (/(^|\.)(query|execute|exec|raw)$/i.test(lower)) return 'sql-query';
  if (/^(exec|execSync|spawn|spawnSync|execFile|fork)$/i.test(last) &&
      /(child-process|\.exec|\.spawn|^exec|^spawn)/i.test(lower)) return 'command';
  if (/(^|\.)(readFile|readFileSync|writeFile|writeFileSync|appendFile|unlink|createReadStream|createWriteStream)$/i.test(lower)) return 'fs';
  if (last === 'eval' || last === 'Function') return 'eval';
  if (/(^|\.)(innerHTML|outerHTML|write|insertAdjacentHTML)$/i.test(lower)) return 'dom';
  return null;
}
// ── 6. Call graph ────────────────────────────────────────────────────────────

/**
 * Build a deterministic intra-file call graph from functions + calls.
 * Returns { nodes, edges }. Edges are caller->callee; unresolved/external
 * callees are represented as "external:<name>" targets. Recursion-safe.
 */
export function buildCallGraph(functions, calls = []) {
  const nodes = functions.map((f) => ({
    id: f.id,
    name: f.name,
    type: f.type,
    location: f.location,
  }));

  const edges = [];
  const seen = new Set();
  const byId = new Map(functions.map((f) => [f.id, f]));

  for (const call of calls) {
    const callerId = call.callerFunctionId;
    if (!callerId) continue; // top-level call, no enclosing function

    // Shadowing: a direct identifier call whose name equals a parameter of the
    // caller resolves to the parameter (shadowing any outer/local function),
    // so we cannot safely bind it to that function → treat as unresolved.
    const caller = byId.get(callerId);
    const shadowed =
      caller &&
      caller.paramNames &&
      caller.paramNames.includes(call.calleeName || '');

    const callee = shadowed ? null : resolveCallee(call, functions);
    const target = callee ? callee.id : `external:${call.calleeName || 'unknown'}`;
    const key = `${callerId}->${target}`;
    if (seen.has(key)) continue;
    seen.add(key);
    edges.push({
      from: callerId,
      to: target,
      external: !callee,
      callSite: {
        calleeName: call.calleeName,
        calleeExpression: call.calleeExpression,
        location: call.location,
      },
    });
  }

  return { nodes, edges };
}

/**
 * Deterministic cycle detection / reachability over the call graph.
 * Uses a visited set so recursion cannot hang. Returns reachable node ids.
 * This is STRUCTURAL only — no taint semantics.
 */
export function reachableFrom(nodeId, callGraph) {
  const result = new Set();
  const visited = new Set();
  const byFrom = new Map();
  for (const e of (callGraph && callGraph.edges) || []) {
    if (!byFrom.has(e.from)) byFrom.set(e.from, []);
    byFrom.get(e.from).push(e);
  }
  const stack = [nodeId];
  while (stack.length) {
    const cur = stack.pop();
    if (visited.has(cur)) continue;
    visited.add(cur);
    if (cur !== nodeId) result.add(cur);
    for (const e of byFrom.get(cur) || []) {
      if (!visited.has(e.to)) stack.push(e.to);
    }
  }
  return [...result].sort();
}

// ── 7. Convenience API ───────────────────────────────────────────────────────

/**
 * Run the complete Phase 5A analysis on a single source file.
 * Returns structural metadata ONLY — never vulnerability verdicts.
 *
 * @param {string} code
 * @param {{filePath?: string}} [opts]
 * @returns {{functions: Array, summaries: Array, calls: Array, callGraph: object}}
 */
export function analyzeFile(code, opts = {}) {
  const filePath = opts.filePath || '';
  const functions = extractFunctions(code, { filePath });
  const summaries = functions
    .map((fn) => buildFunctionSummary(fn, code))
    .filter(Boolean);
  const calls = extractCalls(code, functions, filePath);
  const callGraph = buildCallGraph(functions, calls);
  return { functions, summaries, calls, callGraph };
}

export const FUNCTION_ANALYSIS_VERSION = '5A.0';
