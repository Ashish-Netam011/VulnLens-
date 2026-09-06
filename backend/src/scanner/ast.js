/**
 * AST utilities for the evidence engine (Phase 4C).
 *
 * Wraps `acorn` (the only parser dependency) and provides deterministic
 * predicates and a small intra-function taint analyzer. Everything here is pure
 * and independent of the verdict/confidence engines, so Phase 4D can evolve the
 * analysis without touching the verdict model.
 *
 * Scope note: taint tracking is INTRA-function only (Phase 4 scope). Function
 * parameters are deliberately NOT treated as attacker-controlled, because
 * confirming that would require cross-procedure analysis (deferred to Phase 5).
 */
import { parse } from 'acorn';

const lineOf = (node) => (node && node.loc ? node.loc.start.line : null);

/** Text of a node via source slicing (positions are robust even when loc is off). */
export function nodeText(node, code) {
  if (!node || typeof node.start !== 'number') return '';
  return String(code || '').slice(node.start, node.end).slice(0, 200);
}

export function parseJS(code) {
  if (!code || typeof code !== 'string') return null;
  try {
    return parse(code, {
      ecmaVersion: 'latest',
      sourceType: 'module',
      locations: true,
      allowHashBang: true,
      allowReturnOutsideFunction: true,
      allowImportExportEverywhere: true,
      allowAwaitOutsideFunction: true,
    });
  } catch {
    return null;
  }
}

function propertyName(member) {
  if (!member) return null;
  if (member.computed && member.property && member.property.type === 'Literal') {
    return String(member.property.value);
  }
  return member.property && member.property.type === 'Identifier' ? member.property.name : null;
}

// ── Source (attacker-controlled input) recognition ───────────────────────────

const REQ_PROPS = new Set(['query', 'params', 'body', 'headers', 'cookies']);
const DOC_PROPS = new Set(['cookie', 'URL', 'referrer']);
const LOC_PROPS = new Set(['search', 'hash', 'href', 'pathname']);

/** True when `node` is a member/call expression denoting user-controlled input. */
export function isUserInput(node) {
  if (!node) return false;

  // req.query / req.params / req.body / req.headers / req.cookies / req.files
  if (node.type === 'MemberExpression') {
    const obj = node.object;
    const prop = propertyName(node);
    if (obj && obj.type === 'Identifier' && obj.name === 'req' && (REQ_PROPS.has(prop) || prop === 'files')) {
      return true;
    }
    // process.argv[n]
    if (
      obj &&
      obj.type === 'MemberExpression' &&
      propertyName(obj) === 'argv' &&
      obj.object &&
      obj.object.type === 'Identifier' &&
      obj.object.name === 'process'
    ) {
      return true;
    }
    // Recursive: window.location.search.x, document.cookie.x, ...
    if (isUserInput(obj)) return true;
  }

  // location.search / location.hash / location.href / location.pathname
  if (node.type === 'MemberExpression') {
    const obj = node.object;
    const prop = propertyName(node);
    if (obj && obj.type === 'Identifier' && obj.name === 'location' && LOC_PROPS.has(prop)) return true;
    if (
      obj &&
      obj.type === 'MemberExpression' &&
      propertyName(obj) === 'location' &&
      obj.object &&
      obj.object.type === 'Identifier' &&
      obj.object.name === 'window'
    ) {
      return true;
    }
  }

  // document.cookie / document.URL / document.referrer
  if (
    node.type === 'MemberExpression' &&
    node.object &&
    node.object.type === 'Identifier' &&
    node.object.name === 'document' &&
    DOC_PROPS.has(propertyName(node))
  ) {
    return true;
  }

  // CallExpression sources: req.get("x"), req.header(...), new URLSearchParams(location.search).get(...)
  if (node.type === 'CallExpression') {
    const callee = node.callee;
    const cprop = propertyName(callee);
    if (
      callee &&
      callee.type === 'MemberExpression' &&
      callee.object &&
      callee.object.type === 'Identifier' &&
      callee.object.name === 'req' &&
      (cprop === 'get' || cprop === 'header' || cprop === 'cookies')
    ) {
      return true;
    }
    const objIsSearchParams =
      callee &&
      callee.type === 'MemberExpression' &&
      callee.object &&
      callee.object.type === 'CallExpression' &&
      callee.object.callee &&
      (propertyName(callee.object.callee) === 'URLSearchParams' || callee.object.callee.name === 'URLSearchParams');
    if (objIsSearchParams) return true;
  }

  return false;
}

// ── Constant / literal recognition ───────────────────────────────────────────

/** True when an expression is a literal or composed only of constants. */
export function isLiteralConstant(node) {
  if (!node) return false;
  switch (node.type) {
    case 'Literal':
      return true;
    case 'TemplateLiteral':
      return node.expressions.length === 0;
    case 'BinaryExpression':
      return isLiteralConstant(node.left) && isLiteralConstant(node.right);
    case 'LogicalExpression':
      return isLiteralConstant(node.left) && isLiteralConstant(node.right);
    case 'UnaryExpression':
      return isLiteralConstant(node.argument);
    case 'ConditionalExpression':
      return isLiteralConstant(node.test) && isLiteralConstant(node.consequent) && isLiteralConstant(node.alternate);
    default:
      return false;
  }
}

/** True when a node represents string concatenation or template interpolation. */
export function isConcatenation(node) {
  if (!node) return false;
  if (node.type === 'TemplateLiteral') return node.expressions.length > 0;
  if (node.type === 'BinaryExpression' && node.operator === '+') return true;
  return false;
}

// ── Sink recognition per category ────────────────────────────────────────────

const QUERY_METHODS = new Set(['query', 'execute', 'raw', 'all', 'get', 'find', 'findOne', 'findById', 'where']);
const DB_OBJECTS = new Set(['db', 'pool', 'connection', 'client', 'sequelize', 'knex', 'pg', 'mysql', 'mongo']);
const SQL_KW = /\b(SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b/i;

export function isQuerySink(call) {
  if (!call || call.type !== 'CallExpression') return false;
  const callee = call.callee;
  const cprop = propertyName(callee);
  if (!QUERY_METHODS.has(cprop)) return false;
  const firstArg = call.arguments && call.arguments[0];
  // Bare query(...) — require SQL keywords so we don't treat any `.get()` as SQL.
  if (!callee || callee.type !== 'MemberExpression') {
    return firstArg ? SQL_KW.test(nodeText(firstArg)) : false;
  }
  const obj = callee.object;
  const objName = obj && obj.type === 'Identifier' ? obj.name : null;
  if (DB_OBJECTS.has(objName)) return true;
  if (firstArg) return SQL_KW.test(nodeText(firstArg));
  return false;
}

const DOM_SINK_PROP = new Set(['innerHTML', 'outerHTML', 'insertAdjacentHTML', 'dangerouslySetInnerHTML']);
const DOM_SINK_CALLS = new Set(['write', 'writeln']);
const JQUERY_HTML = new Set(['html', 'append', 'prepend', 'after', 'before']);

export function isDomSink(node) {
  if (!node) return false;
  if (node.type === 'AssignmentExpression') {
    const left = node.left;
    if (left && left.type === 'MemberExpression' && DOM_SINK_PROP.has(propertyName(left))) return true;
    return false;
  }
  if (node.type === 'CallExpression') {
    const cprop = propertyName(node.callee);
    if (DOM_SINK_CALLS.has(cprop)) return true; // document.write(...)
    if (cprop === 'insertAdjacentHTML') return true;
    if (JQUERY_HTML.has(cprop)) return true;
    return false;
  }
  return false;
}

const CMD_METHODS = new Set(['exec', 'spawn', 'execFile', 'fork', 'execSync', 'spawnSync', 'execFileSync']);
const DESERIALIZE = new Set(['JSON.parse', 'deserialize', 'runInContext', 'runInNewContext', 'runInThisContext']);

export function isCommandSink(call) {
  if (!call || call.type !== 'CallExpression') return false;
  return CMD_METHODS.has(propertyName(call.callee));
}

export function isEvalSink(call) {
  return call && call.type === 'CallExpression' && call.callee && call.callee.type === 'Identifier' && call.callee.name === 'eval';
}

export function isFunctionCtorSink(call) {
  return (
    call &&
    call.type === 'NewExpression' &&
    call.callee &&
    call.callee.type === 'Identifier' &&
    call.callee.name === 'Function'
  );
}

export function isDeserializationSink(call) {
  if (!call || call.type !== 'CallExpression') return false;
  const text = nodeText(call.callee);
  for (const p of DESERIALIZE) {
    if (text.includes(p)) return true;
  }
  return false;
}

const FS_METHODS = new Set([
  'readFile', 'readFileSync', 'writeFile', 'writeFileSync', 'readdir', 'readdirSync',
  'appendFile', 'unlink', 'rename', 'createReadStream', 'createWriteStream', 'open',
  'mkdir', 'rm', 'rmdir', 'stat',
]);

export function isFsSink(call) {
  if (!call || call.type !== 'CallExpression') return false;
  return FS_METHODS.has(propertyName(call.callee));
}

// ── Sanitization / parameterization ──────────────────────────────────────────

const SANITIZERS = [
  'escapeHtml', 'escapeHTML', 'escape', 'sanitize', 'DOMPurify', 'encodeURIComponent',
  'encodeURI', 'htmlEscape', 'xss', 'stripTags', 'purify', 'validator.escape',
  'htmlspecialchars', 'sanitizeHtml', 'sanitizeXSS',
];

export function isSanitizerCall(call, code) {
  if (!call || call.type !== 'CallExpression') return false;
  const text = nodeText(call.callee, code);
  return SANITIZERS.some((s) => s && text.includes(s));
}

/** True when a SQL-ish call is parameterized (placeholder + params array). */
export function isParameterizedQueryCall(call) {
  if (!call || call.type !== 'CallExpression' || !isQuerySink(call)) return false;
  const args = call.arguments || [];
  const first = args[0];
  const firstText = first ? nodeText(first) : '';
  const hasPlaceholder = /[?]|:\w+|\$\d+/.test(firstText.replace(/['"`]/g, ''));
  const hasParamsArg = first && args.length >= 2;
  return hasPlaceholder && hasParamsArg;
}

// ── Technology context ───────────────────────────────────────────────────────

/**
 * Best-effort library/framework/db detection from raw source text.
 * @param {string} code The original source text.
 */
export function detectTechContext(code) {
  const ctx = { framework: null, db: null, libs: [] };
  if (!code || typeof code !== 'string') return ctx;
  const saw = (re, label, key) => {
    if (re.test(code)) {
      if (key === 'framework' || key === 'db') ctx[key] = label;
      else if (!ctx.libs.includes(label)) ctx.libs.push(label);
    }
  };
  saw(/\breq\.\s*(query|params|body|headers|get|header)/, 'express', 'framework');
  saw(/\bexpress\b/, 'express', 'framework');
  saw(/dangerouslySetInnerHTML|React\.|createElement\(/, 'react', 'framework');
  saw(/jQuery|\$\s*\(/, 'jquery', 'framework');
  saw(/\b(sequelize|knex|typeorm)\b/, 'sql', 'db');
  saw(/\b(pg|mysql|mysql2|mariadb|pool)\b/, 'sql', 'db');
  saw(/mongoose|mongodb|\bModel\b/, 'nosql', 'db');
  saw(/child_process|spawn|execFile|execSync/, 'node:child_process', 'libs');
  saw(/\bfs\b/, 'node:fs', 'libs');
  return ctx;
}

// ── Taint expression evaluation ──────────────────────────────────────────────

/**
 * Evaluate the taint status of an expression against a scope environment.
 * Returns { tainted, constant, sanitized, sources: string[], direct }.
 */
export function evaluateExpr(expr, env, code) {
  if (!expr) return emptyState();
  switch (expr.type) {
    case 'Literal':
      return emptyState({ constant: true });
    case 'TemplateLiteral':
      if (expr.expressions.length === 0) return emptyState({ constant: true });
      break;
    default:
      break;
  }
  switch (expr.type) {
    case 'Identifier': {
      const st = env.get(expr.name);
      return st ? { ...st } : emptyState();
    }
    case 'MemberExpression': {
      if (isUserInput(expr)) {
        return { tainted: true, constant: false, sanitized: false, sources: [nodeText(expr, code)], direct: true };
      }
      const obj = evaluateExpr(expr.object, env, code);
      return { tainted: obj.tainted, constant: false, sanitized: false, sources: obj.sources, direct: false };
    }
    case 'TemplateLiteral': {
      let tainted = false; let allConst = true; const sources = [];
      for (const e of expr.expressions) {
        const s = evaluateExpr(e, env, code);
        if (s.tainted) { tainted = true; sources.push(...s.sources); }
        if (!s.constant) allConst = false;
      }
      return { tainted, constant: allConst && !tainted, sanitized: false, sources, direct: false };
    }
    case 'BinaryExpression': {
      const l = evaluateExpr(expr.left, env, code);
      const r = evaluateExpr(expr.right, env, code);
      return {
        tainted: l.tainted || r.tainted,
        constant: l.constant && r.constant,
        sanitized: !!(l.sanitized || r.sanitized),
        sources: [...l.sources, ...r.sources],
        direct: false,
      };
    }
    case 'CallExpression': {
      if (isSanitizerCall(expr, code)) return emptyState({ sanitized: true });
      let tainted = false; const sources = [];
      for (const a of expr.arguments || []) {
        const s = evaluateExpr(a, env, code);
        if (s.tainted) { tainted = true; sources.push(...s.sources); }
      }
      return { tainted, constant: false, sanitized: false, sources, direct: false };
    }
    default:
      return genericTaint(expr, env, code);
  }
}

function genericTaint(node, env, code) {
  let tainted = false; const sources = []; const stack = [node];
  while (stack.length) {
    const n = stack.pop();
    if (!n || typeof n !== 'object') continue;
    if (n.type && isUserInput(n)) { tainted = true; sources.push(nodeText(n, code)); continue; }
    if (n.type === 'Identifier' && env.has(n.name)) {
      const st = env.get(n.name);
      if (st && st.tainted) { tainted = true; sources.push(...(st.sources || [])); }
      continue;
    }
    if (n.type === 'CallExpression' && isSanitizerCall(n, code)) continue; // sanitizer blocks taint
    for (const k of Object.keys(n)) {
      if (k === 'loc' || k === 'start' || k === 'end' || k === 'range' || k === 'sourceType') continue;
      const v = n[k];
      if (Array.isArray(v)) v.forEach((x) => stack.push(x));
      else if (v && typeof v === 'object') stack.push(v);
    }
  }
  return { tainted, constant: false, sanitized: false, sources, direct: false };
}

function emptyState(over = {}) {
  return { tainted: false, constant: false, sanitized: false, sources: [], direct: false, ...over };
}

// ── TaintAnalyzer (intra-function, sequential walk) ─────────────────────────

/**
 * Lightweight taint-analyzer that walks the AST in program order, building a
 * per-scope environment and collecting sink call-sites. Parameters are NEVER
 * marked tainted (cross-proc deferred to Phase 5).
 *
 * @param {string} code   The original source text.
 * @param {string|null} category  'sql'|'xss'|'command'|'file'|null (all).
 * @returns {{ ast, env: Map, sinks: SinkInfo[], techContext }}
 */
export function analyzeTaint(code, category) {
  const ast = parseJS(code);
  if (!ast) return { ast: null, env: new Map(), sinks: [], techContext: detectTechContext('') };
  const env = new Map();
  const sinks = [];
  walkStmts(ast.body, env, sinks, category, code);
  const techContext = detectTechContext(code);
  return { ast, env, sinks, techContext };
}

function walkStmts(stmts, env, sinks, category, code) {
  if (!Array.isArray(stmts)) return;
  for (const s of stmts) walkStmt(s, env, sinks, category, code);
}

/**
 * Recursively walk an expression tree looking for arrow functions and function
 * expressions. When found, walk their bodies with the same env so sinks inside
 * callbacks / nested functions are discovered by the taint analyzer.
 *
 * This is intra-function only (same env Map) — no cross-procedure analysis.
 */
function walkNestedFns(expr, env, sinks, category, code) {
  if (!expr || typeof expr !== 'object') return;
  if (expr.type === 'ArrowFunctionExpression' || expr.type === 'FunctionExpression') {
    if (expr.body && expr.body.type === 'BlockStatement' && expr.body.body) {
      walkStmts(expr.body.body, env, sinks, category, code);
    } else if (expr.body && expr.type === 'ArrowFunctionExpression') {
      // Arrow with expression body — treat as implicit return for sink collection
      collectSinks(expr.body, env, sinks, category, code);
    }
    return;
  }
  for (const key of Object.keys(expr)) {
    if (key === 'loc' || key === 'start' || key === 'end' || key === 'range' || key === 'sourceType') continue;
    const val = expr[key];
    if (Array.isArray(val)) {
      for (const item of val) {
        if (item && typeof item === 'object') walkNestedFns(item, env, sinks, category, code);
      }
    } else if (val && typeof val === 'object') {
      walkNestedFns(val, env, sinks, category, code);
    }
  }
}

function walkStmt(stmt, env, sinks, category, code) {
  if (!stmt) return;
  switch (stmt.type) {
    case 'VariableDeclaration':
      for (const d of stmt.declarations || []) {
        // Simple: const x = expr
        if (d.id && d.id.type === 'Identifier' && d.init) {
          env.set(d.id.name, evaluateExpr(d.init, env, code));
        }
        // Destructuring: const { a, b } = expr  or  const [a, b] = expr
        if (d.id && (d.id.type === 'ObjectPattern' || d.id.type === 'ArrayPattern') && d.init) {
          const initVal = evaluateExpr(d.init, env, code);
          if (d.id.type === 'ObjectPattern') {
            for (const prop of d.id.properties || []) {
              if (prop.value && prop.value.type === 'Identifier') {
                env.set(prop.value.name, initVal);
              }
            }
          } else {
            for (const el of d.id.elements || []) {
              if (el && el.type === 'Identifier') {
                env.set(el.name, initVal);
              }
            }
          }
        }
        // Walk nested function bodies in the initializer (arrow / fn expression)
        if (d.init) walkNestedFns(d.init, env, sinks, category, code);
      }
      break;
    case 'ExpressionStatement': {
      const expr = stmt.expression;
      if (expr && expr.type === 'AssignmentExpression' && expr.left) {
        if (expr.left.type === 'Identifier') {
          env.set(expr.left.name, evaluateExpr(expr.right, env, code));
        } else if (expr.left.type === 'ObjectPattern') {
          const initVal = evaluateExpr(expr.right, env, code);
          for (const prop of expr.left.properties || []) {
            if (prop.value && prop.value.type === 'Identifier') {
              env.set(prop.value.name, initVal);
            }
          }
        } else if (expr.left.type === 'ArrayPattern') {
          const initVal = evaluateExpr(expr.right, env, code);
          for (const el of expr.left.elements || []) {
            if (el && el.type === 'Identifier') {
              env.set(el.name, initVal);
            }
          }
        }
      }
      collectSinks(expr, env, sinks, category, code);
      walkNestedFns(expr, env, sinks, category, code);
      break;
    }
    case 'ReturnStatement':
      collectSinks(stmt.argument, env, sinks, category, code);
      walkNestedFns(stmt.argument, env, sinks, category, code);
      break;
    case 'IfStatement':
      if (stmt.consequent) walkStmt(stmt.consequent, env, sinks, category, code);
      if (stmt.alternate) walkStmt(stmt.alternate, env, sinks, category, code);
      break;
    case 'BlockStatement':
      walkStmts(stmt.body, env, sinks, category, code);
      break;
    case 'ForStatement':
    case 'WhileStatement':
    case 'DoWhileStatement':
      walkStmts([stmt.body], env, sinks, category, code);
      break;
    case 'ForInStatement':
    case 'ForOfStatement': {
      if (stmt.left && stmt.left.type === 'VariableDeclaration') {
        for (const d of stmt.left.declarations || []) {
          if (d.id && d.id.type === 'Identifier' && stmt.right) {
            env.set(d.id.name, evaluateExpr(stmt.right, env, code));
          }
        }
      }
      if (stmt.body) walkStmt(stmt.body, env, sinks, category, code);
      break;
    }
    case 'SwitchStatement':
      if (stmt.discriminant) walkNestedFns(stmt.discriminant, env, sinks, category, code);
      for (const cs of stmt.cases || []) {
        if (cs.consequent) walkStmts(cs.consequent, env, sinks, category, code);
      }
      break;
    case 'TryStatement':
      if (stmt.block) walkStmt(stmt.block, env, sinks, category, code);
      if (stmt.handler && stmt.handler.body) walkStmt(stmt.handler.body, env, sinks, category, code);
      if (stmt.finalizer) walkStmt(stmt.finalizer, env, sinks, category, code);
      break;
    case 'FunctionDeclaration':
      if (stmt.body && stmt.body.body) walkStmts(stmt.body.body, env, sinks, category, code);
      break;
    default:
      break;
  }
}

function collectSinks(node, env, sinks, category, code) {
  if (!node) return;
  if (node.type === 'CallExpression') {
    const t = matchSinkType(node, category);
    if (t) sinks.push({ line: lineOf(node), node, type: t.type, argIndex: t.argIdx });
  }
  if (node.type === 'AssignmentExpression' && isDomSink(node)) {
    sinks.push({ line: lineOf(node), node, type: 'dom-assign', argIndex: -1 });
  }
}

function matchSinkType(call, category) {
  if (!call || call.type !== 'CallExpression') return null;
  const any = !category;
  if ((any || category === 'sql') && isQuerySink(call)) return { type: 'sql-query', argIdx: 0 };
  if ((any || category === 'xss') && isDomSink(call)) return { type: 'dom', argIdx: 0 };
  if ((any || category === 'command') && isCommandSink(call)) return { type: 'command', argIdx: 0 };
  if ((any || category === 'command') && isEvalSink(call)) return { type: 'eval', argIdx: 0 };
  if ((any || category === 'command') && isDeserializationSink(call)) return { type: 'deserialization', argIdx: 0 };
  if ((any || category === 'file') && isFsSink(call)) return { type: 'fs', argIdx: 0 };
  return null;
}

/**
 * Compute the taint state of a sink's security-relevant argument.
 */
export function sinkArgTaint(sinkInfo, env, code) {
  if (!sinkInfo || !sinkInfo.node) return emptyState();
  const node = sinkInfo.node;
  if (sinkInfo.type === 'dom-assign') {
    return node.right ? evaluateExpr(node.right, env, code) : emptyState();
  }
  const arg = node.arguments && node.arguments[sinkInfo.argIndex];
  return arg ? evaluateExpr(arg, env, code) : emptyState();
}
