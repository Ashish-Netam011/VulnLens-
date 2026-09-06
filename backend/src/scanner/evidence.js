/**
 * Evidence engine (Phase 4C).
 *
 * Builds a machine-readable `evidence` object for every finding by asking the
 * AST taint analyzer what is actually true about the code, then lets the
 * verdict/confidence engines decide. Two paths:
 *
 *   1. TAINT-ANALYZED: injection, XSS, command, file-handling — evidence comes
 *      from a real source→sink analysis of the file.
 *   2. STATIC-CONFIRMED: hardcoded secrets, weak crypto, misconfiguration,
 *      sensitive-data, eval/Function-ctor — the constant data IS the finding,
 *      so there is nothing to disconfirm.
 *
 * Everything here is deterministic and side-effect free.
 */
import { analyzeTaint, sinkArgTaint, isParameterizedQueryCall } from './ast.js';

// ── Routing ────────────────────────────────────────────────────────────────

/** Categories where constant data IS the vulnerability (always CONFIRMED). */
const STATIC_CATEGORIES = new Set([
  'Hardcoded Credentials and Secrets',
  'Weak Cryptographic Practices',
  'Security Misconfiguration',
  'Sensitive Information Exposure',
]);

/** Dangerous-function rules that are already confirmed by their shape alone. */
const STATIC_RULES = new Set(['eval', 'function-ctor', 'regex-dos']);

/** RuleId -> AST analysis category ('sql'|'xss'|'command'|'file'). */
const RULE_AST_CATEGORY = {
  // Injection
  'sql-concat': 'sql',
  'sql-assign-concat': 'sql',
  'sql-template': 'sql',
  'sql-format': 'sql',
  'sql-unprepared': 'sql',
  'nosql-where': 'sql',
  'nosql-operator': 'sql',
  // XSS
  innerhtml: 'xss',
  dangerouslySetInnerHTML: 'xss',
  'document-write': 'xss',
  'eval-html': 'xss',
  'unsafe-href': 'xss',
  'raw-response': 'xss',
  // Dangerous function usage (taint-sensitive subset)
  'child-process': 'command',
  deserialize: 'command',
  'path-traversal': 'file',
  // Insecure file handling
  'file-write-user': 'file',
  'unchecked-file-read': 'file',
};

// ── Evidence builders ──────────────────────────────────────────────────────

/** Evidence for a static-confirmed finding (no taint analysis needed). */
function staticEvidence(finding) {
  return {
    source: { found: null, names: [], direct: false },
    sink: { found: null, matched: null, type: 'static', line: finding.line },
    flow: { established: null, direct: false, sources: [] },
    constantData: true,
    parameterized: false,
    sanitized: false,
    templateOnly: false,
    techContext: {},
    staticConfirmed: true,
    explanation: EXPLAIN.static,
  };
}

/**
 * Choose the sink most relevant to a finding by line proximity (exact first).
 */
function selectSink(sinks, line) {
  if (!sinks || sinks.length === 0) return null;
  const target = line || 0;
  let best = sinks[0];
  let bestDist = Infinity;
  for (const s of sinks) {
    if (s.line === target) return s;
    const d = Math.abs((s.line || 0) - target);
    if (d < bestDist) {
      bestDist = d;
      best = s;
    }
  }
  return best;
}

function dedupe(arr) {
  return [...new Set((arr || []).filter(Boolean))];
}

/**
 * Build the evidence object for a single finding.
 * @param {string} code  Original source text (single file).
 * @param {object} finding  Normalized finding from the rule engine.
 */
export function buildEvidence(code, finding) {
  const { category, ruleId, line } = finding;

  if (STATIC_CATEGORIES.has(category) || STATIC_RULES.has(ruleId)) {
    return sanitizeEvidence(staticEvidence(finding));
  }

  const astCategory = RULE_AST_CATEGORY[ruleId];
  if (!astCategory) {
    // Unmapped rule — hedge conservatively (never a false-confirmation).
    return sanitizeEvidence({
      source: { found: false, names: [], direct: false },
      sink: { found: false, matched: null, type: null, line: null },
      flow: { established: false, direct: false, sources: [] },
      constantData: false,
      parameterized: false,
      sanitized: false,
      templateOnly: false,
      techContext: {},
      staticConfirmed: false,
      explanation: EXPLAIN.noSink,
    });
  }

  const analysis = analyzeTaint(code, astCategory);
  const sink = selectSink(analysis.sinks, line);
  const argTaint = sink
    ? sinkArgTaint(sink, analysis.env, code)
    : { tainted: false, constant: false, sanitized: false, sources: [] };

  // Parameterization only makes sense on a SQL-ish call expression.
  let parameterized = false;
  if (sink && sink.node && sink.node.type === 'CallExpression') {
    parameterized = isParameterizedQueryCall(sink.node);
  }

  const templateOnly = ruleId === 'sql-template' || ruleId === 'sql-unprepared';
  const sources = dedupe(argTaint.sources);

  const evidence = {
    source: { found: argTaint.tainted, names: sources, direct: !!argTaint.direct },
    sink: {
      found: analysis.sinks.length > 0,
      matched: !!sink,
      type: sink ? sink.type : null,
      line: sink ? sink.line : null,
    },
    flow: { established: argTaint.tainted, direct: !!argTaint.direct, sources },
    constantData: !!argTaint.constant,
    parameterized,
    sanitized: !!argTaint.sanitized,
    templateOnly,
    techContext: analysis.techContext,
    staticConfirmed: false,
  };

  evidence.explanation = explainTaint(evidence);
  return sanitizeEvidence(evidence);
}

// ── Evidence size / shape sanitization (Phase 4E) ───────────────────────────

/**
 * Enforce deterministic, safe bounds on an evidence object before it is used by
 * the verdict/confidence engines and ultimately persisted to MongoDB / exposed
 * over the API. Nothing here changes the *semantics* of the evidence (verdicts
 * and confidence are derived from the same boolean/string fields) — it only
 * truncates unbounded arrays and strings so a pathological finding can never
 * balloon the stored document or leak an arbitrarily long source expression.
 *
 * Rules:
 *   - source.names  .  max 8 entries, each max 120 chars
 *   - flow.sources  .  max 8 entries, each max 120 chars
 *   - techContext.libs . max 5 entries, each max 60 chars
 *   - explanation    .  max 500 chars
 * When any truncation happens a boolean `truncated` flag is set on the evidence
 * so consumers/reporting can tell the record was size-capped.
 *
 * @param {object} ev  Evidence object (mutated in place and returned).
 * @returns {object}
 */
export function sanitizeEvidence(ev) {
  if (!ev || typeof ev !== 'object') return ev;

  const capArray = (arr, maxLen, maxItems) => {
    if (!Array.isArray(arr) || arr.length === 0) return [false, arr];
    let changed = false;
    let out = arr
      .filter((x) => x != null)
      .map((x) => {
        const s = String(x);
        if (s.length > maxLen) {
          changed = true;
          return s.slice(0, maxLen - 3) + '...';
        }
        return s;
      });
    if (out.length > maxItems) {
      out = out.slice(0, maxItems);
      changed = true;
    }
    return [changed, out];
  };

  let truncated = !!ev.truncated;

  if (ev.source && typeof ev.source === 'object') {
    const [c1, names] = capArray(ev.source.names, 120, 8);
    ev.source.names = names;
    truncated = truncated || c1;
  }
  if (ev.flow && typeof ev.flow === 'object') {
    const [c2, sources] = capArray(ev.flow.sources, 120, 8);
    ev.flow.sources = sources;
    truncated = truncated || c2;
  }
  if (ev.techContext && typeof ev.techContext === 'object') {
    const [c3, libs] = capArray(ev.techContext.libs, 60, 5);
    if (c3 || (Array.isArray(ev.techContext.libs) && ev.techContext.libs.length > 5)) {
      ev.techContext.libs = libs;
      truncated = true;
    }
  }
  if (typeof ev.explanation === 'string' && ev.explanation.length > 500) {
    ev.explanation = ev.explanation.slice(0, 497) + '...';
    truncated = true;
  }

  if (truncated) ev.truncated = true;
  return ev;
}

// ── Explanation composition (deterministic, human-readable) ────────────────

const EXPLAIN = {
  static:
    'The flagged construct is inherently sensitive and does not depend on taint: hardcoded secret, weak algorithm, insecure configuration, or static code-execution primitive. Constant data is the vulnerability itself.',
  noSink:
    'No confirmed source-to-sink flow was found for this pattern. Reported as a potential lead; treat at low severity until confirmed.',
  confirmed:
    'A user-controlled input value flows into this sink with no sanitization or parameterization, so the pattern is exploitable.',
  potential:
    'The pattern has the shape of a vulnerability but no user-controlled source provably reaches the sink, so it is only a potential lead.',
  constantSink: 'Constant (non-user) data reaches the sink; there is no injection surface, so this is not exploitable.',
  parameterized: 'The query uses placeholders/parameters, so the input cannot alter the query structure.',
  sanitized: 'The value is passed through a recognized sanitizer/escper before reaching the sink.',
  templateOnly:
    'The template literal interpolates a value but no database/exec sink is present in this file, so the injection cannot be confirmed here.',
};

function explainTaint(ev) {
  if (ev.parameterized) return EXPLAIN.parameterized;
  if (ev.flow && ev.flow.established) return EXPLAIN.confirmed;
  if (ev.constantData) return EXPLAIN.constantSink;
  if (ev.templateOnly && !ev.sink.found) return EXPLAIN.templateOnly;
  if (ev.sanitized) return EXPLAIN.sanitized;
  if (ev.sink.found) return EXPLAIN.potential;
  return EXPLAIN.noSink;
}

export const EVIDENCE_ENGINE_VERSION = '4C.0';

