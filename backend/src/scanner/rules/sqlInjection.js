/**
 * SQL / NoSQL Injection
 * Detects string-concatenated SQL queries and unsafe query patterns.
 */

import { analyzeTaint, sinkArgTaint, nodeText, isNoSqlQuerySink } from '../ast.js';

const SQL_PATTERNS = [
  {
    id: 'sql-concat',
    re: /(?:query|execute|run|all|get|find)\s*\(\s*['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\b[^'\"]*['\"]\s*\+/i,
    title: 'SQL Injection via String Concatenation',
    severity: 'critical',
    confidence: 92,
  },
  {
    id: 'sql-assign-concat',
    re: /(?:=|const\s+|let\s+|var\s+)[^;\n]{0,40}['\"][^'\"]*\b(?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^'\"]*['\"]\s*\+[^;]{1,60}/i,
    title: 'SQL Query Built With Concatenation',
    severity: 'critical',
    confidence: 88,
  },
  {
    id: 'sql-template',
    re: /`[^`]*\b(?:SELECT|UPDATE|DELETE|INSERT)\b[^`]*\$\{[^}]*\}[^`]*`|['"][^'"]*\b(?:SELECT|UPDATE|DELETE|INSERT)\b[^'"]*\$\{[^}]*\}[^'"]*['"]/i,
    title: 'SQL Injection via Template Literal',
    severity: 'critical',
    confidence: 88,
  },
  {
    id: 'sql-format',
    re: /['\"][^'\"]*\b(?:SELECT|UPDATE|DELETE|INSERT)\b[^'\"]*(?:%s|%d|\+|\$\{)[^'\"]*['\"]\s*\.\s*(?:format|replace)/i,
    title: 'SQL Injection via .format()',
    severity: 'critical',
    confidence: 85,
  },
  {
    id: 'nosql-where',
    re: /\.\s*where\s*\(\s*\{\s*[^}]*\$where/i,
    title: 'NoSQL Injection via $where',
    severity: 'critical',
    confidence: 90,
  },
  {
    id: 'nosql-operator',
    re: /['\"][$](?:gt|gte|lt|lte|ne|regex)['\"]\s*>?\s*(?:req\.|body\.|params\.|query\.)/i,
    title: 'NoSQL Operator Injection',
    severity: 'high',
    confidence: 82,
  },
  {
    id: 'sql-unprepared',
    re: /(?:sequelize|knex|pg|mysql)\s*\.\s*(?:query|raw)\s*\(\s*`[^`]*\$\{/i,
    title: 'Unsafe Query Building',
    severity: 'high',
    confidence: 80,
  },
];

// ── NoSQL object-query flows (Phase 7) ───────────────────────────────────────
// MongoDB/Mongoose-style document queries whose first argument is a request-
// controlled object/identifier/whole-request value. With Express extended
// query parsing an attacker can inject MongoDB operator keys ($gt, $ne, ...)
// into such values, so request data in a document-query argument is a genuine
// NoSQL injection surface. Only request-tainted arguments trigger; constant
// or unrelated object filters never do.

const NOSQL_OBJECT_RULE = {
  id: 'nosql-object-query',
  title: 'NoSQL Query Built From Request Data',
  severity: 'high',
  confidence: 82,
  reason:
    'A request-controlled value or object is passed directly into a NoSQL/document query argument. Depending on the query parser, the value can carry MongoDB operator keys ($gt, $ne, $where, ...) and alter the query logic (NoSQL injection).',
};

/**
 * Detect document-query calls (Model.find({...req...}) etc.) whose first
 * argument is request-tainted and not already covered by the string-SQL or
 * $where regex rules above. Reuses the deterministic intra-function taint
 * analysis; purely additive and side-effect free.
 */
export function findNoSqlObjectQueryFlows(code) {
  // Cheap prefilter: a document-query call and a request source on the file.
  if (!/\.\s*(?:find|findOne|where|countDocuments|updateOne|updateMany|deleteOne|deleteMany)\s*\(/.test(code)) return [];
  if (!/(?:req\.|body\.|query\.|params\.|headers\.|cookies\.)/.test(code)) return [];
  const analysis = analyzeTaint(code, 'sql');
  const out = [];
  for (const sink of analysis.sinks || []) {
    if (sink.type !== 'sql-query' || !sink.node) continue;
    const node = sink.node;
    if (!isNoSqlQuerySink(node)) continue;
    const arg0 = node.arguments && node.arguments[0];
    if (!arg0) continue;
    const argText = nodeText(arg0, code);
    // String SQL (quotes/backticks) and $where shapes are owned by the regex
    // rules above; only object/identifier/whole-request document queries land here.
    if (/["'`]/.test(argText) || /\$where/.test(argText)) continue;
    if (arg0.type === 'Literal' || arg0.type === 'TemplateLiteral') continue;
    const t = sinkArgTaint(sink, analysis.env, code);
    if (!t || !t.tainted) continue;
    out.push({
      ruleId: NOSQL_OBJECT_RULE.id,
      vulnerabilityType: 'Injection',
      title: NOSQL_OBJECT_RULE.title,
      severity: NOSQL_OBJECT_RULE.severity,
      confidence: NOSQL_OBJECT_RULE.confidence,
      reason: NOSQL_OBJECT_RULE.reason,
      line: (node.loc && node.loc.start.line) || 1,
      affectedCode: nodeText(node, code).slice(0, 160),
      category: 'Injection Vulnerabilities',
    });
  }
  return out;
}

export default function sqlInjectionRule(code) {
  const findings = [];
  for (const pat of SQL_PATTERNS) {
    let match;
    const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
    while ((match = re.exec(code)) !== null) {
      const line = code.slice(0, match.index).split('\n').length;
      findings.push({
        ruleId: pat.id,
        vulnerabilityType: 'Injection',
        title: pat.title,
        severity: pat.severity,
        confidence: pat.confidence,
        reason:
          'User-supplied input appears to be interpolated directly into a database query, which can allow an attacker to manipulate the query logic (SQL/NoSQL injection).',
        line,
        affectedCode: match[0].slice(0, 160),
        category: 'Injection Vulnerabilities',
      });
    }
  }
  // Phase 7: NoSQL document-query flows the regex rules cannot express.
  findings.push(...findNoSqlObjectQueryFlows(code));
  return findings;
}
