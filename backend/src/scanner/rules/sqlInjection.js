/**
 * SQL / NoSQL Injection
 * Detects string-concatenated SQL queries and unsafe query patterns.
 */

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
  return findings;
}
