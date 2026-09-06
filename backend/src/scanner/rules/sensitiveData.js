/**
 * Sensitive Data Exposure & Authentication Weaknesses
 * Logging secrets, returning sensitive objects, weak auth patterns.
 */

const DATA = [
  {
    id: 'log-secret',
    // Flag logging a sensitive VALUE. Operates on a copy with string literals
    // and comments replaced by spaces (via `preprocess`), so static message text
    // such as 'FATAL: JWT_SECRET must be set...' does NOT trigger, while a bare
    // value identifier like `authToken` or `err.password` does.
    re: /console\.\s*(?:log|info|error|warn)\s*\(\s*[^)]*(?:password|secret|token|api[_-]?key|authorization)[^)]*\)/i,
    preprocess: stripLiterals,
    title: 'Sensitive Value Logged',
    severity: 'medium',
    confidence: 85,
  },
  {
    id: 'return-full-user',
    re: /res\.\s*json\s*\(\s*(?:user|req\.user|users)\s*\)|\.\.\.(?:user|req\.user)\s*\}/i,
    title: 'Potential Full Object Exposure',
    severity: 'medium',
    confidence: 65,
  },
  {
    id: 'hardcoded-jwt-secret',
    re: /jwt\.\s*sign\s*\(\s*[^,]+,\s*['\"][^'\"]{3,}['\"]/i,
    title: 'Hardcoded JWT Signing Secret',
    severity: 'critical',
    confidence: 90,
  },
  {
    id: 'weak-password-check',
    re: /password\s*(?:===|==)\s*['\"][^'\"]{3,}['\"]/i,
    title: 'Hardcoded Password Comparison',
    severity: 'critical',
    confidence: 88,
  },
  {
    id: 'crypto-random-not-used',
    re: /Math\.\s*random\s*\(\s*\)\s*[^;]{0,60}(?:password|salt|token)/i,
    title: 'Insecure Randomness for Auth',
    severity: 'high',
    confidence: 75,
  },
  {
    id: 'send-token-payload',
    re: /res\.\s*(?:send|json)\s*\(\s*(?:token|jwt)\s*\)/i,
    title: 'Token Returned in Response Body',
    severity: 'low',
    confidence: 60,
  },
];

export default function sensitiveDataRule(code) {
  const findings = [];
  for (const pat of DATA) {
    let match;
    // Some rules preprocess the source (e.g. replace string literals/comments
    // with spaces) to avoid flagging static message text. Length is preserved,
    // so line numbers stay accurate against the original source.
    const source = pat.preprocess ? pat.preprocess(code) : code;
    const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
    while ((match = re.exec(source)) !== null) {
      const line = code.slice(0, match.index).split('\n').length;
      const affected = pat.preprocess
        ? code.slice(match.index, match.index + match[0].length).slice(0, 160)
        : match[0].slice(0, 160);
      findings.push({
        ruleId: pat.id,
        vulnerabilityType: 'Sensitive Data Exposure',
        title: pat.title,
        severity: pat.severity,
        confidence: pat.confidence,
        reason:
          'This pattern can expose sensitive data such as credentials, tokens, or internal objects to logs, clients, or unauthorized parties.',
        line,
        affectedCode: affected,
        category: 'Sensitive Information Exposure',
      });
    }
  }
  return findings;
}

/**
 * Replace string literals (single/double/backtick), line comments and block
 * comments with spaces (preserving newlines) so regex rules can operate on the
 * remaining *values* rather than on static message text.
 */
function stripLiterals(code) {
  return code.replace(/(['"`])(?:\\.|(?!\1)[^\\\n])*\1|\/\/[^\n]*|\/\*[\s\S]*?\*\//g, (m) =>
    m.replace(/[^\n]/g, ' ')
  );
}
