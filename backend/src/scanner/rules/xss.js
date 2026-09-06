/**
 * Cross-Site Scripting (XSS)
 * Detects unsafe client-side sinks that can accept unsanitized input.
 */

const XSS_PATTERNS = [
  {
    id: 'innerhtml',
    re: /\.\s*innerHTML\s*=|\$\{\s*[^}]*\}\s*;\s*[^;]*innerHTML|insertAdjacentHTML\s*\(/i,
    title: 'Unsafe innerHTML Assignment',
    severity: 'high',
    confidence: 85,
  },
  {
    id: 'dangerouslySetInnerHTML',
    re: /dangerouslySetInnerHTML\s*=/i,
    title: 'dangerouslySetInnerHTML Used (React)',
    severity: 'high',
    confidence: 88,
  },
  {
    id: 'document-write',
    re: /document\.\s*write\s*\(/i,
    title: 'document.write() Used',
    severity: 'medium',
    confidence: 70,
  },
  {
    id: 'eval-html',
    re: /\.\s*html\s*\(\s*[^)]*req\.|jQuery\s*\(\s*['\"]\s*[^'\"]*['\"]\s*\)\s*\.\s*html\s*\(/i,
    title: 'Unsafe jQuery .html()',
    severity: 'high',
    confidence: 75,
  },
  {
    id: 'unsafe-href',
    re: /(?:href|src)\s*=\s*(?:['\"]?)\s*\{\{\s*[^}]*\}\}/,
    title: 'Unsafe attribute interpolation',
    severity: 'medium',
    confidence: 60,
  },
  {
    id: 'raw-response',
    re: /res\.\s*send\s*\(\s*[^)]*(?:req\.|input|user)[^)]*\)/i,
    title: 'Possible Reflected XSS via Response',
    severity: 'medium',
    confidence: 55,
  },
];

export default function xssRule(code) {
  const findings = [];
  for (const pat of XSS_PATTERNS) {
    let match;
    const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
    while ((match = re.exec(code)) !== null) {
      const line = code.slice(0, match.index).split('\n').length;
      findings.push({
        ruleId: pat.id,
        vulnerabilityType: 'XSS',
        title: pat.title,
        severity: pat.severity,
        confidence: pat.confidence,
        reason:
          'This pattern writes content into the DOM or a response without clear sanitization, which may permit stored or reflected cross-site scripting (XSS).',
        line,
        affectedCode: match[0].slice(0, 160),
        category: 'Cross-Site Scripting (XSS)',
      });
    }
  }
  return findings;
}
