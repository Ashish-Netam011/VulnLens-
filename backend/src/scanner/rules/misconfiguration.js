/**
 * Insecure CORS & Security Misconfiguration
 * Detects permissive CORS, debug mode, missing security libraries, etc.
 */

const MISCONFIG = [
  {
    id: 'cors-wildcard',
    re: /Access-Control-Allow-Origin\s*:\s*['\"]\*['\"]|origin\s*:\s*['\"]\*['\"]/i,
    title: 'Permissive CORS (Wildcard Origin)',
    severity: 'medium',
    confidence: 82,
  },
  {
    id: 'cors-allow-all',
    re: /cors\s*\(\s*\{\s*origin\s*:\s*true\s*\}|allowOrigin\s*:\s*\*/i,
    title: 'CORS Allows All Origins',
    severity: 'medium',
    confidence: 78,
  },
  {
    id: 'debug-mode',
    re: /NODE_ENV\s*=\s*['\"]production['\"]\s*:\s*['\"]*development|debug\s*:\s*true/i,
    title: 'Debug Mode Enabled in Production',
    severity: 'medium',
    confidence: 65,
  },
  {
    id: 'no-helmet',
    re: /app\.\s*use\s*\(\s*(\w+)\s*\)/g,
    title: 'Possible Missing Security Headers Middleware',
    severity: 'low',
    confidence: 45,
  },
  {
    id: 'cors-credentials-wildcard',
    re: /Access-Control-Allow-Credentials\s*:\s*true[\s\S]{0,120}Access-Control-Allow-Origin\s*:\s*\*/i,
    title: 'CORS Credentials with Wildcard Origin',
    severity: 'high',
    confidence: 80,
  },
];

export default function misconfigurationRule(code) {
  const findings = [];
  for (const pat of MISCONFIG) {
    let match;
    const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
    while ((match = re.exec(code)) !== null) {
      const line = code.slice(0, match.index).split('\n').length;
      findings.push({
        ruleId: pat.id,
        vulnerabilityType: 'Security Misconfiguration',
        title: pat.title,
        severity: pat.severity,
        confidence: pat.confidence,
        reason:
          'This configuration setting weakens the application security posture, e.g., by permitting cross-origin data access or exposing debug information.',
        line,
        affectedCode: match[0].slice(0, 160),
        category: 'Security Misconfiguration',
      });
    }
  }
  return findings;
}
