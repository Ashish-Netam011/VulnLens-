/**
 * Hardcoded Secrets & Credentials
 * Detects API keys, passwords, AWS keys, JWT secrets, private keys, tokens.
 */

const SECRET_PATTERNS = {
  apiKey: /(?:api[_-]?key|apikey)\s*[:=]\s*['\"][^'\"]{8,}['\"]/i,
  password: /(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{4,}['\"]/i,
  secret: /(?:secret|client[_-]?secret|token|auth[_-]?token)\s*[:=]\s*['\"][^'\"]{8,}['\"]/i,
  awsAccessKey: /AKIA[0-9A-Z]{16}/,
  awsSecretKey: /(?:aws[_-]?secret|secret[_-]?access[_-]?key)\s*[:=]\s*['\"][^'\"]{16,}['\"]/i,
  jwtSecret: /(?:jwt[_-]?secret|jsonwebtoken[_-]?secret)\s*[:=]\s*['\"][^'\"]{8,}['\"]|jwt\.\s*sign\s*\(\s*(?:\{[^}]*\}|[^,]{0,80}),\s*['\"][^'\"]{8,}['\"]/i,
  privateKey: /-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----/,
  slackToken: /xox[baprs]-[0-9A-Za-z-]{10,}/,
  githubPat: /ghp_[0-9A-Za-z]{20,}/,
};

const VALUE_IN_FUNCTION = /(?:new\s+Date\(\)|undefined|null)/i;

export default function secretsRule(code) {
  const findings = [];

  for (const [key, re] of Object.entries(SECRET_PATTERNS)) {
    let match;
    const globalRe = new RegExp(re.source, re.flags.includes('g') ? re.flags : re.flags + 'g');
    while ((match = globalRe.exec(code)) !== null) {
      const line = code.slice(0, match.index).split('\n').length;
      // Skip obvious dynamic-value patterns (e.g. process.env assignment is fine,
      // but a literal value is not).
      const isFunctionValue = VALUE_IN_FUNCTION.test(match[0]);
      if (isFunctionValue) break;
      findings.push({
        ruleId: `hardcoded-${key}`,
        vulnerabilityType: 'Hardcoded Secret',
        title: `Hardcoded ${friendlyName(key)}`,
        severity: key === 'privateKey' || key === 'awsSecretKey' ? 'critical' : 'high',
        confidence: match[0].length > 24 ? 90 : 80,
        reason: `A possible ${friendlyName(key)} value appears to be embedded directly in the source code instead of being loaded from an environment variable or secret manager.`,
        line,
        affectedCode: maskMatch(match[0]),
        category: 'Hardcoded Credentials and Secrets',
      });
      // Only report the first occurrence per secret type to reduce duplicates.
      break;
    }
  }

  return findings;
}

function friendlyName(key) {
  const names = {
    apiKey: 'API key',
    password: 'password',
    secret: 'secret/token',
    awsAccessKey: 'AWS access key',
    awsSecretKey: 'AWS secret key',
    jwtSecret: 'JWT signing secret',
    privateKey: 'private key',
    slackToken: 'Slack token',
    githubPat: 'GitHub personal access token',
    genericToken: 'credential',
  };
  return names[key] || key;
}

// Mask the actual secret value so we never display it.
// Handles both quoted values (apiKey/password/secret) and bare high-entropy
// tokens (GitHub PATs, Slack tokens, AWS access keys) captured without quotes.
function maskMatch(raw) {
  let out = raw.replace(/['\"]([^'\"]{4,})['\"]/g, (m, val) => maskVal(m, val));
  out = out.replace(/\b([A-Za-z0-9][A-Za-z0-9_\-]{11,})\b/g, (m, val) => maskVal(m, val));
  return out;
}

function maskVal(raw, val) {
  if (val.length <= 4) return raw;
  return raw.replace(val, val.slice(0, 2) + '\u2022\u2022\u2022\u2022' + val.slice(-2));
}
