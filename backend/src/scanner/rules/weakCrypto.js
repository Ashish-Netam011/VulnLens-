/**
 * Weak Cryptography
 * Detects weak/broken hash and cipher algorithms and insecure randomness.
 */

const WEAK_CRYPTO = [
  {
    id: 'md5',
    re: /(?:createHash|hash)\s*\(\s*['\"]md5['\"]/i,
    title: 'Weak Hash Algorithm (MD5)',
    severity: 'medium',
    confidence: 88,
  },
  {
    id: 'sha1',
    re: /(?:createHash|hash)\s*\(\s*['\"]sha1['\"]/i,
    title: 'Deprecated Hash Algorithm (SHA-1)',
    severity: 'medium',
    confidence: 88,
  },
  {
    id: 'des',
    re: /(?:createCipher|createDecipher)\s*\(\s*['\"]des['\"]/i,
    title: 'Weak Cipher (DES)',
    severity: 'high',
    confidence: 90,
  },
  {
    id: 'rc4',
    re: /(?:createCipher|createDecipher)\s*\(\s*['\"]rc4['\"]/i,
    title: 'Insecure Cipher (RC4)',
    severity: 'high',
    confidence: 90,
  },
  {
    id: 'ecb',
    re: /aes-\d+-ecb|createCipheriv\s*\(\s*['\"][^'\"]*ecb/i,
    title: 'Insecure Cipher Mode (ECB)',
    severity: 'high',
    confidence: 85,
  },
  {
    id: 'math-random-security',
    re: /Math\.\s*random\s*\(\s*\)\s*[^;]{0,40}(?:password|token|key|secret|iv|salt)/i,
    title: 'Math.random() Used for Security',
    severity: 'high',
    confidence: 80,
  },
];

export default function weakCryptoRule(code) {
  const findings = [];
  for (const pat of WEAK_CRYPTO) {
    let match;
    const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
    while ((match = re.exec(code)) !== null) {
      const line = code.slice(0, match.index).split('\n').length;
      findings.push({
        ruleId: pat.id,
        vulnerabilityType: 'Weak Cryptography',
        title: pat.title,
        severity: pat.severity,
        confidence: pat.confidence,
        reason:
          'A known-weak or deprecated cryptographic primitive is being used for a security-sensitive operation; modern best practice requires a strong algorithm.',
        line,
        affectedCode: match[0].slice(0, 160),
        category: 'Weak Cryptographic Practices',
      });
    }
  }
  return findings;
}
