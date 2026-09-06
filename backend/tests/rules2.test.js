/**
 * Scanner Rule Category Tests — Part 2
 * Weak crypto, misconfiguration, sensitive data, file handling,
 * determinism, line attribution, comparison key stability.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScanner } from '../src/scanner/scanner.js';
import { calculateScore } from '../src/scanner/score.js';

test('weak crypto: detects MD5', () => {
  const code = "const h = crypto.createHash('md5').update(data).digest('hex');";
  const { findings } = runScanner(code, { filePath: 'c.js' });
  const c = findings.filter((f) => f.category === 'Weak Cryptographic Practices');
  assert.ok(c.length >= 1);
  assert.ok(c.some((f) => f.ruleId === 'md5'));
});

test('weak crypto: SHA-1 detected', () => {
  const code = "const h = crypto.createHash('sha1').update(data).digest('hex');";
  const { findings } = runScanner(code, { filePath: 'c.js' });
  assert.ok(findings.some((f) => f.ruleId === 'sha1'));
});

test('weak crypto: SHA-256 is clean', () => {
  const code = "const h = crypto.createHash('sha256').update(data).digest('hex');";
  const { findings } = runScanner(code, { filePath: 'c.js' });
  const c = findings.filter((f) => f.category === 'Weak Cryptographic Practices');
  assert.equal(c.length, 0);
});

test('weak crypto: DES cipher detected', () => {
  const code = "const c = crypto.createCipher('des', key);";
  const { findings } = runScanner(code, { filePath: 'c.js' });
  assert.ok(findings.some((f) => f.ruleId === 'des'));
});

test('misconfiguration: wildcard CORS detected', () => {
  const code = 'origin: "*"';
  const { findings } = runScanner(code, { filePath: 'cfg.js' });
  const m = findings.filter((f) => f.category === 'Security Misconfiguration');
  assert.ok(m.length >= 1);
});

test('sensitive data: logging secrets detected', () => {
  const code = 'console.log("Token:", authToken);';
  const { findings } = runScanner(code, { filePath: 'log.js' });
  const s = findings.filter((f) => f.category === 'Sensitive Information Exposure');
  assert.ok(s.length >= 1);
});

test('sensitive data: hardcoded JWT secret', () => {
  const code = "jwt.sign(payload, 'hardcoded-secret-value');";
  const { findings } = runScanner(code, { filePath: 'auth.js' });
  assert.ok(findings.some((f) => f.ruleId === 'hardcoded-jwt-secret'));
});

test('file handling: file read from user input', () => {
  const code = 'fs.readFile(req.query.file, callback);';
  const { findings } = runScanner(code, { filePath: 'f.js' });
  const fh = findings.filter((f) => f.category === 'Insecure File Handling');
  assert.ok(fh.length >= 1);
});

test('identical input produces identical findings', () => {
  const code = 'const k = "sk-test-12345678";\nconst h = crypto.createHash("md5").update(pw).digest("hex");';
  const r1 = runScanner(code, { filePath: 'dup.js' });
  const r2 = runScanner(code, { filePath: 'dup.js' });
  assert.equal(r1.findings.length, r2.findings.length);
  assert.deepEqual(r1.severityCounts, r2.severityCounts);
  for (let i = 0; i < r1.findings.length; i++) {
    assert.equal(r1.findings[i].comparisonKey, r2.findings[i].comparisonKey);
  }
});

test('score is deterministic for identical counts', () => {
  const c = { critical: 1, high: 2, medium: 3, low: 4, informational: 5 };
  assert.equal(calculateScore(c), calculateScore(c));
});

test('line numbers are correct', () => {
  const code = 'line1\nline2\nconst apiKey = "sk-live-abcdef1234";\nline4';
  const { findings } = runScanner(code, { filePath: 'l.js' });
  const s = findings.filter((f) => f.category === 'Hardcoded Credentials and Secrets');
  assert.ok(s.some((f) => f.line === 3));
});

test('comparison keys include ruleId', () => {
  const code = 'const API_KEY = "sk-live-abcdefghijklmnop";';
  const { findings } = runScanner(code, { filePath: 'k.js' });
  for (const f of findings) {
    assert.ok(f.comparisonKey.includes(f.ruleId));
  }
});

test('same code in different files has distinct keys', () => {
  const code = 'const API_KEY = "sk-live-abcdefghijklmnop";';
  const { findings } = runScanner(null, {
    files: [
      { path: 'src/a.js', content: code },
      { path: 'src/b.js', content: code },
    ],
  });
  const keys = findings.map((f) => f.comparisonKey);
  assert.equal(new Set(keys).size, keys.length);
  assert.ok(keys.every((k) => k.startsWith('src/')));
});

test('clean code scores exactly 100', () => {
  const { severityCounts } = runScanner('const x = 42;\nfunction add(a, b) { return a + b; }', { filePath: 'c.js' });
  assert.equal(calculateScore(severityCounts), 100);
});
