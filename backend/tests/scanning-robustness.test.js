/**
 * Scanning robustness / adversarial-input tests.
 * Verifies secrets are fully masked (no raw values leak into findings), that
 * the deterministic scanner tolerates hostile/large input within bounded time,
 * and that traversal/header hygiene holds end-to-end.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScanner } from '../src/scanner/scanner.js';
import { sanitizeFileName, sanitizeRelativePath, allowedExtension } from '../src/utils/validation.js';

// ── Secret masking (no value leakage into findings) ─────────────────
test('scanner: bare GitHub PAT is fully masked in affectedCode', () => {
  const PAT = 'ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghij';
  // Unquoted (bare) token — exercises the bare-token masking branch.
  const { findings } = runScanner(`const token = ${PAT};`, { filePath: 'a.js' });
  const f = findings.find((x) => x.ruleId === 'hardcoded-githubPat');
  assert.ok(f, 'githubPat rule should fire');
  assert.ok(!f.affectedCode.includes(PAT), 'PIN should never appear raw');
  assert.ok(f.affectedCode.includes('\u2022'), 'should contain mask character');
});

test('scanner: bare Slack token is masked', () => {
  const TOKEN = 'xoxb-testonly-notarealsecret-abcdefghijklmnop';
  const { findings } = runScanner(`const t = '${TOKEN}';`, { filePath: 'b.js' });
  const f = findings.find((x) => x.ruleId === 'hardcoded-slackToken');
  assert.ok(f, 'slackToken rule should fire');
  assert.ok(!JSON.stringify(findings).includes('testonly-notarealsecret'), 'Slack token must be masked');
});

test('scanner: quoted API key is masked', () => {
  const KEY = 'sk-live-abcdefghijklmnop';
  const { findings } = runScanner(`const API_KEY = "${KEY}";`, { filePath: 'c.js' });
  const f = findings.find((x) => x.category === 'Hardcoded Credentials and Secrets');
  assert.ok(f);
  assert.ok(!JSON.stringify(findings).includes(KEY), 'raw key must not appear in findings');
});

test('scanner: no raw secret leaks anywhere in serialized findings', () => {
  const CODE = [
    "const password = 'p@ssw0rdSecret12345';",
    "const apiKey = 'ak-live-9f8e7d6c5b4a3e2d1c0b9a8f';",
    "const AWS = 'AKIAIOSFODNN7EXAMPLE';",
    "const slack = 'xoxb-testonly-notarealsecret-abcdefghijklmnopqrstuvwxyz';",
    "const github = 'ghp_QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiop12';",
  ].join('\n');
  const { findings } = runScanner(CODE, { filePath: 'secrets.js' });
  const snapshot = JSON.stringify(findings);
  const secrets = [
    'p@ssw0rdSecret12345',
    'ak-live-9f8e7d6c5b4a3e2d1c0b9a8f',
    'AKIAIOSFODNN7EXAMPLE',
    'testonly-notarealsecret-abcdefghijklmnopqrstuvwxyz',
    'QWERTYUIOPASDFGHJKLZXCVBNMqwertyuiop12',
  ];
  for (const s of secrets) {
    assert.ok(!snapshot.includes(s), `raw secret must be masked: ${s.slice(0, 6)}...`);
  }
});

// ── Hostile / large input (ReDoS & throughput smoke) ─────────────────
test('scanner: adversarial unclosed-quote flood completes within time bound', () => {
  // Hundreds of thousands of unclosed quotes stress the [^'"]* scanner regexes.
  const adversarial =
    'const q = ' + '"'.repeat(150000) + ';\n' +
    'const missing = ' + "'".repeat(120000) + ";\n" +
    'let y = "a" + `id` + \'' + "b';\n" +
    '// trailing';
  const start = performance.now();
  const { findings } = runScanner(adversarial, { filePath: 'flood.js' });
  const elapsed = performance.now() - start;
  assert.ok(Array.isArray(findings));
  assert.ok(elapsed < 2000, `scanner took ${elapsed.toFixed(0)}ms (should be well under 2s)`);
});

test('scanner: deeply nested escaping and unicode do not crash', () => {
  const code = Array.from({ length: 500 }, (_, i) => `line${i} = "\\\\'\\\"${'x'.repeat(40)}\u00a9";`).join('\n');
  const { findings } = runScanner(code, { filePath: 'u.js' });
  assert.ok(Array.isArray(findings));
});

test('scanner: near-limit code size still scans within time bound', () => {
  const big = 'function a(n){ return n ? a(n-1) + 1 : 0; }\n'.repeat(12000); // ~ 480k chars
  const start = performance.now();
  const { findings } = runScanner(big, { filePath: 'big.js' });
  const elapsed = performance.now() - start;
  assert.ok(Array.isArray(findings));
  assert.ok(elapsed < 3000, `large scan took ${elapsed.toFixed(0)}ms`);
});

// ── Traversal / header hygiene end-to-end ────────────────────────────
test('upload path pipeline: traversal + CRLF cannot survive sanitization', () => {
  const hostile = '../../../etc/passwd\r\nX-Header: 1/../..\\..\\win.ini.js';
  const out = sanitizeRelativePath(hostile);
  assert.ok(!out.includes('..'), 'no traversal segments');
  assert.ok(!/[\r\n]/.test(out), 'no CR/LF');
  assert.ok(!out.startsWith('/'), 'no absolute path');
});

test('upload pipeline: allowed extensions only; executables dropped', () => {
  assert.ok(allowedExtension(sanitizeFileName('payload.js')));
  assert.ok(!allowedExtension(sanitizeFileName('malware.exe')));
  assert.ok(!allowedExtension(sanitizeFileName('../nested/evil.bin')));
});