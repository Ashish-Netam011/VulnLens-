/**
 * Scanner Rule Category Tests — Part 1
 * Hardcoded secrets, SQL injection, XSS, dangerous functions.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runScanner } from '../src/scanner/scanner.js';

// ── Hardcoded Credentials and Secrets ────────────────────────────────
test('hardcoded secrets: detects API keys and passwords', () => {
  const code = 'const API_KEY = "sk-live-abcdefghijklmnop";\nconst SECRET = "superSecretValue123";';
  const { findings } = runScanner(code, { filePath: 'test.js' });
  const secrets = findings.filter((f) => f.category === 'Hardcoded Credentials and Secrets');
  assert.ok(secrets.length >= 1, `Expected >=1 secret finding, got ${secrets.length}`);
  for (const f of secrets) {
    assert.ok(f.comparisonKey.length > 0);
    assert.ok(f.line >= 1);
    assert.ok(f.severity === 'high' || f.severity === 'critical');
  }
});

test('hardcoded secrets: env vars do not trigger', () => {
  const code = 'const key = process.env.API_KEY;\nconst secret = process.env.SECRET;';
  const { findings } = runScanner(code, { filePath: 'clean.js' });
  const secrets = findings.filter((f) => f.category === 'Hardcoded Credentials and Secrets');
  assert.equal(secrets.length, 0, 'Environment variable usage should not be flagged');
});

test('hardcoded secrets: secret value is masked', () => {
  const code = 'const API_KEY = "sk-live-abcdefghijklmnop";';
  const { findings } = runScanner(code, { filePath: 'mask.js' });
  const s = findings.find((f) => f.category === 'Hardcoded Credentials and Secrets');
  assert.ok(s, 'Should find the secret');
  assert.ok(!s.affectedCode.includes('sk-live-abcdefghijklmnop'), 'Raw secret should be masked');
  assert.ok(s.affectedCode.includes('•'), 'Should contain mask character');
});

// ── Injection Vulnerabilities ────────────────────────────────────────
test('sql injection: detects string concatenation', () => {
  const code = 'db.query("SELECT * FROM users WHERE id=" + id);';
  const { findings } = runScanner(code, { filePath: 'db.js' });
  const inj = findings.filter((f) => f.category === 'Injection Vulnerabilities');
  assert.ok(inj.length >= 1, `Expected >=1 injection finding, got ${inj.length}`);
  // Bare `id` has no confirmed user source, so the evidence engine demotes it
  // to POTENTIAL (low) rather than confirming critical SQL injection.
  assert.equal(inj[0].verdict, 'POTENTIAL');
  assert.equal(inj[0].severity, 'low');
});

test('sql injection: template literal detected', () => {
  const code = 'const q = "SELECT * FROM users WHERE id=${id}";';
  const { findings } = runScanner(code, { filePath: 'tpl.js' });
  const inj = findings.filter((f) => f.category === 'Injection Vulnerabilities');
  assert.ok(inj.length >= 1, 'Template literal SQL injection should be detected');
});

test('sql injection: backtick template literal detected', () => {
  const code = 'const q = `SELECT * FROM users WHERE id=${id}`;';
  const { findings } = runScanner(code, { filePath: 'tpl.js' });
  const inj = findings.filter((f) => f.category === 'Injection Vulnerabilities');
  assert.ok(inj.length >= 1, 'Backtick template literal SQL injection should be detected');
});

test('sql injection: parameterized query is clean', () => {
  const code = 'db.query("SELECT * FROM users WHERE id = ?", [id]);';
  const { findings } = runScanner(code, { filePath: 'safe.js' });
  const inj = findings.filter((f) => f.category === 'Injection Vulnerabilities');
  assert.equal(inj.length, 0, 'Parameterized query should not be flagged');
});

// ── Cross-Site Scripting (XSS) ──────────────────────────────────────
test('xss: detects innerHTML assignment', () => {
  const code = 'document.getElementById("app").innerHTML = userInput;';
  const { findings } = runScanner(code, { filePath: 'ui.js' });
  const xss = findings.filter((f) => f.category === 'Cross-Site Scripting (XSS)');
  assert.ok(xss.length >= 1, `Expected >=1 XSS finding, got ${xss.length}`);
});

test('xss: textContent is safe', () => {
  const code = 'element.textContent = userInput;';
  const { findings } = runScanner(code, { filePath: 'safe.js' });
  const xss = findings.filter((f) => f.category === 'Cross-Site Scripting (XSS)');
  assert.equal(xss.length, 0, 'textContent should not be flagged');
});

// ── Dangerous Function Usage ─────────────────────────────────────────
test('dangerous functions: detects eval()', () => {
  const code = 'function run(input) {\n  eval(input);\n}';
  const { findings } = runScanner(code, { filePath: 'danger.js' });
  const d = findings.filter((f) => f.category === 'Dangerous Function Usage');
  assert.ok(d.length >= 1, `Expected >=1 dangerous function finding, got ${d.length}`);
  assert.ok(d.some((f) => f.ruleId === 'eval'));
});

test('dangerous functions: new Function() detected', () => {
  const code = 'const fn = new Function("return " + code);';
  const { findings } = runScanner(code, { filePath: 'danger.js' });
  assert.ok(findings.some((f) => f.ruleId === 'function-ctor'));
});

test('dangerous functions: child_process detected', () => {
  const code = 'const cp = require("child_process");\ncp.exec(cmd);';
  const { findings } = runScanner(code, { filePath: 'danger.js' });
  assert.ok(findings.some((f) => f.ruleId === 'child-process'));
});
