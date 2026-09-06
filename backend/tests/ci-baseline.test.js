/**
 * CLI baseline tests (Phase 6C).
 *
 * A committed baseline file (backend/vulnlens.baseline.json) documents scanner
 * SELF-REFERENCE findings. The gate must:
 *   - keep baselined findings VISIBLE in the report, but exclude them from the
 *     --fail-on exit-code gate;
 *   - still fail when a genuine (non-baselined) finding meets the threshold;
 *   - fail-visible (exit 2) on a missing (explicit) or malformed baseline,
 *     never silently suppressing.
 *
 * Unit tests cover baselineSignature/loadBaseline/filterBaseline; integration
 * tests spawn the real binary against temp fixtures.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  baselineSignature,
  loadBaseline,
  filterBaseline,
} from '../src/cli/cli.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, '..', 'bin', 'vulnlens.js');

// A single-HIGH fixture: one hardcoded secret on line 1 (ruleId hardcoded-secret).
const SECRET_JS = "const secret = 'sk-abcdef1234567890supersecret';\n";

let tmpDir;
let tmpPath;
let workDir;

before(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnlens-baseline-'));
  tmpPath = (name) => path.join(tmpDir, name);
  workDir = path.join(tmpDir, 'work');
  fs.mkdirSync(workDir, { recursive: true });
  fs.writeFileSync(path.join(workDir, 'vuln.js'), SECRET_JS);
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function runCli(args) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    cwd: workDir,
  });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

// ── Unit: signature ────────────────────────────────────────────────────────

test('baselineSignature: normalizes backslashes and leading slashes', () => {
  assert.equal(
    baselineSignature('src\\scanner\\rules\\xss.js', 'document-write', 24),
    baselineSignature('/src/scanner/rules/xss.js', 'document-write', 24)
  );
  assert.equal(baselineSignature('a/b.js', 'eval', 5), 'a/b.js::eval::5');
});

// ── Unit: loadBaseline ─────────────────────────────────────────────────────

test('loadBaseline: missing file is an error only when explicit', () => {
  assert.throws(() => loadBaseline('nope.json', { explicit: true, cwd: workDir }));
  const empty = loadBaseline('nope.json', { explicit: false, cwd: workDir });
  assert.equal(empty.keys.size, 0);
  assert.equal(empty.filePath, null);
});

test('loadBaseline: malformed JSON throws', () => {
  fs.writeFileSync(tmpPath('bad.json'), '{ not valid json');
  assert.throws(() => loadBaseline(tmpPath('bad.json'), { explicit: true }));
});

test('loadBaseline: entry with missing fields throws', () => {
  fs.writeFileSync(tmpPath('badshape.json'), JSON.stringify({ entries: [{ filePath: 'x.js' }] }));
  assert.throws(() => loadBaseline(tmpPath('badshape.json'), { explicit: true }));
});

test('loadBaseline: valid file yields the expected keys', () => {
  fs.writeFileSync(
    tmpPath('ok.json'),
    JSON.stringify({ entries: [{ filePath: 'src/a.js', ruleId: 'eval', line: 10 }] })
  );
  const b = loadBaseline(tmpPath('ok.json'), { explicit: true });
  assert.equal(b.keys.size, 1);
  assert.ok(b.keys.has('src/a.js::eval::10'));
});

test('filterBaseline: separates kept vs suppressed without dropping findings', () => {
  const findings = [
    { filePath: 'a.js', ruleId: 'eval', line: 1, severity: 'high' },
    { filePath: 'b.js', ruleId: 'md5', line: 2, severity: 'medium' },
  ];
  const keys = new Set(['a.js::eval::1']);
  const { kept, suppressed } = filterBaseline(findings, { keys });
  assert.equal(suppressed.length, 1);
  assert.equal(kept.length, 1);
  assert.deepEqual(kept.map((f) => f.ruleId), ['md5']);
});

// ── Integration ────────────────────────────────────────────────────────────

test('cli: baseline suppresses a HIGH from the gate but keeps it visible', () => {
  fs.writeFileSync(
    path.join(workDir, 'vulnlens.baseline.json'),
    JSON.stringify({ entries: [{ filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 1 }] })
  );
  const { status, stdout } = runCli(['scan', 'vuln.js', '--format', 'json', '--fail-on', 'high', '--baseline', 'vulnlens.baseline.json']);
  assert.equal(status, 0, 'baselined HIGH must not fail the gate');
  const json = JSON.parse(stdout);
  assert.ok(json.findings.length >= 1, 'baselined finding must remain visible in output');
  assert.ok(json.findings.some((f) => f.ruleId === 'hardcoded-secret'));
});

test('cli: a high that is NOT in the baseline still fails the gate', () => {
  fs.unlinkSync(path.join(workDir, 'vulnlens.baseline.json'));
  fs.writeFileSync(
    tmpPath('not-matching.json'),
    JSON.stringify({ entries: [{ filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 99 }] })
  );
  const { status } = runCli(['scan', 'vuln.js', '--fail-on', 'high', '--baseline', tmpPath('not-matching.json')]);
  assert.equal(status, 1, 'unmatched genuine HIGH must fail the gate');
});

test('cli: explicit --baseline with a missing file exits 2', () => {
  const { status } = runCli(['scan', 'vuln.js', '--fail-on', 'high', '--baseline', 'definitely-missing.json']);
  assert.equal(status, 2);
});

test('cli: malformed baseline exits 2 (fail-visible, never silent)', () => {
  fs.writeFileSync(tmpPath('malformed.json'), '{"entries": [');
  const { status } = runCli(['scan', 'vuln.js', '--fail-on', 'high', '--baseline', tmpPath('malformed.json')]);
  assert.equal(status, 2);
});

test('cli: no baseline present -> HIGH still fails the gate', () => {
  fs.rmSync(path.join(workDir, 'vulnlens.baseline.json'), { force: true });
  const { status } = runCli(['scan', 'vuln.js', '--fail-on', 'high']);
  assert.equal(status, 1);
});