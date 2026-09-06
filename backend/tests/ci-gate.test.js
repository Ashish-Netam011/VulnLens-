/**
 * CI security-gate workflow tests (Phase 6B).
 *
 * Two layers:
 *  1. Static validation of `.github/workflows/vulnlens.yml` (parsed as real YAML)
 *     against the CI security-gate contract: triggers, least-privilege
 *     permissions, fork-safety (no pull_request_target), no secrets, correct
 *     CLI flags, SARIF upload, and exit-code capture → enforce gate ordering.
 *  2. Integration tests that spawn the actual CLI binary against temp fixtures
 *     to prove the exit-code + SARIF-preservation contract the workflow relies
 *     on (0 = PASS, 1 = SECURITY GATE FAILED, 2 = WORKFLOW ERROR, 3 = SCANNER
 *     ERROR).
 *
 * The intentionally "red" initial CI result (backend/src has ~10 HIGH findings
 * that are not suppressed) is NOT encoded as a permanent unit-test assertion
 * here (so `npm test` stays green). It is validated by a one-off local CI
 * simulation and documented in docs/ci-cd-github-actions.md.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { load as yamlLoad } from 'js-yaml';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..', '..');
const WORKFLOW_PATH = path.join(ROOT, '.github', 'workflows', 'vulnlens.yml');
const CLI_SRC = path.join(ROOT, 'backend', 'src', 'cli', 'cli.js');
const BIN = path.join(ROOT, 'backend', 'bin', 'vulnlens.js');

// ── Helpers ────────────────────────────────────────────────────────────────

const VULN_JS = `const mysql = require('mysql');
function getUser(id) {
  const query = 'SELECT * FROM users WHERE id = ' + id;
  return db.query(query);
}
const secret = 'sk-abcdef1234567890supersecret';
`;

const CLEAN_JS = `console.log('hi');
`;

let tmpDir;
let tmpPath;

before(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnlens-cigate-'));
  tmpPath = (name) => path.join(tmpDir, name);
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

/** Run the CLI binary synchronously, returning { status, stdout, stderr }. */
function runCli(args, opts = {}) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || tmpDir,
  });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

function workflow() {
  return yamlLoad(fs.readFileSync(WORKFLOW_PATH, 'utf8'));
}

// ── Workflow static validation ─────────────────────────────────────────────

test('workflow: file exists and parses as valid YAML', () => {
  assert.ok(fs.existsSync(WORKFLOW_PATH), 'vulnlens.yml must exist');
  const doc = workflow();
  assert.equal(doc.name, 'vulnlens');
  assert.ok(doc.jobs && doc.jobs['security-scan'], 'must define a security-scan job');
});

test('workflow: triggers are pull_request + push to main', () => {
  const doc = workflow();
  assert.ok(doc.on && doc.on.pull_request !== undefined, 'must run on pull_request');
  assert.ok(doc.on && doc.on.push !== undefined, 'must run on push');
  const branches = doc.on.push.branches || [];
  assert.ok(branches.includes('main'), 'push must target the default branch (main)');
});

test('workflow: least-privilege permissions (read-only + security-events write)', () => {
  const raw = fs.readFileSync(WORKFLOW_PATH, 'utf8');
  const doc = workflow();
  assert.deepEqual(doc.permissions, { contents: 'read', 'security-events': 'write' });
  assert.ok(!/^\s*write-all\s*$/m.test(raw), 'must never use a bare write-all permission');
  assert.ok(!/permissions:[^\n]*write-all/m.test(raw), 'must never use permissions: write-all');
  assert.ok(!/issues:\s*write/.test(raw), 'must not write issues');
  assert.ok(!/pull-requests:\s*write/.test(raw), 'must not write pull-requests');
});

test('workflow: fork-safe - no pull_request_target and no secrets/credentials', () => {
  const raw = fs.readFileSync(WORKFLOW_PATH, 'utf8');
  assert.ok(!/pull_request_target/.test(raw), 'must never use pull_request_target');
  assert.ok(!/\${{ *secrets\./.test(raw), 'must not reference any GitHub secrets');
  const upper = raw.toUpperCase();
  for (const token of [
    'API_KEY', 'OPENROUTER', 'GEMINI', 'OLLAMA',
    'DATABASE_URL', 'MONGODB', 'MONGO_URI', 'JWT_SECRET', 'OPENAI',
  ]) {
    assert.ok(!upper.includes(token), `must not embed credential-looking token: ${token}`);
  }
});
test('workflow: scan step targets first-party src with sarif/fail-on flags', () => {
  const steps = workflow().jobs['security-scan'].steps;
  const scan = steps.find((s) => s.name && s.name.includes('Scan with VulnLens'));
  assert.ok(scan, 'scan step missing');
  const run = scan.run;
  assert.match(run, /vulnlens -- scan \bsrc\b/, 'target must be the literal first-party src tree');
  assert.match(run, /--format sarif/, 'must emit SARIF for Code Scanning');
  assert.match(run, /--output /, 'must write SARIF to a file');
  assert.match(run, /--fail-on /, 'must apply a fail-on threshold');
  assert.ok(run.includes('VULNLENS_FAIL_ON'), 'must read the configurable threshold variable');
  assert.ok(!/scan\s+\$/.test(run) && !/\${{ *inputs/.test(run), 'no user-supplied path interpolation');
});

test('workflow: env exposes VULNLENS_FAIL_ON with a high default', () => {
  const env = workflow().jobs['security-scan'].env || {};
  assert.ok(String(env.VULNLENS_FAIL_ON).includes("'high'"), 'default threshold must be high');
});

test('workflow: SARIF upload step uses codeql upload-sarif and runs even on gate fail', () => {
  const steps = workflow().jobs['security-scan'].steps;
  const upload = steps.find((s) => s.uses && s.uses.includes('upload-sarif'));
  assert.ok(upload, 'upload-sarif step missing');
  assert.match(upload.uses, /^github\/codeql-action\/upload-sarif@/);
  assert.ok(upload.with && String(upload.with.sarif_file).includes('vulnlens.sarif'));
  assert.ok(String(upload.if || '').includes('always()'), 'must upload even when the gate fails');
  assert.match(String(upload.if || ''), /hashFiles\(['"]vulnlens\.sarif['"]\)/);
});

test('workflow: exit code is captured then enforced without hiding failures', () => {
  const steps = workflow().jobs['security-scan'].steps;
  const scan = steps.find((s) => s.name && s.name.includes('Scan with VulnLens'));
  const gate = steps[steps.length - 1];
  assert.ok(scan.run.includes('VULNLENS_EXIT='), 'scan step must capture the exit code');
  assert.match(gate.name, /Enforce security gate/);
  assert.ok(String(gate.if || '').includes('always()'), 'gate must run even when earlier steps fail');
  assert.ok(gate.run.includes('${VULNLENS_EXIT:-3}'), 'gate must default to 3 (fail-closed)');
  assert.ok(gate.run.includes('exit "$code"'), 'gate must re-exit with the captured code');
  assert.ok(!/exit 0/.test(gate.run), 'gate must never force a success exit');
});

test('workflow: runs in backend (install uses lockfile via npm ci)', () => {
  const doc = workflow();
  assert.equal(doc.defaults.run['working-directory'], 'backend');
  assert.ok(fs.existsSync(path.join(ROOT, 'backend', 'package.json')));
  assert.ok(fs.existsSync(path.join(ROOT, 'backend', 'package-lock.json')), 'lockfile must exist for npm ci');
});
// ── CLI exit-code + SARIF preservation contract ───────────────────────────

test('cli: clean file exits 0 with default fail-on high', () => {
  const file = tmpPath('clean.js');
  fs.writeFileSync(file, CLEAN_JS);
  assert.equal(runCli(['scan', file, '--fail-on', 'high']).status, 0);
});

test('cli: high finding exits 1 with high threshold AND SARIF is still written', () => {
  const dir = tmpPath('ci');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'vuln.js'), VULN_JS);
  const sarif = path.join(dir, 'vulnlens.sarif');
  const { status } = runCli([
    'scan', dir, '--format', 'sarif', '--output', sarif, '--fail-on', 'high', '--quiet',
  ]);
  assert.equal(status, 1, 'gate must fail on high');
  assert.ok(fs.existsSync(sarif), 'SARIF must be written even on gate failure');
  const json = JSON.parse(fs.readFileSync(sarif, 'utf8'));
  assert.equal(json.version, '2.1.0');
  assert.ok(Array.isArray(json.runs) && json.runs.length >= 1);
});

test('cli: fail-on none exits 0 even with high findings', () => {
  const dir = tmpPath('ci-none');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'vuln.js'), VULN_JS);
  const { status } = runCli(['scan', dir, '--fail-on', 'none']);
  assert.equal(status, 0);
});

test('cli: missing target exits 2 (workflow error)', () => {
  assert.equal(runCli(['scan']).status, 2);
  assert.equal(runCli(['scan', tmpPath('nope'), '--fail-on', 'high']).status, 2);
});

test('cli: invalid flag value exits 2 (workflow error)', () => {
  const file = tmpPath('clean2.js');
  fs.writeFileSync(file, CLEAN_JS);
  assert.equal(runCli(['scan', file, '--fail-on', 'bogus']).status, 2);
  assert.equal(runCli(['scan', file, '--format', 'xml']).status, 2);
});

test('cli: scanner/runtime errors map to exit 3 (documented contract)', () => {
  const src = fs.readFileSync(CLI_SRC, 'utf8');
  assert.match(src, /Error: Scanner error:/, 'scanner-error path must exist');
  assert.match(src, /Error: Formatting error:/, 'formatting-error path must exist');
  assert.ok((src.match(/return 3;/g) || []).length >= 2, 'both error branches must return 3');
});

// ── Phase 6E: baseline runtime immutability + workflow hardening ──────────

test('workflow: baseline SHA-256 is recorded before the scan and verified after', () => {
  const steps = workflow().jobs['security-scan'].steps;
  const names = steps.map((s) => s.name || '');
  const recordIdx = names.findIndex((n) => /Record baseline/i.test(n));
  const scanIdx = names.findIndex((n) => /Scan with VulnLens/.test(n));
  const verifyIdx = names.findIndex((n) => /Verify baseline/i.test(n));
  assert.ok(recordIdx >= 0, 'record step missing');
  assert.ok(verifyIdx >= 0, 'verify step missing');
  assert.ok(recordIdx < scanIdx, 'record must run before the scan');
  assert.ok(verifyIdx > scanIdx, 'verify must run after the scan');
  assert.ok(verifyIdx === steps.length - 2, 'verify must run right before the final gate step');

  const record = steps[recordIdx].run;
  assert.match(record, /sha256sum vulnlens\.baseline\.json/, 'record must hash the committed baseline');
  assert.match(record, /BASELINE_SHA256/, 'record must export the hash to GITHUB_ENV');

  const verify = steps[verifyIdx].run;
  assert.match(verify, /sha256sum vulnlens\.baseline\.json/, 'verify must recompute the hash');
  assert.match(verify, /BASELINE_SHA256/, 'verify must compare against the recorded hash');
  assert.match(verify, /exit 1/, 'verify must fail the job on mismatch');
  assert.ok(String(steps[verifyIdx].if || '').includes('always()'), 'verify must run even when the gate fails');
});

test('workflow: no hardcoded baseline hash - legitimate source changes pass', () => {
  const raw = fs.readFileSync(WORKFLOW_PATH, 'utf8');
  // A stale/hardcoded SHA-256 would reject a legitimately committed baseline
  // change; the check must always hash the checked-out file at job start.
  assert.ok(!/[0-9a-f]{64}/.test(raw), 'workflow must not embed a fixed SHA-256 literal');
  const record = workflow().jobs['security-scan'].steps.find((s) => /Record baseline/i.test(s.name || '')).run;
  assert.match(record, /sha256sum vulnlens\.baseline\.json/, 'hash must be computed at job start, never hardcoded');
});

test('workflow: install uses lockfile-backed npm ci with --ignore-scripts', () => {
  const install = workflow().jobs['security-scan'].steps.find((s) => s.name && /Install dependencies/.test(s.name));
  assert.ok(install, 'install step missing');
  assert.match(install.run, /npm ci --ignore-scripts/, 'CI must not execute dependency lifecycle scripts');
});

test('workflow: every third-party action is pinned to a full commit SHA', () => {
  const raw = fs.readFileSync(WORKFLOW_PATH, 'utf8');
  const uses = [...raw.matchAll(/uses:\s*([^\s#]+)/g)].map((m) => m[1]);
  assert.ok(uses.length >= 3, 'expected checkout, setup-node and upload-sarif');
  for (const u of uses) {
    assert.match(
      u,
      /^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+(?:\/[A-Za-z0-9_.-]+)?@[0-9a-f]{40}$/,
      `action must be SHA-pinned (got: ${u})`
    );
  }
});

test('integrity: unchanged baseline hashes identically (record -> run -> verify)', () => {
  const file = tmpPath('immutable.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, entries: [] }));
  const record = spawnSync('bash', ['-c', `sha256sum "${file}" | awk '{print $1}'`], { encoding: 'utf8' });
  assert.equal(record.status, 0, 'record command must succeed');
  const verify = spawnSync('bash', ['-c', `sha256sum "${file}" | awk '{print $1}'`], { encoding: 'utf8' });
  assert.equal(verify.status, 0, 'verify command must succeed');
  assert.equal(verify.stdout.trim(), record.stdout.trim(), 'same contents must yield the same hash');
});

test('integrity: modified baseline hashes differently (runtime tampering detected)', () => {
  const file = tmpPath('tampered.json');
  fs.writeFileSync(file, JSON.stringify({ version: 1, entries: [] }));
  const before = spawnSync('bash', ['-c', `sha256sum "${file}" | awk '{print $1}'`], { encoding: 'utf8' }).stdout.trim();
  // Simulate a process modifying the baseline mid-job.
  fs.writeFileSync(file, JSON.stringify({ version: 1, entries: [{ filePath: 'a.js', ruleId: 'r', line: 1 }] }));
  const after = spawnSync('bash', ['-c', `sha256sum "${file}" | awk '{print $1}'`], { encoding: 'utf8' }).stdout.trim();
  assert.notEqual(after, before, 'a modified baseline must produce a different hash');
});
