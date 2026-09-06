/**
 * Phase 6D baseline-aware CI regression-intelligence tests.
 *
 * Contract under test:
 *   - NEW       : current finding whose baseline comparison key
 *                 (filePath::ruleId::line, see baselineSignature) is absent
 *                 from the baseline. Drives the --fail-on gate.
 *   - BASELINED : current finding whose key IS in the baseline. Stays visible
 *                 in every report; excluded from the gate UNLESS its severity
 *                 escalated past the severity recorded in the baseline entry.
 *   - RESOLVED  : baseline entry with no matching current finding. Reported,
 *                 never a current finding, never fails CI, never auto-removed.
 *
 * Invariants: baseline matching NEVER mutates severity / confidence /
 * evidence; baselined findings are never hidden; missing (explicit) /
 * malformed baselines are fail-visible (exit 2); no baseline behaves exactly
 * like Phase 6C.
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
  classifyBaseline,
} from '../src/cli/cli.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BACKEND_ROOT = path.resolve(__dirname, '..');
const BIN = path.join(BACKEND_ROOT, 'bin', 'vulnlens.js');

// Fixtures: a single-HIGH file (hardcoded-secret on line 1) and a two-HIGH file.
const SECRET_JS = "const secret = 'sk-abcdef1234567890supersecret';\n";
// Two HIGH findings on distinct lines (hardcoded-secret:1, hardcoded-awsAccessKey:2).
const TWO_SECRETS_JS =
  "const secret = 'sk-abcdef1234567890supersecret';\n" +
  "const awsKey = 'AKIAIOSFODNN7EXAMPLE';\n";

// One HIGH (hardcoded-secret:1) + one CRITICAL (hardcoded-awsSecretKey:2).
const HIGH_AND_CRITICAL_JS =
  "const secret = 'sk-abcdef1234567890supersecret';\n" +
  "const cfg = { aws_secret_access_key: 'ABCDEFGHIJKLMNOPQRST' };\n";

let tmpDir;
let tmpPath;
let workDir;

before(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnlens-6d-'));
  tmpPath = (name) => path.join(tmpDir, name);
  workDir = path.join(tmpDir, 'work');
  fs.mkdirSync(workDir, { recursive: true });
  fs.writeFileSync(path.join(workDir, 'vuln.js'), SECRET_JS);
  fs.writeFileSync(path.join(workDir, 'two.js'), TWO_SECRETS_JS);
  fs.writeFileSync(path.join(workDir, 'crit.js'), HIGH_AND_CRITICAL_JS);
});

after(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

function runCli(args, opts = {}) {
  const res = spawnSync(process.execPath, [BIN, ...args], {
    encoding: 'utf8',
    cwd: opts.cwd || workDir,
  });
  return { status: res.status, stdout: res.stdout || '', stderr: res.stderr || '' };
}

// ── Helpers ────────────────────────────────────────────────────────────────

/** Build a baseline-shaped object exactly like loadBaseline returns. */
function baselineOf(entries, filePath = '/tmp/baseline.json') {
  const keys = new Set();
  const entryByKey = new Map();
  for (const e of entries) {
    const key = baselineSignature(e.filePath, e.ruleId, e.line);
    keys.add(key);
    if (!entryByKey.has(key)) {
      entryByKey.set(key, {
        filePath: e.filePath,
        ruleId: e.ruleId,
        line: e.line,
        severity: e.severity,
        message: e.message || '',
      });
    }
  }
  return { keys, entries, entryByKey, filePath };
}

function finding(filePath, ruleId, line, severity, extra = {}) {
  return { filePath, ruleId, line, severity, ...extra };
}

function writeBaseline(file, entries) {
  fs.writeFileSync(file, JSON.stringify({ version: 1, entries }));
}

// ── Unit: classification core ──────────────────────────────────────────────

test('classifyBaseline: no baseline loaded -> every finding gated, no status attached', () => {
  const findings = [finding('a.js', 'eval', 1, 'high'), finding('b.js', 'md5', 2, 'medium')];
  const baseline = baselineOf([], null);
  const { gateFindings, resolved, counts } = classifyBaseline(findings, baseline);
  assert.equal(gateFindings.length, 2, 'no baseline must gate everything');
  assert.deepEqual(counts, { new: 0, baselined: 0, resolved: 0, escalated: 0 });
  assert.equal(resolved.length, 0);
  assert.equal(findings[0].baselineStatus, undefined, 'no status metadata without a baseline');
});

test('classifyBaseline: empty baseline -> all NEW and gated', () => {
  const findings = [finding('a.js', 'eval', 1, 'high')];
  const { gateFindings, counts } = classifyBaseline(findings, baselineOf([]));
  assert.equal(counts.new, 1);
  assert.equal(counts.baselined, 0);
  assert.deepEqual(gateFindings, findings);
  assert.equal(findings[0].baselineStatus, 'NEW');
});

test('classifyBaseline: exact match -> BASELINED, not gated, nothing resolved', () => {
  const findings = [finding('a.js', 'eval', 10, 'high')];
  const baseline = baselineOf([{ filePath: 'a.js', ruleId: 'eval', line: 10, severity: 'high' }]);
  const { gateFindings, counts, resolved } = classifyBaseline(findings, baseline);
  assert.equal(findings[0].baselineStatus, 'BASELINED');
  assert.equal(counts.baselined, 1);
  assert.equal(counts.new, 0);
  assert.equal(gateFindings.length, 0, 'baselined findings must not fail the gate');
  assert.equal(resolved.length, 0);
});

test('classifyBaseline: partial match -> A BASELINED, B NEW, unmatched entry RESOLVED', () => {
  const findings = [
    finding('a.js', 'rule-A', 1, 'high'),
    finding('b.js', 'rule-B', 2, 'high'),
  ];
  const baseline = baselineOf([
    { filePath: 'a.js', ruleId: 'rule-A', line: 1 },
    { filePath: 'c.js', ruleId: 'rule-C', line: 3 },
  ]);
  const { gateFindings, counts, resolved } = classifyBaseline(findings, baseline);
  assert.equal(findings[0].baselineStatus, 'BASELINED');
  assert.equal(findings[1].baselineStatus, 'NEW');
  assert.equal(counts.baselined, 1);
  assert.equal(counts.new, 1);
  assert.equal(counts.resolved, 1);
  assert.deepEqual(gateFindings.map((f) => f.ruleId), ['rule-B'], 'only NEW findings gate');
  assert.equal(resolved[0].ruleId, 'rule-C');
  assert.equal(resolved[0].comparisonKey, 'c.js::rule-C::3');
});

test('classifyBaseline: resolved detection with two baseline entries (A kept, B resolved)', () => {
  const findings = [finding('a.js', 'rule-A', 1, 'high')];
  const baseline = baselineOf([
    { filePath: 'a.js', ruleId: 'rule-A', line: 1 },
    { filePath: 'b.js', ruleId: 'rule-B', line: 5 },
  ]);
  const { counts, resolved } = classifyBaseline(findings, baseline);
  assert.equal(counts.baselined, 1);
  assert.equal(counts.resolved, 1);
  assert.equal(resolved[0].ruleId, 'rule-B');
});

test('classifyBaseline: severity integrity + escalation policy (CRITICAL never downgraded)', () => {
  // Spec Test 5: baseline records HIGH, current finding is CRITICAL at the same
  // key. Identity still matches -> BASELINED; severity stays CRITICAL (baseline
  // matching NEVER mutates severity). Chosen CI policy: because the current
  // severity exceeds the recorded one, it is an escalation and is re-added to
  // the gate.
  const findings = [finding('a.js', 'rule-A', 1, 'critical')];
  const baseline = baselineOf([{ filePath: 'a.js', ruleId: 'rule-A', line: 1, severity: 'high' }]);
  const { gateFindings, counts } = classifyBaseline(findings, baseline);
  assert.equal(findings[0].baselineStatus, 'BASELINED');
  assert.equal(findings[0].severity, 'critical', 'severity must never be downgraded by a baseline');
  assert.equal(findings[0].baselineEscalated, true);
  assert.equal(counts.escalated, 1);
  assert.deepEqual(gateFindings, findings, 'escalated baselined finding must re-enter the gate');
});

test('classifyBaseline: no escalation when recorded severity is >= current', () => {
  const same = [finding('a.js', 'rule-A', 1, 'high')];
  const sameBase = baselineOf([{ filePath: 'a.js', ruleId: 'rule-A', line: 1, severity: 'high' }]);
  const { gateFindings: sameGate, counts: sameCounts } = classifyBaseline(same, sameBase);
  assert.equal(sameGate.length, 0);
  assert.equal(sameCounts.escalated, 0);

  const downgraded = [finding('a.js', 'rule-A', 1, 'medium')];
  const downgradeBase = baselineOf([{ filePath: 'a.js', ruleId: 'rule-A', line: 1, severity: 'high' }]);
  const { gateFindings: downgradeGate, counts: downgradeCounts } = classifyBaseline(downgraded, downgradeBase);
  assert.equal(downgradeGate.length, 0, 'a finding that got LESS severe must not escalate');
  assert.equal(downgradeCounts.escalated, 0);
});

test('classifyBaseline: entries without recorded severity never escalate (Phase 6C compat)', () => {
  const findings = [finding('a.js', 'rule-A', 1, 'critical')];
  const baseline = baselineOf([{ filePath: 'a.js', ruleId: 'rule-A', line: 1 }]);
  const { gateFindings, counts } = classifyBaseline(findings, baseline);
  assert.equal(findings[0].baselineStatus, 'BASELINED');
  assert.equal(findings[0].severity, 'critical');
  assert.equal(counts.escalated, 0);
  assert.equal(gateFindings.length, 0, 'no recorded severity -> gate exactly like Phase 6C');
});

test('classifyBaseline: location change -> NEW (line is part of the documented identity)', () => {
  // Spec Test 6: baseline pins line 10; current finding is on line 25. Line is
  // part of the comparison key, so the finding no longer matches and is
  // classified NEW (fail-safe drift), while the old entry becomes RESOLVED.
  const findings = [finding('a.js', 'rule-A', 25, 'high')];
  const baseline = baselineOf([{ filePath: 'a.js', ruleId: 'rule-A', line: 10, severity: 'high' }]);
  const { gateFindings, counts, resolved } = classifyBaseline(findings, baseline);
  assert.equal(findings[0].baselineStatus, 'NEW');
  assert.equal(counts.new, 1);
  assert.equal(counts.resolved, 1);
  assert.equal(resolved[0].line, 10);
  assert.deepEqual(gateFindings, findings);
});

test('classifyBaseline: resolved entries carry baseline metadata (severity, message, key)', () => {
  const findings = [finding('a.js', 'rule-A', 1, 'high')];
  const baseline = baselineOf([
    { filePath: 'a.js', ruleId: 'rule-A', line: 1 },
    { filePath: 'b.js', ruleId: 'rule-B', line: 9, severity: 'high', message: 'moved to secure code' },
  ]);
  const { resolved } = classifyBaseline(findings, baseline);
  assert.equal(resolved.length, 1);
  assert.equal(resolved[0].filePath, 'b.js');
  assert.equal(resolved[0].ruleId, 'rule-B');
  assert.equal(resolved[0].line, 9);
  assert.equal(resolved[0].severity, 'high');
  assert.equal(resolved[0].message, 'moved to secure code');
  assert.equal(resolved[0].comparisonKey, 'b.js::rule-B::9');
});

test('classifyBaseline: duplicate baseline entries collapse to a single resolved entry', () => {
  const baseline = baselineOf([
    { filePath: 'a.js', ruleId: 'rule-A', line: 1 },
    { filePath: 'a.js', ruleId: 'rule-A', line: 1 },
  ]);
  const { counts, resolved } = classifyBaseline([], baseline);
  assert.equal(counts.resolved, 1);
  assert.equal(resolved.length, 1);
});

// ── Unit: loadBaseline validation (fail-visible, never silent) ─────────────

test('loadBaseline: rejects non-integer, float and negative line values', () => {
  writeBaseline(tmpPath('line-bad.json'), [{ filePath: 'a.js', ruleId: 'r', line: 'ten' }]);
  assert.throws(() => loadBaseline(tmpPath('line-bad.json'), { explicit: true }));
  writeBaseline(tmpPath('line-float.json'), [{ filePath: 'a.js', ruleId: 'r', line: 1.5 }]);
  assert.throws(() => loadBaseline(tmpPath('line-float.json'), { explicit: true }));
  writeBaseline(tmpPath('line-neg.json'), [{ filePath: 'a.js', ruleId: 'r', line: -1 }]);
  assert.throws(() => loadBaseline(tmpPath('line-neg.json'), { explicit: true }));
});

test('loadBaseline: rejects unknown severity values', () => {
  writeBaseline(tmpPath('sev-bad.json'), [{ filePath: 'a.js', ruleId: 'r', line: 1, severity: 'insane' }]);
  assert.throws(() => loadBaseline(tmpPath('sev-bad.json'), { explicit: true }));
});

test('loadBaseline: accepts optional severity and message (additive, backward compatible)', () => {
  writeBaseline(tmpPath('sev-ok.json'), [
    { filePath: 'a.js', ruleId: 'r', line: 1, severity: 'HIGH', message: 'reviewed' },
  ]);
  const b = loadBaseline(tmpPath('sev-ok.json'), { explicit: true });
  assert.equal(b.keys.size, 1);
  const entry = b.entryByKey.get('a.js::r::1');
  assert.equal(entry.severity, 'high', 'severity must be normalized to lowercase');
  assert.equal(entry.message, 'reviewed');
});

test('loadBaseline: rejects control characters and overlong fields', () => {
  writeBaseline(tmpPath('ctrl.json'), [{ filePath: 'a\u0000b.js', ruleId: 'r', line: 1 }]);
  assert.throws(() => loadBaseline(tmpPath('ctrl.json'), { explicit: true }));
  writeBaseline(tmpPath('long.json'), [{ filePath: 'a.js', ruleId: 'r'.repeat(200), line: 1 }]);
  assert.throws(() => loadBaseline(tmpPath('long.json'), { explicit: true }));
});

test('loadBaseline: missing file is an error only when explicit (auto-discovery safe)', () => {
  assert.throws(() => loadBaseline('nope.json', { explicit: true, cwd: workDir }));
  const empty = loadBaseline('nope.json', { explicit: false, cwd: workDir });
  assert.equal(empty.keys.size, 0);
  assert.equal(empty.filePath, null);
});

// ── Unit: deterministic comparison key (spec Test 12) ──────────────────────

test('baselineSignature: deterministic across repeated calls and platforms', () => {
  for (let i = 0; i < 5; i++) {
    assert.equal(baselineSignature('src/a/b.js', 'eval', 10), 'src/a/b.js::eval::10');
  }
  assert.equal(
    baselineSignature('src\\a\\b.js', 'eval', 10),
    baselineSignature('src/a/b.js', 'eval', 10),
    'Windows and POSIX separators must produce the same key'
  );
  assert.equal(baselineSignature('/src/a/b.js', 'eval', 10), 'src/a/b.js::eval::10');
  assert.equal(baselineSignature('src/a/b.js', 'eval', 0), 'src/a/b.js::eval::0');
});

// ── Integration: CLI behavior matrix ───────────────────────────────────────

test('cli: empty baseline -> finding is NEW and the gate fails (Test 1)', () => {
  writeBaseline(path.join(workDir, 'base.json'), []);
  const { status, stdout } = runCli(['scan', 'vuln.js', '--format', 'json', '--baseline', 'base.json', '--fail-on', 'high']);
  assert.equal(status, 1, 'NEW high must fail');
  const json = JSON.parse(stdout);
  const f = json.findings.find((x) => x.ruleId === 'hardcoded-secret');
  assert.equal(f.baselineStatus, 'NEW');
  assert.equal(json.baseline.new, 1);
  assert.equal(json.baseline.baselined, 0);
  assert.equal(json.findings[0].severity, 'high');
});

test('cli: matching baseline -> BASELINED and the gate passes (Test 2)', () => {
  writeBaseline(path.join(workDir, 'base.json'), [
    { filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 1, severity: 'high' },
  ]);
  const { status, stdout } = runCli(['scan', 'vuln.js', '--format', 'json', '--baseline', 'base.json', '--fail-on', 'high']);
  assert.equal(status, 0, 'baselined high must not fail');
  const json = JSON.parse(stdout);
  const f = json.findings.find((x) => x.ruleId === 'hardcoded-secret');
  assert.equal(f.baselineStatus, 'BASELINED');
  assert.equal(f.severity, 'high', 'baseline must never mutate severity');
  assert.equal(json.baseline.baselined, 1);
  assert.equal(json.baseline.resolved, 0);
});

test('cli: resolved baseline entries are reported and never fail the gate (Test 3)', () => {
  writeBaseline(path.join(workDir, 'base.json'), [
    { filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 1 },
    { filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 99, severity: 'high' },
  ]);
  const { status, stdout } = runCli(['scan', 'vuln.js', '--format', 'json', '--baseline', 'base.json', '--fail-on', 'high']);
  assert.equal(status, 0, 'resolved entries must not fail CI');
  const json = JSON.parse(stdout);
  assert.equal(json.baseline.baselined, 1);
  assert.equal(json.baseline.resolved, 1);
  assert.equal(json.baseline.resolvedEntries.length, 1);
  assert.equal(json.baseline.resolvedEntries[0].line, 99);
  assert.equal(json.baseline.resolvedEntries[0].severity, 'high');
  assert.equal(json.findings.length, 1, 'resolved entries are not current findings');
});

test('cli: new HIGH alongside a baselined HIGH -> gate fails, both visible (Test 4)', () => {
  writeBaseline(path.join(workDir, 'base.json'), [
    { filePath: 'two.js', ruleId: 'hardcoded-secret', line: 1 },
  ]);
  const { status, stdout } = runCli(['scan', 'two.js', '--format', 'json', '--baseline', 'base.json', '--fail-on', 'high']);
  assert.equal(status, 1, 'NEW high alongside baselined must fail');
  const json = JSON.parse(stdout);
  assert.ok(json.findings.length >= 2, 'all findings must remain visible');
  const byLine = Object.fromEntries(json.findings.map((x) => [x.line, x.baselineStatus]));
  assert.equal(byLine[1], 'BASELINED');
  assert.equal(byLine[2], 'NEW');
  assert.ok(json.findings.every((x) => x.severity === 'high'), 'severity must never be mutated');
});

test('cli: escalation policy — recorded low + current high -> BASELINED but gate fails (Test 5)', () => {
  writeBaseline(path.join(workDir, 'base.json'), [
    { filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 1, severity: 'low' },
  ]);
  const { status, stdout } = runCli(['scan', 'vuln.js', '--format', 'json', '--baseline', 'base.json', '--fail-on', 'high']);
  assert.equal(status, 1, 'severity escalation must re-enter the gate');
  const json = JSON.parse(stdout);
  const f = json.findings.find((x) => x.ruleId === 'hardcoded-secret');
  assert.equal(f.baselineStatus, 'BASELINED', 'identity matched -> still BASELINED');
  assert.equal(f.severity, 'high', 'severity never mutated');
  assert.equal(f.baselineEscalated, true);
  assert.equal(json.baseline.escalated, 1);
});

test('cli: recorded severity equal to current -> gate passes (no escalation)', () => {
  writeBaseline(path.join(workDir, 'base.json'), [
    { filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 1, severity: 'high' },
  ]);
  const { status, stdout } = runCli(['scan', 'vuln.js', '--format', 'json', '--baseline', 'base.json', '--fail-on', 'high']);
  assert.equal(status, 0);
  const json = JSON.parse(stdout);
  assert.equal(json.baseline.escalated, 0);
});

test('cli: BASELINED HIGH + NEW CRITICAL together -> gate fails, both visible', () => {
  writeBaseline(path.join(workDir, 'base.json'), [
    { filePath: 'crit.js', ruleId: 'hardcoded-secret', line: 1 },
  ]);
  const { status, stdout } = runCli(['scan', 'crit.js', '--format', 'json', '--baseline', 'base.json', '--fail-on', 'high']);
  assert.equal(status, 1, 'NEW critical must fail the gate alongside a baselined high');
  const json = JSON.parse(stdout);
  const byLine = Object.fromEntries(json.findings.map((x) => [x.line, { status: x.baselineStatus, sev: x.severity }]));
  assert.equal(byLine[1].status, 'BASELINED');
  assert.equal(byLine[1].sev, 'high', 'baselined high must stay high');
  assert.equal(byLine[2].status, 'NEW');
  assert.equal(byLine[2].sev, 'critical', 'new critical must stay critical');
  assert.equal(json.baseline.baselined, 1);
  assert.equal(json.baseline.new, 1);
  // Also fails at the stricter --fail-on critical threshold.
  const strict = runCli(['scan', 'crit.js', '--format', 'json', '--baseline', 'base.json', '--fail-on', 'critical']);
  assert.equal(strict.status, 1, 'NEW critical must fail --fail-on critical');
});

test('cli: line move -> NEW (documented identity model) and gate fails (Test 6)', () => {
  writeBaseline(path.join(workDir, 'base.json'), [
    { filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 10, severity: 'high' },
  ]);
  const { status, stdout } = runCli(['scan', 'vuln.js', '--format', 'json', '--baseline', 'base.json', '--fail-on', 'high']);
  assert.equal(status, 1, 'drifted finding must return to the gate (fail-safe)');
  const json = JSON.parse(stdout);
  const f = json.findings.find((x) => x.ruleId === 'hardcoded-secret');
  assert.equal(f.baselineStatus, 'NEW');
  assert.equal(json.baseline.resolved, 1, 'stale line-10 entry is reported resolved');
});

test('cli: explicit --baseline with a missing file exits 2 (Test 7)', () => {
  const { status, stderr } = runCli(['scan', 'vuln.js', '--fail-on', 'high', '--baseline', 'definitely-missing.json']);
  assert.equal(status, 2);
  assert.ok(stderr.includes('not found'));
});

test('cli: malformed baseline (invalid severity) exits 2, never bypasses CI (Test 8)', () => {
  writeBaseline(tmpPath('bad-sev.json'), [
    { filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 1, severity: 'catastrophic' },
  ]);
  const { status } = runCli(['scan', 'vuln.js', '--fail-on', 'high', '--baseline', tmpPath('bad-sev.json')]);
  assert.equal(status, 2);
});

test('cli: baseline is automatically discovered from the working directory (Test 9)', () => {
  writeBaseline(path.join(workDir, 'vulnlens.baseline.json'), [
    { filePath: 'vuln.js', ruleId: 'hardcoded-secret', line: 1 },
  ]);
  const { status, stdout } = runCli(['scan', 'vuln.js', '--format', 'json', '--fail-on', 'high']);
  assert.equal(status, 0, 'auto-discovered baseline must apply');
  const json = JSON.parse(stdout);
  assert.ok(json.baseline, 'baseline summary must be present');
  assert.equal(json.findings.find((x) => x.ruleId === 'hardcoded-secret').baselineStatus, 'BASELINED');
  fs.unlinkSync(path.join(workDir, 'vulnlens.baseline.json'));
});

test('cli: no baseline -> normal scanner behavior, no baseline fields, gate unchanged (Test 10)', () => {
  fs.rmSync(path.join(workDir, 'vulnlens.baseline.json'), { force: true });
  const { status, stdout } = runCli(['scan', 'vuln.js', '--format', 'json', '--fail-on', 'high']);
  assert.equal(status, 1);
  const json = JSON.parse(stdout);
  assert.equal(json.baseline, undefined, 'no baseline summary when no baseline is loaded');
  assert.equal(json.findings[0].baselineStatus, undefined, 'no status metadata when no baseline');
  assert.equal(json.findings.length, 1);
  assert.equal(json.findings[0].severity, 'high');
});

test('cli: SARIF retains NEW and BASELINED findings with status, valid 2.1.0 (Test 11)', () => {
  writeBaseline(path.join(workDir, 'base.json'), [
    { filePath: 'two.js', ruleId: 'hardcoded-secret', line: 1 },
  ]);
  const { status, stdout } = runCli(['scan', 'two.js', '--format', 'sarif', '--baseline', 'base.json', '--fail-on', 'high']);
  assert.equal(status, 1, 'the NEW finding must still fail the gate');
  const json = JSON.parse(stdout);
  assert.equal(json.version, '2.1.0');
  const results = json.runs[0].results;
  assert.ok(results.length >= 2, 'baselined findings must remain in SARIF');
  const statuses = results.map((r) => r.properties && r.properties.baselineStatus);
  assert.ok(statuses.includes('BASELINED'), 'BASELINED result must carry status');
  assert.ok(statuses.includes('NEW'), 'NEW result must carry status');
});

test('cli: self-scan regression against the committed Phase 6C baseline (Test 13)', () => {
  // Runs the real CLI over the project's own backend/src with the committed
  // 17-entry baseline. Expected: every HIGH finding is BASELINED (reviewed
  // self-references), zero RESOLVED (no drift), zero escalations, gate green.
  const res = spawnSync(process.execPath, [
    BIN, 'scan', 'src', '--format', 'json',
    '--baseline', 'vulnlens.baseline.json', '--fail-on', 'high',
  ], { encoding: 'utf8', cwd: BACKEND_ROOT });
  assert.equal(res.status, 0, `self-scan must pass with the committed baseline: ${res.stderr}`);
  const json = JSON.parse(res.stdout);
  assert.ok(json.baseline, 'baseline summary expected');
  assert.equal(json.baseline.resolved, 0, 'no baselined self-reference may drift');
  assert.equal(json.baseline.escalated, 0);
  assert.equal(json.baseline.new + json.baseline.baselined, json.findingsCount);
  const highFindings = json.findings.filter((f) => f.severity === 'high');
  assert.ok(highFindings.length >= 1, 'self-scan should still surface HIGH self-references');
  for (const f of highFindings) {
    assert.equal(f.baselineStatus, 'BASELINED', `${f.ruleId}@${f.filePath}:${f.line} must be baselined`);
  }
});