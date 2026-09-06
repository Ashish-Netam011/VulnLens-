/**
 * CLI tests (Phase 6A).
 *
 * Two layers:
 *  1. Unit tests for the pure CLI helpers (parseArgs, discoverFiles,
 *     formatTable, formatJson, formatSarif, deriveExitCode).
 *  2. Integration tests that spawn the actual binary and assert on
 *     stdout/stderr/exit codes.
 *
 * All scanner fixtures live in an OS temp directory created per suite.
 */
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

import {
  parseArgs,
  discoverFiles,
  deriveExitCode,
  formatTable,
  formatJson,
  formatSarif,
  getHelp,
  getVersion,
  CLI_VERSION,
  SEVERITY_RANK,
} from '../src/cli/cli.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const BIN = path.join(__dirname, '..', 'bin', 'vulnlens.js');

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
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'vulnlens-cli-'));
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

// ── parseArgs ──────────────────────────────────────────────────────────────

test('parseArgs: no args yields help', () => {
  const p = parseArgs(['node', 'vulnlens.js']);
  assert.equal(p.help, true);
});

test('parseArgs: --help and -h', () => {
  assert.equal(parseArgs(['x', 'y', '--help']).help, true);
  assert.equal(parseArgs(['x', 'y', '-h']).help, true);
});

test('parseArgs: --version and -V', () => {
  assert.equal(parseArgs(['x', 'y', '--version']).version, true);
  assert.equal(parseArgs(['x', 'y', '-V']).version, true);
});

test('parseArgs: unknown command yields error', () => {
  const p = parseArgs(['x', 'y', 'frobnicate', './x']);
  assert.ok(p.errors.some((e) => e.includes('Unknown command')));
});

test('parseArgs: scan with target + format json', () => {
  const p = parseArgs(['x', 'y', 'scan', './src', '--format', 'json']);
  assert.equal(p.command, 'scan');
  assert.equal(p.target, './src');
  assert.equal(p.format, 'json');
  assert.equal(p.errors.length, 0);
});

test('parseArgs: scan without target yields error', () => {
  const p = parseArgs(['x', 'y', 'scan']);
  assert.ok(p.errors.some((e) => e.includes('Missing target')));
});

test('parseArgs: invalid format yields error', () => {
  const p = parseArgs(['x', 'y', 'scan', './src', '--format', 'xml']);
  assert.ok(p.errors.some((e) => e.includes('Invalid format')));
});

test('parseArgs: format is case-insensitive', () => {
  assert.equal(parseArgs(['x', 'y', 'scan', '.', '--format', 'SARIF']).format, 'sarif');
});

test('parseArgs: --fail-on accepts valid severities', () => {
  assert.equal(parseArgs(['x', 'y', 'scan', '.', '--fail-on', 'none']).failOn, 'none');
  assert.equal(parseArgs(['x', 'y', 'scan', '.', '--fail-on', 'critical']).failOn, 'critical');
  const bad = parseArgs(['x', 'y', 'scan', '.', '--fail-on', 'insane']);
  assert.ok(bad.errors.some((e) => e.includes('Invalid severity')));
});

test('parseArgs: --output and --quiet', () => {
  const p = parseArgs(['x', 'y', 'scan', '.', '--output', 'r.json', '--quiet']);
  assert.equal(p.output, 'r.json');
  assert.equal(p.quiet, true);
});

test('parseArgs: unknown flag yields error', () => {
  const p = parseArgs(['x', 'y', 'scan', '.', '--bogus']);
  assert.ok(p.errors.some((e) => e.includes('Unknown option')));
});

// ── deriveExitCode ─────────────────────────────────────────────────────────

test('deriveExitCode: default high threshold', () => {
  assert.equal(deriveExitCode([{ severity: 'critical' }], 'high'), 1);
  assert.equal(deriveExitCode([{ severity: 'high' }], 'high'), 1);
  assert.equal(deriveExitCode([{ severity: 'medium' }], 'high'), 0);
  assert.equal(deriveExitCode([{ severity: 'low' }], 'high'), 0);
});

test('deriveExitCode: none never fails', () => {
  assert.equal(deriveExitCode([{ severity: 'critical' }], 'none'), 0);
  assert.equal(deriveExitCode([{ severity: 'low' }], 'none'), 0);
  assert.equal(deriveExitCode([], 'none'), 0);
});

test('deriveExitCode: threshold boundary', () => {
  assert.equal(deriveExitCode([{ severity: 'medium' }], 'medium'), 1);
  assert.equal(deriveExitCode([{ severity: 'low' }], 'medium'), 0);
  assert.equal(deriveExitCode([{ severity: 'critical' }], 'critical'), 1);
  assert.equal(deriveExitCode([{ severity: 'high' }], 'critical'), 0);
});

test('deriveExitCode: empty findings never fails', () => {
  assert.equal(deriveExitCode([], 'high'), 0);
  assert.equal(deriveExitCode([], 'low'), 0);
});

test('SEVERITY_RANK ordering', () => {
  assert.ok(SEVERITY_RANK.critical > SEVERITY_RANK.high);
  assert.ok(SEVERITY_RANK.high > SEVERITY_RANK.medium);
  assert.ok(SEVERITY_RANK.medium > SEVERITY_RANK.low);
  assert.ok(SEVERITY_RANK.low > SEVERITY_RANK.informational);
});

// ── discoverFiles ──────────────────────────────────────────────────────────

test('discoverFiles: finds supported files recursively, skips unsupported', () => {
  fs.mkdirSync(path.join(tmpDir, 'tree', 'sub'), { recursive: true });
  fs.writeFileSync(path.join(tmpDir, 'tree', 'a.js'), 'x');
  fs.writeFileSync(path.join(tmpDir, 'tree', 'sub', 'b.py'), 'y');
  fs.writeFileSync(path.join(tmpDir, 'tree', 'bin.exe'), 'MZ');

  const { files } = discoverFiles(path.join(tmpDir, 'tree'));
  const names = files.map((f) => f.path.replace(/\\/g, '/'));
  assert.ok(names.some((n) => n.endsWith('a.js')));
  assert.ok(names.some((n) => n.endsWith('b.py')));
  assert.ok(!names.some((n) => n.includes('bin.exe')));
});

test('discoverFiles: skips binary files (NUL byte)', () => {
  fs.mkdirSync(path.join(tmpDir, 'bin'), { recursive: true });
  fs.writeFileSync(path.join(tmpDir, 'bin', 'data.js'), Buffer.from([0x00, 0x01, 0x02, 0x03]));
  fs.writeFileSync(path.join(tmpDir, 'bin', 'ok.js'), 'const a = 1;');

  const { files } = discoverFiles(path.join(tmpDir, 'bin'));
  assert.equal(files.length, 1);
  assert.ok(files[0].path.endsWith('ok.js'));
});

test('discoverFiles: respects maxFiles limit', () => {
  fs.mkdirSync(path.join(tmpDir, 'many'), { recursive: true });
  for (let i = 0; i < 10; i++) {
    fs.writeFileSync(path.join(tmpDir, 'many', `f${i}.js`), 'x');
  }
  const { files, truncated } = discoverFiles(path.join(tmpDir, 'many'), { maxFiles: 3 });
  assert.ok(files.length <= 3);
  assert.equal(truncated, true);
  assert.ok(files.length > 0);
});

test('discoverFiles: empty directory yields no files', () => {
  fs.mkdirSync(path.join(tmpDir, 'empty'), { recursive: true });
  const { files } = discoverFiles(path.join(tmpDir, 'empty'));
  assert.equal(files.length, 0);
});

// ── getHelp / getVersion ───────────────────────────────────────────────────

test('getVersion includes CLI version', () => {
  assert.ok(getVersion().includes(CLI_VERSION));
});

test('getHelp documents options and exit codes', () => {
  const help = getHelp();
  assert.ok(help.includes('--format'));
  assert.ok(help.includes('--fail-on'));
  assert.ok(help.includes('--output'));
  assert.ok(help.includes('Exit codes'));
});

// ── formatters (pure) ──────────────────────────────────────────────────────

const sampleFindings = [
  {
    ruleId: 'hardcoded-secret',
    vulnerabilityType: 'Hardcoded Secret',
    title: 't',
    severity: 'high',
    confidence: 90,
    line: 6,
    filePath: 'a.js',
    ai: { explanation: 'x' }, // must be stripped in JSON
    _ruleEnrichment: 'internal',
  },
];

const sampleResult = {
  findings: sampleFindings,
  severityCounts: { critical: 0, high: 1, medium: 0, low: 0, informational: 0 },
  riskScore: 90,
  fileCount: 1,
  filePaths: ['a.js'],
};

test('formatJson: produces parseable JSON with expected keys', () => {
  const text = formatJson(sampleResult, 'a.js');
  const json = JSON.parse(text);
  assert.equal(json.tool, 'VulnLens');
  assert.equal(json.version, CLI_VERSION);
  assert.equal(json.target, 'a.js');
  assert.equal(json.findingsCount, 1);
  assert.equal(json.riskScore, 90);
  assert.equal(json.severityCounts.high, 1);
  assert.equal(json.findings[0].ruleId, 'hardcoded-secret');
  // AI fields must not leak into CLI output
  assert.equal(json.findings[0].ai, undefined);
});

test('formatTable: includes target, counts, severity and finding', () => {
  const text = formatTable(sampleResult, 'a.js');
  assert.ok(text.includes('a.js'));
  assert.ok(text.includes('Findings: 1'));
  assert.ok(text.includes('High'));
  assert.ok(text.includes('hardcoded-secret'));
});

test('formatSarif: produces valid SARIF 2.1.0', () => {
  const text = formatSarif(sampleResult);
  const json = JSON.parse(text);
  assert.equal(json.version, '2.1.0');
  assert.ok(Array.isArray(json.runs));
  assert.equal(json.runs[0].results.length, 1);
  assert.ok(Array.isArray(json.runs[0].tool.driver.rules));
});

// ── Integration (spawn binary) ─────────────────────────────────────────────

test('integration: --version exits 0 and prints version', () => {
  const { status, stdout } = runCli(['--version']);
  assert.equal(status, 0);
  assert.ok(stdout.includes(CLI_VERSION));
});

test('integration: --help exits 0', () => {
  const { status, stdout } = runCli(['--help']);
  assert.equal(status, 0);
  assert.ok(stdout.includes('Exit codes'));
});

test('integration: clean file exits 0', () => {
  const file = tmpPath('clean.js');
  fs.writeFileSync(file, CLEAN_JS);
  const { status, stdout } = runCli(['scan', file, '--format', 'json']);
  assert.equal(status, 0);
  const json = JSON.parse(stdout);
  assert.equal(json.findingsCount, 0);
});

test('integration: vulnerable file defaults to high threshold -> exit 1', () => {
  const file = tmpPath('vuln.js');
  fs.writeFileSync(file, VULN_JS);
  const { status, stdout } = runCli(['scan', file, '--format', 'json']);
  assert.equal(status, 1);
  const json = JSON.parse(stdout);
  assert.ok(json.findingsCount >= 1);
});

test('integration: secret value is masked in output', () => {
  const file = tmpPath('vuln.js');
  fs.writeFileSync(file, VULN_JS);
  const { stdout } = runCli(['scan', file, '--format', 'json']);
  assert.ok(!stdout.includes('sk-abcdef1234567890supersecret'));
});

test('integration: --fail-on none exits 0 even with findings', () => {
  const file = tmpPath('vuln.js');
  fs.writeFileSync(file, VULN_JS);
  const { status } = runCli(['scan', file, '--fail-on', 'none']);
  assert.equal(status, 0);
});

test('integration: --fail-on critical exits 0 when no critical finding', () => {
  const file = tmpPath('vuln.js');
  fs.writeFileSync(file, VULN_JS);
  const { status } = runCli(['scan', file, '--fail-on', 'critical']);
  assert.equal(status, 0);
});

test('integration: nonexistent target exits 2', () => {
  const { status, stderr } = runCli(['scan', tmpPath('does-not-exist')]);
  assert.equal(status, 2);
  assert.ok(stderr.toLowerCase().includes('does not exist'));
});

test('integration: missing path exits 2', () => {
  const { status } = runCli(['scan']);
  assert.equal(status, 2);
});

test('integration: invalid format exits 2', () => {
  const file = tmpPath('clean.js');
  fs.writeFileSync(file, CLEAN_JS);
  const { status } = runCli(['scan', file, '--format', 'xml']);
  assert.equal(status, 2);
});

test('integration: unsupported file type exits 2', () => {
  const file = tmpPath('blob.exe');
  fs.writeFileSync(file, 'MZ');
  const { status, stderr } = runCli(['scan', file]);
  assert.equal(status, 2);
  assert.ok(stderr.toLowerCase().includes('unsupported'));
});

test('integration: --output writes file and summary to stderr', () => {
  const dir = tmpPath('out');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'vuln.js');
  fs.writeFileSync(file, VULN_JS);
  const outFile = path.join(dir, 'report.json');

  const { status, stdout, stderr } = runCli(['scan', file, '--format', 'json', '--output', outFile]);
  assert.equal(status, 1);
  assert.equal(stdout, ''); // full payload must not leak to stdout
  assert.ok(stderr.includes('written to'));
  const json = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.ok(json.findingsCount >= 1);
});

test('integration: --output with --quiet prints no summary', () => {
  const dir = tmpPath('out2');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'vuln.js');
  fs.writeFileSync(file, VULN_JS);
  const outFile = path.join(dir, 'report.json');

  const { stderr } = runCli(['scan', file, '--format', 'json', '--output', outFile, '--quiet']);
  assert.equal(stderr, '');
});

test('integration: sarif command writes valid sarif to file', () => {
  const dir = tmpPath('out3');
  fs.mkdirSync(dir, { recursive: true });
  const file = path.join(dir, 'vuln.js');
  fs.writeFileSync(file, VULN_JS);
  const outFile = path.join(dir, 'report.sarif');

  const { status } = runCli(['scan', file, '--format', 'sarif', '--output', outFile, '--quiet']);
  assert.equal(status, 1);
  const json = JSON.parse(fs.readFileSync(outFile, 'utf8'));
  assert.equal(json.version, '2.1.0');
});

test('integration: scan directory recursively', () => {
  const dir = tmpPath('pkg');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'a.js'), VULN_JS);
  fs.writeFileSync(path.join(dir, 'b.js'), CLEAN_JS);

  const { status, stdout } = runCli(['scan', dir, '--format', 'json']);
  assert.equal(status, 1);
  const json = JSON.parse(stdout);
  assert.ok(json.files >= 2);
  assert.ok(json.findingsCount >= 1);
});

test('integration: scan a single file target', () => {
  const file = tmpPath('single.js');
  fs.writeFileSync(file, VULN_JS);
  const { stdout } = runCli(['scan', file, '--format', 'json']);
  const json = JSON.parse(stdout);
  assert.equal(json.files, 1);
  assert.ok(json.findings.length >= 1);
});

test('integration: relative paths are relative and sanitized', () => {
  const dir = tmpPath('reldir');
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, 'a.js'), VULN_JS);
  const { stdout } = runCli(['scan', dir, '--format', 'json'], { cwd: dir });
  const json = JSON.parse(stdout);
  const p = json.findings[0].filePath;
  assert.ok(!path.isAbsolute(p), 'filePath must be relative');
  assert.ok(!p.includes('..'), 'filePath must be sanitized');
});




