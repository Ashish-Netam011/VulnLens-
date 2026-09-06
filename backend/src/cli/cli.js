/**
 * VulnLens CLI - Production command-line interface (Phase 6A).
 *
 * Exposes the existing VulnLens scanner pipeline as a deterministic,
 * AI-free CLI.  The pipeline runs exactly the same code paths as the web API.
 *
 * Design guarantees: no second engine, no AI, no network, no DB,
 * deterministic output, secure paths, no secret leakage.
 *
 * Phase 6C added baseline support (`--baseline`, auto-discovery of
 * vulnlens.baseline.json): matched findings stay VISIBLE but are excluded from
 * the --fail-on gate; missing (explicit) / malformed baselines are fail-visible
 * workflow errors (exit 2).
 *
 * Phase 6D adds baseline-aware regression intelligence: every current finding
 * is classified NEW or BASELINED, and baseline entries with no matching current
 * finding are reported RESOLVED. Baselined findings never mutate severity,
 * confidence, or evidence — only CI gating behavior changes. See
 * docs/baseline-regression-intelligence.md.
 *
 * Phase 8 adds an OPT-IN AI Security Copilot (`--explain`): deterministic
 * findings get structured explanations/remediation from the configured AI
 * provider. Normal scans stay deterministic, offline, and AI-free; --explain
 * never changes findings, baseline classification, SARIF, or exit codes.
 */

import fs from 'node:fs';
import path from 'node:path';
import { runScanner } from '../scanner/scanner.js';
import { calculateScore } from '../scanner/score.js';
import { buildSarifReport, serializeSarif } from '../services/sarifService.js';
import { allowedExtension, sanitizeRelativePath } from '../utils/validation.js';
import { explainFindingWithAI, MAX_EXPLAINED_FINDINGS } from '../ai/copilot.js';

// Constants ----------------------------------------------------------------

export const CLI_VERSION = '1.0.0';
export const MAX_FILES = 100;
export const MAX_TOTAL_CHARS = 5_000_000;

export const SEVERITY_RANK = Object.freeze({
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
  informational: 0,
});

const SEVERITY_LABELS = Object.freeze({
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
  informational: 'Info',
});

const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'informational'];

// Argument Parsing ---------------------------------------------------------

/**
 * Parse a process.argv-style array into a structured config object.
 */
export function parseArgs(argv) {
  const result = {
    command: null, target: null, format: 'table', output: null,
    failOn: 'high', quiet: false, version: false, help: false, errors: [],
    baseline: null, explain: false,
  };

  const args = argv.slice(2);
  if (args.length === 0) { result.help = true; return result; }

  let i = 0;
  while (i < args.length && args[i].startsWith('-')) {
    const flag = args[i];
    if (flag === '--version' || flag === '-V') { result.version = true; i++; continue; }
    if (flag === '--help' || flag === '-h') { result.help = true; i++; continue; }
    result.errors.push('Unknown option: ' + flag);
    i++;
  }

  if (i >= args.length) {
    if (!result.version && !result.help && result.errors.length === 0) {
      result.errors.push('Missing command. Usage: vulnlens scan <path>');
    }
    return result;
  }

  result.command = args[i++];
  if (result.command !== 'scan') {
    result.errors.push('Unknown command: ' + result.command + '. Available commands: scan');
    return result;
  }

  if (i < args.length && !args[i].startsWith('-')) {
    result.target = args[i++];
  } else {
    result.errors.push('Missing target path. Usage: vulnlens scan <path>');
  }

  while (i < args.length) {
    const arg = args[i];
    if (arg === '--version' || arg === '-V') { result.version = true; i++; continue; }
    if (arg === '--help' || arg === '-h') { result.help = true; i++; continue; }
    if (arg === '--quiet') { result.quiet = true; i++; continue; }
    if (arg === '--explain') { result.explain = true; i++; continue; }

    if (arg === '--format') {
      i++;
      if (i >= args.length) {
        result.errors.push('--format requires a value: table, json, or sarif');
      } else {
        const val = args[i].toLowerCase();
        if (!['table', 'json', 'sarif'].includes(val)) {
          result.errors.push('Invalid format: ' + args[i] + '. Supported: table, json, sarif');
        } else { result.format = val; }
        i++;
      }
      continue;
    }
    if (arg === '--output') {
      i++;
      if (i >= args.length) { result.errors.push('--output requires a file path'); }
      else { result.output = args[i]; i++; }
      continue;
    }
    if (arg === '--fail-on') {
      i++;
      if (i >= args.length) {
        result.errors.push('--fail-on requires a severity: critical, high, medium, low, or none');
      } else {
        const val = args[i].toLowerCase();
        if (!['critical', 'high', 'medium', 'low', 'none'].includes(val)) {
          result.errors.push('Invalid severity: ' + args[i] + '. Supported: critical, high, medium, low, none');
        } else { result.failOn = val; }
        i++;
      }
      continue;
    }
    if (arg === '--baseline') {
      i++;
      if (i >= args.length) {
        result.errors.push('--baseline requires a file path');
      } else { result.baseline = args[i]; i++; }
      continue;
    }
    result.errors.push('Unknown option: ' + arg);
    i++;
  }

  return result;
}

// Help & Version -----------------------------------------------------------

export function getHelp() {
  return `VulnLens AI - Security Scanner CLI

Usage:
  vulnlens scan <path> [options]

Options:
  --format <format>    Output format: table (default), json, sarif
  --output <file>      Write results to file instead of stdout
  --fail-on <severity> Exit code 1 if NEW findings meet threshold (default: high)
                         critical | high | medium | low | none
  --baseline <file>    Path to a committed baseline JSON. Findings matching it
                         are classified BASELINED (vs NEW / RESOLVED), stay
                         visible in all reports, and are excluded from the
                         --fail-on gate unless their severity escalated past
                         the severity recorded in the baseline entry.
                         (default: vulnlens.baseline.json in the working dir)
  --explain            Explain findings with the AI Security Copilot (opt-in,
                         requires a configured AI provider; findings, gate,
                         SARIF, and exit codes are never changed by AI)
  --quiet              Suppress stderr summary
  --version, -V        Print version
  --help, -h           Show this help

Examples:
  vulnlens scan ./src
  vulnlens scan ./src --format json
  vulnlens scan ./src --format sarif --output vulnlens.sarif
  vulnlens scan ./src --fail-on medium
  vulnlens scan ./src --baseline vulnlens.baseline.json
  vulnlens scan ./src --explain

Exit codes:
  0  Scan completed; no NEW findings meet failure threshold
  1  Scan completed; NEW findings meet failure threshold
  2  CLI usage or configuration error (incl. missing explicit / malformed baseline)
  3  Scanner or runtime error`;
}

export function getVersion() {
  return `VulnLens CLI v${CLI_VERSION}`;
}

// File Discovery -----------------------------------------------------------

/**
 * Recursively discover supported source files under a root directory.
 * Guarantees: deterministic ordering, no symlink traversal, respects limits,
 * skips binaries, returns safe relative sanitized paths.
 */
export function discoverFiles(root, opts = {}) {
  const maxFiles = opts.maxFiles ?? MAX_FILES;
  const maxTotalChars = opts.maxTotalChars ?? MAX_TOTAL_CHARS;
  const files = [];
  let totalChars = 0;
  let truncated = false;

  function walk(dir) {
    if (truncated || files.length >= maxFiles) return;
    let entries;
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }

    entries.sort((a, b) => {
      const aDir = a.isDirectory() ? 0 : 1;
      const bDir = b.isDirectory() ? 0 : 1;
      return aDir !== bDir ? aDir - bDir : a.name.localeCompare(b.name);
    });

    for (const entry of entries) {
      if (truncated || files.length >= maxFiles) { truncated = true; return; }
      const abs = path.join(dir, entry.name);
      if (entry.isSymbolicLink()) continue;
      if (entry.isDirectory()) { walk(abs); continue; }
      if (!entry.isFile()) continue;
      if (!allowedExtension(entry.name)) continue;

      let content;
      try {
        const buf = fs.readFileSync(abs);
        if (buf.subarray(0, 8192).includes(0)) continue; // binary
        content = buf.toString('utf8');
      } catch { continue; }

      if (totalChars + content.length > maxTotalChars) { truncated = true; break; }
      const relPath = sanitizeRelativePath(path.relative(process.cwd(), abs));
      if (!relPath) continue;
      totalChars += content.length;
      files.push({ path: relPath, content });
    }
  }

  walk(root);
  return { files, truncated };
}

// Scanning -----------------------------------------------------------------

function stripInternalFields(findings) {
  return findings.map(({ _ruleEnrichment, _ruleSeverity, ...rest }) => rest);
}

/**
 * Run the full VulnLens scanner pipeline on a target path.
 */
export function scanTarget(targetPath, targetLabel) {
  let files;
  const stat = fs.statSync(targetPath);

  if (stat.isFile()) {
    const buf = fs.readFileSync(targetPath);
    files = [{ path: targetLabel, content: buf.toString('utf8') }];
  } else if (stat.isDirectory()) {
    const { files: discovered } = discoverFiles(targetPath);
    if (discovered.length === 0) {
      return {
        findings: [],
        severityCounts: { critical: 0, high: 0, medium: 0, low: 0, informational: 0 },
        riskScore: 100, fileCount: 0, filePaths: [], truncated: false,
      };
    }
    files = discovered;
  } else {
    throw new Error('Target is not a file or directory');
  }

  const scanResult = runScanner(null, { files });
  let findings = scanResult.findings;
  const severityCounts = scanResult.severityCounts;
  findings = stripInternalFields(findings);
  const riskScore = calculateScore(severityCounts, { findings });
  const filePaths = [...new Set(findings.map((f) => f.filePath).filter(Boolean))];

  return { findings, severityCounts, riskScore, fileCount: files.length, filePaths, truncated: false };
}

// Formatting: Table --------------------------------------------------------

export function formatTable(result, targetLabel) {
  const lines = [];
  lines.push('VulnLens AI Security Scan');
  lines.push('------------------------------------------------------------');
  lines.push('');
  lines.push(`  Target:   ${targetLabel}`);
  lines.push(`  Files:    ${result.fileCount}`);
  lines.push(`  Findings: ${result.findings.length}`);
  lines.push(`  Score:    ${result.riskScore}`);
  lines.push('');

  const sevLines = [];
  for (const sev of SEVERITY_ORDER) {
    const count = result.severityCounts[sev] || 0;
    if (count > 0) sevLines.push(`  ${SEVERITY_LABELS[sev].padEnd(12)} ${count}`);
  }
  if (sevLines.length > 0) {
    lines.push('Severity');
    lines.push(sevLines.join('\n'));
    lines.push('');
  }

  if (result.findings.length > 0) {
    lines.push('Findings');
    lines.push('------------------------------------------------------------');
    for (const f of result.findings) {
      const sev = (f.severity || 'info').toUpperCase().padEnd(10);
      const ruleId = (f.ruleId || 'unknown').padEnd(24);
      const loc = `${f.filePath || ''}:${f.line || 0}`;
      // Phase 6D: baseline status marker ([NEW] / [BASELINED]) when a baseline
      // comparison is active. Findings are never hidden.
      const status = f.baselineStatus ? `  [${f.baselineStatus}]` : '';
      lines.push(`  ${sev} ${ruleId} ${loc}${status}`);
    }
    lines.push('');
  }

  // Phase 8: optional AI Copilot summaries (only present with --explain).
  // Deterministic output and SARIF are unaffected; this section is display-only.
  const explained = result.findings.filter((f) => f.copilot);
  if (explained.length > 0) {
    lines.push('AI Copilot explanations (--explain)');
    lines.push('------------------------------------------------------------');
    for (const f of explained) {
      const c = f.copilot;
      lines.push(`  ${f.ruleId || 'unknown'}  ${f.filePath || ''}:${f.line || 0}`);
      if (c.explanation) lines.push(`    Explanation: ${c.explanation}`);
      if (c.remediation) lines.push(`    Remediation: ${c.remediation}`);
    }
    lines.push('');
  }

  // Phase 6D: baseline regression summary (NEW / BASELINED / RESOLVED counts
  // plus the resolved entries, which are never current findings and never
  // affect the gate).
  if (result.baseline) {
    const b = result.baseline;
    lines.push('Baseline comparison');
    lines.push('------------------------------------------------------------');
    lines.push(`  File:      ${b.file}`);
    lines.push(`  NEW        ${b.new}`);
    lines.push(`  BASELINED  ${b.baselined}`);
    lines.push(`  RESOLVED   ${b.resolved}`);
    if (b.escalated > 0) lines.push(`  ESCALATED  ${b.escalated}`);
    if (b.resolvedEntries && b.resolvedEntries.length > 0) {
      lines.push('  Resolved findings:');
      for (const r of b.resolvedEntries) {
        const sev = r.severity ? String(SEVERITY_LABELS[r.severity] || r.severity).toUpperCase() : 'UNKNOWN';
        lines.push(`    ${sev.padEnd(10)} ${r.ruleId}  ${r.filePath}:${r.line}`);
      }
    }
    lines.push('');
  }
  return lines.join('\n');
}

// Formatting: JSON --------------------------------------------------------

function stripAiFields(findings) {
  return findings.map(({ ai, ...rest }) => rest);
}

export function formatJson(result, targetLabel) {
  const json = {
    tool: 'VulnLens',
    version: CLI_VERSION,
    target: targetLabel,
    files: result.fileCount,
    findingsCount: result.findings.length,
    severityCounts: { ...result.severityCounts },
    riskScore: result.riskScore,
    findings: stripAiFields(result.findings),
  };
  if (result.baseline) {
    json.baseline = {
      file: result.baseline.file,
      new: result.baseline.new,
      baselined: result.baseline.baselined,
      resolved: result.baseline.resolved,
      escalated: result.baseline.escalated,
      resolvedEntries: result.baseline.resolvedEntries,
    };
  }
  // Phase 8: AI Copilot summary is included only when --explain ran.
  if (result.aiCopilot) {
    json.aiCopilot = {
      explained: result.aiCopilot.explained,
      unavailable: result.aiCopilot.unavailable,
      source: result.aiCopilot.source,
    };
  }
  return JSON.stringify(json, null, 2) + '\n';
}

// Formatting: SARIF -------------------------------------------------------

export function formatSarif(result) {
  return serializeSarif(buildSarifReport({ findings: result.findings })) + '\n';
}

// Exit Code Logic ---------------------------------------------------------

export function deriveExitCode(findings, failOn) {
  if (failOn === 'none') return 0;
  const threshold = SEVERITY_RANK[failOn];
  if (threshold === undefined) return 0;
  for (const f of findings) {
    const rank = SEVERITY_RANK[f.severity];
    if (rank !== undefined && rank >= threshold) return 1;
  }
  return 0;
}

// AI Copilot (Phase 8) ------------------------------------------------------

/**
 * Explain up to MAX_EXPLAINED_FINDINGS deterministic findings with the AI
 * Copilot. Highest-severity findings are explained first; RESOLVED baseline
 * entries are never explained (they are not current findings).
 *
 * Bounded source context: each finding's file is re-read from disk and the
 * Copilot service extracts only a small window around the finding's line —
 * never the whole file, never the repository.
 *
 * AI failure is strictly non-fatal: copilot results are attached as an
 * additive `copilot` field, and callers must ignore them for gating.
 */
export async function runCopilotExplanations(findings) {
  const candidates = findings
    .filter((f) => f.baselineStatus !== 'RESOLVED')
    .slice()
    .sort((a, b) => (SEVERITY_RANK[b.severity] || 0) - (SEVERITY_RANK[a.severity] || 0))
    .slice(0, MAX_EXPLAINED_FINDINGS);

  const results = await Promise.all(
    candidates.map(async (f) => {
      let code = '';
      try {
        const p = path.resolve(process.cwd(), f.filePath || '');
        if (fs.existsSync(p) && fs.statSync(p).isFile()) {
          code = fs.readFileSync(p, 'utf8');
        }
      } catch {
        code = ''; // no source context available — the Copilot says so
      }
      const r = await explainFindingWithAI(f, { code, fileName: f.filePath });
      if (r.success) f.copilot = r.copilot; // additive, display-only
      return r;
    })
  );

  return {
    explained: results.filter((r) => r.success).length,
    unavailable: results.filter((r) => !r.success).length,
    source: (results.find((r) => r.success && r.source) || {}).source || null,
  };
}

// Baseline Suppression ------------------------------------------------------

const DEFAULT_BASELINE_FILENAME = 'vulnlens.baseline.json';

/**
 * Stable identity for a finding, used to match against a baseline entry.
 * Uses filePath + ruleId + line. The base-36 hash inside `comparisonKey` is
 * intentionally NOT part of the identity: `filePath:ruleId:line` is stable
 * enough to identify a self-reference while staying acceptably robust.
 *
 * Phase 6D: this signature IS the documented baseline comparison key. It is
 * deterministic and stable across developer machines, CI, repeated scans, and
 * baseline generation, because it depends only on rule identity + the
 * normalized relative path + line number — never on generated IDs, timestamps,
 * AI descriptions, mutable messages, content hashes, or machine-specific
 * absolute paths. Consequence (documented, intentional): if a finding moves to
 * a different line it no longer matches and is re-classified NEW (fail-safe
 * drift detection).
 */
export function baselineSignature(filePath, ruleId, line) {
  const p = String(filePath || '').replace(/\\/g, '/').replace(/^\/+/, '');
  return `${p}::${String(ruleId || '')}::${Number(line) || 0}`;
}

/**
 * Load a committed baseline file and return the set of known signatures plus
 * the parsed document. Entries are declared as:
 *   { "entries": [ { "filePath": "...", "ruleId": "...", "line": 42, ... }, ... ] }
 * A missing file is only an error when the user explicitly requested it via
 * --baseline; auto-discovery returns an empty set. Malformed content is always
 * an error (fail-visible, never silently suppress).
 *
 * Phase 6D validation (all fail-visible, exit 2): filePath/ruleId must be
 * non-empty strings within length limits and free of control characters; line
 * must be a non-negative integer. Entries MAY carry an optional normalized
 * `severity` (used by the escalation guard) and a human-readable `message` —
 * both additive and backward compatible with the Phase 6C schema.
 */
export function loadBaseline(baselinePath, { explicit = false, cwd = process.cwd() } = {}) {
  const abs = path.resolve(cwd, baselinePath || DEFAULT_BASELINE_FILENAME);
  if (!fs.existsSync(abs)) {
    if (explicit) throw new Error(`Baseline file not found: ${baselinePath}`);
    return { keys: new Set(), entries: [], entryByKey: new Map(), filePath: null };
  }

  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(abs, 'utf8'));
  } catch (err) {
    throw new Error(`Baseline file is not valid JSON: ${err.message}`);
  }

  const entries = Array.isArray(parsed && parsed.entries) ? parsed.entries : [];
  const keys = new Set();
  const entryByKey = new Map();
  for (const e of entries) {
    if (!e || typeof e !== 'object' ||
        typeof e.filePath !== 'string' || e.filePath.length === 0 ||
        typeof e.ruleId !== 'string' || e.ruleId.length === 0) {
      throw new Error('Baseline entries must have non-empty string "filePath" and "ruleId".');
    }
    if (!Number.isInteger(e.line) || e.line < 0) {
      throw new Error(`Baseline entry has invalid "line" (${JSON.stringify(e.line)}): expected a non-negative integer.`);
    }
    if (e.filePath.length > 512 || e.ruleId.length > 128) {
      throw new Error('Baseline entry "filePath"/"ruleId" exceed length limits.');
    }
    if (/[\u0000-\u001f]/.test(e.filePath) || /[\u0000-\u001f]/.test(e.ruleId)) {
      throw new Error('Baseline entry "filePath"/"ruleId" contain control characters.');
    }
    let severity;
    if (e.severity !== undefined && e.severity !== null) {
      severity = String(e.severity).toLowerCase();
      if (!(severity in SEVERITY_RANK)) {
        throw new Error(`Baseline entry has invalid "severity" (${JSON.stringify(e.severity)}). Expected one of: ${SEVERITY_ORDER.join(', ')}.`);
      }
    }
    const key = baselineSignature(e.filePath, e.ruleId, e.line);
    keys.add(key);
    if (!entryByKey.has(key)) {
      entryByKey.set(key, {
        filePath: e.filePath,
        ruleId: e.ruleId,
        line: e.line,
        severity,
        message: typeof e.message === 'string' ? e.message : '',
      });
    }
  }
  return { keys, entries, entryByKey, filePath: abs };
}

/**
 * Split findings into those gated by the exit code (`kept`) and those matched
 * by the baseline (`suppressed`). Findings in the baseline remain visible in
 * scan output but do not contribute to the --fail-on gate.
 *
 * Phase 6D: `main()` now uses classifyBaseline() (which is escalation-aware);
 * this helper is preserved for backward compatibility and direct unit tests.
 */
export function filterBaseline(findings, baseline) {
  const kept = [];
  const suppressed = [];
  for (const f of findings) {
    if (baseline && baseline.keys.has(baselineSignature(f.filePath, f.ruleId, f.line))) {
      suppressed.push(f);
    } else {
      kept.push(f);
    }
  }
  return { kept, suppressed };
}

// Baseline Classification (Phase 6D) ----------------------------------------

/**
 * Rank-based severity comparison for the escalation guard. A finding whose
 * current severity EXCEEDS the severity recorded in its baseline entry is an
 * escalation: it remains BASELINED (identity matched, severity untouched) but
 * is re-added to the --fail-on gate so a reviewed baseline can never mask a
 * worse finding at the same location. Entries that do not record a severity
 * (all Phase 6C entries) cannot detect escalation and gate exactly as before.
 */
function isSeverityEscalation(currentSeverity, baselineSeverity) {
  if (baselineSeverity === undefined || baselineSeverity === null) return false;
  const current = SEVERITY_RANK[currentSeverity];
  const recorded = SEVERITY_RANK[baselineSeverity];
  if (current === undefined || recorded === undefined) return false;
  return current > recorded;
}

/**
 * Phase 6D baseline-aware classification.
 *
 * For every current finding:
 *   - baseline comparison key (baselineSignature: filePath::ruleId::line)
 *     present in the baseline -> BASELINED (known/accepted; stays visible in
 *     all reports; excluded from the --fail-on gate unless severity escalated
 *     past the severity recorded in the entry);
 *   - key absent               -> NEW (drives the --fail-on gate normally).
 *
 * Baseline entries with no matching current finding -> RESOLVED. Resolved
 * findings are reported (table/JSON summaries + the returned `resolved` list)
 * but are NEVER current findings, NEVER fail CI, and are NEVER removed from
 * the baseline file (baselines are only ever changed by explicit, reviewed,
 * human edits).
 *
 * INVARIANT: classification is additive metadata only. It NEVER mutates
 * severity, confidence, risk, evidence, vulnerability classification, source
 * location, rule identity, or the finding's comparisonKey.
 *
 * When no baseline file was loaded (baseline.filePath is null) every finding
 * is gated exactly as in Phase 6C and no status metadata is attached, so
 * scans without a baseline are byte-identical in behavior.
 *
 * @returns {{findings, gateFindings, resolved, counts}}
 */
export function classifyBaseline(findings, baseline) {
  const active = !!(baseline && baseline.filePath);
  const gateFindings = [];
  const resolved = [];
  const counts = { new: 0, baselined: 0, resolved: 0, escalated: 0 };
  const matchedKeys = new Set();
  const list = findings || [];

  if (!active) {
    for (const f of list) gateFindings.push(f);
    return { findings: list, gateFindings, resolved, counts };
  }

  for (const f of list) {
    const key = baselineSignature(f.filePath, f.ruleId, f.line);
    const entry = baseline.entryByKey.get(key);
    if (entry) {
      f.baselineStatus = 'BASELINED';
      counts.baselined++;
      matchedKeys.add(key);
      if (isSeverityEscalation(f.severity, entry.severity)) {
        f.baselineEscalated = true;
        counts.escalated++;
        gateFindings.push(f);
      }
    } else {
      f.baselineStatus = 'NEW';
      counts.new++;
      gateFindings.push(f);
    }
  }

  const reportedKeys = new Set();
  for (const entry of baseline.entries || []) {
    const key = baselineSignature(entry.filePath, entry.ruleId, entry.line);
    // Skip entries already matched by a current finding, and collapse
    // duplicate baseline entries into a single resolved report.
    if (matchedKeys.has(key) || reportedKeys.has(key)) continue;
    reportedKeys.add(key);
    resolved.push({
      comparisonKey: key,
      filePath: entry.filePath,
      ruleId: entry.ruleId,
      line: entry.line,
      severity: entry.severity || null,
      message: entry.message || '',
    });
  }
  counts.resolved = resolved.length;

  return { findings: list, gateFindings, resolved, counts };
}

// Main Entry Point --------------------------------------------------------

export async function main(argv) {
  const config = parseArgs(argv);

  if (config.help) { if (!config.quiet) process.stdout.write(getHelp() + '\n'); return 0; }
  if (config.version) { if (!config.quiet) process.stdout.write(getVersion() + '\n'); return 0; }

  if (config.errors.length > 0) {
    if (!config.quiet) process.stderr.write('Error: ' + config.errors[0] + '\n');
    return 2;
  }

  let targetPath;
  try { targetPath = path.resolve(config.target); } catch {
    if (!config.quiet) process.stderr.write('Error: Invalid target path.\n');
    return 2;
  }

  if (!fs.existsSync(targetPath)) {
    if (!config.quiet) process.stderr.write('Error: Target path does not exist.\n');
    return 2;
  }

  const stat = fs.statSync(targetPath);
  if (stat.isFile() && !allowedExtension(targetPath)) {
    if (!config.quiet) process.stderr.write('Error: Unsupported file type.\n');
    return 2;
  }

  const targetLabel = sanitizeRelativePath(path.relative(process.cwd(), targetPath)) || '.';

  let result;
  try { result = scanTarget(targetPath, targetLabel); } catch (err) {
    if (!config.quiet) process.stderr.write('Error: Scanner error: ' + err.message + '\n');
    return 3;
  }

  // Baseline: load committed self-reference baseline (explicit --baseline path,
  // else auto-discover vulnlens.baseline.json in the working directory). Phase
  // 6D: every finding is then classified NEW / BASELINED / RESOLVED against it.
  // Baselined findings stay visible in every report but are excluded from the
  // --fail-on exit-code gate unless their severity escalated past the recorded
  // baseline severity. A malformed baseline is a workflow error (exit 2).
  let baseline;
  try {
    baseline = loadBaseline(config.baseline, {
      explicit: config.baseline != null,
      cwd: process.cwd(),
    });
  } catch (err) {
    if (!config.quiet) process.stderr.write('Error: ' + err.message + '\n');
    return 2;
  }

  // Phase 6D: baseline-aware classification. Runs BEFORE formatting so table,
  // JSON, and SARIF all carry the per-finding baseline status, and BEFORE the
  // exit-code gate. Never mutates severity/confidence/evidence.
  const classification = classifyBaseline(result.findings, baseline);
  if (baseline.filePath) {
    result.baseline = {
      file: baseline.filePath,
      new: classification.counts.new,
      baselined: classification.counts.baselined,
      resolved: classification.counts.resolved,
      escalated: classification.counts.escalated,
      resolvedEntries: classification.resolved,
    };
  }

  // Phase 8: optional AI Copilot explanations (opt-in via --explain). Runs
  // AFTER classification but BEFORE formatting so JSON/table output can carry
  // the additive `copilot` fields. Never touches findings, baseline status,
  // SARIF, the gate, or the exit code.
  if (config.explain) {
    const copilotSummary = await runCopilotExplanations(result.findings);
    result.aiCopilot = copilotSummary;
    if (!config.quiet) {
      if (copilotSummary.explained === 0) {
        process.stderr.write(
          'AI Copilot: unavailable (no provider configured) — findings remain deterministic only.\n'
        );
      } else {
        process.stderr.write(
          `AI Copilot: ${copilotSummary.explained} finding(s) explained via ${copilotSummary.source || 'AI provider'}.\n`
        );
      }
    }
  }

  let output;
  try {
    switch (config.format) {
      case 'json': output = formatJson(result, targetLabel); break;
      case 'sarif': output = formatSarif(result); break;
      default: output = formatTable(result, targetLabel); break;
    }
  } catch (err) {
    if (!config.quiet) process.stderr.write('Error: Formatting error: ' + err.message + '\n');
    return 3;
  }

  if (config.output) {
    try {
      fs.writeFileSync(path.resolve(config.output), output, 'utf8');
      if (!config.quiet) {
        const sevSummary = SEVERITY_ORDER
          .filter((s) => (result.severityCounts[s] || 0) > 0)
          .map((s) => `${result.severityCounts[s]} ${SEVERITY_LABELS[s]}`).join(', ');
        process.stderr.write(
          'Scan complete: ' + result.findings.length + ' finding(s)' +
          (sevSummary ? ' (' + sevSummary + ')' : '') +
          ', risk score ' + result.riskScore + ' - written to ' + config.output + '\n'
        );
      }
    } catch (err) {
      if (!config.quiet) process.stderr.write('Error: Cannot write output: ' + err.message + '\n');
      return 2;
    }
  } else {
    process.stdout.write(output);
  }

  // Phase 6D: baseline regression summary on stderr (suppressed by --quiet).
  // Baselined findings remain visible in the report above; only the gate
  // differs. Escalations are called out because they are re-added to the gate.
  if (baseline.filePath && !config.quiet) {
    const { counts } = classification;
    let note = `Baseline (${baseline.filePath}): ${counts.new} new, ${counts.baselined} baselined, ${counts.resolved} resolved`;
    if (counts.escalated > 0) {
      note += `, ${counts.escalated} severity escalation(s) re-added to the gate`;
    }
    note += '. Baselined findings stay visible but are excluded from the --fail-on gate. See docs/baseline-regression-intelligence.md.';
    process.stderr.write(note + '\n');
  }

  // The gate only fails on findings that are NOT baselined (i.e. genuinely
  // new or escalated), while all findings remain in the report above.
  return deriveExitCode(classification.gateFindings, config.failOn);
}