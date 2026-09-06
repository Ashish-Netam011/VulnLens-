/**
 * Security-fixture corpus harness (Phase 4F).
 *
 * Loads every fixture under ./security-fixtures, runs the deterministic rule
 * engine over each one, and compares the result to the ground-truth declared in
 * the fixture's `// @expects {...}` header comment.
 *
 * Two families of metrics are reported:
 *
 *  1. DETECTION metrics (ground truth = `flagged`): whether the engine reports
 *     a finding on the right files.
 *       TP/FP/FN/TN, precision, recall, false-positive-rate, accuracy.
 *
 *  2. OVER-CLAIM metric: counts findings that are severity- and confidence-
 *     INFLATED relative to what the truth justifies (a no-source "tricky" case
 *     reported as CRITICAL at 88%, or a pure false-positive reported HIGH).
 *     This is the "don't trust an unsafe 88%" signal the evidence/verdict
 *     engine (Phase 4C/4D) is built to eliminate — it is the baseline noise.
 *
 * `verdict` / `cwe` fields are stored as forward-looking assertions: they are
 * validated by `assertVerdicts()` once findings carry a `verdict`, and are
 * ignored by the current detection metrics.
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { dirname, join, relative } from 'node:path';
import { runScanner } from '../../src/scanner/scanner.js';

const __dirname = dirname(fileURLToPath(import.meta.url));
export const FIXTURES_ROOT = __dirname;

/** A finding is "over-claimed" if it is reported at high severity + strong
 *  confidence on a target that the truth does not justify as confirmed. */
const OVERCLAIM_SEVERITIES = new Set(['critical', 'high']);
const OVERCLAIM_MIN_CONFIDENCE = 70;

/** Single-line header: `// @expects { ...json... }` */
const EXPECTS_RE = /^\s*\/\/\s*@expects\s+(\{.*\})\s*$/m;

export function parseExpects(content) {
  const m = EXPECTS_RE.exec(content || '');
  if (!m || !m[1]) return null;
  try {
    const parsed = JSON.parse(m[1]);
    return {
      case: parsed.case || 'unknown',
      flagged: parsed.flagged === true,
      verdict: parsed.verdict || null,
      cwe: parsed.cwe || null,
      ruleId: parsed.ruleId || null,
    };
  } catch {
    return null;
  }
}

function filesUnder(dir, acc = []) {
  for (const name of readdirSync(dir)) {
    const full = join(dir, name);
    const st = statSync(full);
    if (st.isDirectory()) filesUnder(full, acc);
    else if (name.endsWith('.js')) acc.push(full);
  }
  return acc;
}

/** Load every fixture with a valid `@expects` header. */
export function loadFixtures() {
  const out = [];
  for (const full of filesUnder(FIXTURES_ROOT).sort()) {
    const content = readFileSync(full, 'utf8');
    const expects = parseExpects(content);
    if (!expects) continue;
    const rel = relative(FIXTURES_ROOT, full).split(/[\\/]/);
    out.push({
      id: rel.join('/'),
      group: rel[0],
      case: expects.case,
      flagged: expects.flagged,
      verdict: expects.verdict,
      cwe: expects.cwe,
      ruleId: expects.ruleId,
      content,
    });
  }
  return out;
}

/** Run the engine on one fixture. */
export function evaluateFixture(fixture) {
  const { findings } = runScanner(fixture.content, { filePath: fixture.id });
  const severityDescending = [...findings].sort(
    (a, b) => sevRank(b.severity) - sevRank(a.severity)
  );
  const top = severityDescending[0];
  return {
    findings,
    count: findings.length,
    topSeverity: top ? top.severity : null,
    topConfidence: top ? top.confidence : null,
    topRuleId: top ? top.ruleId : null,
  };
}

function sevRank(s) {
  return ['critical', 'high', 'medium', 'low', 'informational'].indexOf(s);
}

/**
 * Run the corpus and compute metrics.
 * @returns {object} metrics object (see README for field description)
 */
export function runCorpus() {
  const fixtures = loadFixtures();
  const rows = [];
  const byGroup = {};
  let tp = 0, fp = 0, fn = 0, tn = 0;
  let overClaimed = 0;

  for (const fx of fixtures) {
    const res = evaluateFixture(fx);
    const found = res.count > 0;
    const isPositive = fx.flagged;

    const row = {
      id: fx.id,
      group: fx.group,
      case: fx.case,
      expected: fx.flagged ? 'positive' : 'negative',
      found,
      count: res.count,
      topSeverity: res.topSeverity,
      topConfidence: res.topConfidence,
      topRuleId: res.topRuleId,
      expectedVerdict: fx.verdict,
    };

    if (isPositive && found) { tp++; row.label = 'TP'; }
    else if (!isPositive && found) { fp++; row.label = 'FP'; row.overClaim = true; }
    else if (isPositive && !found) { fn++; row.label = 'FN'; }
    else { tn++; row.label = 'TN'; }

    // Over-claim: strong severity + confidence on a target the truth demotes to
    // FALSE_POSITIVE (a pure FP) or POTENTIAL (a no-source tricky case).
    const demoted = fx.verdict === 'FALSE_POSITIVE' || fx.verdict === 'POTENTIAL';
    if (
      found &&
      demoted &&
      res.topSeverity &&
      OVERCLAIM_SEVERITIES.has(res.topSeverity) &&
      res.topConfidence >= OVERCLAIM_MIN_CONFIDENCE
    ) {
      overClaimed++;
      row.overClaim = true;
    }

    byGroup[fx.group] = byGroup[fx.group] || { tp: 0, fp: 0, fn: 0, tn: 0 };
    const g = byGroup[fx.group];
    if (isPositive && found) g.tp++;
    else if (!isPositive && found) g.fp++;
    else if (isPositive && !found) g.fn++;
    else g.tn++;

    rows.push(row);
  }

  const total = rows.length;
  const precision = tp + fp > 0 ? tp / (tp + fp) : 0;
  const recall = tp + fn > 0 ? tp / (tp + fn) : 0;
  const fpr = fp + tn > 0 ? fp / (fp + tn) : 0;
  const accuracy = total > 0 ? (tp + tn) / total : 0;

  return {
    total,
    tp, fp, fn, tn,
    precision,
    recall,
    fpr,
    accuracy,
    overClaimed,
    rows,
    byGroup,
  };
}

const pct = (x) => `${(100 * x).toFixed(1)}%`;

export function formatReport(metrics) {
  const lines = [];
  lines.push('Security-fixture corpus report');
  lines.push('──────────────────────────────');
  lines.push(`Fixtures: ${metrics.total}`);
  lines.push('');
  lines.push('Per-fixture:');
  lines.push('  STATUS  GROUP               CASE        CONF  SEV   FINDING ID');
  for (const r of metrics.rows) {
    const status = r.label.padEnd(6);
    const conf = r.topConfidence != null ? String(r.topConfidence).padEnd(4) : '  - ';
    const sev = (r.topSeverity || '-').padEnd(8);
    lines.push(`  ${status}  ${r.group.padEnd(19)} ${r.case.padEnd(11)} ${conf} ${sev} ${r.id}`);
  }
  lines.push('');
  lines.push('Detection metrics (ground truth = flagged):');
  lines.push(`  TP=${metrics.tp}  FP=${metrics.fp}  FN=${metrics.fn}  TN=${metrics.tn}`);
  lines.push(`  Precision       : ${pct(metrics.precision)}`);
  lines.push(`  Recall          : ${pct(metrics.recall)}`);
  lines.push(`  False-positive  : ${pct(metrics.fpr)}   (rate)`);
  lines.push(`  Accuracy        : ${pct(metrics.accuracy)}`);
  lines.push('');
  lines.push(`Over-claimed (critical/high at >=${OVERCLAIM_MIN_CONFIDENCE}% on unconfirmed targets): ${metrics.overClaimed}`);
  lines.push('');
  lines.push('By group:');
  for (const [g, m] of Object.entries(metrics.byGroup)) {
    lines.push(`  ${g.padEnd(19)} TP=${m.tp} FP=${m.fp} FN=${m.fn} TN=${m.tn}`);
  }
  return lines.join('\n');
}

export default { parseExpects, loadFixtures, evaluateFixture, runCorpus, formatReport };
