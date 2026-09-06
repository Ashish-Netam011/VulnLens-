#!/usr/bin/env node
/**
 * CLI wrapper around the security-fixture corpus harness.
 *
 * Usage:
 *   node tests/run-corpus.mjs                 # print report (exit 0)
 *   node tests/run-corpus.mjs --strict        # fail if thresholds are not met
 *
 * Thresholds can be overridden via env:
 *   CORPUS_MIN_PRECISION  (default 1.00)
 *   CORPUS_MIN_RECALL     (default 1.00)
 *   CORPUS_MAX_FPR        (default 0.00)
 *   CORPUS_MAX_OVERCLAIM  (default 0)
 */
import { runCorpus, formatReport } from './security-fixtures/corpus.js';

const args = process.argv.slice(2);
const strict = args.includes('--strict');

const thresholds = {
  minPrecision: Number(process.env.CORPUS_MIN_PRECISION ?? 1.0),
  minRecall: Number(process.env.CORPUS_MIN_RECALL ?? 1.0),
  maxFpr: Number(process.env.CORPUS_MAX_FPR ?? 0.0),
  maxOverclaim: Number(process.env.CORPUS_MAX_OVERCLAIM ?? 0),
};

console.log(formatReport(runCorpus()));

if (strict) {
  const m = runCorpus();
  const failures = [];
  if (m.precision < thresholds.minPrecision)
    failures.push(`precision ${(100 * m.precision).toFixed(1)}% < ${(100 * thresholds.minPrecision).toFixed(0)}%`);
  if (m.recall < thresholds.minRecall)
    failures.push(`recall ${(100 * m.recall).toFixed(1)}% < ${(100 * thresholds.minRecall).toFixed(0)}%`);
  if (m.fpr > thresholds.maxFpr)
    failures.push(`fpr ${(100 * m.fpr).toFixed(1)}% > ${(100 * thresholds.maxFpr).toFixed(0)}%`);
  if (m.overClaimed > thresholds.maxOverclaim)
    failures.push(`overClaims ${m.overClaimed} > ${thresholds.maxOverclaim}`);
  if (failures.length) {
    console.error('\nCorpus gate FAILED:');
    for (const f of failures) console.error(`  - ${f}`);
    console.error('\nRun `npm run test:corpus` to see the full report.');
    process.exit(1);
  }
  console.log('\nCorpus gate passed.');
}
