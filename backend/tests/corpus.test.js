/**
 * Corpus harness node:test entrypoint.
 *
 * After Phase 4C (evidence/verdict/confidence engines) these are TARGET pins:
 * the engine must preserve 100% recall while removing false positives and
 * severity/confidence over-claims. `assertVerdicts()` additionally checks that
 * every fixture is assigned the verdict its ground-truth header declares.
 *
 * See tests/security-fixtures/README.md.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runCorpus, loadFixtures, parseExpects, evaluateFixture } from './security-fixtures/corpus.js';

test('corpus: every fixture has a parseable @expects header', () => {
  const fx = loadFixtures();
  assert.ok(fx.length >= 41, `expected >=41 fixtures, got ${fx.length}`);
  for (const f of fx) {
    assert.equal(typeof f.flagged, 'boolean', `${f.id}: flagged must be boolean`);
    assert.ok(['vulnerable', 'safe', 'tricky'].includes(f.case), `${f.id}: bad case "${f.case}"`);
  }
});

test('corpus: parseExpects handles valid and invalid headers', () => {
  assert.deepEqual(parseExpects('// @expects {"flagged": true, "verdict": "CONFIRMED"}'), {
    case: 'unknown', flagged: true, verdict: 'CONFIRMED', cwe: null, ruleId: null,
  });
  assert.equal(parseExpects('// just a comment'), null);
  assert.equal(parseExpects('// @expects {not json'), null);
});

test('corpus: evidence/verdict engine reaches the precision target (see README)', () => {
  const m = runCorpus();
  const listing = m.rows.map((r) => `${r.id}=${r.label}`).join(', ');
  // Phase 4C/4D target: 100% precision AND recall, 0% FPR with no over-claims.
  assert.ok(m.tp >= 33, `expected >=33 TP, got ${m.tp} (${listing})`);
  assert.equal(m.recall, 1, `recall must be 1.0, got ${m.recall} (${listing})`);
  assert.equal(m.precision, 1, `precision must be 1.0, got ${m.precision} (${listing})`);
  assert.equal(m.fpr, 0, `fpr must be 0.0, got ${m.fpr} (${listing})`);
  // All severity/confidence inflation on unconfirmed targets must be gone.
  assert.equal(m.overClaimed, 0, `expected 0 over-claims, got ${m.overClaimed} (${listing})`);
});

test('corpus: evaluateFixture reports severity/confidence for finding-bearing fixtures', () => {
  const fx = loadFixtures().find((f) => f.case === 'vulnerable');
  const res = evaluateFixture(fx);
  assert.ok(res.count >= 1, `${fx.id}: vulnerable fixture should yield a finding`);
  assert.ok(res.topSeverity, 'topSeverity should be set');
  assert.ok(typeof res.topConfidence === 'number', 'topConfidence should be a number');
});

test('corpus: Phase 4D adversarial coverage spans all target categories', () => {
  const fx = loadFixtures();
  const byGroup = new Set(fx.map((f) => f.group));
  // Phase 4D added fixtures across the full adversarial matrix.
  for (const g of ['sql-injection', 'xss', 'command-injection', 'path-traversal', 'misc']) {
    assert.ok(byGroup.has(g), `missing adversarial group: ${g}`);
  }
  // Every group must contain at least one true positive fixture.
  const m = runCorpus();
  const groupsWithTP = new Set(m.rows.filter((r) => r.label === 'TP').map((r) => r.group));
  for (const g of ['sql-injection', 'xss', 'command-injection', 'path-traversal', 'misc']) {
    assert.ok(groupsWithTP.has(g), `group ${g} has no TP fixture`);
  }
});


/**
 * Validates that every fixture is assigned exactly the verdict its @expects
 * header declares:
 *   - FALSE_POSITIVE expectations must produce NO finding (dropped by engine).
 *   - CONFIRMED / POTENTIAL expectations must produce a finding whose top
 *     verdict matches the declared one.
 */
function assertVerdicts() {
  const failures = [];
  for (const fx of loadFixtures()) {
    const res = evaluateFixture(fx);
    const expected = fx.verdict;
    if (!expected) {
      failures.push(`${fx.id}: missing expected verdict in @expects`);
      continue;
    }
    if (expected === 'FALSE_POSITIVE') {
      if (res.count !== 0) {
        failures.push(`${fx.id}: expected FALSE_POSITIVE (0 findings), got ${res.count}`);
      }
      continue;
    }
    const top = res.findings[0];
    if (!top || top.verdict !== expected) {
      const got = top ? top.verdict : 'none';
      failures.push(`${fx.id}: expected verdict ${expected}, got ${got}`);
    }
  }
  assert.deepEqual(failures, [], `verdict mismatches:\n  ${failures.join('\n  ')}`);
}

test('corpus: every fixture is assigned its @expects verdict', assertVerdicts);
