/**
 * Phase 5E — Verdict Integration — unit tests.
 *
 * 50+ tests across 11 categories covering policy-controlled adjustments
 * to finding verdict / confidence / severity based on calibrated
 * interprocedural evidence.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  integrateVerdict,
  isValidVerdict,
  CONFIDENCE_DELTAS,
  MAX_INTEGRATED_CONFIDENCE,
  VERDICT_INTEGRATION_VERSION,
  VERDICT_TRANSITIONS,
} from '../src/scanner/verdictIntegration.js';
import { EVIDENCE_LEVELS } from '../src/scanner/evidenceCalibration.js';
import { runScanner } from '../src/scanner/scanner.js';

// ── Test Helpers ────────────────────────────────────────────────────────────

/** Build a minimal finding with calibration metadata at a given evidence level. */
function makeFinding(opts = {}) {
  const level = opts.level || EVIDENCE_LEVELS.NONE;
  const verdict = opts.verdict || 'POTENTIAL';
  const confidence = opts.confidence ?? 25;
  const severity = opts.severity || 'low';
  const uncertainty = opts.uncertainty ?? [];
  const directPathCount = opts.directPathCount ?? 0;

  return {
    verdict,
    confidence,
    severity,
    _ruleSeverity: opts._ruleSeverity || 'medium',
    kind: opts.kind || undefined,
    ruleId: opts.ruleId || 'test-rule',
    evidence: {
      interprocedural: {
        correlation: {
          calibration: {
            version: '5D.0',
            level,
            strength: 25,
            pathCount: 0,
            shortestPathLength: 0,
            longestPathLength: 0,
            directPathCount,
            truncated: false,
            uncertainty,
            summary: 'test',
          },
        },
      },
    },
  };
}

/** Convenience: finding without calibration. */
function makeFindingNoCalibration() {
  return { verdict: 'POTENTIAL', confidence: 25, severity: 'low', ruleId: 'test' };
}

// ═════════════════════════════════════════════════════════════════════════════
// 1. BASELINE — No Integration (evidence absent / wrong shape)
// ═════════════════════════════════════════════════════════════════════════════

test('baseline: null finding returns null', () => {
  assert.equal(integrateVerdict(null), null);
});

test('baseline: undefined finding returns undefined', () => {
  assert.equal(integrateVerdict(undefined), undefined);
});

test('baseline: non-object returns as-is', () => {
  assert.equal(integrateVerdict('string'), 'string');
  assert.equal(integrateVerdict(42), 42);
});

test('baseline: finding without calibration passes through unchanged', () => {
  const f = makeFindingNoCalibration();
  const result = integrateVerdict(f);
  assert.equal(result.verdict, 'POTENTIAL');
  assert.equal(result.confidence, 25);
  assert.equal(result.severity, 'low');
});

test('baseline: finding with missing interprocedural passes through', () => {
  const f = makeFinding();
  f.evidence = {};
  const result = integrateVerdict(f);
  assert.equal(result.verdict, 'POTENTIAL');
  assert.equal(result.confidence, 25);
});

test('baseline: finding with missing correlation passes through', () => {
  const f = makeFinding();
  f.evidence.interprocedural = {};
  const result = integrateVerdict(f);
  assert.equal(result.verdict, 'POTENTIAL');
  assert.equal(result.confidence, 25);
});

test('baseline: dependency findings are excluded', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 25, kind: 'dependency' });
  const result = integrateVerdict(f);
  assert.equal(result.verdict, 'POTENTIAL');
  assert.equal(result.confidence, 25);
});

test('baseline: already-integrated finding is not re-processed', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, confidence: 25 });
  integrateVerdict(f);
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.equal(cal.integration.applied, true);
  const confAfterFirst = f.confidence;
  integrateVerdict(f);
  assert.equal(f.confidence, confAfterFirst);
});

// ═════════════════════════════════════════════════════════════════════════════
// 2. EVIDENCE LEVELS — Confidence Delta Mapping
// ═════════════════════════════════════════════════════════════════════════════

test('delta: NONE evidence level → +0 confidence', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.NONE, confidence: 25 });
  integrateVerdict(f);
  assert.equal(f.confidence, 25);
});

test('delta: STRUCTURAL evidence level → +0 confidence', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.STRUCTURAL, confidence: 25 });
  integrateVerdict(f);
  assert.equal(f.confidence, 25);
});

test('delta: CORRELATED evidence level → +3 confidence', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, confidence: 25 });
  integrateVerdict(f);
  assert.equal(f.confidence, 28);
});

test('delta: DATA_FLOW evidence level → +5 confidence', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DATA_FLOW, confidence: 25 });
  integrateVerdict(f);
  assert.equal(f.confidence, 30);
});

test('delta: DIRECT evidence level → +10 confidence', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 25 });
  integrateVerdict(f);
  assert.equal(f.confidence, 35);
});

test('delta: all CONFIDENCE_DELTAS values are non-negative', () => {
  for (const [level, delta] of Object.entries(CONFIDENCE_DELTAS)) {
    assert.ok(delta >= 0, `${level} delta must be >= 0, got ${delta}`);
  }
});

test('delta: CONFIDENCE_DELTAS covers all evidence levels', () => {
  for (const level of Object.values(EVIDENCE_LEVELS)) {
    assert.ok(level in CONFIDENCE_DELTAS, `${level} must be in CONFIDENCE_DELTAS`);
  }
});

// ═════════════════════════════════════════════════════════════════════════════
// 3. VERDICT TRANSITIONS — POTENTIAL → LIKELY only
// ═════════════════════════════════════════════════════════════════════════════

test('transition: POTENTIAL + DIRECT + zero uncertainty + directPaths → LIKELY', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT,
    verdict: 'POTENTIAL',
    confidence: 25,
    uncertainty: [],
    directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'LIKELY');
});

test('transition: POTENTIAL + DIRECT + uncertainty present → stays POTENTIAL', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT,
    verdict: 'POTENTIAL',
    confidence: 25,
    uncertainty: ['computed-call'],
    directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'POTENTIAL');
});

test('transition: POTENTIAL + DIRECT + zero uncertainty + zero directPaths → stays POTENTIAL', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT,
    verdict: 'POTENTIAL',
    confidence: 25,
    uncertainty: [],
    directPathCount: 0,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'POTENTIAL');
});

test('transition: POTENTIAL + DATA_FLOW (below DIRECT threshold) → stays POTENTIAL', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DATA_FLOW,
    verdict: 'POTENTIAL',
    confidence: 25,
    uncertainty: [],
    directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'POTENTIAL');
});

test('transition: LIKELY + DIRECT → stays LIKELY (no LIKELY transition)', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT,
    verdict: 'LIKELY',
    confidence: 40,
    severity: 'medium',
    uncertainty: [],
    directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'LIKELY');
});

test('transition: CONFIRMED is never changed', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT,
    verdict: 'CONFIRMED',
    confidence: 85,
    severity: 'critical',
    _ruleSeverity: 'critical',
    uncertainty: [],
    directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'CONFIRMED');
  assert.equal(f.confidence, 85);
  assert.equal(f.severity, 'critical');
});

test('transition: only POTENTIAL → LIKELY is in VERDICT_TRANSITIONS', () => {
  assert.deepEqual(Object.keys(VERDICT_TRANSITIONS), ['POTENTIAL']);
  assert.equal(VERDICT_TRANSITIONS.POTENTIAL.target, 'LIKELY');
  assert.equal(VERDICT_TRANSITIONS.POTENTIAL.minEvidenceLevel, EVIDENCE_LEVELS.DIRECT);
  assert.equal(VERDICT_TRANSITIONS.POTENTIAL.requireNoUncertainty, true);
});

// ═════════════════════════════════════════════════════════════════════════════
// 4. CONFIDENCE BOUNDS — Ceiling enforcement
// ═════════════════════════════════════════════════════════════════════════════

test('bounds: confidence never exceeds MAX_INTEGRATED_CONFIDENCE', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 45 });
  integrateVerdict(f);
  assert.ok(f.confidence <= MAX_INTEGRATED_CONFIDENCE);
});

test('bounds: already-high confidence is never reduced', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT,
    verdict: 'CONFIRMED',
    confidence: 85,
    severity: 'critical',
    _ruleSeverity: 'critical',
    uncertainty: [],
    directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.confidence, 85);
});

test('bounds: confidence at ceiling stays at ceiling', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 50 });
  integrateVerdict(f);
  assert.equal(f.confidence, 50);
});

test('bounds: confidence near ceiling is capped properly', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 48 });
  integrateVerdict(f);
  assert.equal(f.confidence, 50);
});

test('bounds: low confidence is boosted', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, confidence: 10 });
  integrateVerdict(f);
  assert.equal(f.confidence, 13);
});

test('bounds: MAX_INTEGRATED_CONFIDENCE is 50', () => {
  assert.equal(MAX_INTEGRATED_CONFIDENCE, 50);
});

// ═════════════════════════════════════════════════════════════════════════════
// 5. SEVERITY — Re-derivation from (possibly new) verdict
// ═════════════════════════════════════════════════════════════════════════════

test('severity: POTENTIAL stays low when verdict unchanged', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, verdict: 'POTENTIAL', confidence: 25 });
  integrateVerdict(f);
  assert.equal(f.severity, 'low');
});

test('severity: POTENTIAL -> LIKELY with high rule severity becomes high', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT, verdict: 'POTENTIAL', confidence: 25,
    _ruleSeverity: 'high', uncertainty: [], directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'LIKELY');
  assert.equal(f.severity, 'high');
});

test('severity: POTENTIAL -> LIKELY with critical rule caps at high', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT, verdict: 'POTENTIAL', confidence: 25,
    _ruleSeverity: 'critical', uncertainty: [], directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'LIKELY');
  assert.equal(f.severity, 'high');
});

test('severity: POTENTIAL -> LIKELY with low rule severity stays low', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT, verdict: 'POTENTIAL', confidence: 25,
    _ruleSeverity: 'low', uncertainty: [], directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'LIKELY');
  assert.equal(f.severity, 'low');
});

test('severity: CORRELATED boost does not change severity', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, verdict: 'POTENTIAL', confidence: 25 });
  integrateVerdict(f);
  assert.equal(f.severity, 'low');
});

// ═════════════════════════════════════════════════════════════════════════════
// 6. EVIDENCE STATE — Integration metadata
// ═════════════════════════════════════════════════════════════════════════════

test('metadata: applied=true when integration changes finding', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, confidence: 25 });
  integrateVerdict(f);
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.ok(cal.integration);
  assert.equal(cal.integration.applied, true);
});

test('metadata: no integration when nothing changes', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.NONE, confidence: 25 });
  integrateVerdict(f);
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.equal(cal.integration, undefined);
});

test('metadata: records original and final verdict', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT, verdict: 'POTENTIAL', confidence: 25,
    uncertainty: [], directPathCount: 1,
  });
  integrateVerdict(f);
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.equal(cal.integration.originalVerdict, 'POTENTIAL');
  assert.equal(cal.integration.finalVerdict, 'LIKELY');
});

test('metadata: records confidence change', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DATA_FLOW, confidence: 25 });
  integrateVerdict(f);
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.equal(cal.integration.originalConfidence, 25);
  assert.equal(cal.integration.finalConfidence, 30);
});

test('metadata: includes evidenceLevel and evidenceStrength', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 25 });
  integrateVerdict(f);
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.equal(cal.integration.evidenceLevel, 'DIRECT');
  assert.equal(cal.integration.evidenceStrength, 100);
});

test('metadata: integration metadata is frozen', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 25 });
  integrateVerdict(f);
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.ok(Object.isFrozen(cal.integration));
  assert.ok(Object.isFrozen(cal));
});

test('metadata: replacement calibration retains original fields', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, confidence: 25 });
  integrateVerdict(f);
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.equal(cal.version, '5D.0');
  assert.equal(cal.level, EVIDENCE_LEVELS.CORRELATED);
  assert.equal(cal.summary, 'test');
});

// ═════════════════════════════════════════════════════════════════════════════
// 7. SECURITY — Invariant preservation
// ═════════════════════════════════════════════════════════════════════════════

test('security: ruleId is never mutated', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 25 });
  f.ruleId = 'sql-injection';
  integrateVerdict(f);
  assert.equal(f.ruleId, 'sql-injection');
});

test('security: comparisonKey is never mutated', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 25 });
  f.comparisonKey = 'original-key';
  integrateVerdict(f);
  assert.equal(f.comparisonKey, 'original-key');
});

test('security: riskScore is never mutated', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 25 });
  f.riskScore = 80;
  integrateVerdict(f);
  assert.equal(f.riskScore, 80);
});

test('security: malformed finding with circular evidence does not crash', () => {
  const circular = { verdict: 'POTENTIAL', confidence: 25, severity: 'low' };
  circular.evidence = { interprocedural: circular };
  assert.doesNotThrow(() => integrateVerdict(circular));
});

test('security: isValidVerdict rejects invalid values', () => {
  assert.equal(isValidVerdict('CONFIRMED'), true);
  assert.equal(isValidVerdict('LIKELY'), true);
  assert.equal(isValidVerdict('POTENTIAL'), true);
  assert.equal(isValidVerdict('FALSE_POSITIVE'), false);
  assert.equal(isValidVerdict(''), false);
  assert.equal(isValidVerdict(null), false);
});

// ═════════════════════════════════════════════════════════════════════════════
// 8. AI ISOLATION — Deterministic pipeline boundaries
// ═════════════════════════════════════════════════════════════════════════════

test('ai-isolation: integration does not affect riskScore', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, confidence: 25 });
  f.riskScore = 42;
  integrateVerdict(f);
  assert.equal(f.riskScore, 42);
});

test('ai-isolation: integration does not affect score', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, confidence: 25 });
  f.score = 72;
  integrateVerdict(f);
  assert.equal(f.score, 72);
});

test('ai-isolation: CONFIRMED confidence (80+) is never capped to 50', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT, verdict: 'CONFIRMED', confidence: 85,
    severity: 'critical', _ruleSeverity: 'critical',
  });
  integrateVerdict(f);
  assert.ok(f.confidence >= 80);
});

test('ai-isolation: integration metadata absent on no-change findings', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.STRUCTURAL, confidence: 25 });
  integrateVerdict(f);
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.equal(cal.integration, undefined);
});

// ═════════════════════════════════════════════════════════════════════════════
// 9. DETERMINISM — Same input -> same output
// ═════════════════════════════════════════════════════════════════════════════

test('determinism: identical inputs produce identical results', () => {
  const f1 = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 25, uncertainty: [], directPathCount: 1 });
  const f2 = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 25, uncertainty: [], directPathCount: 1 });
  integrateVerdict(f1);
  integrateVerdict(f2);
  assert.equal(f1.verdict, f2.verdict);
  assert.equal(f1.confidence, f2.confidence);
  assert.equal(f1.severity, f2.severity);
  assert.deepEqual(
    f1.evidence.interprocedural.correlation.calibration.integration,
    f2.evidence.interprocedural.correlation.calibration.integration,
  );
});

test('determinism: runScanner findings are deterministic with Phase 5E', () => {
  const code = 'function handler(req) { const id = req.query.id; const sql = "SELECT * FROM users WHERE id = " + id; db.query(sql); }';
  const r1 = runScanner(code, { filePath: 'det1.js' });
  const r2 = runScanner(code, { filePath: 'det2.js' });
  assert.equal(r1.findings.length, r2.findings.length);
  for (let i = 0; i < r1.findings.length; i++) {
    assert.equal(r1.findings[i].verdict, r2.findings[i].verdict);
    assert.equal(r1.findings[i].confidence, r2.findings[i].confidence);
    assert.equal(r1.findings[i].severity, r2.findings[i].severity);
  }
});

test('determinism: policy constants are frozen', () => {
  assert.ok(Object.isFrozen(CONFIDENCE_DELTAS));
  assert.ok(Object.isFrozen(VERDICT_TRANSITIONS));
  assert.ok(Object.isFrozen(VERDICT_TRANSITIONS.POTENTIAL));
});

test('determinism: version string is stable', () => {
  assert.equal(VERDICT_INTEGRATION_VERSION, '5E.0');
  assert.equal(typeof VERDICT_INTEGRATION_VERSION, 'string');
});

// ═════════════════════════════════════════════════════════════════════════════
// 10. INVARIANT REGRESSION — Phase 5E must not break INV 1–9
// ═════════════════════════════════════════════════════════════════════════════

test('regression INV 2: POTENTIAL findings stay low severity via runScanner', () => {
  const code = 'function handler(id) { const x = id; }';
  const { findings } = runScanner(code, { filePath: 'inv2.js' });
  for (const f of findings) {
    if (f.verdict === 'POTENTIAL') {
      assert.equal(f.severity, 'low');
      assert.ok(f.confidence <= 50);
    }
  }
});

test('regression INV 4: severity normalization still overrides rule severity', () => {
  const code = 'function handler(req) { const id = req.query.id; const sql = "SELECT * FROM users WHERE id = " + id; db.query(sql); }';
  const { findings } = runScanner(code, { filePath: 'inv4.js' });
  for (const f of findings) {
    if (f.verdict === 'POTENTIAL') assert.equal(f.severity, 'low');
    if (f.verdict === 'CONFIRMED') {
      assert.ok(['critical', 'high', 'medium'].includes(f.severity));
    }
  }
});

test('regression: FALSE_POSITIVE findings are never surfaced', () => {
  const r = runScanner('el.innerHTML = "static text";', { filePath: 'inv1b.js' });
  assert.equal(r.findings.length, 0);
  assert.ok(r.findings.every((f) => f.verdict !== 'FALSE_POSITIVE'));
});

// ═════════════════════════════════════════════════════════════════════════════
// 11. EDGE CASES
// ═════════════════════════════════════════════════════════════════════════════

test('edge: POTENTIAL at confidence 0 with DIRECT → boosted to 10', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.DIRECT, confidence: 0, uncertainty: [], directPathCount: 0 });
  integrateVerdict(f);
  assert.equal(f.confidence, 10);
});

test('edge: missing severity field → fail-closed', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED, confidence: 25 });
  delete f.severity;
  const result = integrateVerdict(f);
  assert.equal(result.confidence, 25);
});

test('edge: missing confidence field → fail-closed', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.CORRELATED });
  delete f.confidence;
  const result = integrateVerdict(f);
  assert.equal(result.verdict, 'POTENTIAL');
});

test('edge: non-array uncertainty → no verdict transition', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.DIRECT, confidence: 25,
    uncertainty: 'unknown', directPathCount: 1,
  });
  integrateVerdict(f);
  assert.equal(f.verdict, 'POTENTIAL');
});

test('edge: CORRELATED on CONFIRMED → confidence stays unchanged', () => {
  const f = makeFinding({
    level: EVIDENCE_LEVELS.CORRELATED, verdict: 'CONFIRMED',
    confidence: 85, severity: 'critical', _ruleSeverity: 'critical',
  });
  integrateVerdict(f);
  assert.equal(f.confidence, 85);
  assert.equal(f.verdict, 'CONFIRMED');
});

test('edge: STRUCTURAL on POTENTIAL → no-op (no metadata)', () => {
  const f = makeFinding({ level: EVIDENCE_LEVELS.STRUCTURAL, confidence: 30 });
  integrateVerdict(f);
  assert.equal(f.confidence, 30);
  assert.equal(f.verdict, 'POTENTIAL');
  const cal = f.evidence.interprocedural.correlation.calibration;
  assert.equal(cal.integration, undefined);
});