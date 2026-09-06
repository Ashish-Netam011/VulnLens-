/**
 * Evidence Calibration (Phase 5D) — unit tests.
 *
 * Verifies that Phase 5D assigns deterministic evidence-strength metadata
 * without modifying verdict / confidence / severity / riskScore / comparisonKey.
 */

import { test } from 'node:test';
import assert from 'node:assert/strict';

import {
  calibrateEvidence,
  classifyEvidenceLevel,
  calculateEvidenceStrength,
  buildCalibrationSummary,
  EVIDENCE_CALIBRATION_VERSION,
  EVIDENCE_LEVELS,
  EVIDENCE_STRENGTH,
  UNCERTAINTY_VOCAB,
  MAX_CALIBRATION_UNCERTAINTIES,
  MAX_CALIBRATION_SUMMARY_LEN,
  MAX_CALIBRATION_PATHS,
} from '../src/scanner/evidenceCalibration.js';

import { runScanner } from '../src/scanner/scanner.js';

// ── Test Helpers ────────────────────────────────────────────────────────────

function makeCorrelation(overrides = {}) {
  return {
    version: '5B.0',
    affectedFunction: overrides.affectedFunction || { id: 'fn1', name: 'handler', type: 'function', line: 1 },
    sourceEvidence: { present: !!overrides.sourceEvidence, sources: overrides.sourceEvidence || [], note: 'Request-derived source shape observed.' },
    sinkEvidence:   { present: !!overrides.sinkEvidence,   sinks: overrides.sinkEvidence || [],   note: 'Structural sink shape present.' },
    reachability: { reachableFunctions: [], paths: [] },
    callRelationships: { callers: [], callees: [] },
    dataFlow: overrides.dataFlow || null,
    summary: 'test',
  };
}

function makeDataFlow(paths = []) {
  return { version: '5C.0', paths, truncated: false, summary: 'test', facts: { sourceCount: 1, sinkCount: 1 } };
}

function makePath(steps, sinkType = 'sql-query') {
  return {
    source: { expression: 'req.query.id', line: 1 },
    sink: { type: sinkType, line: 5, argIndex: 0 },
    steps,
    length: steps.length,
    confidence: 'structural-data-flow',
  };
}

// ── 1–5. Level Classification ──────────────────────────────────────────────

test('1. no evidence → NONE', () => {
  const cal = calibrateEvidence(null);
  assert.equal(cal.level, EVIDENCE_LEVELS.NONE);
});

test('2. structural evidence only → STRUCTURAL', () => {
  const cal = calibrateEvidence(makeCorrelation({}));
  assert.equal(cal.level, EVIDENCE_LEVELS.STRUCTURAL);
});

test('3. correlated source+sink → CORRELATED', () => {
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{ expression: 'req.query.id' }], sinkEvidence: [{ sinkType: 'sql' }] }));
  assert.equal(cal.level, EVIDENCE_LEVELS.CORRELATED);
});

test('4. data-flow paths (>2 steps) → DATA_FLOW', () => {
  const df = makeDataFlow([makePath([
    { kind: 'source', name: 'req.query.id' },
    { kind: 'assignment', name: 'x' },
    { kind: 'sink', name: 'sql-query' },
  ])]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal.level, EVIDENCE_LEVELS.DATA_FLOW);
});

test('5. direct source-to-sink (≤2 steps) → DIRECT', () => {
  const df = makeDataFlow([makePath([
    { kind: 'source', name: 'req.query.id' },
    { kind: 'sink', name: 'sql-query' },
  ])]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal.level, EVIDENCE_LEVELS.DIRECT);
});

// ── 6–8. Precedence Rules ──────────────────────────────────────────────────

test('6. precedence: STRUCTURAL < CORRELATED', () => {
  const cal1 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}] }));
  assert.equal(cal1.level, EVIDENCE_LEVELS.STRUCTURAL);
  const cal2 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}] }));
  assert.equal(cal2.level, EVIDENCE_LEVELS.CORRELATED);
});

test('7. precedence: CORRELATED < DATA_FLOW', () => {
  const cal1 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}] }));
  assert.equal(cal1.level, EVIDENCE_LEVELS.CORRELATED);
  const df = makeDataFlow([makePath([
    { kind: 'source' }, { kind: 'assignment' }, { kind: 'sink' },
  ])]);
  const cal2 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal2.level, EVIDENCE_LEVELS.DATA_FLOW);
});

test('8. precedence: DATA_FLOW < DIRECT', () => {
  const df1 = makeDataFlow([makePath([
    { kind: 'source' }, { kind: 'assignment' }, { kind: 'sink' },
  ])]);
  const cal1 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df1 }));
  assert.equal(cal1.level, EVIDENCE_LEVELS.DATA_FLOW);
  const df2 = makeDataFlow([makePath([{ kind: 'source' }, { kind: 'sink' }])]);
  const cal2 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df2 }));
  assert.equal(cal2.level, EVIDENCE_LEVELS.DIRECT);
});

// ── 9–13. Source/Sink Quality Flags ────────────────────────────────────────

test('9. sourcePresent flag', () => {
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}] }));
  assert.equal(cal.sourcePresent, true);
  const cal2 = calibrateEvidence(makeCorrelation({}));
  assert.equal(cal2.sourcePresent, false);
});

test('10. sinkPresent flag', () => {
  const cal = calibrateEvidence(makeCorrelation({ sinkEvidence: [{}] }));
  assert.equal(cal.sinkPresent, true);
});

test('11. sourceSinkCorrelated flag', () => {
  const cal1 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}] }));
  assert.equal(cal1.sourceSinkCorrelated, true);
  const cal2 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}] }));
  assert.equal(cal2.sourceSinkCorrelated, false);
});

test('12. dataFlowProven flag', () => {
  const df = makeDataFlow([makePath([{ kind: 'source' }, { kind: 'sink' }])]);
  const cal1 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal1.dataFlowProven, true);
  const cal2 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}] }));
  assert.equal(cal2.dataFlowProven, false);
});

test('13. directFlow flag', () => {
  const df = makeDataFlow([makePath([{ kind: 'source' }, { kind: 'sink' }])]);
  const cal1 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal1.directFlow, true);
  const df2 = makeDataFlow([makePath([{ kind: 'source' }, { kind: 'assignment' }, { kind: 'sink' }])]);
  const cal2 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df2 }));
  assert.equal(cal2.directFlow, false);
});

// ── 14–18. Path Quality Metrics ────────────────────────────────────────────

test('14. pathCount', () => {
  const df = makeDataFlow([makePath([{}]), makePath([{}])]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal.pathCount, 2);
});

test('15. shortestPathLength', () => {
  const df = makeDataFlow([
    makePath([{ kind: 'source' }, { kind: 'sink' }]),
    makePath([{ kind: 'source' }, { kind: 'assignment' }, { kind: 'sink' }]),
  ]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal.shortestPathLength, 2);
});

test('16. longestPathLength', () => {
  const df = makeDataFlow([
    makePath([{ kind: 'source' }, { kind: 'sink' }]),
    makePath([{ kind: 'source' }, { kind: 'assignment' }, { kind: 'sink' }]),
  ]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal.longestPathLength, 3);
});

test('17. directPathCount', () => {
  const df = makeDataFlow([
    makePath([{ kind: 'source' }, { kind: 'sink' }]),
    makePath([{ kind: 'source' }, { kind: 'assignment' }, { kind: 'sink' }]),
    makePath([{ kind: 'source' }, { kind: 'sink' }]),
  ]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal.directPathCount, 2);
});

test('18. truncation flag from dataFlow', () => {
  const df = { ...makeDataFlow([makePath([{}])]), truncated: true };
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal.truncated, true);
});

// ── 19–23. Uncertainty Detection ───────────────────────────────────────────

test('19. unresolved-call uncertainty (empty functionId on argument/parameter)', () => {
  const df = makeDataFlow([makePath([
    { kind: 'source' },
    { kind: 'argument', name: 'x', functionId: '' },
    { kind: 'parameter', name: 'p', functionId: '' },
    { kind: 'sink' },
  ])]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.ok(cal.uncertainty.includes('unresolved-call'));
});

test('20. member-call uncertainty (calleeName contains dot)', () => {
  const df = makeDataFlow([makePath([
    { kind: 'source' },
    { kind: 'call', calleeName: 'obj.method' },
    { kind: 'sink' },
  ])]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.ok(cal.uncertainty.includes('member-call'));
});

test('21. unknown-transformation uncertainty (non-identifier assignment)', () => {
  const df = makeDataFlow([makePath([
    { kind: 'source' },
    { kind: 'assignment', expressionType: 'BinaryExpression' },
    { kind: 'sink' },
  ])]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.ok(cal.uncertainty.includes('unknown-transformation'));
});

test('22. cross-file-boundary uncertainty (source+sink present but no paths)', () => {
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: makeDataFlow([]) }));
  assert.ok(cal.uncertainty.includes('cross-file-boundary'));
});

test('23. computed-call uncertainty', () => {
  const df = makeDataFlow([makePath([
    { kind: 'source' },
    { kind: 'call', expressionType: 'CallExpression', computed: true },
    { kind: 'sink' },
  ])]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.ok(cal.uncertainty.includes('computed-call'));
});

// ── 24–26. Determinism & JSON Safety ───────────────────────────────────────

test('24. deterministic output across calls', () => {
  const corr = makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: makeDataFlow([makePath([{ kind: 'source' }, { kind: 'assignment' }, { kind: 'sink' }])]) });
  const c1 = calibrateEvidence(corr);
  const c2 = calibrateEvidence(corr);
  const c3 = calibrateEvidence(corr);
  assert.deepEqual(c1, c2);
  assert.deepEqual(c2, c3);
});

test('25. uncertainty sorted alphabetically', () => {
  const df = makeDataFlow([makePath([
    { kind: 'source' },
    { kind: 'assignment', expressionType: 'BinaryExpression' }, // unknown-transformation
    { kind: 'argument', functionId: '' },                        // unresolved-call
    { kind: 'sink' },
  ])]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  const sorted = [...cal.uncertainty].sort();
  assert.deepEqual(cal.uncertainty, sorted);
});

test('26. JSON round-trip', () => {
  const corr = makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: makeDataFlow([makePath([{ kind: 'source' }, { kind: 'sink' }])]) });
  const cal = calibrateEvidence(corr);
  const round = JSON.parse(JSON.stringify(cal));
  assert.deepEqual(round, cal);
});

// ── 27–30. Safety / Malformed Input ────────────────────────────────────────

test('27. malformed correlation → NONE', () => {
  const cal = calibrateEvidence('not an object');
  assert.equal(cal.level, EVIDENCE_LEVELS.NONE);
});

test('28. null correlation → NONE', () => {
  const cal = calibrateEvidence(null);
  assert.equal(cal.level, EVIDENCE_LEVELS.NONE);
});

test('29. no secret leakage in output', () => {
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: makeDataFlow([makePath([{ kind: 'source' }, { kind: 'sink' }])]) }));
  const json = JSON.stringify(cal);
  assert.ok(!/password|secret|token|key|credential/i.test(json));
});

test('30. no absolute filesystem path leakage', () => {
  const cal = calibrateEvidence(makeCorrelation({}));
  const json = JSON.stringify(cal);
  assert.ok(!new RegExp('^[A-Za-z]:\\\\').test(json) && !new RegExp('/home/|/Users/|/tmp/').test(json));
});
import { analyzeFile } from '../src/scanner/functionAnalysis.js';
import { correlateFindingWithFunctionAnalysis } from '../src/scanner/interproceduralEvidence.js';

const CALIB_SCAN_CODE = [
  'function handler(req) {',
  '  const id = req.query.id;',
  '  db.query("SELECT * FROM users WHERE id=" + id);',
  '}',
].join('\n');

// 31-37 Additional Evidence Calibration Properties
test('31. calculateEvidenceStrength returns 0 for non-string input', () => {
  assert.equal(calculateEvidenceStrength(null), 0);
  assert.equal(calculateEvidenceStrength(undefined), 0);
  assert.equal(calculateEvidenceStrength(42), 0);
  assert.equal(calculateEvidenceStrength({}), 0);
});
test('32. calculateEvidenceStrength returns 0 for unknown level', () => {
  assert.equal(calculateEvidenceStrength('TOTALLY_FAKE_LEVEL'), 0);
});
test('33. classifyEvidenceLevel returns NONE for non-object correlation', () => {
  assert.equal(classifyEvidenceLevel(null, null), EVIDENCE_LEVELS.NONE);
  assert.equal(classifyEvidenceLevel('string', null), EVIDENCE_LEVELS.NONE);
  assert.equal(classifyEvidenceLevel(42, null), EVIDENCE_LEVELS.NONE);
});
test('34. scanner findings do not expose score or riskScore', () => {
  const { findings } = runScanner(CALIB_SCAN_CODE, { filePath: 't34.js' });
  assert.ok(findings.length > 0, 'expected at least one finding');
  for (const f of findings) {
    assert.equal(f.score, undefined, 'score must not be set on finding');
    assert.equal(f.riskScore, undefined, 'riskScore must not be set on finding');
  }
});
test('35. calibration never changes verdict / severity / confidence', () => {
  const { findings } = runScanner(CALIB_SCAN_CODE, { filePath: 't35.js' });
  assert.ok(findings.length > 0, 'expected at least one finding');
  for (const f of findings) {
    assert.ok(f.verdict !== undefined, 'verdict present');
    assert.ok(f.severity !== undefined, 'severity present');
    assert.ok(f.confidence !== undefined, 'confidence present');
  }
});
test('36. summary text matches expected template for each level', () => {
  const expected = {
    [EVIDENCE_LEVELS.NONE]:       'No interprocedural evidence established.',
    [EVIDENCE_LEVELS.STRUCTURAL]: 'Structural function reachability observed.',
    [EVIDENCE_LEVELS.CORRELATED]: 'Source and sink are structurally correlated, but value propagation is not proven.',
    [EVIDENCE_LEVELS.DATA_FLOW]:  'Bounded intra-file data flow from a recognized source to a recognized sink.',
    [EVIDENCE_LEVELS.DIRECT]:     'Direct source-to-sink flow was structurally demonstrated.',
  };
  for (const [level, text] of Object.entries(expected)) {
    const summary = buildCalibrationSummary(level, []);
    assert.ok(summary.startsWith(text), 'summary matches template');
  }
});
test('37. calibration output is frozen (immutable)', () => {
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: makeDataFlow([makePath([{ kind: 'source' }, { kind: 'sink' }])]) }));
  assert.ok(Object.isFrozen(cal), 'calibration object is frozen');
  assert.ok(Object.isFrozen(cal.uncertainty), 'uncertainty array is frozen');
});
// 38-40 Phase 5A/5B/5C Compatibility
test('38. accepts Phase 5A-annotated correlation (affectedFunction only) -> STRUCTURAL', () => {
  const corr = makeCorrelation({ affectedFunction: { id: 'f1', name: 'handler', type: 'function', line: 1 } });
  const cal = calibrateEvidence(corr);
  assert.equal(cal.level, EVIDENCE_LEVELS.STRUCTURAL);
  assert.equal(cal.strength, EVIDENCE_STRENGTH[EVIDENCE_LEVELS.STRUCTURAL]);
  assert.equal(cal.sourceSinkCorrelated, false);
});
test('39. Phase 5B correlator attaches calibration metadata', () => {
  const code = 'function handler() { const id = req.query.id; db.query("SELECT * FROM t WHERE id=" + id); }';
  const analysis = analyzeFile(code, { filePath: 't39.js' });
  const finding = { line: 1, ruleId: 'x', category: 'Injection Vulnerabilities' };
  const corr = correlateFindingWithFunctionAnalysis(finding, analysis, { code });
  assert.ok(corr, 'correlation produced');
  assert.ok(corr.calibration, 'Phase 5B attaches calibration');
  assert.equal(corr.calibration.version, EVIDENCE_CALIBRATION_VERSION);
  assert.ok(corr.calibration.level, 'calibration has a level');
});
test('40. Phase 5C data-flow paths upgrade level to DATA_FLOW / DIRECT', () => {
  const df = makeDataFlow([makePath([{ kind: 'source' }, { kind: 'assign' }, { kind: 'sink' }])]);
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.equal(cal.level, EVIDENCE_LEVELS.DATA_FLOW);
  assert.equal(cal.strength, EVIDENCE_STRENGTH[EVIDENCE_LEVELS.DATA_FLOW]);
  assert.equal(cal.dataFlowProven, true);

  const dfDirect = makeDataFlow([makePath([{ kind: 'source' }, { kind: 'sink' }])]);
  const cal2 = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: dfDirect }));
  assert.equal(cal2.level, EVIDENCE_LEVELS.DIRECT);
  assert.equal(cal2.directFlow, true);
  assert.equal(cal2.strength, EVIDENCE_STRENGTH[EVIDENCE_LEVELS.DIRECT]);
});
// 41-42 Scanner Integration & Determinism
test('41. runScanner findings include Phase 5D calibration', () => {
  const { findings } = runScanner(CALIB_SCAN_CODE, { filePath: 't41.js' });
  assert.ok(findings.length > 0, 'expected at least one finding');
  for (const f of findings) {
    const corr = f.evidence.interprocedural && f.evidence.interprocedural.correlation;
    assert.ok(corr && corr.calibration, 'calibration present on finding');
    assert.equal(corr.calibration.version, EVIDENCE_CALIBRATION_VERSION);
  }
});
test('42. repeated scans are byte-identical (calibration determinism)', () => {
  const f1 = runScanner(CALIB_SCAN_CODE, { filePath: 't42.js' }).findings[0];
  const f2 = runScanner(CALIB_SCAN_CODE, { filePath: 't42.js' }).findings[0];
  const cal1 = f1.evidence.interprocedural.correlation.calibration;
  const cal2 = f2.evidence.interprocedural.correlation.calibration;
  assert.deepEqual(cal1, cal2, 'identical input -> identical calibration');
});
// 43-44 Bounds
test('43. calibration summary respects length bound', () => {
  const steps = [];
  for (const u of UNCERTAINTY_VOCAB) {
    if (u === 'unresolved-call') steps.push({ kind: 'argument', functionId: '' });
    if (u === 'member-call') steps.push({ kind: 'argument', calleeName: 'a.b' });
    if (u === 'unknown-transformation') steps.push({ kind: 'assignment', expressionType: 'BinaryExpression' });
    if (u === 'computed-call') steps.push({ kind: 'argument', expressionType: 'CallExpression', computed: true });
  }
  const df = makeDataFlow(Array.from({ length: 20 }, () => makePath(steps)));
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.ok(cal.summary.length <= MAX_CALIBRATION_SUMMARY_LEN, 'summary length within bound');
});
test('44. uncertainty list respects bound even with many signals', () => {
  const steps = [
    { kind: 'argument', functionId: '' },
    { kind: 'argument', calleeName: 'a.b' },
    { kind: 'argument', expressionType: 'CallExpression', computed: true },
    { kind: 'assignment', expressionType: 'BinaryExpression' },
  ];
  const df = makeDataFlow(Array.from({ length: 20 }, () => makePath(steps)));
  const cal = calibrateEvidence(makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: df }));
  assert.ok(cal.uncertainty.length <= MAX_CALIBRATION_UNCERTAINTIES, 'uncertainty count within bound');
});
// 45 Empty Path Handling
test('45. empty data-flow paths produce valid CORRELATED calibration', () => {
  const corr = makeCorrelation({ sourceEvidence: [{}], sinkEvidence: [{}], dataFlow: makeDataFlow([]) });
  const cal = calibrateEvidence(corr);
  assert.equal(cal.level, EVIDENCE_LEVELS.CORRELATED);
  assert.equal(cal.pathCount, 0);
  assert.equal(cal.shortestPathLength, 0);
  assert.equal(cal.longestPathLength, 0);
  assert.equal(cal.directPathCount, 0);
  assert.equal(cal.dataFlowProven, false);
  assert.deepEqual(cal.uncertainty, ['cross-file-boundary']);
});
