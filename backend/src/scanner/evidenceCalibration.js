/**
 * Phase 5D — Evidence Calibration & Confidence Modeling.
 *
 * Assigns deterministic, explainable strength metadata to the evidence already
 * produced by the scanner and interprocedural analysis (Phases 5A-5C).  The
 * output is evidence-quality metadata ONLY — it must never change verdict,
 * severity, confidence, riskScore, score, ruleId, or comparisonKey.
 *
 * Properties:
 *   - Pure, deterministic, synchronous, JSON-safe, bounded, side-effect-free.
 */

// ── Version ─────────────────────────────────────────────────────────────────

export const EVIDENCE_CALIBRATION_VERSION = '5D.0';

// ── Evidence Levels (ordered weakest → strongest) ───────────────────────────

export const EVIDENCE_LEVELS = Object.freeze({
  NONE:       'NONE',
  STRUCTURAL: 'STRUCTURAL',
  CORRELATED: 'CORRELATED',
  DATA_FLOW:  'DATA_FLOW',
  DIRECT:     'DIRECT',
});

const _LEVEL_ORDER = [
  EVIDENCE_LEVELS.NONE,
  EVIDENCE_LEVELS.STRUCTURAL,
  EVIDENCE_LEVELS.CORRELATED,
  EVIDENCE_LEVELS.DATA_FLOW,
  EVIDENCE_LEVELS.DIRECT,
];

const _LEVEL_RANK = new Map(_LEVEL_ORDER.map((l, i) => [l, i]));

// ── Strength Mapping ────────────────────────────────────────────────────────

export const EVIDENCE_STRENGTH = Object.freeze({
  [EVIDENCE_LEVELS.NONE]:       0,
  [EVIDENCE_LEVELS.STRUCTURAL]: 25,
  [EVIDENCE_LEVELS.CORRELATED]: 50,
  [EVIDENCE_LEVELS.DATA_FLOW]:  75,
  [EVIDENCE_LEVELS.DIRECT]:     100,
});

// ── Uncertainty Vocabulary ──────────────────────────────────────────────────

export const UNCERTAINTY_VOCAB = Object.freeze([
  'ambiguous-branch', 'computed-call', 'cross-file-boundary',
  'dynamic-call', 'member-call', 'unresolved-call',
  'unknown-transformation', 'unsupported-destructuring',
]);

// ── Bounds ──────────────────────────────────────────────────────────────────

export const MAX_CALIBRATION_UNCERTAINTIES = 10;
export const MAX_CALIBRATION_SUMMARY_LEN  = 300;
export const MAX_CALIBRATION_PATHS        = 20;

// ── Summary Templates ───────────────────────────────────────────────────────

const _SUMMARY_TEXT = Object.freeze({
  [EVIDENCE_LEVELS.NONE]:       'No interprocedural evidence established.',
  [EVIDENCE_LEVELS.STRUCTURAL]: 'Structural function reachability observed.',
  [EVIDENCE_LEVELS.CORRELATED]: 'Source and sink are structurally correlated, but value propagation is not proven.',
  [EVIDENCE_LEVELS.DATA_FLOW]:  'Bounded intra-file data flow from a recognized source to a recognized sink.',
  [EVIDENCE_LEVELS.DIRECT]:     'Direct source-to-sink flow was structurally demonstrated.',
});

// ── Public API ──────────────────────────────────────────────────────────────

/**
 * Look up the deterministic numeric strength for an evidence level.
 * @param {string} level  One of EVIDENCE_LEVELS values.
 * @returns {number} 0-100
 */
export function calculateEvidenceStrength(level) {
  if (typeof level !== 'string') return 0;
  return EVIDENCE_STRENGTH[level] ?? 0;
}

/**
 * Classify the evidence level from the correlation and dataFlow objects.
 * @param {object|null} correlation  Phase 5B correlation object.
 * @param {object|null} dataFlow     Phase 5C dataFlow result.
 * @returns {string} One of EVIDENCE_LEVELS values.
 */
export function classifyEvidenceLevel(correlation, dataFlow) {
  if (!correlation || typeof correlation !== 'object') {
    return EVIDENCE_LEVELS.NONE;
  }

  const hasSource = !!(correlation.sourceEvidence && correlation.sourceEvidence.present);
  const hasSink   = !!(correlation.sinkEvidence   && correlation.sinkEvidence.present);
  const paths     = dataFlow && Array.isArray(dataFlow.paths) ? dataFlow.paths : [];
  const hasPaths  = paths.length > 0;

  // No source and no sink evidence
  if (!hasSource && !hasSink) {
    return correlation.affectedFunction ? EVIDENCE_LEVELS.STRUCTURAL : EVIDENCE_LEVELS.NONE;
  }

  // Both source AND sink present with proven data-flow paths
  if (hasSource && hasSink && hasPaths) {
    const shortest = _shortestPathLength(paths);
    // DIRECT: Phase 5C explicitly proved a direct path (<= 2 steps = source + sink)
    return shortest <= 2 ? EVIDENCE_LEVELS.DIRECT : EVIDENCE_LEVELS.DATA_FLOW;
  }

  // Both source AND sink present, but no data-flow path
  if (hasSource && hasSink) {
    return EVIDENCE_LEVELS.CORRELATED;
  }

  // Only one of source / sink → structural enrichment, not yet correlated
  return EVIDENCE_LEVELS.STRUCTURAL;
}

/**
 * Build a complete calibration object for a finding's interprocedural
 * correlation.  Main entry point.
 *
 * @param {object|null} correlation  Phase 5B correlation (may be null).
 * @returns {object}  Calibration metadata (NEVER null).
 */
export function calibrateEvidence(correlation) {
  if (!correlation || typeof correlation !== 'object') {
    return _emptyCalibration(_SUMMARY_TEXT[EVIDENCE_LEVELS.NONE]);
  }

  const dataFlow = correlation.dataFlow || null;
  const level = classifyEvidenceLevel(correlation, dataFlow);

  const sourcePresent    = !!(correlation.sourceEvidence && correlation.sourceEvidence.present);
  const sinkPresent      = !!(correlation.sinkEvidence   && correlation.sinkEvidence.present);
  const dataFlowProven   = !!(dataFlow && Array.isArray(dataFlow.paths) && dataFlow.paths.length > 0);

  const paths = dataFlow && Array.isArray(dataFlow.paths) ? dataFlow.paths : [];
  const inspectedPaths = paths.slice(0, MAX_CALIBRATION_PATHS);
  const pathCount          = inspectedPaths.length;
  const shortestPathLength = pathCount > 0 ? _shortestPathLength(inspectedPaths) : 0;
  const longestPathLength  = pathCount > 0 ? _longestPathLength(inspectedPaths)  : 0;
  const directPathCount    = _countDirectPaths(inspectedPaths);
  const truncated          = !!(dataFlow && dataFlow.truncated);

  const uncertainty = _detectUncertainties(inspectedPaths, correlation);
  const summary = buildCalibrationSummary(level, pathCount, uncertainty);

  return Object.freeze({
    version:              EVIDENCE_CALIBRATION_VERSION,
    level,
    strength:             calculateEvidenceStrength(level),
    sourcePresent,
    sinkPresent,
    sourceSinkCorrelated: sourcePresent && sinkPresent,
    dataFlowProven,
    directFlow:           level === EVIDENCE_LEVELS.DIRECT,
    pathCount,
    shortestPathLength,
    longestPathLength,
    directPathCount,
    truncated,
    uncertainty,
    summary,
  });
}

/**
 * Generate a deterministic, bounded, human-readable summary string.
 */
export function buildCalibrationSummary(level, pathCount, uncertainty) {
  let text = _SUMMARY_TEXT[level] || _SUMMARY_TEXT[EVIDENCE_LEVELS.NONE];
  if (Array.isArray(uncertainty) && uncertainty.length > 0) {
    text += ' Uncertainty: ' + uncertainty.join(', ') + '.';
  }
  return text.slice(0, MAX_CALIBRATION_SUMMARY_LEN);
}

// ── Internal Helpers ────────────────────────────────────────────────────────

function _pathLen(p) {
  if (typeof p.length === 'number') return p.length;
  if (Array.isArray(p.steps)) return p.steps.length;
  return 0;
}

function _shortestPathLength(paths) {
  let min = Infinity;
  for (const p of paths) { const l = _pathLen(p); if (l < min) min = l; }
  return min === Infinity ? 0 : min;
}

function _longestPathLength(paths) {
  let max = 0;
  for (const p of paths) { const l = _pathLen(p); if (l > max) max = l; }
  return max;
}

function _countDirectPaths(paths) {
  let count = 0;
  for (const p of paths) { if (_pathLen(p) <= 2) count++; }
  return count;
}

/**
 * Detect uncertainty tokens across data-flow paths and the correlation.
 * Returns a sorted, capped, frozen array.
 */
function _detectUncertainties(paths, correlation) {
  const found = new Set();

  for (const p of paths) {
    if (!p.steps || !Array.isArray(p.steps)) continue;
    for (const step of p.steps) {
      if (!step || typeof step !== 'object') continue;
      // Unresolved call: argument/parameter step with empty functionId
      if ((step.kind === 'argument' || step.kind === 'parameter') &&
          step.functionId === '') {
        found.add('unresolved-call');
      }
      // Member call: calleeName contains a dot
      if (typeof step.calleeName === 'string' && step.calleeName.includes('.')) {
        found.add('member-call');
      }
      // Unknown transformation: assignment with non-identifier expressionType
      if (step.kind === 'assignment' && step.expressionType &&
          step.expressionType !== 'Identifier' &&
          step.expressionType !== 'MemberExpression') {
        found.add('unknown-transformation');
      }
      // Computed call
      if (step.expressionType === 'CallExpression' && step.computed) {
        found.add('computed-call');
      }
    }
  }

  // Cross-file boundary: source+sink present but no data-flow paths
  if (correlation && (!correlation.dataFlow || !correlation.dataFlow.paths ||
      correlation.dataFlow.paths.length === 0)) {
    const hasSource = !!(correlation.sourceEvidence && correlation.sourceEvidence.present);
    const hasSink   = !!(correlation.sinkEvidence   && correlation.sinkEvidence.present);
    if (hasSource && hasSink) {
      found.add('cross-file-boundary');
    }
  }

  const sorted = [...found].sort().slice(0, MAX_CALIBRATION_UNCERTAINTIES);
  return Object.freeze(sorted);
}

function _emptyCalibration(summaryText) {
  return Object.freeze({
    version:              EVIDENCE_CALIBRATION_VERSION,
    level:                EVIDENCE_LEVELS.NONE,
    strength:             EVIDENCE_STRENGTH[EVIDENCE_LEVELS.NONE],
    sourcePresent:        false,
    sinkPresent:          false,
    sourceSinkCorrelated: false,
    dataFlowProven:       false,
    directFlow:           false,
    pathCount:            0,
    shortestPathLength:   0,
    longestPathLength:    0,
    directPathCount:      0,
    truncated:            false,
    uncertainty:          Object.freeze([]),
    summary:              summaryText.slice(0, MAX_CALIBRATION_SUMMARY_LEN),
  });
}

