/**
 * Phase 5E — Controlled Verdict Integration.
 *
 * Provides a single, policy-controlled bridge between calibrated
 * interprocedural evidence (Phases 5A–5D) and the finding's
 * verdict / confidence / severity.
 *
 * Properties:
 *   - Pure, deterministic, synchronous, JSON-safe, bounded, side-effect-free.
 *   - Never touches ruleId, comparisonKey, score, riskScore.
 *   - Dependency findings are explicitly excluded.
 *   - Idempotent: applying twice produces the same result.
 *   - Fail-closed: malformed / missing calibration → finding preserved unchanged.
 */

import { EVIDENCE_LEVELS } from './evidenceCalibration.js';

// ── Version ─────────────────────────────────────────────────────────────────

export const VERDICT_INTEGRATION_VERSION = '5E.0';

// ── Policy Constants (frozen) ───────────────────────────────────────────────

/** Bounded confidence delta per evidence level. */
export const CONFIDENCE_DELTAS = Object.freeze({
  [EVIDENCE_LEVELS.NONE]:       0,
  [EVIDENCE_LEVELS.STRUCTURAL]: 0,
  [EVIDENCE_LEVELS.CORRELATED]: 3,
  [EVIDENCE_LEVELS.DATA_FLOW]:  5,
  [EVIDENCE_LEVELS.DIRECT]:     10,
});

/** Hard ceiling for confidence after Phase 5E adjustment. */
export const MAX_INTEGRATED_CONFIDENCE = 50;

/** Allowed verdict transitions (allowlist). */
export const VERDICT_TRANSITIONS = Object.freeze({
  POTENTIAL: Object.freeze({
    target: 'LIKELY',
    minEvidenceLevel: EVIDENCE_LEVELS.DIRECT,
    requireNoUncertainty: true,
  }),
});

// Ordered level array for comparison
const _LEVEL_ORDER = Object.freeze([
  EVIDENCE_LEVELS.NONE,
  EVIDENCE_LEVELS.STRUCTURAL,
  EVIDENCE_LEVELS.CORRELATED,
  EVIDENCE_LEVELS.DATA_FLOW,
  EVIDENCE_LEVELS.DIRECT,
]);

// ── Main Function ───────────────────────────────────────────────────────────

/**
 * Apply controlled verdict integration to a finding.
 * Reads the calibration metadata from Phase 5D and, if policy conditions
 * are met, applies a bounded adjustment to confidence and/or verdict.
 * Severity is re-derived from the (possibly new) verdict.
 *
 * @param {object} finding - A processed finding with verdict, confidence,
 *   severity, and evidence.interprocedural.calibration.
 * @returns {object} The same finding, mutated if integration applied,
 *   or unchanged if any guard fails (fail-closed).
 */
export function integrateVerdict(finding) {
  if (!finding || typeof finding !== 'object') return finding;

  const spot = _safeCalibrationContext(finding);
  if (!spot) return finding;
  const cal = spot.calibration;
  const correlation = spot.correlation;

  if (finding.kind === 'dependency') return finding;
  if (cal.integration && cal.integration.applied) return finding;

  if (!isValidVerdict(finding.verdict)) return finding;
  if (typeof finding.confidence !== 'number') return finding;
  if (!isValidSeverity(finding.severity)) return finding;

  const level = cal.level;
  if (!isValidLevel(level)) return finding;

  // ── Compute confidence delta ────────────────────────────────────────────
  const delta = CONFIDENCE_DELTAS[level] || 0;
  // Never reduce existing confidence — only boost up to the Phase 5E ceiling.
  const boostedConfidence = Math.min(finding.confidence + delta, MAX_INTEGRATED_CONFIDENCE);
  const finalConfidence = Math.max(boostedConfidence, finding.confidence);

  // ── Compute verdict transition ──────────────────────────────────────────
  let finalVerdict = finding.verdict;
  const transition = VERDICT_TRANSITIONS[finding.verdict];
  if (transition && levelMeetsThreshold(level, transition.minEvidenceLevel)) {
    if (!transition.requireNoUncertainty) {
      finalVerdict = transition.target;
    } else {
      const uncertainty = cal.uncertainty;
      const hasNoUncertainty = Array.isArray(uncertainty) && uncertainty.length === 0;
      const hasDirectPaths = typeof cal.directPathCount === 'number' && cal.directPathCount > 0;
      if (hasNoUncertainty && hasDirectPaths) {
        finalVerdict = transition.target;
      }
    }
  }

  // ── Derive severity from (possibly new) verdict ────────────────────────
  const finalSeverity = _deriveSeverityFromVerdict(finalVerdict, _findOriginalSeverity(finding));

  // ── Bail if nothing changed ─────────────────────────────────────────────
  if (
    finalConfidence === finding.confidence &&
    finalVerdict === finding.verdict &&
    finalSeverity === finding.severity
  ) {
    return finding;
  }

  // ── Apply changes ───────────────────────────────────────────────────────
  const origVerdict = finding.verdict;
  const origConfidence = finding.confidence;
  const origSeverity = finding.severity;

  finding.verdict = finalVerdict;
  finding.confidence = finalConfidence;
  finding.severity = finalSeverity;

  // ── Attach integration metadata ─────────────────────────────────────────
  const verdictChanged = origVerdict !== finalVerdict;
  const policy = verdictChanged
    ? `${origVerdict}+${level}→${finalVerdict}`
    : `${level}→confidence+${delta}`;

  _attachIntegrationMetadata(correlation, cal, {
    applied: true,
    originalVerdict: origVerdict,
    finalVerdict,
    originalConfidence: origConfidence,
    finalConfidence,
    originalSeverity: origSeverity,
    finalSeverity,
    evidenceLevel: level,
    evidenceStrength: _evidenceStrength(level),
    policy,
    reason: _buildReason(origVerdict, finalVerdict, level, delta),
  });

  return finding;
}

// ── Internal Helpers ────────────────────────────────────────────────────────

function _safeCalibrationContext(finding) {
  try {
    const ip = finding.evidence && finding.evidence.interprocedural;
    if (!ip || typeof ip !== 'object') return null;
    const corr = ip.correlation;
    if (!corr || typeof corr !== 'object') return null;
    const cal = corr.calibration;
    if (!cal || typeof cal !== 'object') return null;
    return { correlation: corr, calibration: cal };
  } catch {
    return null;
  }
}

export function isValidVerdict(v) {
  return v === 'CONFIRMED' || v === 'LIKELY' || v === 'POTENTIAL';
}

function isValidSeverity(s) {
  return s === 'critical' || s === 'high' || s === 'medium' || s === 'low' || s === 'informational';
}

function isValidLevel(level) {
  return Object.values(EVIDENCE_LEVELS).includes(level);
}

function levelMeetsThreshold(actual, required) {
  const a = _LEVEL_ORDER.indexOf(actual);
  const r = _LEVEL_ORDER.indexOf(required);
  if (a === -1 || r === -1) return false;
  return a >= r;
}

function _evidenceStrength(level) {
  const map = {
    [EVIDENCE_LEVELS.NONE]:       0,
    [EVIDENCE_LEVELS.STRUCTURAL]: 25,
    [EVIDENCE_LEVELS.CORRELATED]: 50,
    [EVIDENCE_LEVELS.DATA_FLOW]:  75,
    [EVIDENCE_LEVELS.DIRECT]:     100,
  };
  return map[level] || 0;
}

/** Severity derivation mirroring the deterministic deriveSeverity logic. */
function _deriveSeverityFromVerdict(verdict, ruleSeverity) {
  if (verdict === 'CONFIRMED') return _normalizeSeverity(ruleSeverity);
  if (verdict === 'LIKELY') {
    const s = _normalizeSeverity(ruleSeverity);
    return s === 'critical' ? 'high' : s;
  }
  if (verdict === 'POTENTIAL') return 'low';
  return _normalizeSeverity(ruleSeverity);
}

function _normalizeSeverity(s) {
  const map = { critical:'critical', high:'high', medium:'medium', low:'low', informational:'informational' };
  return map[s] || 'medium';
}

function _attachIntegrationMetadata(correlation, cal, meta) {
  // The calibration returned by Phase 5D is frozen, so we can't add a
  // property in place. Build a fresh calibration carrying the integration
  // metadata and reassign it on the (mutable) correlation object.
  const fresh = Object.freeze({
    ...cal,
    integration: Object.freeze({ ...meta }),
  });
  correlation.calibration = fresh;
}

/**
 * Recover the original rule severity before deriveSeverity overwrote it.
 * scanner.js saves it as _ruleSeverity before calling deriveSeverity.
 * For POTENTIAL→LIKELY upgrade, LIKELY needs the rule severity to derive from.
 */
function _findOriginalSeverity(finding) {
  if (finding._ruleSeverity) return finding._ruleSeverity;
  return 'medium'; // conservative fallback
}

function _buildReason(origVerdict, finalVerdict, level, delta) {
  if (origVerdict !== finalVerdict) {
    return `Interprocedural evidence level ${level} with ${delta} confidence delta supports upgrading ${origVerdict} to ${finalVerdict}.`;
  }
  if (delta > 0) {
    return `Interprocedural evidence level ${level} strengthens confidence by ${delta}.`;
  }
  return 'No policy condition met for adjustment.';
}

