/**
 * Deterministic verdict engine (Phase 4C).
 *
 * Maps AST-derived `evidence` for a finding to one of four verdicts:
 *   - CONFIRMED      : a user-controlled source provably reaches the sink.
 *   - LIKELY         : strong circumstantial evidence (reserved for Phase 4D).
 *   - POTENTIAL      : suspicious shape, but no confirmed source→sink flow.
 *   - FALSE_POSITIVE : provably safe (e.g. constant data on a DOM sink).
 *
 * The engine is pure and deterministic: the same evidence always yields the
 * same verdict. No AI involvement. Severity is derived from the verdict by the
 * scanner (see applyEvidenceEngine), NOT copied from the rule.
 */

export const VERDICTS = ['CONFIRMED', 'LIKELY', 'POTENTIAL', 'FALSE_POSITIVE'];

const XSS_CATEGORY = 'Cross-Site Scripting (XSS)';

/**
 * @param {object} evidence  Evidence object produced by evidence.js.
 * @param {{category: string, ruleId: string}} ctx
 * @returns {string} one of VERDICTS
 */
export function determineVerdict(evidence, { category, ruleId }) {
  if (!evidence) return 'POTENTIAL';

  // Static-confirmed categories/rules: constant data IS the vulnerability
  // (hardcoded secrets, weak crypto, misconfig, sensitive data, eval, etc.).
  if (evidence.staticConfirmed) return 'CONFIRMED';

  // A parameterized / prepared query is provably safe.
  if (evidence.parameterized) return 'FALSE_POSITIVE';

  // Confirmed attacker-controlled source reaches the sink.
  if (evidence.flow && evidence.flow.established) return 'CONFIRMED';

  // No confirmed flow. Constant data reaching an injection sink is suspicious
  // but not exploitable; constant data on a DOM sink is a pure false positive.
  if (evidence.constantData && !(evidence.flow && evidence.flow.established)) {
    return category === XSS_CATEGORY ? 'FALSE_POSITIVE' : 'POTENTIAL';
  }

  // Everything else (sink present with unknown/unconfirmed taint, template-only
  // interpolation, sanitized values) is a POTENTIAL lead, never a confirmation.
  return 'POTENTIAL';
}
