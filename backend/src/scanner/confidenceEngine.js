/**
 * Deterministic confidence engine (Phase 4C).
 *
 * Produces a 0–100 confidence score purely from the evidence + verdict, so
 * confidence is a stable function of what the engine can actually prove rather
 * than an arbitrary rule-authored number. No AI involvement.
 *
 * Mapping (deterministic):
 *   CONFIRMED + direct flow          -> 95
 *   CONFIRMED + indirect flow        -> 90
 *   CONFIRMED + static confirmation  -> max(82, base)
 *   LIKELY                           -> capped at 70
 *   POTENTIAL                        -> capped at 35
 *   FALSE_POSITIVE                   -> 0 (dropped by the scanner)
 */

const clamp = (x) => Math.max(0, Math.min(100, Math.round(x)));

/**
 * @param {object} evidence  Evidence object from evidence.js.
 * @param {string} verdict   One of VERDICTS.
 * @param {number} [baseConfidence] The rule-authored confidence (fallback only).
 * @returns {number} 0–100
 */
export function computeConfidence(evidence, verdict, baseConfidence = 0) {
  const base = Number(baseConfidence) || 0;

  switch (verdict) {
    case 'FALSE_POSITIVE':
      return 0;
    case 'CONFIRMED':
      if (evidence && evidence.staticConfirmed) return clamp(Math.max(82, base));
      if (evidence && evidence.flow && evidence.flow.established) {
        return evidence.flow.direct ? 95 : 90;
      }
      return clamp(Math.max(80, base));
    case 'LIKELY':
      return clamp(Math.min(70, base || 70));
    case 'POTENTIAL':
    default:
      return clamp(Math.min(35, base || 35));
  }
}
