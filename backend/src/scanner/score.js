/**
 * Risk Scoring service.
 * Computes a reproducible 0-100 security score from findings and severity counts.
 * The score is independent of the AI layer: AI can enrich findings but cannot
 * arbitrarily determine the final score (PRD §7, PHASES.md Phase 7).
 */

// Weights define how much each severity detracts from a perfect score of 100.
// A single critical finding heavily reduces the score; informational almost not at all.
const SEVERITY_WEIGHTS = {
  critical: 18,
  high: 10,
  medium: 5,
  low: 2,
  informational: 0.5,
};

export function calculateScore(severityCounts, opts = {}) {
  const counts = {
    critical: severityCounts.critical || 0,
    high: severityCounts.high || 0,
    medium: severityCounts.medium || 0,
    low: severityCounts.low || 0,
    informational: severityCounts.informational || 0,
  };

  let deduction = 0;
  for (const [sev, weight] of Object.entries(SEVERITY_WEIGHTS)) {
    // Diminishing returns: each additional finding of a severity adds less.
    // 1 - 0.9^n keeps score in [0,100] and discourages massive finding churn
    // from tanking the score to arbitrary extremes.
    deduction += weight * (1 - Math.pow(0.9, counts[sev]));
  }

  const score = Math.max(0, Math.min(100, Math.round(100 - deduction)));

  // Confidence-adjusted: findings with very low confidence pull slightly less.
  // With optional per-finding confidence provided, adjust mildy.
  if (opts.findings && opts.findings.length) {
    const avgConf = opts.findings.reduce((a, c) => a + (c.confidence || 50), 0) / opts.findings.length;
    // Only nudge when confidence is very low (<40), up to a small bonus.
    if (avgConf < 40) {
      const bonus = Math.min(4, Math.round((40 - avgConf) * 0.1));
      return Math.min(score + bonus, 100);
    }
  }

  return score;
}

export function scoreLabel(score) {
  if (score >= 85) return { label: 'Excellent', color: 'green' };
  if (score >= 70) return { label: 'Good', color: 'lime' };
  if (score >= 50) return { label: 'Fair', color: 'amber' };
  if (score >= 30) return { label: 'Poor', color: 'orange' };
  return { label: 'Critical', color: 'red' };
}

export default { calculateScore, scoreLabel, SEVERITY_WEIGHTS };
