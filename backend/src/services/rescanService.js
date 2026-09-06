/**
 * Rescan & Verification service (PHASES.md Phase 9).
 * Compares findings between a previous scan and a current scan to classify
 * resolved / remaining / newly-introduced findings.
 *
 * Matching is based on the stable comparisonKey (ruleId + line + fingerprint).
 */

export function compareScans(previousScan, currentScan) {
  const prevKeys = new Set((previousScan.findings || []).map((f) => f.comparisonKey));
  const currKeys = new Set((currentScan.findings || []).map((f) => f.comparisonKey));

  // Remaining: present in both previous and current.
  // Resolved: present in previous but not in current.
  // New: present in current but not in previous.
  let resolved = 0;
  let remaining = 0;
  let newCount = 0;

  for (const key of prevKeys) {
    if (currKeys.has(key)) remaining++;
    else resolved++;
  }
  for (const key of currKeys) {
    if (!prevKeys.has(key)) newCount++;
  }

  return { resolved, remaining, new: newCount };
}

/**
 * Produce a detailed per-finding comparison for the frontend so users can see
 * exactly which findings were resolved/remaining/new.
 */
export function buildComparisonDetail(previousScan, currentScan) {
  const prevByKey = new Map((previousScan.findings || []).map((f) => [f.comparisonKey, f]));
  const currByKey = new Map((currentScan.findings || []).map((f) => [f.comparisonKey, f]));

  const resolved = [];
  const remaining = [];
  const newlyIntroduced = [];

  for (const [key, f] of prevByKey) {
    if (currByKey.has(key)) remaining.push({ finding: f, status: 'remaining' });
    else resolved.push({ finding: f, status: 'resolved' });
  }
  for (const [key, f] of currByKey) {
    if (!prevByKey.has(key)) newlyIntroduced.push({ finding: f, status: 'new' });
  }

  return {
    resolved,
    remaining,
    newlyIntroduced,
    counts: {
      resolved: resolved.length,
      remaining: remaining.length,
      new: newlyIntroduced.length,
    },
  };
}

export default { compareScans, buildComparisonDetail };
