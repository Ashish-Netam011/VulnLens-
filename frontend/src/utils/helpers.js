// Shared helpers for the VulnLens security cockpit.
// Severity visuals are semantic (label + tone) — color is a supporting signal.

export const SEVERITY_META = {
  critical: {
    label: 'Critical',
    color: '#fb4d63',
    badge: 'bg-critical/10 text-critical border-critical/35',
    dot: 'bg-critical',
    text: 'text-critical',
    rank: 0,
    bar: 'bg-critical',
  },
  high: {
    label: 'High',
    color: '#f97316',
    badge: 'bg-high/10 text-high border-high/35',
    dot: 'bg-high',
    text: 'text-high',
    rank: 1,
    bar: 'bg-high',
  },
  medium: {
    label: 'Medium',
    color: '#eab308',
    badge: 'bg-medium/10 text-medium border-medium/35',
    dot: 'bg-medium',
    text: 'text-medium',
    rank: 2,
    bar: 'bg-medium',
  },
  low: {
    label: 'Low',
    color: '#38bdf8',
    badge: 'bg-low/10 text-low border-low/35',
    dot: 'bg-low',
    text: 'text-low',
    rank: 3,
    bar: 'bg-low',
  },
  informational: {
    label: 'Info',
    color: '#94a3b8',
    badge: 'bg-informational/10 text-informational border-informational/35',
    dot: 'bg-informational',
    text: 'text-informational',
    rank: 4,
    bar: 'bg-informational',
  },
};

export const SEVERITIES = Object.keys(SEVERITY_META);

export function severityMeta(sev) {
  return SEVERITY_META[sev] || SEVERITY_META.informational;
}

export function severityRank(sev) {
  return (SEVERITY_META[sev] || SEVERITY_META.informational).rank;
}

/** Order findings critical → info, then confidence desc, then line asc. */
export function sortFindings(findings = []) {
  return [...findings].sort((a, b) => {
    const d = severityRank(a.severity) - severityRank(b.severity);
    if (d !== 0) return d;
    const c = (b.confidence || 0) - (a.confidence || 0);
    if (c !== 0) return c;
    return (a.line || 0) - (b.line || 0);
  });
}

export const VERDICT_META = {
  CONFIRMED: { label: 'Confirmed', tone: 'critical', note: 'User-controlled input reaches the sink with no sanitization.' },
  LIKELY: { label: 'Likely', tone: 'high', note: 'Shape matches the pattern; input reaches the sink.' },
  POTENTIAL: { label: 'Potential', tone: 'medium', note: 'Pattern present but no confirmed source flow.' },
  FALSE_POSITIVE: { label: 'False positive', tone: 'success', note: 'Provably safe in this context.' },
};

export function verdictMeta(v) {
  return VERDICT_META[v] || { label: v || '—', tone: 'slate', note: '' };
}

/** Human label + tone for a finding's rescan status (from /comparison detail). */
export function rescanStatus(f, comparison) {
  const d = comparison?.detail;
  if (!d) return null;
  const key = f.comparisonKey;
  const has = (arr) => (arr || []).some((r) => r.finding?.comparisonKey === key);
  if (has(d.newlyIntroduced)) return { label: 'New', tone: 'critical' };
  if (has(d.resolved)) return { label: 'Resolved', tone: 'success' };
  if (has(d.remaining)) return { label: 'Pre-existing', tone: 'slate' };
  return null;
}

export function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return (
    d.toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' }) +
    ' ' +
    d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' })
  );
}

export function formatShortDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

export function relativeTime(iso) {
  if (!iso) return '—';
  const diff = Date.now() - new Date(iso).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return 'just now';
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  return formatShortDate(iso);
}

export function scoreColor(score) {
  if (score >= 85) return '#34d399';
  if (score >= 70) return '#a3e635';
  if (score >= 50) return '#eab308';
  if (score >= 30) return '#fb923c';
  return '#fb4d63';
}

export function scoreTone(score) {
  if (score >= 85) return 'success';
  if (score >= 70) return 'success';
  if (score >= 50) return 'warn';
  if (score >= 30) return 'danger';
  return 'danger';
}

export function scoreLabelText(score) {
  if (score >= 85) return 'Strong';
  if (score >= 70) return 'Good';
  if (score >= 50) return 'Fair';
  if (score >= 30) return 'Weak';
  return 'Critical';
}

export function errorMessage(err, fallback = 'Something went wrong. Please try again.') {
  if (err?.response?.data?.error) return err.response.data.error;
  if (err?.message) return err.message;
  return fallback;
}

export function pluralize(n, word) {
  return `${n} ${word}${n === 1 ? '' : 's'}`;
}

export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

export function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Join conditional class names. */
export function cx(...parts) {
  return parts.filter(Boolean).join(' ');
}

export function truncate(str, n) {
  const s = String(str || '');
  return s.length > n ? s.slice(0, n - 1) + '…' : s;
}

export function isDependency(f) {
  return f?.kind === 'dependency';
}

/** Short display of a file path, keeping its tail meaningful. */
export function fileTail(path, max = 44) {
  const s = String(path || '');
  if (s.length <= max) return s;
  const tail = s.slice(-max);
  const cut = tail.indexOf('/');
  return cut > 0 ? `…${tail.slice(cut)}` : `…${tail}`;
}

/** Sum severity counts into a number. */
export function countOf(counts, sev) {
  if (sev) return counts?.[sev] || 0;
  return (counts?.critical || 0) + (counts?.high || 0) + (counts?.medium || 0) + (counts?.low || 0) + (counts?.informational || 0);
}

export function sumCounts(counts) {
  return countOf(counts);
}
