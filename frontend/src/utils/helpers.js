// Severity helpers shared across the frontend (DESIGN.md §4).
// Colors are semantic and consistent across cards, badges, charts, and reports.

export const SEVERITY_META = {
  critical: { label: 'Critical', color: '#f43f5e', badge: 'bg-critical/15 text-critical border-critical/30', dot: 'bg-critical', rank: 0 },
  high: { label: 'High', color: '#f97316', badge: 'bg-high/15 text-high border-high/30', dot: 'bg-high', rank: 1 },
  medium: { label: 'Medium', color: '#eab308', badge: 'bg-medium/15 text-medium border-medium/30', dot: 'bg-medium', rank: 2 },
  low: { label: 'Low', color: '#38bdf8', badge: 'bg-low/15 text-low border-low/30', dot: 'bg-low', rank: 3 },
  informational: { label: 'Informational', color: '#94a3b8', badge: 'bg-informational/15 text-informational border-informational/30', dot: 'bg-informational', rank: 4 },
};

export const SEVERITIES = Object.keys(SEVERITY_META);

export function severityMeta(sev) {
  return SEVERITY_META[sev] || SEVERITY_META.informational;
}

export function formatDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  return d.toLocaleDateString(undefined, { day: '2-digit', month: 'short', year: 'numeric' }) +
    ' ' +
    d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

export function scoreColor(score) {
  if (score >= 85) return '#4ade80';
  if (score >= 70) return '#a3e635';
  if (score >= 50) return '#eab308';
  if (score >= 30) return '#fb923c';
  return '#f43f5e';
}

export function scoreLabelText(score) {
  if (score >= 85) return 'Excellent';
  if (score >= 70) return 'Good';
  if (score >= 50) return 'Fair';
  if (score >= 30) return 'Poor';
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

// Copy to clipboard helper.
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    return false;
  }
}

// Simple HTML-escape for displaying user-provided code/titles safely.
export function escapeHtml(s) {
  return String(s || '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}