import { useCallback, useRef, useState } from 'react';
import api from '../api/client.js';

const cache = new Map(); // `${scanId}|${comparisonKey}` -> copilot payload

/**
 * Explain a single deterministic finding via POST /api/ai/explain.
 * Returns { status, copilot, error, explain } where status is one of
 * 'idle' | 'loading' | 'done' | 'unavailable'. Provider/parse failures surface
 * as 'unavailable' — the deterministic finding is never affected.
 */
export function useCopilot({ scanId, finding, code }) {
  const [state, setState] = useState(() => {
    const key = finding ? `${scanId}|${finding.comparisonKey}` : '';
    const hit = key && cache.get(key);
    return hit ? { status: 'done', copilot: hit, error: null } : { status: 'idle', copilot: null, error: null };
  });
  const inflight = useRef(false);

  const explain = useCallback(async () => {
    if (!finding || inflight.current) return;
    const key = `${scanId}|${finding.comparisonKey}`;
    const hit = cache.get(key);
    if (hit) {
      setState({ status: 'done', copilot: hit, error: null });
      return;
    }
    inflight.current = true;
    setState({ status: 'loading', copilot: null, error: null });
    try {
      const { data } = await api.post('/ai/explain', {
        finding: {
          ruleId: finding.ruleId,
          severity: finding.severity,
          confidence: finding.confidence != null ? finding.confidence / 100 : undefined,
          filePath: finding.filePath,
          line: finding.line || undefined,
          reason: finding.reason || undefined,
          title: finding.title || undefined,
          affectedCode: finding.affectedCode || undefined,
          comparisonKey: finding.comparisonKey || undefined,
          evidence: finding.evidence || undefined,
        },
        code: code || undefined,
        fileName: finding.filePath || undefined,
      });
      if (data && data.success && data.copilot) {
        cache.set(key, data.copilot);
        setState({ status: 'done', copilot: data.copilot, error: null });
      } else {
        setState({ status: 'unavailable', copilot: null, error: data?.error || 'AI explanation unavailable' });
      }
    } catch (err) {
      setState({ status: 'unavailable', copilot: null, error: err?.response?.data?.error || 'AI explanation unavailable' });
    } finally {
      inflight.current = false;
    }
  }, [finding, scanId, code]);

  return { ...state, explain };
}
