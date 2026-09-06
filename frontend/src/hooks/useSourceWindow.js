import { useEffect, useState } from 'react';
import api from '../api/client.js';

const cache = new Map(); // `${scanId}|${file}|${line}` -> window

/**
 * Fetch the bounded (~40-line) source window around a finding via the
 * read-only source endpoint. Returns { window, loading, error, reload }.
 */
export function useSourceWindow({ scanId, file, line, enabled = true }) {
  const key = `${scanId}|${file}|${line}`;
  const [window, setWindow] = useState(() => cache.get(key) || null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');

  async function load() {
    if (!enabled || !scanId || !file || !line) {
      setWindow(null);
      return;
    }
    const hit = cache.get(key);
    if (hit) {
      setWindow(hit);
      return;
    }
    setLoading(true);
    setError('');
    try {
      const { data } = await api.get(`/scans/${scanId}/source`, {
        params: { file, around: line },
      });
      cache.set(key, data);
      setWindow(data);
    } catch (err) {
      setError(err?.response?.data?.error || 'Source window unavailable');
      setWindow(null);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [key, enabled]);

  return { window, loading, error, reload: load };
}
