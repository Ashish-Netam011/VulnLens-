import env from '../config/env.js';
import * as openrouterModule from './openrouter.js';
import * as ollamaModule from './ollama.js';

/**
 * Modular AI provider layer (PRD §16, PHASES.md Phase 6).
 * The rest of the application depends only on this facade, so providers can be
 * added/changed without redesigning the app.
 *
 * Each provider exposes: async analyze(input) => { ...enriched fields }
 * and a name. If AI is disabled or fails, callers fall back to rule-authored
 * enrichment.
 */

const providers = {
  openrouter: openrouterModule,
  ollama: ollamaModule,
};

/**
 * @param {object} input - { code, findings, projectName, fileName }
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs] - Override AI timeout in ms
 * @param {number} [opts.maxRetries] - Override max retry count
 * @returns {Promise<{ok: boolean, source: string, results: Map<string, object>, error?: string, timedOut?: boolean}>}
 */
export async function analyzeWithAI(input, opts = {}) {
  const providerName = (env.AI_PROVIDER || 'none').toLowerCase();

  if (providerName === 'none' || !providers[providerName]) {
    return { ok: false, source: 'none', results: new Map(), error: 'No AI provider configured' };
  }

  const provider = providers[providerName];
  const timeoutMs = opts.timeoutMs ?? env.AI_TIMEOUT_MS ?? 30000;
  const maxRetries = opts.maxRetries ?? env.AI_MAX_RETRIES ?? 1;

  let lastError = null;
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      // `prompts` is an optional per-call override (used by the Phase 8 AI
      // Security Copilot for its dedicated injection-aware prompts). When
      // absent, each provider uses its default enrichment prompts — existing
      // scanService behavior is unchanged.
      const results = await provider.analyze(input, {
        signal: controller.signal,
        prompts: opts.prompts,
      });
      return { ok: true, source: provider.name, results };
    } catch (err) {
      lastError = err;
      const isAbort = err.name === 'AbortError' || err.message === 'The operation was aborted';
      const timedOut = isAbort;
      // Don't retry on auth/configuration errors or aborts
      const nonRetryable =
        isAbort ||
        /not configured|unauthorized|forbidden|invalid api key/i.test(err.message || '');
      if (nonRetryable || attempt === maxRetries) {
        return {
          ok: false,
          source: provider.name,
          results: new Map(),
          error: timedOut ? `AI request timed out after ${timeoutMs}ms` : err.message,
          timedOut,
        };
      }
      // Exponential backoff before retry
      const delay = Math.min(1000 * Math.pow(2, attempt), 4000);
      await new Promise((r) => setTimeout(r, delay));
    } finally {
      clearTimeout(timer);
    }
  }

  return {
    ok: false,
    source: providerName,
    results: new Map(),
    error: lastError?.message || 'AI request failed',
    timedOut: lastError?.name === 'AbortError',
  };
}

export function isAIEnabled() {
  const name = (env.AI_PROVIDER || 'none').toLowerCase();
  return name !== 'none' && !!providers[name];
}
