/**
 * AI Reliability Tests
 * Verifies AI parse/validation, offline fallback, and that AI failure
 * does not break the deterministic scan pipeline.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import env from '../src/config/env.js';
import { parseStructured as parseOpenRouter } from '../src/ai/openrouter.js';
import { parseStructured as parseOllama } from '../src/ai/ollama.js';
import { analyzeWithAI, isAIEnabled } from '../src/ai/provider.js';
import { runScanner } from '../src/scanner/scanner.js';
import { calculateScore } from '../src/scanner/score.js';

// ── OpenAI-style structured parsing (shared by both providers) ──────
test('parseStructured: handles plain JSON', () => {
  const json = '{"findings":[{"comparisonKey":"a:1:xyz","explanation":"e"}]}';
  const map = parseOpenRouter(json);
  assert.ok(map.has('a:1:xyz'));
  assert.equal(map.get('a:1:xyz').explanation, 'e');
});

test('parseStructured: tolerates markdown fences', () => {
  const json = '```json\n{"findings":[{"comparisonKey":"k1","explanation":"x"}]}\n```';
  const map = parseOllama(json);
  assert.ok(map.has('k1'));
});

test('parseStructured: tolerates surrounding text', () => {
  const json = 'Here is the result:\n{"findings":[{"comparisonKey":"k1","title":"t"}]}\nThat is all.';
  const map = parseOpenRouter(json);
  assert.ok(map.has('k1'));
});

test('parseStructured: throws on invalid JSON', () => {
  assert.throws(() => parseOpenRouter('not json at all'));
  assert.throws(() => parseOpenRouter('{"broken":'));
});

test('parseStructured: ignores entries without comparisonKey', () => {
  const json = '{"findings":[{"explanation":"no key"},{"comparisonKey":"valid","explanation":"y"}]}';
  const map = parseOpenRouter(json);
  assert.ok(map.has('valid'));
  assert.equal(map.size, 1);
});

// ── analyzeWithAI behavior ───────────────────────────────────────────
test('analyzeWithAI: returns ok=false when provider disabled', async () => {
  // Must simulate AI_PROVIDER=none by pointing at a nonexistent provider.
  const original = process.env.AI_PROVIDER;
  process.env.AI_PROVIDER = 'none';
  try {
    const result = await analyzeWithAI({ code: 'x', findings: [] });
    assert.equal(result.ok, false);
    assert.equal(result.source, 'none');
  } finally {
    process.env.AI_PROVIDER = original;
  }
});

test('analyzeWithAI: returns ok=false for unknown provider', async () => {
  const original = process.env.AI_PROVIDER;
  process.env.AI_PROVIDER = 'does-not-exist';
  try {
    const result = await analyzeWithAI({ code: 'x', findings: [] });
    assert.equal(result.ok, false);
  } finally {
    process.env.AI_PROVIDER = original;
  }
});

test('isAIEnabled: false when AI disabled', () => {
  const original = process.env.AI_PROVIDER;
  process.env.AI_PROVIDER = 'none';
  try {
    assert.equal(isAIEnabled(), false);
  } finally {
    process.env.AI_PROVIDER = original;
  }
});

// ── Timeout / retry / circuit-behavior ────────────────────────────────
test('analyzeWithAI: times out when provider hangs', async () => {
  const origFetch = globalThis.fetch;
  const origProvider = env.AI_PROVIDER;
  const origTimeout = env.AI_TIMEOUT_MS;
  try {
    env.AI_PROVIDER = 'openrouter';
    env.AI_TIMEOUT_MS = 100;
    env.OPENROUTER_API_KEY = 'test-key';
    // Fake a hanging provider: never resolves, but respects the abort signal.
    globalThis.fetch = (_url, { signal } = {}) =>
      new Promise((_resolve, reject) => {
        if (!signal) return reject(new Error('no signal'));
        signal.addEventListener('abort', () => reject(new Error('The operation was aborted')));
      });
    const result = await analyzeWithAI(
      { code: 'x', findings: [] },
      { maxRetries: 0 }
    );
    assert.equal(result.ok, false);
    assert.equal(result.timedOut, true);
    assert.match(result.error, /timed out/i);
  } finally {
    globalThis.fetch = origFetch;
    env.AI_PROVIDER = origProvider;
    env.AI_TIMEOUT_MS = origTimeout;
    env.OPENROUTER_API_KEY = '';
  }
});

test('analyzeWithAI: aborts pending request via signal', async () => {
  const origFetch = globalThis.fetch;
  const origProvider = env.AI_PROVIDER;
  const origTimeout = env.AI_TIMEOUT_MS;
  try {
    env.AI_PROVIDER = 'openrouter';
    env.AI_TIMEOUT_MS = 100;
    env.OPENROUTER_API_KEY = 'test-key';
    globalThis.fetch = (_url, { signal } = {}) =>
      new Promise((_resolve, reject) => {
        if (!signal) return reject(new Error('no signal'));
        signal.addEventListener('abort', () => reject(new Error('The operation was aborted')));
      });
    const result = await analyzeWithAI(
      { code: 'x', findings: [] },
      { maxRetries: 0 }
    );
    assert.equal(result.ok, false);
    assert.equal(result.timedOut, true);
  } finally {
    globalThis.fetch = origFetch;
    env.AI_PROVIDER = origProvider;
    env.AI_TIMEOUT_MS = origTimeout;
    env.OPENROUTER_API_KEY = '';
  }
});

test('analyzeWithAI: retries transient failures then succeeds', async () => {
  const origFetch = globalThis.fetch;
  const origProvider = env.AI_PROVIDER;
  const origTimeout = env.AI_TIMEOUT_MS;
  let calls = 0;
  try {
    env.AI_PROVIDER = 'openrouter';
    env.AI_TIMEOUT_MS = 2000;
    env.OPENROUTER_API_KEY = 'test-key';
    globalThis.fetch = async () => {
      calls += 1;
      if (calls < 2) {
        const e = new Error('502 Bad Gateway');
        e.status = 502;
        throw e;
      }
      return {
        ok: true,
        json: async () => ({
          choices: [{ message: { content: '{"findings":[{"comparisonKey":"k1","title":"t"}]}' } }],
        }),
      };
    };
    const result = await analyzeWithAI({ code: 'x', findings: [] }, { maxRetries: 1 });
    assert.equal(result.ok, true);
    assert.equal(calls, 2, 'Expected exactly 2 attempts (1 retry)');
  } finally {
    globalThis.fetch = origFetch;
    env.AI_PROVIDER = origProvider;
    env.AI_TIMEOUT_MS = origTimeout;
    env.OPENROUTER_API_KEY = '';
  }
});

test('analyzeWithAI: does not retry on config errors', async () => {
  const origFetch = globalThis.fetch;
  const origProvider = env.AI_PROVIDER;
  try {
    env.AI_PROVIDER = 'openrouter';
    const prevKey = env.OPENROUTER_API_KEY;
    env.OPENROUTER_API_KEY = '';
    let fetchCalls = 0;
    globalThis.fetch = async () => {
      fetchCalls += 1;
      throw new Error('should never be called');
    };
    const result = await analyzeWithAI({ code: 'x', findings: [] }, { maxRetries: 3 });
    assert.equal(result.ok, false);
    assert.match(result.error, /not configured/i);
    assert.equal(fetchCalls, 0, 'Config errors should short-circuit before any request');
    env.OPENROUTER_API_KEY = prevKey;
  } finally {
    globalThis.fetch = origFetch;
    env.AI_PROVIDER = origProvider;
  }
});

// ── Scan continues to work when AI is disabled ───────────────────────
test('scanner + score pipeline works without AI', () => {
  const code = 'db.query("SELECT * FROM users WHERE id=" + id);';
  const { findings, severityCounts } = runScanner(code, { filePath: 'a.js' });
  assert.ok(findings.length > 0);
  const score = calculateScore(severityCounts, { findings });
  assert.ok(score >= 0 && score <= 100);
});
