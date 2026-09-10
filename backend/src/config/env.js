import dotenv from 'dotenv';
import crypto from 'node:crypto';

// Preserve any NODE_ENV that was set before dotenv loaded (e.g. NODE_ENV=test
// in the test script) so the server doesn't auto-start when imported by tests.
const _preDotenvNodeEnv = process.env.NODE_ENV;
dotenv.config({ override: true });
if (_preDotenvNodeEnv !== undefined) {
  process.env.NODE_ENV = _preDotenvNodeEnv;
}

const NODE_ENV = process.env.NODE_ENV || 'development';

// JWT signing secret — never embed a hardcoded literal (that would let any
// reader of the source forge tokens). In production it must be provided via
// process.env.JWT_SECRET (fail-closed below).  In non-production environments
// we generate an ephemeral random secret at boot: it is never persisted and
// never appears as a literal in source, so it cannot be leaked or reused
// across restarts.  Sessions won't survive a restart, which is acceptable for
// local and CI development.
const JWT_SECRET = process.env.JWT_SECRET || undefined;

// Fail-closed in production: do NOT start with a missing JWT signing secret.
if (NODE_ENV === 'production' && !JWT_SECRET) {
  console.error('FATAL: JWT_SECRET must be set to a strong random value in production.');
  process.exit(1);
}

const env = {
  // AI reliability
  AI_TIMEOUT_MS: parseInt(process.env.AI_TIMEOUT_MS || '30000', 10),
  AI_MAX_RETRIES: parseInt(process.env.AI_MAX_RETRIES || '1', 10),

  PORT: parseInt(process.env.PORT || '5000', 10),
  NODE_ENV,
  MONGODB_URI: process.env.MONGODB_URI || 'mongodb://localhost:27017/vulnlens',
  // For non-production: generate an ephemeral random secret so no hardcoded
  // literal exists in source.  For production: the env-var must have been
  // set or the process already exited above.
  JWT_SECRET: process.env.JWT_SECRET || (NODE_ENV === 'production' ? '' : crypto.randomBytes(48).toString('hex')),
  JWT_EXPIRES_IN: process.env.JWT_EXPIRES_IN || '7d',
  AI_PROVIDER: process.env.AI_PROVIDER || 'none',
  OPENROUTER_API_KEY: process.env.OPENROUTER_API_KEY || '',
  OPENROUTER_MODEL: process.env.OPENROUTER_MODEL || 'meta-llama/llama-3.1-8b-instruct',
  OLLAMA_BASE_URL: process.env.OLLAMA_BASE_URL || 'http://localhost:11434',
  OLLAMA_MODEL: process.env.OLLAMA_MODEL || 'codellama',
  RATE_LIMIT_WINDOW_MS: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '900000', 10),
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '5000', 10),
  AUTH_RATE_LIMIT_WINDOW_MS: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS || '900000', 10),
  AUTH_RATE_LIMIT_MAX: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '500', 10),
  MAX_FILE_SIZE_BYTES: parseInt(process.env.MAX_FILE_SIZE_BYTES || '2097152', 10),
  CORS_ORIGIN: process.env.CORS_ORIGIN || '',

  // Dependency / CVE intelligence (Phase 2)
  OSV_API_URL: process.env.OSV_API_URL || 'https://api.osv.dev/v1/querybatch',
  CVE_LOOKUP_TIMEOUT_MS: parseInt(process.env.CVE_LOOKUP_TIMEOUT_MS || '12000', 10),
  CVE_LOOKUP_CACHE_TTL_MS: parseInt(process.env.CVE_LOOKUP_CACHE_TTL_MS || '21600000', 10),
};

// Guarantee the signer never runs in production with a missing secret. The
// primary guard ran before `env` was built; this is a second, fail-safe check
// against the actual exported value.
if (env.NODE_ENV === 'production' && !env.JWT_SECRET) {
  console.error('FATAL: JWT_SECRET must be set to a strong random value in production.');
  process.exit(1);
}

export default env;
