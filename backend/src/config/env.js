import dotenv from 'dotenv';
import crypto from 'node:crypto';

// Preserve pre-existing env vars that were set by the platform (Render, CI, etc.)
// before dotenv loads. dotenv must NEVER override a variable the platform already
// provided — those are the authoritative production values (PORT, MONGODB_URI,
// JWT_SECRET, etc.). We only let .env fill in missing values for local development.
//
// We snapshot every platform-provided var before dotenv runs, load .env without
// overriding, then restore the platform values so .env cannot clobber them.
const _platformVars = new Set([
  'NODE_ENV',
  'PORT',
  'MONGODB_URI',
  'JWT_SECRET',
  'JWT_EXPIRES_IN',
  'CORS_ORIGIN',
  'AI_PROVIDER',
  'RATE_LIMIT_WINDOW_MS',
  'RATE_LIMIT_MAX_REQUESTS',
  'AUTH_RATE_LIMIT_WINDOW_MS',
  'AUTH_RATE_LIMIT_MAX',
  'MAX_FILE_SIZE_BYTES',
  'OSV_API_URL',
  'CVE_LOOKUP_TIMEOUT_MS',
  'CVE_LOOKUP_CACHE_TTL_MS',
  'OPENROUTER_API_KEY',
  'OPENROUTER_MODEL',
  'OLLAMA_BASE_URL',
  'OLLAMA_MODEL',
  'AI_TIMEOUT_MS',
  'AI_MAX_RETRIES',
]);
const _preDotenv = {};
for (const k of _platformVars) {
  if (process.env[k] !== undefined) _preDotenv[k] = process.env[k];
}

// Only load .env for missing values (local dev). Never override platform values.
dotenv.config();

// Restore any platform-provided values that .env may have overwritten (safety net).
for (const [k, v] of Object.entries(_preDotenv)) {
  process.env[k] = v;
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
  RATE_LIMIT_MAX_REQUESTS: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
  AUTH_RATE_LIMIT_WINDOW_MS: parseInt(process.env.AUTH_RATE_LIMIT_WINDOW_MS || '900000', 10),
  AUTH_RATE_LIMIT_MAX: parseInt(process.env.AUTH_RATE_LIMIT_MAX || '10', 10),
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
