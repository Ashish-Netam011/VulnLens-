import rateLimit from 'express-rate-limit';
import env from '../config/env.js';

export function createRateLimiter() {
  return rateLimit({
    windowMs: env.RATE_LIMIT_WINDOW_MS,
    max: env.RATE_LIMIT_MAX_REQUESTS,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests, please try again later.' },
  });
}

/**
 * Stricter rate limiter for authentication endpoints (login / register).
 * Limits to a small number of attempts per window to slow brute-force attacks.
 */
export function createAuthRateLimiter() {
  return rateLimit({
    windowMs: env.AUTH_RATE_LIMIT_WINDOW_MS,
    max: env.AUTH_RATE_LIMIT_MAX,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many authentication attempts. Please try again later.' },
    keyGenerator: (req) => req.ip,
  });
}
