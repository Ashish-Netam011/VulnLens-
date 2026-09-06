import env from '../config/env.js';

/* eslint-disable no-unused-vars */
export function notFound(req, res, next) {
  // Strip query parameters to avoid echoing potentially sensitive data
  // (e.g. tokens accidentally placed in query strings).
  const safePath = (req.originalUrl || '').split('?')[0] || req.originalUrl;
  res.status(404).json({ error: `Route not found: ${req.method} ${safePath}` });
}

export function errorHandler(err, req, res, next) {
  // Validation errors (zod)
  if (err.name === 'ZodError') {
    return res.status(400).json({
      error: 'Validation failed',
      details: err.issues.map((i) => ({ path: i.path.join('.'), message: i.message })),
    });
  }
  // Mongoose validation
  if (err.name === 'ValidationError') {
    const details = Object.values(err.errors).map((e) => e.message);
    return res.status(400).json({ error: 'Validation failed', details });
  }
  // Multer errors
  if (err.name === 'MulterError') {
    return res.status(400).json({ error: err.message });
  }

  // Malformed MongoDB ObjectIds (CastError) — treat as a missing resource
  // instead of a 500 so malformed ids never leak stack traces or internals.
  if (err.name === 'CastError') {
    return res.status(404).json({ error: 'Resource not found' });
  }

  const status = err.status || err.statusCode || 500;
  const message =
    status >= 500 && env.NODE_ENV === 'production'
      ? 'Internal server error'
      : err.message || 'Internal server error';

  // In development, surface the stack for debugging (never in production).
  const response = { error: message };
  if (status >= 500 && env.NODE_ENV !== 'production') {
    response.stack = err.stack;
  }
  res.status(status).json(response);
}

export function createHttpError(status, message) {
  const e = new Error(message);
  e.status = status;
  return e;
}
