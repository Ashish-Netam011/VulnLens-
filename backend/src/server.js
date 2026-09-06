import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import env from './config/env.js';
import connectDB from './config/db.js';
import authRoutes from './routes/auth.js';
import projectRoutes from './routes/projects.js';
import scanRoutes from './routes/scans.js';
import reportRoutes from './routes/reports.js';
import dashboardRoutes from './routes/dashboard.js';
import { createRateLimiter } from './middleware/rateLimit.js';
import { notFound, errorHandler } from './middleware/errorHandler.js';

const app = express();

// Security headers with CSP tuned for API responses.
// The backend only returns JSON — no HTML, inline styles, or inline scripts —
// so 'unsafe-inline' is unnecessary and removed as a hardening measure.
app.use(
  helmet({
    contentSecurityPolicy: {
      directives: {
        defaultSrc: ["'self'"],
        scriptSrc: ["'self'"],
        styleSrc: ["'self'"],
        imgSrc: ["'self'", 'data:'],
        connectSrc: ["'self'"],
        fontSrc: ["'self'"],
        objectSrc: ["'none'"],
        frameAncestors: ["'none'"],
        baseUri: ["'none'"],
        upgradeInsecureRequests: [],
      },
    },
    referrerPolicy: { policy: 'strict-origin-when-cross-origin' },
    hsts: { maxAge: 31536000, includeSubDomains: true },
  })
);

// CORS — in production only allow the configured origin; in dev allow all.
const corsOrigin =
  env.NODE_ENV === 'production'
    ? env.CORS_ORIGIN
      ? [env.CORS_ORIGIN]
      : false
    : true;

app.use(cors({ origin: corsOrigin, credentials: true }));

// Rate limiting for the API.
app.use('/api', createRateLimiter());

// Body parsing with size limits.
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: false, limit: '2mb' }));

// Health check (no auth needed).
app.get('/api/health', (_req, res) =>
  res.json({ ok: true, service: 'vulnlens-backend' })
);

// API routes.
app.use('/api/auth', authRoutes);
app.use('/api/projects', projectRoutes);
app.use('/api/scans', scanRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/dashboard', dashboardRoutes);

// 404 + centralized error handling.
app.use(notFound);
app.use(errorHandler);

async function start() {
  await connectDB();
  const server = app.listen(env.PORT, () => {
    console.log(`VulnLens backend running on http://localhost:${env.PORT}`);
  });

  // Graceful shutdown on SIGTERM / SIGINT.
  const shutdown = (signal) => {
    console.log(`\n${signal} received — shutting down gracefully...`);
    server.close(() => {
      console.log('HTTP server closed.');
      process.exit(0);
    });
    // Force exit after 10s if connections hang.
    setTimeout(() => process.exit(1), 10_000);
  };
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
}

export default app;

// Only start listening when run directly (not when imported by tests).
if (process.env.NODE_ENV !== 'test') {
  start();
}
