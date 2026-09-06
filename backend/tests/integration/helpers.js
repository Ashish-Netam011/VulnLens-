/**
 * Integration-test bootstrap (Phase 4E).
 *
 * Boots the real Express app against an in-memory MongoDB instance so the full
 * production path — scanner → evidence → verdict → confidence → severity →
 * scanService → Scan model → MongoDB → API — is exercised against real
 * persistence, not stubs.
 *
 * Bootstrap order matters:
 *  1. Import env.js first so `dotenv.config({override:true})` runs.
 *  2. Re-set process.env.NODE_ENV to 'test' (dotenv from .env overwrites it).
 *  3. Mutate the env object directly (env.AI_PROVIDER='none') so all code paths
 *     that read env.* get the test values.
 *  4. Import server.js — it checks process.env.NODE_ENV, sees 'test', and
 *     skips auto-start/connectDB().
 *  5. Connect mongoose to the in-memory URI ourselves.
 */
import process from 'node:process';

// Pre-set before any imports execute.
process.env.NODE_ENV = 'test';
process.env.JWT_SECRET = 'integration-test-secret';
process.env.AI_PROVIDER = 'none';

let mongoose;
let server;
let memoryServer;
let env; // shared env module (mutated after dotenv)
let baseUrl = '';

/**
 * Start the in-memory MongoDB + Express app.
 * @returns {Promise<{baseUrl: string}>}
 */
export async function setupTestServer() {
  // 1. Boot in-memory MongoDB first.
  const { MongoMemoryServer } = await import('mongodb-memory-server');
  memoryServer = await MongoMemoryServer.create();
  const memoryUri = memoryServer.getUri('vulnlens_test');

  // 2. Import env.js — this triggers dotenv.config({override:true}) which reads
  //    .env and overwrites our process.env values.  That's expected; we re-assert
  //    right after.
  env = (await import('../../src/config/env.js')).default;

  // Re-assert NODE_ENV (dotenv clobbered it to 'development' from .env).
  process.env.NODE_ENV = 'test';

  // Point MONGODB_URI to the in-memory server on the env module so every
  // consumer that reads env.MONGODB_URI (config, controllers) sees the right URI.
  env.MONGODB_URI = memoryUri;

  // Ensure AI is forced off for all integration tests (override .env value).
  env.AI_PROVIDER = 'none';

  // 3. Connect mongoose directly (no server auto-start; NODE_ENV is 'test').
  mongoose = (await import('mongoose')).default;
  await mongoose.connect(memoryUri);

  // 4. Dynamically import the server — it evaluates the `if (NODE_ENV !== 'test')`
  //    guard and skips start(), so no Atlas connect and no port collision.
  const { default: appModule } = await import('../../src/server.js');

  // 5. Bind to an ephemeral port so tests don't clash with the dev server.
  await new Promise((resolve) => {
    server = appModule.listen(0, () => resolve());
  });
  const { port } = server.address();
  baseUrl = `http://127.0.0.1:${port}`;

  return { baseUrl };
}

/** Shut down the server + in-memory DB (idempotent). */
export async function teardownTestServer() {
  if (server) {
    await new Promise((resolve) => server.close(() => resolve()));
    server = null;
  }
  if (mongoose) {
    await mongoose.disconnect();
    mongoose = null;
  }
  if (memoryServer) {
    await memoryServer.stop();
    memoryServer = null;
  }
}

/**
 * Create an authenticated test user (via the real User model) and return its
 * id, plus a signed JWT that `protect` will accept.
 * @returns {Promise<{userId: string, token: string}>}
 */
export async function createAuthUser() {
  const User = (await import('../../src/models/User.js')).default;
  const user = await User.create({
    email: `user_${Date.now()}_${Math.random().toString(36).slice(2, 8)}@test.local`,
    passwordHash: '$2a$10$CwTycUXWue0Thq9StjUM0uJ4wX8vYpZplmKpI6GH6XqG9mFxv0G2i', // dummy hash; pw never verified in tests
    name: 'Integration Tester',
  });

  // Sign with the SAME secret protect.js will verify against (env.JWT_SECRET,
  // which was loaded from .env by dotenv during env.js initialization).
  const { default: jwt } = await import('jsonwebtoken');
  const jwtSecret = env.JWT_SECRET || process.env.JWT_SECRET || 'integration-test-secret';
  const token = jwt.sign(
    { id: user._id.toString(), email: user.email },
    jwtSecret,
    { algorithm: 'HS256', expiresIn: '1h' }
  );
  return { userId: user._id.toString(), token };
}

/** Create a Project owned by userId. */
export async function createProject(userId) {
  const Project = (await import('../../src/models/Project.js')).default;
  const project = await Project.create({
    owner: userId,
    name: `Project ${Date.now()}`,
  });
  return project._id.toString();
}

/** Authorization header value for the given token. */
export function authHeader(token) {
  return `Bearer ${token}`;
}

/**
 * Convenience HTTP helper. Returns the parsed JSON body and the status; throws
 * on network/JSON errors so failures surface loudly.
 */
export async function api(baseUrlIn, method, path, { token, body } = {}) {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers.Authorization = authHeader(token);
  const res = await fetch(`${baseUrlIn}${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let json = null;
  try {
    json = text ? JSON.parse(text) : null;
  } catch {
    json = text;
  }
  return { status: res.status, body: json };
}

export { baseUrl };
