/**
 * Security / attack-surface tests (hardening pass).
 * Covers JWT protection, auth registration hygiene, centralized error handling,
 * and report authorization. DB-free: model methods are stubbed per test.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import jwt from 'jsonwebtoken';
import env from '../src/config/env.js';
import bcrypt from 'bcryptjs';
import { protect } from '../src/middleware/auth.js';
import { errorHandler, notFound } from '../src/middleware/errorHandler.js';
import { register } from '../src/controllers/authController.js';
import { generateReport } from '../src/services/reportService.js';
import User from '../src/models/User.js';
import Scan from '../src/models/Scan.js';
import Project from '../src/models/Project.js';
import { isValidObjectId } from '../src/utils/validation.js';
import app from '../src/server.js';
import http from 'node:http';

function makeRes() {
  const res = { statusCode: 200, body: undefined };
  res.status = (c) => {
    res.statusCode = c;
    return res;
  };
  res.json = (o) => {
    res.body = o;
    return res;
  };
  return res;
}

const VALID_ID = '507f1f77bcf86cd799439011';

// ── protect middleware (JWT auth) ────────────────────────────────────
test('protect: rejects missing Authorization header', async () => {
  const res = makeRes();
  await protect({ headers: {} }, res, () => assert.fail('should not continue'));
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, 'Not authenticated');
});

test('protect: rejects non-Bearer scheme', async () => {
  const res = makeRes();
  await protect({ headers: { authorization: 'Basic abc' } }, res, () => assert.fail());
  assert.equal(res.statusCode, 401);
});

test('protect: rejects tampered / random-signed token', async () => {
  const good = jwt.sign({ id: VALID_ID }, env.JWT_SECRET, { expiresIn: '5m' });
  // Flip one character in the signature portion.
  const tampered = good.slice(0, -2) + (good.endsWith('aa') ? 'bb' : 'aa');
  const res = makeRes();
  await protect({ headers: { authorization: `Bearer ${tampered}` } }, res, () => assert.fail());
  assert.equal(res.statusCode, 401);
});

test('protect: rejects token signed with wrong secret', async () => {
  const token = jwt.sign({ id: VALID_ID }, 'attacker-known-secret', { expiresIn: '5m' });
  const res = makeRes();
  await protect({ headers: { authorization: `Bearer ${token}` } }, res, () => assert.fail());
  assert.equal(res.statusCode, 401);
});

test('protect: rejects expired token', async () => {
  const pastExp = Math.floor(Date.now() / 1000) - 1000;
  const token = jwt.sign({ id: VALID_ID, exp: pastExp }, env.JWT_SECRET);
  const res = makeRes();
  await protect({ headers: { authorization: `Bearer ${token}` } }, res, () => assert.fail());
  assert.equal(res.statusCode, 401);
  assert.equal(res.body.error, 'Invalid or expired token');
});

test('protect: rejects token for deleted user', async () => {
  const prev = User.findById;
  User.findById = async () => null;
  try {
    const token = jwt.sign({ id: VALID_ID }, env.JWT_SECRET, { expiresIn: '5m' });
    const res = makeRes();
    await protect({ headers: { authorization: `Bearer ${token}` } }, res, () => assert.fail());
    assert.equal(res.statusCode, 401);
    assert.equal(res.body.error, 'User no longer exists');
  } finally {
    User.findById = prev;
  }
});

test('protect: accepts valid token and sets req.user / req.userId', async () => {
  const prev = User.findById;
  const fakeUser = { id: VALID_ID, _id: VALID_ID, email: 'a@b.com' };
  User.findById = async () => fakeUser;
  try {
    const token = jwt.sign({ id: VALID_ID }, env.JWT_SECRET, { expiresIn: '5m' });
    const req = { headers: { authorization: `Bearer ${token}` } };
    let nexted = false;
    await protect(req, makeRes(), () => {
      nexted = true;
    });
    assert.ok(nexted, 'next() must be called');
    assert.equal(req.userId, VALID_ID);
    assert.equal(req.user, fakeUser);
  } finally {
    User.findById = prev;
// ── errorHandler (error info leakage) ────────────────────────────────
test('errorHandler: CastError maps to 404, never leaks stack', async () => {
  const err = new Error('bad cast');
  err.name = 'CastError';
  const res = makeRes();
  errorHandler(err, {}, res, () => {});
  assert.equal(res.statusCode, 404);
  assert.equal(res.body.error, 'Resource not found');
  assert.equal(res.body.stack, undefined);
});

test('errorHandler: generic internal error returns 500', () => {
  const res = makeRes();
  errorHandler(new Error('boom'), {}, res, () => {});
  assert.equal(res.statusCode, 500);
});

// ── register: enumeration resistance + duplicate handling ────────────
test('register: existing account returns generic 409 (no enumeration)', async () => {
  const prevFind = User.findOne;
  User.findOne = async () => ({ _id: 'u1', email: 'a@b.com' });
  try {
    const res = makeRes();
    await register(
      { body: { email: 'A@B.COM', password: 'longpassword', name: 'T' } },
      res,
      () => {}
    );
    assert.equal(res.statusCode, 409);
    assert.ok(
      !res.body.error.toLowerCase().includes('account with this email'),
      'must not reveal account existence'
    );
  } finally {
    User.findOne = prevFind;
  }
});

test('register: duplicate-key race (E11000) maps to 409, not 500', async () => {
  const prevFind = User.findOne;
  const prevCreate = User.create;
  const prevHash = bcrypt.hash;
  User.findOne = async () => null;
  User.create = async () => {
    const e = new Error('duplicate');
    e.code = 11000;
    throw e;
  };
  bcrypt.hash = async () => 'hash';
  try {
    const res = makeRes();
    await register({ body: { email: 'a@b.com', password: 'longpassword' } }, res, () => {});
    assert.equal(res.statusCode, 409);
  } finally {
    User.findOne = prevFind;
    User.create = prevCreate;
    bcrypt.hash = prevHash;
  }
});

test('register: normalizes email to lowercase and returns 201', async () => {
  const prevFind = User.findOne;
  const prevCreate = User.create;
  const prevHash = bcrypt.hash;
  let createdEmail = null;
  User.findOne = async () => null;
  User.create = async (doc) => {
    createdEmail = doc.email;
    return {
      _id: 'u1',
      email: doc.email,
      name: doc.name,
      createdAt: new Date(),
      toSafeJSON() {
        return { id: this._id, email: this.email, name: this.name, createdAt: this.createdAt };
      },
    };
  };
  bcrypt.hash = async () => 'hash';
  try {
    const res = makeRes();
    await register({ body: { email: 'UsEr@Test.COM', password: 'longpassword' } }, res, () => {});
    assert.equal(res.statusCode, 201);
    assert.equal(createdEmail, 'user@test.com');
    assert.equal(res.body.user.passwordHash, undefined, 'passwordHash must never serialize');
  } finally {
    User.findOne = prevFind;
    User.create = prevCreate;
    bcrypt.hash = prevHash;
  }
});
  }
});

// ── report authorization (IDOR) ──────────────────────────────────────
test('generateReport: non-owner is forbidden (403)', async () => {
  const prevScanFind = Scan.findById;
  const prevProjFind = Project.findById;
  Scan.findById = () => ({
    exec: async () => ({
      _id: 's1',
      owner: 'ownerA',
      project: 'p1',
      score: 75,
    }),
  });
  Project.findById = () => ({ exec: async () => null });
  try {
    await assert.rejects(
      () => generateReport('507f1f77bcf86cd799439011', 'ownerB'),
      (err) => {
        assert.equal(err.status, 403);
        return true;
      }
    );
  } finally {
    Scan.findById = prevScanFind;
    Project.findById = prevProjFind;
  }
});

test('generateReport: missing scan returns 404', async () => {
  const prevScanFind = Scan.findById;
  Scan.findById = () => ({ exec: async () => null });
  try {
    await assert.rejects(
      () => generateReport('507f1f77bcf86cd799439011', 'ownerA'),
      (err) => {
        assert.equal(err.status, 404);
        return true;
      }
    );
  } finally {
    Scan.findById = prevScanFind;
  }
});

// ── ObjectId validator ───────────────────────────────────────────────
test('isValidObjectId: accepts 24-hex, rejects everything else', () => {
  assert.ok(isValidObjectId('507f1f77bcf86cd799439011'));
  assert.ok(isValidObjectId('507f1f77BCF86cd799439011'));
  assert.ok(!isValidObjectId('abc123'));
  assert.ok(!isValidObjectId('not-an-object-id'));
  assert.ok(!isValidObjectId('507f1f77bcf86cd79943901')); // too short
  assert.ok(!isValidObjectId('507f1f77bcf86cd7994390111')); // too long
  assert.ok(!isValidObjectId(null));
  assert.ok(!isValidObjectId(123));
});

// ── Phase 7: CSP hardening ──────────────────────────────────────────
test('CSP: no unsafe-inline in styleSrc', () => {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const port = server.address().port;
      http.get(`http://127.0.0.1:${port}/api/health`, (res) => {
        const csp = res.headers['content-security-policy'] || '';
        server.close(() => {
          // Must NOT contain unsafe-inline
          assert.ok(!csp.includes("'unsafe-inline'"), `CSP must not contain 'unsafe-inline', got: ${csp}`);
          // Must contain base-uri 'none'
          assert.ok(csp.includes("base-uri 'none'"), `CSP must contain base-uri 'none', got: ${csp}`);
          // Must contain upgrade-insecure-requests
          assert.ok(csp.includes('upgrade-insecure-requests'), `CSP must contain upgrade-insecure-requests, got: ${csp}`);
          resolve();
        });
        res.resume();
      }).on('error', (e) => { server.close(() => reject(e)); });
    });
  });
});

test('CSP: strict directives — no script-src unsafe-eval', () => {
  return new Promise((resolve, reject) => {
    const server = app.listen(0, () => {
      const port = server.address().port;
      http.get(`http://127.0.0.1:${port}/api/health`, (res) => {
        const csp = res.headers['content-security-policy'] || '';
        server.close(() => {
          assert.ok(!csp.includes("'unsafe-eval'"), `CSP must not contain 'unsafe-eval', got: ${csp}`);
          assert.ok(!csp.includes("'unsafe-inline'"), `CSP must not contain 'unsafe-inline', got: ${csp}`);
          assert.ok(csp.includes("object-src 'none'"), `CSP must contain object-src 'none'`);
          assert.ok(csp.includes("frame-ancestors 'none'"), `CSP must contain frame-ancestors 'none'`);
          resolve();
        });
        res.resume();
      }).on('error', (e) => { server.close(() => reject(e)); });
    });
  });
});

// ── Phase 7: notFound handler strips query parameters ───────────────
test('notFound: does not echo query parameters in error response', async () => {
  const fakeReq = { method: 'GET', originalUrl: '/api/secret?token=abc123&key=xyz' };
  const res = makeRes();
  notFound(fakeReq, res, () => {});
  assert.equal(res.statusCode, 404);
  assert.ok(!res.body.error.includes('token='), 'query params must not leak');
  assert.ok(!res.body.error.includes('key='), 'query params must not leak');
  assert.ok(res.body.error.includes('/api/secret'), 'path should be preserved');
  assert.ok(!res.body.error.includes('?'), 'query string separator must not appear');
});