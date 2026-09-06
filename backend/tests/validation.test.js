/**
 * Validation & Sanitization Tests
 * Tests Zod schemas, path sanitization, extension checks, language normalization.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  registerSchema,
  loginSchema,
  scanCreateSchema,
  projectCreateSchema,
  normalizeLanguage,
  allowedExtension,
  sanitizeRelativePath,
  sanitizeFileName,
  ALLOWED_EXTENSIONS,
} from '../src/utils/validation.js';

// ── registerSchema ───────────────────────────────────────────────────
test('registerSchema: valid input passes', () => {
  const r = registerSchema.safeParse({ email: 'a@b.com', password: 'longpassword' });
  assert.ok(r.success);
});

test('registerSchema: rejects invalid email', () => {
  const r = registerSchema.safeParse({ email: 'notanemail', password: 'longpassword' });
  assert.ok(!r.success);
});

test('registerSchema: rejects short password', () => {
  const r = registerSchema.safeParse({ email: 'a@b.com', password: '123' });
  assert.ok(!r.success);
});

test('registerSchema: rejects extra fields', () => {
  const r = registerSchema.safeParse({ email: 'a@b.com', password: 'longpassword', admin: true });
  assert.ok(!r.success);
});

test('registerSchema: optional name accepted', () => {
  const r = registerSchema.safeParse({ email: 'a@b.com', password: 'longpassword', name: 'Test' });
  assert.ok(r.success);
});

// ── loginSchema ──────────────────────────────────────────────────────
test('loginSchema: valid input passes', () => {
  const r = loginSchema.safeParse({ email: 'a@b.com', password: 'pw' });
  assert.ok(r.success);
});

test('loginSchema: rejects empty password', () => {
  const r = loginSchema.safeParse({ email: 'a@b.com', password: '' });
  assert.ok(!r.success);
});

test('loginSchema: rejects extra fields', () => {
  const r = loginSchema.safeParse({ email: 'a@b.com', password: 'pw', session: true });
  assert.ok(!r.success);
});

// ── scanCreateSchema ─────────────────────────────────────────────────
// projectId must now be a 24-hex MongoDB ObjectId so garbage ids fail fast
// before any DB lookup (hardening: no CastError path, no spurious 500s).
const VALID_OBJECT_ID = '507f1f77bcf86cd799439011';

test('scanCreateSchema: valid input passes', () => {
  const r = scanCreateSchema.safeParse({ projectId: VALID_OBJECT_ID, code: 'const x = 1;' });
  assert.ok(r.success);
});

test('scanCreateSchema: rejects malformed projectId', () => {
  const r = scanCreateSchema.safeParse({ projectId: 'not-an-object-id', code: 'const x = 1;' });
  assert.ok(!r.success);
});

test('scanCreateSchema: rejects short projectId', () => {
  const r = scanCreateSchema.safeParse({ projectId: 'abc123', code: 'const x = 1;' });
  assert.ok(!r.success);
});

test('scanCreateSchema: rejects empty code', () => {
  const r = scanCreateSchema.safeParse({ projectId: VALID_OBJECT_ID, code: '' });
  assert.ok(!r.success);
});

test('scanCreateSchema: rejects missing projectId', () => {
  const r = scanCreateSchema.safeParse({ code: 'const x = 1;' });
  assert.ok(!r.success);
});

test('scanCreateSchema: rejects code > 500000 chars', () => {
  const r = scanCreateSchema.safeParse({ projectId: VALID_OBJECT_ID, code: 'x'.repeat(500001) });
  assert.ok(!r.success);
});

test('scanCreateSchema: accepts code at exactly 500000 chars', () => {
  const r = scanCreateSchema.safeParse({ projectId: VALID_OBJECT_ID, code: 'x'.repeat(500000) });
  assert.ok(r.success);
});

// ── projectCreateSchema ──────────────────────────────────────────────
test('projectCreateSchema: valid input passes', () => {
  const r = projectCreateSchema.safeParse({ name: 'My Project' });
  assert.ok(r.success);
});

test('projectCreateSchema: rejects empty name', () => {
  const r = projectCreateSchema.safeParse({ name: '' });
  assert.ok(!r.success);
});

test('projectCreateSchema: rejects > 100 char name', () => {
  const r = projectCreateSchema.safeParse({ name: 'x'.repeat(101) });
  assert.ok(!r.success);
});

// ── normalizeLanguage ────────────────────────────────────────────────
test('normalizeLanguage: known language passes through', () => {
  assert.equal(normalizeLanguage('python'), 'python');
  assert.equal(normalizeLanguage('javascript'), 'javascript');
  assert.equal(normalizeLanguage('TypeScript'), 'typescript');
});

test('normalizeLanguage: unknown defaults to text', () => {
  assert.equal(normalizeLanguage('brainfuck'), 'text');
  assert.equal(normalizeLanguage(''), 'javascript');
  assert.equal(normalizeLanguage(null), 'javascript');
});

// ── allowedExtension ─────────────────────────────────────────────────
test('allowedExtension: accepts .js', () => assert.ok(allowedExtension('app.js')));
test('allowedExtension: accepts .py', () => assert.ok(allowedExtension('main.py')));
test('allowedExtension: accepts .go', () => assert.ok(allowedExtension('server.go')));
test('allowedExtension: rejects .exe', () => assert.ok(!allowedExtension('virus.exe')));
test('allowedExtension: rejects .bin', () => assert.ok(!allowedExtension('data.bin')));
test('allowedExtension: no extension', () => assert.ok(!allowedExtension('Makefile')));

// ── sanitizeRelativePath ─────────────────────────────────────────────
test('sanitizeRelativePath: normal path passes', () => {
  assert.equal(sanitizeRelativePath('src/index.js'), 'src/index.js');
});

test('sanitizeRelativePath: strips leading slash', () => {
  assert.equal(sanitizeRelativePath('/etc/passwd'), 'etc/passwd');
});

test('sanitizeRelativePath: strips traversal', () => {
  assert.equal(sanitizeRelativePath('../../../etc/passwd'), 'etc/passwd');
});

test('sanitizeRelativePath: handles backslashes', () => {
  assert.equal(sanitizeRelativePath('src\\index.js'), 'src/index.js');
});

test('sanitizeRelativePath: strips control chars', () => {
  assert.equal(sanitizeRelativePath('src\r\n/index.js'), 'src/index.js');
});

test('sanitizeRelativePath: truncates at 255', () => {
  const long = 'a/'.repeat(200) + 'file.js';
  assert.ok(sanitizeRelativePath(long).length <= 255);
});

test('sanitizeRelativePath: empty/null returns empty', () => {
  assert.equal(sanitizeRelativePath(''), '');
  assert.equal(sanitizeRelativePath(null), '');
});

test('sanitizeRelativePath: no traversal segments remain', () => {
  const result = sanitizeRelativePath('src/./lib/../lib/util.js');
  assert.ok(!result.includes('..'), 'No .. segments should remain');
  assert.ok(!result.includes('/./'), 'No /./ segments should remain');
});

// ── Phase 7: null-byte stripping ────────────────────────────────────
test('sanitizeRelativePath: strips null bytes', () => {
  assert.equal(sanitizeRelativePath('src/index\0.js'), 'src/index.js');
  assert.equal(sanitizeRelativePath('\0etc/passwd'), 'etc/passwd');
  assert.equal(sanitizeRelativePath('path\0\0/file.js'), 'path/file.js');
});

test('sanitizeRelativePath: null byte with traversal attempt', () => {
  const result = sanitizeRelativePath('../\0../etc/passwd');
  assert.ok(!result.includes('\0'), 'null bytes must be stripped');
  assert.ok(!result.includes('..'), 'no traversal segments');
});

test('sanitizeRelativePath: CRLF + null byte combined attack', () => {
  const result = sanitizeRelativePath('safe\r\nX-Injected: 1\0path.js');
  assert.ok(!result.includes('\r'), 'no CR');
  assert.ok(!result.includes('\n'), 'no LF');
  assert.ok(!result.includes('\0'), 'no null byte');
});

// ── sanitizeFileName (shared with scanController) ───────────────────
test('sanitizeFileName: strips directory components', () => {
  assert.equal(sanitizeFileName('a/b/c/final.js'), 'final.js');
  assert.equal(sanitizeFileName('C:\\Users\\x\\app.js'), 'app.js');
});

test('sanitizeFileName: blocks CRLF header injection', () => {
  const out = sanitizeFileName('x.js\r\nInjected: true');
  assert.ok(!out.includes('\r') && !out.includes('\n'), 'no CR/LF survive');
  // Headers live on colon-delimited lines; the ':' and CR/LF chars are neutralized.
  assert.ok(!out.includes(':'), 'no header-delimiter survives');
});

test('sanitizeFileName: neutralizes < > : * ? " | chars', () => {
  const out = sanitizeFileName('a<b>:c*?d"|e.js');
  assert.ok(!/[<>:*?"|]/.test(out));
});

test('sanitizeFileName: truncates at 255', () => {
  assert.ok(sanitizeFileName('x'.repeat(300) + '.js').length <= 255);
});

test('sanitizeFileName: empty/null falls back to submission.txt', () => {
  assert.equal(sanitizeFileName(''), 'submission.txt');
  assert.equal(sanitizeFileName(null), 'submission.txt');
});
