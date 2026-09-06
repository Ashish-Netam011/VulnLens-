import { z } from 'zod';

/**
 * Zod schemas for validating user input across the API (PHASES.md Phase 3).
 */

export const registerSchema = z
  .object({
    email: z.string().email('A valid email is required').max(254),
    password: z.string().min(8, 'Password must be at least 8 characters').max(128),
    name: z.string().max(100).optional(),
  })
  .strict();

export const loginSchema = z
  .object({
    email: z.string().email('A valid email is required'),
    password: z.string().min(1, 'Password is required').max(128),
  })
  .strict();

export const projectCreateSchema = z
  .object({
    name: z.string().min(1, 'Project name is required').max(100),
    description: z.string().max(1000).optional(),
  })
  .strict();

export const projectUpdateSchema = z
  .object({
    name: z.string().min(1).max(100).optional(),
    description: z.string().max(1000).optional(),
  })
  .strict();

export const OBJECT_ID_RE = /^[0-9a-fA-F]{24}$/;

export function isValidObjectId(value) {
  return typeof value === 'string' && OBJECT_ID_RE.test(value);
}

// Mirrors the former scanController sanitizeFileName — strips directories,
// CRLF/header-injection chars, and truncates. See scanController for docs.
export function sanitizeFileName(name) {
  if (!name || typeof name !== 'string') return 'submission.txt';
  const base = name.split(/[\\/]/).pop() || 'submission.txt';
  return base.replace(/[\r\n<>:*?"|]/g, '_').slice(0, 255) || 'submission.txt';
}

export const scanCreateSchema = z
  .object({
    projectId: z.string().regex(OBJECT_ID_RE, 'projectId must be a valid id'),
    code: z.string().min(1, 'Code is required').max(500000, 'Code is too large'),
    language: z.string().max(50).optional(),
    fileName: z.string().max(255).optional(),
  })
  .strict();

// Phase 8: AI Security Copilot request contract. The finding is bounded here
// (field lengths + strict shape) so attacker-supplied evidence/code can never
// blow up the model prompt budget. The Copilot can only explain a supplied
// finding — it never decides vulnerability status.
export const aiExplainSchema = z
  .object({
    finding: z.object({
      ruleId: z.string().min(1).max(64),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'informational']).optional(),
      confidence: z.union([z.number().min(0).max(1), z.string().max(32)]).optional(),
      filePath: z.string().max(500).optional(),
      line: z.number().int().min(1).max(10000000).optional(),
      reason: z.string().max(2000).optional(),
      title: z.string().max(300).optional(),
      affectedCode: z.string().max(2000).optional(),
      comparisonKey: z.string().max(200).optional(),
      evidence: z.any().optional(),
    }),
    code: z.string().max(500000, 'Code is too large').optional(),
    fileName: z.string().max(255).optional(),
  })
  .strict();

const SAFE_LANGUAGES = new Set([
  'javascript', 'typescript', 'js', 'ts', 'jsx', 'tsx', 'python', 'py',
  'java', 'c', 'cpp', 'cs', 'go', 'ruby', 'php', 'shell', 'bash', 'json',
  'yaml', 'yml', 'html', 'css', 'sql', 'text',
]);

export function normalizeLanguage(lang) {
  const v = String(lang || 'javascript').toLowerCase();
  return SAFE_LANGUAGES.has(v) ? v : 'text';
}

// Supported upload file extensions (Phase 3: validate extensions and types).
export const ALLOWED_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs', '.py', '.java', '.c', '.cpp',
  '.cs', '.go', '.rb', '.php', '.sh', '.bash', '.json', '.yaml', '.yml',
  '.html', '.css', '.sql', '.txt', '.md',
]);

export function allowedExtension(filename) {
  const ext = (filename.match(/(\.[^.]+)$/) || [])[1];
  return ext ? ALLOWED_EXTENSIONS.has(ext.toLowerCase()) : false;
}

/**
 * Normalize a folder-upload relative path into a safe, predictable string.
 * Strips traversal segments (..), leading slashes, and controls newlines.
 */
export function sanitizeRelativePath(p) {
  if (!p || typeof p !== 'string') return '';
  return String(p)
    .replace(/\\/g, '/')
    .replace(/\0/g, '')             // strip null bytes
    .replace(/^\/+/, '')
    .split('/')
    .filter((seg) => seg && seg !== '.' && seg !== '..')
    .join('/')
    .replace(/[\r\n]/g, '')
    .slice(0, 255);
}
