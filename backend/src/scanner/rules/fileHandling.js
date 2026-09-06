/**
 * Insecure File Handling & Authorization
 * Unvalidated file paths, missing auth checks, upload issues.
 */

import { analyzeTaint, sinkArgTaint, nodeText } from '../ast.js';

const FILES = [
  {
    id: 'file-write-user',
    re: /fs\.\s*writeFile\s*\(\s*[^)]*(?:req\.|params\.|query\.|filename)/i,
    title: 'Unvalidated File Write From User Input',
    severity: 'high',
    confidence: 75,
  },
  {
    id: 'unchecked-file-read',
    re: /readFile\s*\(\s*[^)]*(?:req\.|params\.|query\.|file)/i,
    title: 'File Read From User Input',
    severity: 'medium',
    confidence: 68,
  },
  {
    id: 'no-auth-check',
    re: /(?:get|post|put|delete)\s*\(\s*['\"][^'\"]*['\"]\s*,[^)]*\)\s*\)\s*;[\s\S]{0,80}(?:(?:next|done)|;\s*\})/i,
    title: 'Potential Missing Authorization',
    severity: 'low',
    confidence: 40,
  },
  {
    id: 'multer-no-limits',
    // Flag multer() upload configs that use `dest`/`storage` WITHOUT a `limits`
    // option. The negative lookahead skips configs that already cap requests
    // via `limits:` (per-file size, total size, file count) so code is not
    // falsely flagged just because it configures a storage backend.
    re: /multer\s*\(\s*\{\s*(?![^{}]*\blimits\s*:)(?:dest|storage)\s*:/i,
    title: 'File Upload Without Size Limits',
    severity: 'medium',
    confidence: 60,
  },
  {
    id: 'tempfile-upload',
    re: /upload\.single|upload\.array|upload\.fields/i,
    title: 'File Upload Present',
    severity: 'informational',
    confidence: 100,
  },
];

// ── Request-tainted path arguments (Phase 7) ────────────────────────────────
// The regex rules above can only see an inline `req./params./query.` token inside
// the call. They miss request-derived paths that arrive via variable aliases and
// the *Sync / stream variants (readFileSync, writeFileSync, appendFileSync,
// createReadStream). This pass reuses the deterministic intra-function taint
// analysis and only emits a finding when the PATH argument (arg 0) is
// request-tainted, so constant or unrelated paths never trigger.

const READ_PATH_METHODS = new Set(['readFile', 'readFileSync']);
const WRITE_PATH_METHODS = new Set(['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync']);
const INLINE_REQUEST_TOKEN = /(?:req\.|params\.|query\.|body\.)/;

function fsPathMethodName(call) {
  if (!call || !call.callee || call.callee.type !== 'MemberExpression') return '';
  const prop = call.callee.property;
  if (prop && prop.type === 'Identifier') return prop.name;
  if (prop && prop.type === 'Literal') return String(prop.value);
  return '';
}

/**
 * Detect fs read/write calls whose path argument is request-derived through an
 * alias chain (p, filePath, dest, ...) that the regex rules cannot see.
 * Skips calls already reported by the inline-request regex on the same line so
 * findings are never duplicated.
 */
export function findRequestPathFlows(code, existingFindings) {
  // Cheap prefilter: an fs path call and a request source on the same file.
  if (!/readFile(?:Sync)?\s*\(|writeFile(?:Sync)?\s*\(|appendFile(?:Sync)?\s*\(/.test(code)) return [];
  if (!/(?:req\.|body\.|query\.|params\.|headers\.|cookies\.)/.test(code)) return [];

  const analysis = analyzeTaint(code, 'file');
  const existingKeys = new Set();
  for (const f of existingFindings || []) existingKeys.add(f.ruleId + ':' + f.line);
  const out = [];

  for (const sink of analysis.sinks || []) {
    if (sink.type !== 'fs' || !sink.node || sink.node.type !== 'CallExpression') continue;
    const node = sink.node;
    const method = fsPathMethodName(node);
    const readPat = READ_PATH_METHODS.has(method);
    const writePat = WRITE_PATH_METHODS.has(method);
    if (!readPat && !writePat) continue;

    const arg0 = node.arguments && node.arguments[0];
    if (!arg0) continue;
    const argText = nodeText(arg0, code);
    // Inline request member expression → already covered by the regex rules.
    if (INLINE_REQUEST_TOKEN.test(argText)) continue;
    if (arg0.type === 'Literal' || arg0.type === 'TemplateLiteral') continue;

    const t = sinkArgTaint(sink, analysis.env, code);
    if (!t || !t.tainted) continue;

    const line = (node.loc && node.loc.start.line) || 1;
    const rule = readPat
      ? FILES.find((f) => f.id === 'unchecked-file-read')
      : FILES.find((f) => f.id === 'file-write-user');
    if (!rule || existingKeys.has(rule.id + ':' + line)) continue;

    out.push({
      ruleId: rule.id,
      vulnerabilityType: 'Insecure File Handling',
      title: rule.title,
      severity: rule.severity,
      confidence: rule.confidence,
      reason:
        'A request-derived path value reaches a file operation through an alias or a *Sync/stream variant, which can enable path traversal or unauthorized file access.',
      line,
      affectedCode: nodeText(node, code).slice(0, 160),
      category: 'Insecure File Handling',
    });
  }
  return out;
}

export default function fileHandlingRule(code) {
  const findings = [];
  for (const pat of FILES) {
    let match;
    const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
    while ((match = re.exec(code)) !== null) {
      const line = code.slice(0, match.index).split('\n').length;
      findings.push({
        ruleId: pat.id,
        vulnerabilityType: 'Insecure File Handling',
        title: pat.title,
        severity: pat.severity,
        confidence: pat.confidence,
        reason:
          'File operations appear to use values that may originate from user input without sufficient validation, which can enable path traversal or unauthorized file access.',
        line,
        affectedCode: match[0].slice(0, 160),
        category: 'Insecure File Handling',
      });
    }
  }
  // Phase 7: request-tainted path args via aliases / *Sync / stream variants.
  findings.push(...findRequestPathFlows(code, findings));
  return findings;
}
