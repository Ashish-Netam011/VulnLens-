/**
 * Insecure File Handling & Authorization
 * Unvalidated file paths, missing auth checks, upload issues.
 */

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
  return findings;
}
