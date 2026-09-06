/**
 * Dangerous Function Usage / Unsafe Input Handling
 * eval, Function constructor, child_process, deserialization, path traversal.
 */

const DANGEROUS = [
  {
    id: 'eval',
    re: /\beval\s*\(/i,
    title: 'eval() Used',
    severity: 'high',
    confidence: 90,
  },
  {
    id: 'function-ctor',
    re: /new\s+Function\s*\(/i,
    title: 'Function Constructor Used',
    severity: 'high',
    confidence: 88,
  },
  {
    id: 'child-process',
    // Require an actual reference to the child_process module (require/import
    // or the string name) or one of Node's global *Sync spawn helpers.  A bare
    // `.exec(`/`.spawn(`/`.execFile(` would also match unrelated methods such
    // as RegExp.prototype.exec or Mongoose's Query#exec, producing false
    // positives.
    re: /child_process|(?:exec|spawn|execFile)Sync\s*\(/i,
    title: 'Child Process Execution',
    severity: 'critical',
    confidence: 85,
  },
  {
    id: 'deserialize',
    re: /JSON\.parse\(\s*[^)]*req\.|(?:vm\.|node:vm).*runIn|deserialize\s*\(\s*[^)]*req\./i,
    title: 'Unsafe Deserialization / VM Execution',
    severity: 'high',
    confidence: 78,
  },
  {
    id: 'path-traversal',
    re: /path\.\s*join\s*\(\s*[^)]*req\.|readFile\s*\(\s*[^)]*(?:req\.|params\.|query\.)/i,
    title: 'Potential Path Traversal',
    severity: 'high',
    confidence: 72,
  },
  {
    id: 'regex-dos',
    // A regex constructed from user-controlled input (request query/params/
    // body) is the classic ReDoS sink.  The old broad heuristic that also
    // matched any static regex containing `(` ... `+` caused false positives
    // on perfectly benign literals (e.g. `/\.([^.]+)$/` for extension
    // matching), so it was removed.
    re: /new\s+RegExp\s*\(\s*[^)]*(?:req\.|params\.|query\.|body\.|input)/i,
    title: 'Possible ReDoS (User-Controlled Regex)',
    severity: 'medium',
    confidence: 60,
  },
];

export default function dangerousFunctionsRule(code) {
  const findings = [];
  for (const pat of DANGEROUS) {
    let match;
    const re = new RegExp(pat.re.source, pat.re.flags.includes('g') ? pat.re.flags : pat.re.flags + 'g');
    while ((match = re.exec(code)) !== null) {
      const line = code.slice(0, match.index).split('\n').length;
      findings.push({
        ruleId: pat.id,
        vulnerabilityType: 'Dangerous Function',
        title: pat.title,
        severity: pat.severity,
        confidence: pat.confidence,
        reason:
          'This pattern executes dynamic code or accesses resources using values that may be derived from user input, which can lead to code execution, injection, or path traversal.',
        line,
        affectedCode: match[0].slice(0, 160),
        category: 'Dangerous Function Usage',
      });
    }
  }
  return findings;
}
