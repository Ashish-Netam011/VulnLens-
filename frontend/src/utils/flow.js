// Data-flow evidence helpers. Everything here reads ONLY deterministic scanner
// output (finding.evidence) — it never fabricates flows.

export const SINK_LABELS = {
  sql: 'SQL query sink',
  nosql: 'NoSQL query sink',
  'nosql-object-query': 'NoSQL query sink',
  dom: 'DOM / HTML sink',
  command: 'Command execution',
  eval: 'Code evaluation',
  fs: 'Filesystem access',
  deserialize: 'Deserialization sink',
  childprocess: 'Child process',
};

export function sinkLabel(type) {
  if (!type) return 'Dangerous sink';
  if (SINK_LABELS[type]) return SINK_LABELS[type];
  // Humanize snake/kebab/space-separated technical labels (e.g. db-query).
  const words = String(type).replace(/[-_]+/g, ' ').split(' ').filter(Boolean);
  const out = words.map((w) => (w.toLowerCase() === 'db' ? 'DB' : w[0].toUpperCase() + w.slice(1))).join(' ');
  return `${out} sink`;
}

/**
 * Structural flags the deterministic evidence engine proved about this finding.
 */
export function flowFlags(finding) {
  const ev = finding?.evidence || {};
  return {
    established: !!ev.flow?.established,
    direct: !!ev.flow?.direct,
    sources: ev.flow?.sources || ev.source?.names || [],
    parameterized: !!ev.parameterized,
    sanitized: !!ev.sanitized,
    constantData: !!ev.constantData,
    templateOnly: !!ev.templateOnly,
    staticConfirmed: !!ev.staticConfirmed,
    sinkType: ev.sink?.type || null,
    sinkLine: ev.sink?.line || null,
  };
}

/**
 * Build renderable vertical chains (source → propagation → sink) for a finding.
 * Prefers Phase 5C correlated paths; falls back to the 4C source/sink flags so
 * single-file findings still render a meaningful (shorter) chain.
 * Returns [] when no flow evidence exists.
 */
export function extractFlows(finding) {
  if (!finding) return [];
  const paths = finding.evidence?.interprocedural?.correlation?.dataFlow?.paths;
  if (Array.isArray(paths) && paths.length > 0) {
    return paths.map((p) => ({
      source: { expression: String(p.source?.expression || ''), line: p.source?.line },
      steps: Array.isArray(p.steps)
        ? p.steps
            .filter((s) => s && s.kind !== 'source' && s.kind !== 'sink')
            .map((s) => ({ expression: String(s.name || s.expression || ''), line: s.line, kind: s.kind }))
        : [],
      sink: { type: p.sink?.type || null, line: p.sink?.line, argIndex: p.sink?.argIndex },
      confidence: p.confidence || null,
    }));
  }

  const flags = flowFlags(finding);
  if (flags.established || flags.sources.length > 0 || flags.sinkType) {
    return [
      {
        source: { expression: flags.sources[0] || 'untrusted input', line: null },
        steps: flags.sources.slice(1).map((s) => ({ expression: String(s), line: null, kind: 'propagation' })),
        sink: { type: flags.sinkType, line: flags.sinkLine },
        confidence: 'evidence',
      },
    ];
  }
  return [];
}

export function pathLines(path) {
  const lines = [];
  if (path?.source?.line) lines.push(path.source.line);
  for (const s of path?.steps || []) if (s?.line) lines.push(s.line);
  if (path?.sink?.line) lines.push(path.sink.line);
  return lines;
}
