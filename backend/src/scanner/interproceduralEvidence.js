/**
 * Interprocedural Evidence Correlation (Phase 5B).
 *
 * Purely structural enrichment that maps existing security findings to the
 * Phase 5A function analysis (functions, summaries, call graph).  Appends
 * evidence metadata ONLY — never changes verdict, confidence, severity,
 * risk score, score, ruleId, or comparisonKey.
 *
 * Design invariants:
 *   - Deterministic: identical code + findings -> identical JSON.
 *   - Pure: no I/O, no DB, no network, no LLM.
 *   - Bounded: all arrays are capped; recursion uses visited sets.
 *   - Conservative: never infers semantic data-flow; "structural" only.
 *   - Backward-compatible: consumers that only read Phase 5A metadata are
 *     unaffected (new `correlation` key is additive).
 */
import { analyzeFile, reachableFrom } from './functionAnalysis.js';
import { analyzeDataFlow, buildDataFlowSafe } from './dataFlowAnalysis.js';
import { calibrateEvidence } from './evidenceCalibration.js';

export const INTERPROCEDURAL_EVIDENCE_VERSION = '5B.0';

// Bounds
export const MAX_FUNCTIONS   = 500;
export const MAX_PATHS       = 20;
export const MAX_PATH_LENGTH = 10;
export const MAX_SOURCES     = 20;
export const MAX_SINKS       = 20;
export const MAX_CALLERS     = 20;
export const MAX_CALLEES     = 20;
export const MAX_SUMMARY_LEN = 500;

// Sink-type mapping intentionally NOT duplicated: Phase 5B only reuses sink
// types already assigned by Phase 5A's summary builder (sql-query, dom, eval,
// fs).  No new sink taxonomy is introduced here.

/**
 * Test whether `line` falls inside a function's source location range.
 * Both bounds are inclusive to match the function's start/end lines.
 */
function lineInRange(line, fn) {
  const loc = fn && fn.location;
  return (
    typeof line === 'number' &&
    loc && typeof loc.startLine === 'number' && typeof loc.endLine === 'number' &&
    line >= loc.startLine && line <= loc.endLine
  );
}

/**
 * Safe wrapper around `analyzeFile`.  Returns null on non-string / empty input
 * or when the parser throws.
 */
export function buildAnalysisSafe(code, filePath) {
  if (typeof code !== 'string' || code.length === 0) return null;
  try {
    return analyzeFile(code, { filePath: filePath || '' });
  } catch {
    return null;
  }
}

/**
 * Serialize a Phase 5A analysis result into the bounded JSON-safe metadata
 * object that has been attached to `evidence.interprocedural` since Phase 5A.
 */
export function serializeAnalysis(analysis) {
  if (!analysis) return null;
  const r = analysis;
  return {
    version: '5A.0',
    functionCount: r.functions.length,
    functions: r.functions
      .map((fn) => ({ name: fn.name, type: fn.type, line: fn.location.startLine }))
      .slice(0, 100),
    callCount: r.calls.length,
    callGraph: {
      nodeCount: r.callGraph.nodes.length,
      edgeCount: r.callGraph.edges.length,
      edges: r.callGraph.edges.slice(0, 300),
    },
  };
}
/**
 * Locate the innermost function whose source range contains `finding.line`.
 * When multiple functions contain the line the smallest (innermost) span is
 * selected.  Returns null when no function contains the line (e.g. top-level
 * code outside any function body).
 */
function locateAffectedFunction(finding, functions) {
  if (!finding || typeof finding.line !== 'number' || !Array.isArray(functions)) return null;

  let best = null;
  let bestSpan = Infinity;

  for (const fn of functions) {
    if (!lineInRange(finding.line, fn)) continue;
    const loc = fn.location;
    const span = loc.endLine - loc.startLine;
    if (span < bestSpan) {
      bestSpan = span;
      best = fn;
    }
  }
  return best || null;
}

/**
 * Deterministic BFS shortest-path through the internal call graph from
 * `startId` to `targetId`.  Follows non-external edges only.  Returns an
 * array of function descriptors `[{ id, name, type, line }]` (bounded to
 * MAX_PATH_LENGTH nodes including start and target) or null when unreachable.
 */
function buildPath(startId, targetId, nodeById, graphEdges) {
  if (startId === targetId) {
    const n = nodeById.get(startId);
    return n ? [{ id: n.id, name: n.name, type: n.type, line: n.location.startLine }] : null;
  }

  // Build adjacency (non-external only), sorted for determinism.
  const adj = new Map();
  for (const e of graphEdges || []) {
    if (e.external) continue;
    if (!adj.has(e.from)) adj.set(e.from, []);
    adj.get(e.from).push(e.to);
  }
  for (const [k, v] of adj) adj.set(k, [...new Set(v)].sort());

  const visited = new Set([startId]);
  const queue   = [[startId]];   // each element is the path-so-far

  while (queue.length > 0) {
    const curPath = queue.shift();
    const last    = curPath[curPath.length - 1];
    if (curPath.length > MAX_PATH_LENGTH) continue;

    for (const next of adj.get(last) || []) {
      if (visited.has(next)) continue;
      visited.add(next);
      const extended = [...curPath, next];
      if (next === targetId) {
        return extended.map((id) => {
          const n = nodeById.get(id);
          return n
            ? { id: n.id, name: n.name, type: n.type, line: n.location.startLine }
            : { id, name: '?', type: '?', line: 0 };
        }).slice(0, MAX_PATH_LENGTH);
      }
      if (extended.length < MAX_PATH_LENGTH) queue.push(extended);
    }
  }
  return null;
}

/**
 * Collect IDs of functions that directly call `anchorId` (callers) and
 * functions that `anchorId` directly calls (callees).  External / unresolved
 * edges are excluded.  Result is capped at the corresponding MAX_ constant.
 */
function collectCallRelationships(anchorId, graphEdges, nodeById) {
  const callerIds = new Set();
  const calleeIds = new Set();

  for (const e of graphEdges || []) {
    if (e.external) continue;
    if (e.to   === anchorId) callerIds.add(e.from);
    if (e.from === anchorId) calleeIds.add(e.to);
  }

  const callers = [...callerIds]
    .sort()
    .slice(0, MAX_CALLERS)
    .map((id) => {
      const n = nodeById.get(id);
      return n ? { id: n.id, name: n.name } : { id, name: '?' };
    });

  const callees = [...calleeIds]
    .sort()
    .slice(0, MAX_CALLEES)
    .map((id) => {
      const n = nodeById.get(id);
      return n ? { id: n.id, name: n.name } : { id, name: '?' };
    });

  return { callers, callees };
}

/**
 * Collect structural source shapes (req.* etc.) from summaries belonging to
 * any of the given function IDs.
 */
function collectSourceEvidence(relevantIds, summaries, nodeById) {
  const result = [];
  const seen   = new Set();

  for (const s of summaries || []) {
    if (!relevantIds.has(s.functionId)) continue;
    for (const src of s.sources || []) {
      const key = `${s.functionId}::${src.expression}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const n = nodeById.get(s.functionId);
      result.push({
        function: n ? { id: n.id, name: n.name, type: n.type } : { id: s.functionId, name: '?', type: '?' },
        expression: src.expression,
      });
    }
  }

  return result.sort((a, b) => (a.function.name + a.expression).localeCompare(b.function.name + b.expression))
    .slice(0, MAX_SOURCES);
}

/**
 * Collect structural sink shapes from summaries belonging to any of the given
 * function IDs.  Only the sink types already recognised by the scanner are
 * included (sql-query, dom, eval, fs).
 */
function collectSinkEvidence(relevantIds, summaries, nodeById) {
  const result = [];
  const seen   = new Set();

  for (const s of summaries || []) {
    if (!relevantIds.has(s.functionId)) continue;
    for (const sink of s.sinks || []) {
      const key = `${s.functionId}::${sink.type}`;
      if (seen.has(key)) continue;
      seen.add(key);
      const n = nodeById.get(s.functionId);
      result.push({
        function: n ? { id: n.id, name: n.name, type: n.type } : { id: s.functionId, name: '?', type: '?' },
        sinkType: sink.type,
        expression: sink.expression,
      });
    }
  }

  return result.sort((a, b) => (a.function.name + a.sinkType).localeCompare(b.function.name + b.sinkType))
    .slice(0, MAX_SINKS);
}

// Main public API

/**
 * Correlate a single finding with the Phase 5A function analysis of the
 * same file.  Returns a bounded, JSON-safe correlation object or null when
 * the analysis is unavailable.
 *
 * The returned object is purely additive metadata — it never mutates the
 * finding and never touches verdict / confidence / severity / score / ruleId
 * / comparisonKey.
 *
 * @param {object} finding   Normalized finding (must have `.line`).
 * @param {object} analysis  Result of `analyzeFile()`.
 * @returns {object|null}
 */
export function correlateFindingWithFunctionAnalysis(finding, analysis, opts = {}) {
  if (!finding || !analysis) return null;

  const { functions, summaries, callGraph } = analysis;
  if (!functions || !summaries || !callGraph) return null;

  // Phase 5C: data-flow enrichment (additive only, computed from opts.code)
  let dataFlow = null;
  if (typeof opts.code === 'string' && opts.code.length > 0) {
    dataFlow = buildDataFlowSafe(opts.code, {
      filePath: finding.filePath,
      analysis,
    });
  }

  // 1. Affected function (anchor)
  const affectedFn = locateAffectedFunction(finding, functions);

  // 2. Reachable + anchor set
  const reachableIds = affectedFn
    ? reachableFrom(affectedFn.id, callGraph)
    : [];
  const affectedIds = affectedFn
    ? new Set([affectedFn.id, ...reachableIds])
    : new Set();

  // 3. Sources + sinks in anchor / reachable
  const nodeById = new Map(functions.map((fn) => [fn.id, fn]));
  const sourceEvidence = collectSourceEvidence(affectedIds, summaries, nodeById);
  const sinkEvidence   = collectSinkEvidence(affectedIds, summaries, nodeById);

  // 4. Reachable-target functions (only non-anchor, internal/known nodes)
  const reachableTargets = new Set(
    reachableIds.filter(
      (id) => id !== (affectedFn && affectedFn.id) && nodeById.has(id),
    ),
  );

  // 5. Structural paths to reachable targets that hold sources/sinks
  const paths = [];
  if (affectedFn) {
    const targetIds = new Set();
    for (const s of summaries || []) {
      if (!reachableTargets.has(s.functionId)) continue;
      if ((s.sources && s.sources.length > 0) || (s.sinks && s.sinks.length > 0)) {
        targetIds.add(s.functionId);
      }
    }
    for (const tid of [...targetIds].sort().slice(0, MAX_PATHS)) {
      const p = buildPath(affectedFn.id, tid, nodeById, callGraph.edges);
      if (p) {
        paths.push({
          path: p,
          relationship: 'caller-callee',
          confidence: 'structural',
        });
      }
    }
  }

  // 6. Caller / callee relationships
  const callRels = affectedFn
    ? collectCallRelationships(affectedFn.id, callGraph.edges, nodeById)
    : { callers: [], callees: [] };

  // 7. Assemble correlation
  const sourceNote =
    sourceEvidence.length > 0
      ? 'Request-derived source shape observed in reachable function.'
      : null;
  const sinkNote =
    sinkEvidence.length > 0
      ? 'Structural sink shape present in reachable function.'
      : null;

  return {
    version: INTERPROCEDURAL_EVIDENCE_VERSION,

    affectedFunction: affectedFn
      ? { id: affectedFn.id, name: affectedFn.name, type: affectedFn.type, line: affectedFn.location.startLine }
      : null,

    sourceEvidence: {
      present: sourceEvidence.length > 0,
      sources: sourceEvidence,
      note: sourceNote,
    },

    sinkEvidence: {
      present: sinkEvidence.length > 0,
      sinks: sinkEvidence,
      note: sinkNote,
    },

    reachability: {
      reachableFunctions: reachableIds
        .filter((id) => nodeById.has(id))
        .map((id) => {
          const n = nodeById.get(id);
          return { id: n.id, name: n.name, type: n.type };
        })
        .slice(0, MAX_FUNCTIONS),
      paths,
    },

    callRelationships: {
      callers: callRels.callers,
      callees: callRels.callees,
    },

    dataFlow: dataFlow || null,

    calibration: calibrateEvidence({
      version: INTERPROCEDURAL_EVIDENCE_VERSION,
      affectedFunction: affectedFn
        ? { id: affectedFn.id, name: affectedFn.name, type: affectedFn.type, line: affectedFn.location.startLine }
        : null,
      sourceEvidence: {
        present: sourceEvidence.length > 0,
        sources: sourceEvidence,
        note: sourceNote,
      },
      sinkEvidence: {
        present: sinkEvidence.length > 0,
        sinks: sinkEvidence,
        note: sinkNote,
      },
      reachability: {
        reachableFunctions: reachableIds
          .filter((id) => nodeById.has(id))
          .map((id) => {
            const n = nodeById.get(id);
            return { id: n.id, name: n.name, type: n.type };
          })
          .slice(0, MAX_FUNCTIONS),
        paths,
      },
      callRelationships: {
        callers: callRels.callers,
        callees: callRels.callees,
      },
      dataFlow: dataFlow || null,
      summary: _buildSummaryString(affectedFn, sourceEvidence, sinkEvidence, paths, dataFlow),
    }),

    summary: _buildSummaryString(affectedFn, sourceEvidence, sinkEvidence, paths, dataFlow),
  };
}


/**
 * Produce a bounded, human-readable summary string describing the correlation.
 */
function _buildSummaryString(affectedFn, sourceEvidence, sinkEvidence, paths, dataFlow) {
  const parts = [];

  if (affectedFn) {
    parts.push(`Affected function: ${affectedFn.name}`);
  } else {
    parts.push('No enclosing function identified');
  }

  if (sourceEvidence.length > 0) {
    const names = [...new Set(sourceEvidence.map((s) => s.function.name))];
    parts.push(`Request-derived source shape in reachable: ${names.join(', ')}`);
  }

  if (sinkEvidence.length > 0) {
    const types = [...new Set(sinkEvidence.map((s) => s.sinkType))];
    parts.push(`Structural sink shape present: ${types.join(', ')}`);
  }

  if (paths.length > 0) {
    parts.push(`Reachable path(s): ${paths.length}`);
  }

  if (dataFlow && dataFlow.paths && dataFlow.paths.length > 0) {
    const dfTypes = [...new Set(dataFlow.paths.map((p) => p.sink.type))];
    parts.push(`Data-flow path(s): ${dataFlow.paths.length} (${dfTypes.join(', ')})`);
  }

  return parts.join('; ').slice(0, MAX_SUMMARY_LEN);
}

