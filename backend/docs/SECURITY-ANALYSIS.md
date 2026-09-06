# VulnLens Security Analysis Pipeline — Documentation

This document describes the **deterministic security analysis pipeline** in
VulnLens, what it produces, what it cannot and will not do, and the security
boundaries that define a *verdict* vs. an *opinion*. It is the companion to
`tests/invariants.test.js`, `tests/integration/pipeline.integration.test.js`,
and the scanner/evidence/verdict/confidence engine sources.

> **TL;DR** — VulnLens makes *deterministic*, *evidence-backed* security claims,
> then layers *advisory* AI enrichment on top. The two are never mixed: what you
> can prove about the code is a verdict; what a model "thinks" is an ai.* note.

---

## 1. The Pipeline

For every submitted code unit the following runs, in order:

```
source ──▶ runScanner() ──▶ normalize ──▶ dedupe
              │
              ▼
        buildEvidence()  ──▶ evidence object (what the AST proves)
              │
              ▼
        determineVerdict() ──▶ CONFIRMED | LIKELY | POTENTIAL | FALSE_POSITIVE
              │
              ▼
        computeConfidence() ──▶ 0–100 (derived from the verdict + evidence)
              │
              ▼
        deriveSeverity() ──▶ critical|high|medium|low|informational
              │
              ▼
        (advisory) analyzeWithAI() ──▶ writes only to finding.ai.*
              │
              ▼
        score / counts ──▶ persist to Scan model ──▶ serializeScan() ──▶ API
```

Each stage is deterministic and side-effect free (aside from the optional AI
step and the persistence step). Same input → same output, which is what makes
rescans comparable and regressions testable.

---

## 2. What "Evidence" Contains (and What It Never Contains)

`evidence` is the machine-readable record of what the static analysis could
actually prove about a finding. Canonical shape (see `src/scanner/evidence.js`):

| Field | Meaning |
|-------|---------|
| `source.found` / `source.names` | whether a user-controlled source was found, and its expression names |
| `sink.found` / `sink.type` / `sink.line` | the matched dangerous sink |
| `flow.established` / `flow.direct` / `flow.sources` | whether a source→sink path was proven, directness, and tracked sources |
| `constantData` | the value reaching the sink is a constant (no injection surface) |
| `parameterized` | the query uses placeholders (provably safe) |
| `sanitized` | the value passed through a recognized sanitizer |
| `templateOnly` | interpolation present but no DB/exec sink in the file |
| `techContext.{framework,db,libs}` | detected framework / database / libraries |
| `staticConfirmed` | constant data IS the vulnerability (secret, weak crypto, misconfig) |
| `explanation` | deterministic human-readable explanation |

**Evidence contains code *shapes* and *flags*, never secrets.** A hardcoded
secret finding reports that a secret matched a pattern — the secret's payload is
masked from `affectedCode` and never written into `evidence`. This is enforced
and regression-tested in `tests/evidence.test.js` ("SECURITY") and
`tests/scanner.test.js` (secret masking is already covered by the existing
serialization tests).

### Size bounds (Phase 4E)

`sanitizeEvidence()` enforces deterministic caps so a pathological finding can
never balloon a persisted document:

| Field | Cap |
|-------|-----|
| `flow.sources` / `source.names` | max **8** entries, each ≤ **120** chars |
| `techContext.libs` | max **5** entries, each ≤ **60** chars |
| `explanation` | ≤ **500** chars |

When any cap is hit, the object is flagged with `truncated: true`. Truncation
never changes the *semantics* the verdict/confidence engines read.

---

## 3. Verdicts

| Verdict | Meaning | Severity | Confidence |
|---------|---------|----------|------------|
| **CONFIRMED** | a user-controlled source provably reaches a sink (or the pattern is static-confirmed) | rule severity (normalized) | ≥ 80 (95 direct / 90 indirect / ≥82 static) |
| **LIKELY** | strong circumstantial evidence, no full proof (reserved) | capped at high | capped at 70 |
| **POTENTIAL** | suspicious shape, but no confirmed source→sink flow | **low** | **≤ 35** |
| **FALSE_POSITIVE** | provably safe (constant DOM sink, parameterized query) | **dropped** | 0 |

**FALSE_POSITIVE findings are never returned or persisted.** They are removed by
`applyEvidenceEngine`. A persisted scan can never contain a FALSE_POSITIVE.

**POTENTIAL is a lead, not a claim.** It is always demoted to `low` severity and
confidence ≤ 35, so it can never masquerade as a high-confidence finding.

---

## 4. Confidence

Confidence is derived from the verdict + evidence (see
`src/scanner/confidenceEngine.js`), **not** from a rule-authored number. It
answers "how sure is the *engine*, from the code alone?" — not "how verbose is
the rule?"

---

## 5. Severity Normalization

Severity is re-derived from the verdict by the scanner (`deriveSeverity`), never
copied blindly from the rule:

- CONFIRMED → keep rule severity, run through `normalizeSeverity` (critical/high/medium/low/informational).
- LIKELY → cap at high.
- POTENTIAL → low.

So even if a rule claims CRITICAL, the persisted severity for a POTENTIAL lead
is `low`. Rule-authored severity is advisory; the verdict is authoritative.
This is locked by Invariant 4.

---

## 6. AI Is Advisory, Never Authoritative

AI enrichment (`src/ai/*`, orchestrated in `scanService`) writes **only** to
`finding.ai.*` (`ai.explanation`, `ai.severity`, `ai.confidence`, `ai.source`,
etc.). It **never** writes to `finding.verdict`, `finding.severity`,
`finding.confidence`, or `finding.evidence`.

Consequences, deliberately regression-tested:

- A hostile AI response claiming `critical` / confidence 0.99 **cannot** escalate
  a deterministic POTENTIAL (it stays `low`, ≤ 35).
- The malicious claim remains visible under `ai.*` so reviewers can see the
  model disagreed — but it cannot change the surfaced security posture.

> Why: the deterministic engine is auditable and reproducible. An LLM is a black
> box. Making AI advisory means a model failure can never silently turn a low-risk
> lead into a "CRITICAL, must fix now" alert. (Integration test "§2 AI cannot
> override deterministic verdict/severity/confidence" proves this against the
> real HTTP + persistence path.)

---

## 7. Parser Failure Policy

The scanner is fully error-isolated:

- `parseJS` (acorn) failures return `null` instead of throwing.
- The rule loop wraps every `rule.check` in try/catch; a faulty rule can never
  abort a scan.
- In multi-file mode a malformed file cannot prevent other files from being
  scanned.
- A broken AST can **never** manufacture a `CONFIRMED` result — evidence analysis
  only confirms a flow it can actually prove.

Confirmed by Invariant 8, the scanner "EO:" tests, and integration test "§7
malformed source returns 200".

---

## 8. Analysis Boundary

What the deterministic engine can prove is intentionally narrow and honest:

- It detects **source→sink flows** and **static security primitives** it can
  verify from one submission's code.
- It does **not** model runtime behavior, external services, or cross-request
  state. "POTENTIAL" is the correct answer when it cannot prove exploitability.
- Parameters are not treated as attacker-controlled in the default analysis — an
  unconfirmed sink is POTENTIAL, never CONFIRMED (defense against over-claiming).

The system prefers **under-claiming to over-claiming**: a real but unprovable
issue shows as LOW/POTENTIAL rather than a false CRITICAL. This is the
anti-overclaim guarantee (0 over-claims in the corpus gate).

---

## 9. Persistence & Serialization

- Findings (with `verdict` + `evidence`) persist in the `Scan` schema and
  round-trip faithfully through MongoDB and `serializeScan()`.
- **Legacy compatibility**: findings created before the verdict/evidence era
  (no `verdict`/`evidence` fields) load, serialize, and display cleanly — no
  fabricated verdicts, no crashes. Verified by integration test "§3 legacy
  findings".
- `sourceCode`/`sourceFiles` are retained for reporting but are not parsed or
  executed on read.

---

## 10. Interprocedural Analysis Foundation (Phase 5A)

Phase 5A adds the *structural* foundation for future interprocedural taint
propagation, implemented in `src/scanner/functionAnalysis.js`. It is
**documentation-friendly metadata only**: it does **not** change verdict
semantics, produce findings, or make AI/LLM decisions.

It provides four deterministic intra-file capabilities:

1. **Function extraction** — declarations, function expressions, arrow
   functions, object/class methods, async functions, nested functions, IIFEs,
   and callbacks. Each yields a stable id, name (or the enclosing
   variable/property name when anonymous), parameter list, location, and async
   flag.
2. **Function summaries** — for each function, which parameter kinds it takes,
   what it returns, the calls it makes, any structural sink patterns, and any
   `req.*` user-input *shapes* — all **structural only**, never a claim.
3. **Call-site extraction** — every `CallExpression` with its resolved callee
   name (identifier or full dotted member path), argument descriptors, location,
   and the id of the enclosing function (null for top-level calls).
4. **Deterministic intra-file call graph** — nodes = functions, edges =
   caller→callee. Edges to callees that cannot be confirmed are emitted as
   `external:<name>` rather than guessed.

### Conservative rules (no guessing)

- **Member/`this` calls never resolve.** `service.findUser()` cannot confirm
  that `service` holds the local `findUser`, so it stays unresolved.
- **Shadowing is honored.** A call whose name matches a parameter of the caller
  resolves to that parameter, so it is treated as unresolved, not bound to an
  outer function of the same name.
- **Dynamic/computed dispatch is unresolved.**
- **Recursion and cycles terminate** via visited sets; `reachableFrom()` never
  hangs.
- **Malformed or hostile input never crashes** — extraction returns safe empty
  results.

### Metadata integration

`applyEvidenceEngine` attaches a bounded, JSON-safe `evidence.interprocedural`
object (functions, call counts, call-graph edges) to each surviving finding.
It is computed **after** verdict/confidence/severity are derived, so it can
never influence them. It is additive metadata for the downstream AI/analysis
layers.

---

## 10b. Interprocedural Evidence Correlation (Phase 5B)

Phase 5B, implemented in `src/scanner/interproceduralEvidence.js`, **correlates**
the Phase 5A structural analysis with existing findings. It is a pure
evidence-enrichment layer, **not a second vulnerability detector**.

> **Phase 5B does not determine vulnerability verdicts.** It executes strictly
> after verdict / confidence / severity have been finalized and only appends
> `evidence.interprocedural.correlation`. It never modifies
> `verdict`, `severity`, `confidence`, `riskScore`, `score`, `ruleId`, or
> `comparisonKey`.

### What it produces

For each finding, a bounded `correlation` object is built:

- `affectedFunction` — the innermost function whose source range contains the
  finding's line (or `null` when the finding is at top level).
- `sourceEvidence` — `req.*` **source shapes** observed in the affected
  function or anything reachable from it. The note is phrased
  *"Request-derived source shape observed in reachable function"* — it does
  **not** claim "user-controlled input" (only the taint engine may do that).
- `sinkEvidence` — **structural sink shapes** (only the sink types Phase 5A
  already recognizes: `sql-query`, `dom`, `eval`, `fs`) present in the affected
  or reachable functions. No new sink taxonomy is introduced.
- `reachability` — the list of reachable functions plus bounded
  `caller-callee` **paths** (e.g. `handler → processInput → executeQuery`)
  marked `confidence: "structural"`. Paths are also recorded toward reachable
  targets that hold a source or sink shape.
- `callRelationships` — direct `callers` and `callees` of the affected function.
- `summary` — a bounded, human-readable one-line summary.

### Schema (backward-compatible)

The Phase 5A fields remain at the top level of `evidence.interprocedural`;
Phase 5B adds a single new `correlation` key. Consumers that only understand
Phase 5A metadata are unaffected.

```jsonc
{
  "version": "5A.0",
  "functionCount": 3,
  "functions": [ /* unchanged Phase 5A */ ],
  "callGraph": { /* unchanged Phase 5A */ },
  "correlation": {
    "version": "5B.0",
    "affectedFunction": { "id": "…", "name": "handler", "type": "function", "line": 4 },
    "sourceEvidence":  { "present": true, "sources": [ /* … */ ], "note": "…" },
    "sinkEvidence":    { "present": true, "sinks": [ /* … */ ], "note": "…" },
    "reachability": {
      "reachableFunctions": [ /* … */ ],
      "paths": [
        { "path": [ /* function descriptors */ ],
          "relationship": "caller-callee",
          "confidence": "structural" }
      ]
    },
    "callRelationships": { "callers": [ /* … */ ], "callees": [ /* … */ ] },
    "summary": "Affected function: handler; …"
  }
}
```

### Conservative resolution rules (no guessing)

Phase 5B reuses Phase 5A's resolution semantics and does **not** bind or infer:

- dynamic calls, member calls (`obj.run(...)`), `this.foo(...)`, computed
  properties, aliases, destructured function aliases,
- callbacks whose target cannot be proven,
- cross-file calls, imported / re-exported functions, higher-order functions,
  reflection, `eval`-based dispatch, dynamic module loading.

External / unresolved targets are excluded from `reachableFunctions`,
`callers`/`callees`, and reachable paths.

### Bounds

| Resource | Cap |
|----------|-----|
| reachable functions | `MAX_FUNCTIONS` = 500 |
| paths | `MAX_PATHS` = 20 |
| path length | `MAX_PATH_LENGTH` = 10 |
| sources | `MAX_SOURCES` = 20 |
| sinks | `MAX_SINKS` = 20 |
| callers / callees | `MAX_CALLERS` / `MAX_CALLEES` = 20 |
| summary string | `MAX_SUMMARY_LEN` = 500 chars |

Recursion and cycles terminate via visited sets; output is deterministic and
JSON-safe.

### Security properties

- No absolute filesystem paths (function ids stay project-relative), no
  secrets, credentials, raw environment variables, network access, arbitrary
  code execution, or stack traces.
- The correlator never mutates the finding object — verified by tests that
  snapshot a finding's JSON before/after correlation.
- Malformed source fails safely (returns `null` analysis / no correlation).

### Non-goals

Phase 5B does **not** implement taint analysis, inter-file analysis, symbolic
execution, a data-flow engine, automatic vulnerability confirmation, AI/LLM
reasoning, remediation, or any verdict-affecting logic. Those belong to later
phases.

---

## 10c. Intra-File Data-Flow Evidence (Phase 5C)

Phase 5C, implemented in `src/scanner/dataFlowAnalysis.js`, enriches a finding
with **bounded intra-file data-flow evidence**: it traces HOW a user-controlled
value could reach a dangerous sink *within the same file*. It is the first
phase that reasons about *propagation* (not just structural co-location), but
it remains **purely additive evidence metadata** — it is not a second
vulnerability detector and never changes a verdict.

> **Phase 5C does not determine vulnerability verdicts.** It executes strictly
> after verdict / confidence / severity have been finalized and only appends
> `dataFlow` inside the Phase 5B `correlation` object. It never modifies
> `verdict`, `severity`, `confidence`, `riskScore`, `score`, `ruleId`, or
> `comparisonKey`.

### What it produces

Inside `evidence.interprocedural.correlation`, Phase 5C adds a single `dataFlow`
key (`null` when no source code is available). The value is a bounded object:

```jsonc
"dataFlow": {
  "version": "5C.0",
  "paths": [
    {
      "source": { "expression": "req.query.id", "line": 4 },
      "sink":   { "type": "sql-query", "line": 6, "argIndex": 0 },
      "steps": [ /* propagation steps: assignment, alias, param, return, argument */ ],
      "length": 5,
      "confidence": "structural-data-flow"
    }
  ],
  "truncated": false,
  "summary": "1 path(s) from source to sink (sql-query).",
  "facts": {
    "sourceCount": 2, "sinkCount": 1,
    "bindingCount": 4, "paramCount": 2,
    "returnCount": 0, "callSiteCount": 3
  }
}
```

### Supported propagation shapes (conservative)

Phase 5C only recognizes a small, provable set of shapes; anything more complex
is silently skipped:

1. **Direct assignment** — `const x = req.query.id`
2. **Variable reassignment** — `x = y` (when `y` is already tainted)
3. **Identifier alias** — `const alias = x` (when `x` is already tainted)
4. **Function parameter** — `f(x)` → inside `f`, the parameter receives `x`'s taint
5. **Return value** — `return x` from a callee → the caller's assignment target is tainted
6. **Direct argument** — `f(source)` as a call-site fact (no callee body required)

Taint propagation uses a bounded fixed-point iteration over bindings; recursion
and cycles terminate via visited sets. Unsupported constructs (destructuring,
spread, dynamic/computed properties, more complex expressions) are **not**
followed — the analyzer conservatively reports the paths it *can* prove.

### Conservative resolution rules (no guessing)

Phase 5C reuses Phase 5A's function extraction and sink taxonomy. It does not
cross file boundaries, does not resolve dynamic or member calls, does not follow
`eval`-based dispatch, and never infers *semantic* taint: the `source` and `sink`
shapes are recognized structurally from the known `req.*` / query-source and
sink patterns, and each emitted path is labeled
`confidence: "structural-data-flow"`.

### Bounds

| Resource | Cap |
|----------|-----|
| data-flow paths | `MAX_DF_PATHS` = 20 |
| path depth (steps) | `MAX_DF_DEPTH` = 10 |
| propagation states | `MAX_DF_STATES` = 5000 |
| facts | `MAX_DF_FACTS` = 500 |
| summary string | `MAX_DF_SUMMARY_LEN` = 500 chars |

Recursion and cycles terminate via visited sets; output is deterministic and
JSON-safe. When a bound is hit, `truncated` is set to `true`.

### Security properties

- No absolute filesystem paths, secrets, credentials, raw environment
  variables, network access, arbitrary code execution, or stack traces.
- The data-flow layer never mutates the finding object.
- Malformed source fails safely (`analyzeDataFlow` returns an empty result;
  `buildDataFlowSafe` returns `null` on invalid input).
- Runs entirely in-memory with bounded loops, so hostile input cannot hang or
  exhaust the process.

### Non-goals

Phase 5C does **not** implement inter-file taint, symbolic execution, dynamic
analysis, automatic vulnerability confirmation, AI/LLM reasoning, remediation,
or any verdict-affecting logic.

---

## 10d. Evidence Calibration (Phase 5D)

Phase 5D, implemented in `src/scanner/evidenceCalibration.js`, assigns
**deterministic, explainable strength metadata** to the evidence already produced
by the scanner and interprocedural analysis (Phases 5A–5C). The output is
evidence-quality metadata **only** — it must never change verdict, severity,
confidence, risk score, score, ruleId, or comparisonKey.

> **Phase 5D calibrates evidence strength only. It does not determine
> vulnerability verdicts, severity, risk score, or confidence.**

### Evidence Levels

Phase 5D classifies evidence into five ordered levels (weakest → strongest):

| Level | Strength | Meaning |
|-------|----------|---------|
| `NONE` | 0 | No useful interprocedural evidence |
| `STRUCTURAL` | 25 | Function/call-graph structure exists but no source-to-sink relationship demonstrated |
| `CORRELATED` | 50 | Source and sink correlated through functions/call relationships, but value propagation not proven |
| `DATA_FLOW` | 75 | Bounded intra-file source-to-sink value path demonstrated by Phase 5C |
| `DIRECT` | 100 | Direct source-to-sink relationship proven (path ≤ 2 steps) |

### Precedence Rules

When multiple evidence signals exist, the **strongest proven** level wins:

- `STRUCTURAL` + `CORRELATED` → `CORRELATED`
- `CORRELATED` + `DATA_FLOW` → `DATA_FLOW`
- `DATA_FLOW` + `DIRECT` → `DIRECT`

Multiple weak signals never upgrade the level. Two sources and two sinks with
reachability do **not** automatically equal `DATA_FLOW`.

### Source/Sink Quality Flags

The calibration object includes explicit boolean flags:

| Flag | Meaning |
|------|---------|
| `sourcePresent` | A recognized source shape was observed |
| `sinkPresent` | A recognized sink shape was observed |
| `sourceSinkCorrelated` | Both source and sink are present |
| `dataFlowProven` | Phase 5C produced at least one proven path |
| `directFlow` | Level is `DIRECT` (path ≤ 2 steps) |

### Path Quality

For Phase 5C paths, calibration computes deterministic metadata:

| Field | Meaning |
|-------|---------|
| `pathCount` | Number of inspected paths (capped at `MAX_CALIBRATION_PATHS` = 20) |
| `shortestPathLength` | Length of the shortest path (fewest steps) |
| `longestPathLength` | Length of the longest path (most steps) |
| `directPathCount` | Number of direct paths (≤ 2 steps) |
| `truncated` | Whether Phase 5C truncated output |

One proven direct path is stronger than ten ambiguous paths. Path count does
not upgrade the evidence level.

### Uncertainty Model

When a path terminates because of an unresolved construct, the calibration
records bounded uncertainty tokens:

| Token | Meaning |
|-------|---------|
| `unresolved-call` | Argument/parameter step with empty functionId |
| `dynamic-call` | Callee is a computed expression |
| `member-call` | Callee name contains a dot (method call) |
| `computed-call` | CallExpression with computed property |
| `unknown-transformation` | Assignment with non-identifier/non-member expression type |
| `cross-file-boundary` | Source and sink present but no data-flow paths |
| `ambiguous-branch` | Control flow divergence |
| `unsupported-destructuring` | Destructuring pattern not followed |

Paths with uncertainty tokens must **not** be treated as proven data flow.

### Calibration Schema

The calibration object lives at `finding.evidence.interprocedural.calibration`:

```jsonc
{
  "version": "5D.0",
  "level": "DATA_FLOW",
  "strength": 75,
  "sourcePresent": true,
  "sinkPresent": true,
  "sourceSinkCorrelated": true,
  "dataFlowProven": true,
  "directFlow": false,
  "pathCount": 1,
  "shortestPathLength": 4,
  "longestPathLength": 4,
  "directPathCount": 0,
  "truncated": false,
  "uncertainty": [],
  "summary": "Bounded intra-file data flow from a recognized source to a recognized sink."
}
```

### Bounds

| Resource | Cap |
|----------|-----|
| uncertainties | `MAX_CALIBRATION_UNCERTAINTIES` = 10 |
| summary string | `MAX_CALIBRATION_SUMMARY_LEN` = 300 chars |
| paths inspected | `MAX_CALIBRATION_PATHS` = 20 |

### Deterministic Behavior

- Identical input always produces identical JSON output.
- Uncertainty arrays are sorted alphabetically and capped.
- No timestamps, random IDs, filesystem ordering, or nondeterministic iteration.
- Output is frozen (immutable) and JSON-serializable.

### Verdict Independence

Phase 5D executes **after** verdict / confidence / severity have been finalized
by the verdict engine, confidence engine, and severity derivation. It only
appends `calibration` inside the Phase 5B `correlation` object. The following
fields are **never modified**:

- `verdict`
- `severity`
- `confidence`
- `riskScore`
- `score`
- `ruleId`
- `comparisonKey`

### Non-Goals

Phase 5D does **not** implement new vulnerability rules, taint semantics, cross-file
analysis, symbolic execution, AI/LLM reasoning, automatic exploitability
determination, automatic remediation, or any verdict-affecting logic.

---

## 10e. Controlled Verdict Integration (Phase 5E)

Phase 5E, implemented in `src/scanner/verdictIntegration.js`, is the single,
policy-controlled bridge that allows calibrated interprocedural evidence
(Phases 5A–5D) to make **bounded adjustments** to a finding's verdict,
confidence, and severity. It is invoked exactly once per finding, **after**
Phase 5D calibration is attached, from `scanner.js` `applyEvidenceEngine()`.

> **Phase 5E tightens, never loosens.** It only ever strengthens confidence or
> upgrades a single conservative verdict transition (POTENTIAL → LIKELY). It
> can never downgrade a verdict, reduce a confidence, or raise severity above
> what the LIKELY verdict derivation permits.

### Policy Constants (frozen)

The entire policy is expressed as frozen, exported constants so it can be
audited and cannot be mutated at runtime.

| Constant | Value | Meaning |
|---|---|---|
| `CONFIDENCE_DELTAS` | `{NONE:0, STRUCTURAL:0, CORRELATED:3, DATA_FLOW:5, DIRECT:10}` | Max confidence boost per evidence level |
| `MAX_INTEGRATED_CONFIDENCE` | `50` | Hard ceiling on Phase 5E-adjusted confidence |
| `VERDICT_TRANSITIONS` | `{POTENTIAL → LIKELY}` | The single allowlisted verdict upgrade |

### The Only Verdict Transition

`VERDICT_TRANSITIONS` contains exactly one entry:

- **POTENTIAL → LIKELY**, allowed only when **all** of these hold:
  1. Evidence level is **DIRECT** (the strongest level).
  2. `uncertainty` is an empty array (`requireNoUncertainty: true`).
  3. `directPathCount > 0` (at least one direct interprocedural path).

If any condition fails, the finding remains POTENTIAL (fail-closed).

### Confidence Bounds

- Each evidence level contributes a fixed positive delta.
- The adjusted confidence never exceeds `MAX_INTEGRATED_CONFIDENCE` (50).
- The adjustment **never reduces** an existing confidence. A finding already
  at high confidence (e.g. a CONFIRMED finding at 85) is left untouched — it
  is never capped down to 50.

### Severity Re-derivation

When a verdict changes, severity is re-derived from the new verdict using the
same deterministic mapping as the core engine:

- **CONFIRMED** → rule severity
- **LIKELY** → rule severity, with `critical` capped at `high`
- **POTENTIAL** → `low`

The original rule severity is captured by the scanner (as `_ruleSeverity`)
before `deriveSeverity` overwrites it, so Phase 5E can re-derive correctly.

### Integration Metadata

When Phase 5E changes a finding, it records a frozen `integration` block on
the (fresh copy of the) `calibration` object:

```jsonc
{
  "applied": true,
  "originalVerdict": "POTENTIAL",
  "finalVerdict": "LIKELY",
  "originalConfidence": 25,
  "finalConfidence": 35,
  "originalSeverity": "low",
  "finalSeverity": "medium",
  "evidenceLevel": "DIRECT",
  "evidenceStrength": 100,
  "policy": "POTENTIAL+DIRECT→LIKELY",
  "reason": "Interprocedural evidence level DIRECT ... supports upgrading ..."
}
```

Because the Phase 5D calibration object is frozen, Phase 5E builds a fresh
calibration carrying the `integration` block and reassigns it on the (mutable)
`correlation` object. `ruleId`, `comparisonKey`, `score`, and `riskScore` are
never touched.

### Guards & Isolation

- **Fail-closed**: missing / malformed calibration, dependency findings, or an
  invalid verdict / severity / confidence all return the finding unchanged.
- **Idempotent**: a finding already integrated (`integration.applied === true`)
  is not re-processed.
- **CONFIRMED findings are never changed** — they are the strongest result the
  deterministic engine can produce and Phase 5E leaves them untouched.
- **Deterministic**: identical input always yields identical output (verified in
  the test suite), so rescans, diffing, and invariants remain meaningful.
- **Performance**: O(1) per finding — no loops, no I/O, no shared state.

---



1. **Prove, then present.** A number only means something if you know exactly
   what it proves.
2. **Determinism is a security property.** Reproducible analysis is auditably
   correct; it also makes rescans, diffing, and regressions meaningful.
3. **Never lie upward.** If we cannot prove it, it is a lead (POTENTIAL), not a
   finding (CONFIRMED).
4. **AI augments, it does not adjudicate.** Models can draft explanations and
   suggest context; they cannot flip a verdict.

---

*See also:* `tests/invariants.test.js` (the hard gate), `tests/integration/`
(the real-persistence path), and the source in `src/scanner/`.

