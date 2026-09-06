# Security-fixture corpus (Phase 4F)

A regression + calibration harness for the VulnLens scanning engine. Every
fixture is a small source file declaring its **ground truth** in a single-line
`// @expects { ... }` header. The harness runs the deterministic rule engine
over every fixture and reports **precision / recall / false-positive-rate /
accuracy** plus an **over-claim** metric that quantifies confidence/severity
inflation.

## How to run

```bash
cd backend
npm run test:corpus             # print the report
npm run test:corpus:strict      # fail CI if thresholds are violated
npm test                        # includes corpus.test.js
```

## Fixture format

Each fixture lives under `security-fixtures/<category>/<case>-<name>.js` and
begins with a single-line JSON header:

```js
// @expects {"case": "vulnerable", "flagged": true, "verdict": "CONFIRMED", "cwe": "CWE-89", "ruleId": "sql-assign-concat"}
```

| Field | Meaning |
|---|---|
| `case` | `vulnerable` · `safe` · `tricky` |
| `flagged` | **Ground truth** for detection metrics — should a *correct* engine report this file at all? |
| `verdict` | **Forward-looking** target verdict (`CONFIRMED`/`LIKELY`/`POTENTIAL`/`FALSE_POSITIVE`). Validated once findings carry a `verdict` (Phase 4C/4D). |
| `cwe` | Target CWE id (e.g. `CWE-89`). `null` for clean/safe files. |
| `ruleId` | Expected rule that should fire (informational). |

The header must stay on **one line** (the harness regex parses a single line).

## Metrics

- **Detection** (`ground truth = flagged`): `TP` = flagged & found, `FP` =
  not-flagged & found, `FN` = flagged & not-found, `TN` = not-flagged &
  not-found. Then `precision = TP/(TP+FP)`, `recall = TP/(TP+FN)`,
  `FPR = FP/(FP+TN)`, `accuracy = (TP+TN)/total`.
- **Over-claim**: a finding is over-claimed when it is reported at
  `critical`/`high` **and** `confidence >= 70` on a fixture whose target verdict
  is `FALSE_POSITIVE` or `POTENTIAL` (i.e. the truth does not justify a
  confirmed high/critical). This is the "don't trust an unsafe 88%" signal.

## Current baseline (post Phase 4C evidence engine)

With the evidence engine wired in, the corpus reaches its **target** state:

- **TP=10, FP=0, FN=0, TN=5**
- **Precision = 100% · Recall = 100% · FPR = 0% · Accuracy = 100%**
- **Over-claims = 0**

Phase 4C added AST-based evidence extraction (`src/scanner/ast.js` →
`evidence.js` → `verdictEngine.js` → `confidenceEngine.js`), then `scanner.js`
re-derives `severity` from the `verdict` and **drops** `FALSE_POSITIVE`
findings. The three pre-4C over-claims are now handled as their ground truth
dictates:

| Fixture | Before 4C | After 4C |
|---|---|---|
| `sql-injection/tricky-no-source-internal` | CRITICAL @ 92 | `POTENTIAL` / low / conf ≤ 35 |
| `sql-injection/tricky-template-no-source` | CRITICAL @ 88 | `POTENTIAL` / low / conf ≤ 35 |
| `xss/tricky-innerhtml-constant` | HIGH @ 85 (FP) | dropped (`FALSE_POSITIVE`) |

## Phase 4D baseline (adversarial hardening)

Phase 4D stress-tested the evidence/verdict/confidence pipeline with 26
adversarial fixtures across nested scopes, parser edge cases, destructuring,
callbacks, and looping constructs. The corpus is now **41 fixtures**:

- **TP=33, FP=0, FN=0, TN=8**
- **Precision = 100% · Recall = 100% · FPR = 0% · Accuracy = 100%**
- **Over-claims = 0**

Three genuine `ast.js` bugs were found and fixed while hardening:

1. **Nested-function sinks invisible.** The taint analyzer never walked
   `ArrowFunctionExpression` / `FunctionExpression` bodies (callbacks) nor
   `ForInStatement` / `ForOfStatement` / `SwitchStatement`, so real sinks inside
   them were missed. Added a recursive `walkNestedFns()` + the missing statement
   cases (intra-function, shared `env`).
2. **Destructuring unhandled.** `const { id } = req.query` was not recognized.
   Added `ObjectPattern` / `ArrayPattern` handling in declarations and
   assignments. Destructured values are treated as confirmed (not POTENTIAL).
3. **Sanitizer detection was dead code.** `isSanitizerCall()` called
   `nodeText(callee)` without passing `code`, so the callee text was always
   empty and **no sanitizer was ever recognized**. Fixed to pass `code` and made
   `BinaryExpression` propagate the `sanitized` flag. `safe-sanitized-query` /
   `safe-sanitized-html` now correctly report `POTENTIAL` / low instead of a
   false CONFIRMED.

### Known, documented limitation

The `tricky-shadowed-variable` fixture documents that the analyzer shares one
`env` across nested function bodies and **cannot reason about parameter
shadowing** — an outer tainted variable bleeds into an identically-named inner
parameter. The analyzer conservatively confirms (errs toward flagging) rather
than silently dropping it. Cross-procedure / proper scoping is deferred to
Phase 5.

`corpus.test.js` (in `npm test`) and `test:corpus:strict` now **enforce** the
tighter Phase 4D target: **precision = recall = 1.0, FPR = 0, exactly 0
over-claims**, and `assertVerdicts()` requires every fixture to be assigned the
exact `verdict` its `@expects` header declares.

## Phase 4E baseline (production integration & regression quality gate)

Phase 4E added a **production-path regression gate** on top of the corpus: the
deterministic pipeline is now validated end-to-end against real persistence
(MongoDB) and the real HTTP API, not just the scanner in isolation. The corpus
metrics remain locked at the Phase 4D target.

New coverage added in 4E:

- `tests/integration/pipeline.integration.test.js` — boots the real Express app
  against an **in-memory MongoDB** (`mongodb-memory-server`) and exercises the
  full path `scanner → evidence → verdict → confidence → severity → scanService →
  Scan model → MongoDB → API` for CONFIRMED/POTENTIAL/FALSE_POSITIVE flows,
  round-trip persistence, multi-file uploads, malformed input, legacy findings,
  and the AI-override-resistance contract.
- `tests/invariants.test.js` — the **mandatory security invariants** (the hard
  gate that runs without a DB): FALSE_POSITIVE dropped, POTENTIAL → low/≤35,
  CONFIRMED requires proof, severity normalization overrides rules, AI confined
  to `ai.*`, determinism, evidence size bounds, error isolation, and key
  preservation through `applyEvidenceEngine`.
- **`sanitizeEvidence()`** (`src/scanner/evidence.js`) enforces deterministic
  evidence size caps (sources/names ≤ 8 × 120 chars, libs ≤ 5 × 60, explanation
  ≤ 500) so a pathological finding can never balloon the stored document.
- Additional security/size/determinism unit tests in `tests/evidence.test.js`
  and error-isolation/determinism tests in `tests/scanner.test.js`.
- `docs/SECURITY-ANALYSIS.md` — the full analysis-boundary & security-policy
  document for the pipeline.

**Gate:** `npm test` (all suites incl. integration + invariants) and
`npm run test:corpus:strict` must both pass with **precision = recall = 1.0,
FPR = 0, 0 over-claims**.


## Phase 5A — interprocedural analysis foundation fixtures

The `interprocedural/` directory holds **structural** fixtures that exercise the
Phase 5A foundation module (`src/scanner/functionAnalysis.js`). These are NOT
vulnerability proofs and are **not** part of the precision/recall corpus — they
validate extraction, summaries, call sites, and call-graph behavior.

Coverage in `tests/functionAnalysis.test.js` + fixtures:

- `basic-declarations.js` — named function declarations and inter-function calls.
- `arrow-functions.js` — arrow functions, async arrows, curried arrows.
- `object-methods.js` — object methods, async methods, class methods (incl. static).
- `nested-functions.js` — nested declarations and inline callbacks.
- `params-destructuring.js` — destructuring, defaults, rest, optional chaining.
- `control-flow.js` — calls inside branches, loops, ternaries, and callbacks.
- `recursion.js` — recursion and mutual-recursion termination.
- `external-calls.js` — library calls resolved as `external:` (never guessed).
- `multi-callee.js` — dynamic/member dispatch stays unresolved.
- `source-sink.js` — structural source/sink metadata, no verdict claim.
- `iife-callback.js` — IIFE and function-passing patterns.
- `malformed.js` — hostile input never crashes analysis.
- `reachable-sink.js` — A → B → C reachable-path structural sink (Phase 5B).

**Gate:** `node --test tests/functionAnalysis.test.js` (29 tests) plus the full
`npm test` regression and `npm run test:corpus:strict` (which must still report
100% precision/recall, 0 FPR, 0 over-claims — Phase 5A changes no verdicts).

## Phase 5B — interprocedural evidence correlation

Phase 5B (`src/scanner/interproceduralEvidence.js`,
`tests/interproceduralEvidence.test.js`) correlates Phase 5A structural
analysis with existing findings. It is **purely additive** evidence
enrichment: it appends `evidence.interprocedural.correlation` and never changes
verdict / confidence / severity / risk score / comparisonKey.

Coverage: source-shaped request input, structural sinks, caller→callee,
reachable `A → B → C` paths, recursion, cycles, unresolved/member/`this`/
dynamic calls, nested functions, callbacks, shadowing, multiple paths, path /
source / sink bounding, malformed input, empty analysis, missing finding,
missing finding location, determinism, JSON serialization, no absolute-path
leakage, unchanged verdict/severity/confidence/riskScore/comparisonKey, secret
masking, folder-fixture integration, and scanner attachment. The fixtures in
`interprocedural/` are analyzed to ensure the correlator never hangs and never
leaks sensitive payloads.

**Gate:** add `tests/interproceduralEvidence.test.js`, keep `npm test` green,
and keep `npm run test:corpus:strict` at 100% precision/recall, 0 FPR,
0 over-claims — Phase 5B changes no verdicts.

## Phase 5C — intra-file data-flow evidence

Phase 5C (`src/scanner/dataFlowAnalysis.js`,
`tests/dataFlowAnalysis.test.js`) traces bounded **intra-file** source→sink
propagation paths and attaches them as a `dataFlow` key inside the Phase 5B
`correlation`. It is **purely additive** evidence: it never changes verdict /
confidence / severity / risk score / comparisonKey, and only supports a small
set of *provable* propagation shapes (direct assignment, reassignment, alias,
function parameter, return value, direct call-site argument).

Coverage in `tests/dataFlowAnalysis.test.js`: direct assignment to a query sink,
variable reassignment, aliasing, function-argument propagation, return-value
propagation, no-sink / no-source short circuits, sink-type mapping (`sql-query`,
`dom`, `eval`, `fs`, command, deserialization), path bounding (`truncated`),
depth bounding, malformed input, determinism, JSON serialization, empty result,
and the `buildDataFlowSafe` wrapper. Integration (via
`tests/interproceduralEvidence.test.js`) confirms the `dataFlow` key appears in
`correlation` with version `5C.0` and never mutates the finding.

**Gate:** add `tests/dataFlowAnalysis.test.js`, keep `npm test` green, and keep
`npm run test:corpus:strict` at 100% precision/recall, 0 FPR, 0 over-claims —
Phase 5C changes no verdicts.



## Adding a fixture

Drop a `.js` file in the right category with a valid `@expects` header; it is
automatically picked up by `loadFixtures()`. Keep fixtures **single-focus**
(one vulnerability) so detection metrics stay unambiguous.
