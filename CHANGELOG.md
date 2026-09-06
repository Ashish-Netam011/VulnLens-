# Changelog

All notable changes to **VulnLens** are documented here, grouped by phase. The
project uses a phase-based roadmap (see `README.md` → Phase roadmap).

## UI/UX Redesign — Security Investigation Cockpit (2026-09-06)

Complete frontend redesign around the product story **detect the risk → trace
the attack path → understand the impact → fix the vulnerability**. The
redesign is presentation-only: no scanner rule, verdict, severity, baseline,
SARIF, CI, or AI-safety behavior changed. Every screen renders real,
endpoint-backed data — nothing is fabricated.

### Backend (additive, read-only)
- `GET /api/scans/:id/source?file=&around=` — bounded (~40-line) source window
  for a finding, owner-scoped exactly like other scan routes, resolved purely
  against the scan's own stored sources (no filesystem access). Strict file
  grammar rejects `..`, percent-encoding, backslashes, absolute/drive paths
  with 400; well-formed-but-absent files return 404; non-integer/out-of-range
  lines return 400. `backend/src/controllers/scanController.js` +
  `backend/src/routes/scans.js`.
- `backend/tests/integration/source-context.integration.test.js` — 13 tests
  (auth, path safety incl. encoded/cross-scan traversal, window clamping,
  validation, correctness) against the in-memory MongoDB HTTP harness.

### Frontend redesign
- Design system: layered graphite palette + indigo accent, Inter/JetBrains
  Mono tokens, CSS primitives, focus-visible rings, reduced-motion support
  (`tailwind.config.js`, `index.css`).
- Component library: `SeverityBadge` (icon+label, never color-only),
  `StatusBadge`, `EmptyState`/`ErrorState`/`Skeleton`, accessible `Modal`,
  `CopyButton`, `RiskBar`, `CodeWindow` (line-numbered source w/ source/sink
  emphasis), `DataFlowGraph` (SOURCE → propagation → SINK), `FindingTable`
  (sortable, keyboard accessible), `CopilotPanel`.
- New IA: Overview (+ Projects), Scans (New Scan / History), Findings,
  Security Analysis → Data Flow, AI Copilot, Reports, Settings — compact,
  group-based sidebar with current-page state and a mobile drawer.
- Overview (`/`): security posture score, latest-scan summary, risk
  distribution, recent scans, priority findings.
- Scans: honest scan experience (no fake progress; real per-file read count
  and request states) with a completion summary; history table with files,
  findings, score trend.
- Findings hub + dedicated Finding Detail (`/findings/:scanId/:key`): verdict
  header, “what happened”, source window with sink/source emphasis, data-flow
  diagram, deterministic-evidence side panel, and the AI Copilot panel wired
  to `POST /api/ai/explain` (auto, cached, retry, unavailable state).
  Keyboard left/right navigation across findings of a scan.
- Security Analysis / Data Flow page, AI Copilot hub, Reports (SARIF/JSON/
  summary exports via the real authenticated endpoints), and Settings
  (session-only, no invented toggles).
- A pre-existing bug fixed along the way: rescan status chips now read the
  real `/comparison` detail arrays (`newlyIntroduced`/`remaining`/`resolved`)
  so New/Pre-existing labels actually render.

## Phase 8 — AI Security Copilot (2026-09-06)

Opt-in AI explanations on top of deterministic findings. The deterministic
scanner remains the source of truth: the Copilot can never create findings,
suppress findings, or modify severity/confidence/comparisonKey/baseline status
— it only explains already-detected findings with structured remediation.

### Core service
- `backend/src/ai/copilot.js` — `explainFindingWithAI()` turns ONE deterministic
  finding into a validated `{explanation, impact, attackScenario, remediation,
  secureExample, confidence}` object. Bounded source context (±4 lines, ≤2000
  chars), compact data-flow summary from finding evidence (Phase 7 flows
  included), injection-aware dedicated prompts, schema-validated output with
  safe fallback on any parse/provider failure. Finding objects are never
  mutated.

### Provider reuse (no new provider abstraction)
- `backend/src/ai/provider.js` / `openrouter.js` / `ollama.js` accept an
  optional per-call `prompts` override; default prompts are unchanged, so
  existing scanService enrichment behavior is byte-identical. No new provider,
  no new RAG, no new dependencies.

### API
- `POST /api/ai/explain` (`backend/src/routes/ai.js` + `aiController.js`),
  auth-protected like all routes, request bounded by the strict
  `aiExplainSchema` (zod). AI unavailable → `success:false, copilot:null`
  (HTTP 200) — the scanner never fails because AI is unavailable.

### CLI
- `vulnlens scan <path> --explain` — opt-in per-finding explanations (≤10
  findings, highest severity first). Normal scans remain deterministic,
  offline, and AI-free; `--explain` never changes findings, baseline
  classification, SARIF, the security gate, or exit codes. AI explanations are
  additive `copilot` fields in table/JSON output; SARIF stays untouched.

### Tests / docs
- `backend/tests/copilot.test.js` — 31 tests, all against mocked providers
  (offline, deterministic): happy path, provider failure, malformed AI output,
  prompt injection, secret safety, finding integrity, data-flow context,
  bounded context, API schema, CLI opt-in.
- `docs/ai-copilot.md` — responsibilities split, providers/config, request/
  response schema, security guardrails, fallback behavior, limitations.

## Phase 7 — Targeted data-flow analysis (2026-09-06)

Request-source → dangerous-sink detection for the flows the regex rules could
not express, layered on the existing AST taint engine. No new dependencies, no
network, deterministic, and purely additive to the verdict model.

### File-access flows
- `backend/src/scanner/rules/fileHandling.js` now uses the deterministic
  intra-function taint analysis (`analyzeTaint`/`sinkArgTaint`) to detect
  request-derived paths reaching `fs.readFile`/`readFileSync` and
  `writeFile`/`writeFileSync`/`appendFile`/`appendFileSync` through variable
  aliases and the `*Sync` forms — shapes the inline-request regex rules could
  not see. Emits the existing `unchecked-file-read` / `file-write-user` rule
  IDs; constant or unrelated paths never trigger, and calls already covered by
  the regex are not duplicated.

### NoSQL document-query flows
- `backend/src/scanner/ast.js` adds conservative object-query sink recognition
  (`isNoSqlQuerySink`: capitalized models, `db.<collection>` chains, known db
  roots; document-query ops only — `findById`-style id lookups excluded).
- `backend/src/scanner/rules/sqlInjection.js` reports the new rule ID
  `nosql-object-query` (high) when a request-tainted object literal, alias, or
  whole-request value is passed to a document query.
- `backend/src/scanner/evidence.js` routes the new rule ID to the `sql` taint
  category so the existing evidence gate confirms the flow.

### Tests / docs
- New corpus groups: `nosql-injection` (3 vulnerable / 3 safe fixtures),
  plus 2 vulnerable and 2 safe `path-traversal` fixtures for the sync/alias
  shapes — strict gate stays 100% precision/recall, 0 over-claims.
- `backend/tests/phase7-dataflow.test.js` — 22 tests (source recognition,
  alias/destructuring propagation, sink recognition, sanitizer/parameterized
  negatives, constants/unrelated variables, determinism, ruleId stability).
- `docs/taint-dataflow.md` — capability, source/sink model, sanitizer limits,
  false-positive philosophy, known limitations, examples.
- Baseline re-anchor: adding code to `src/scanner/ast.js` shifted two unchanged
  baselined self-scan self-references by +40 lines (`document-write`
  202→242, `child-process` 299→339); their entries were updated so the
  reviewed findings remain BASELINED (no drift, no new accepted findings).

## Phase 6E — CI & baseline integrity hardening (2026-09-06)

Hardening so the security gate cannot silently weaken via baseline, workflow,
or dependency modification.

### Baseline runtime immutability
- `.github/workflows/vulnlens.yml` hashes `backend/vulnlens.baseline.json`
  (SHA-256, exact contents) right after checkout and re-verifies it after the
  scan in an `if: always()` step; any runtime change/delete/replace during the
  job fails the job. A legitimately committed baseline change passes (hashed at
  job start — no hardcoded hash). Schema validation (exit 2) is unchanged and
  separate.

### Workflow hardening
- All three actions pinned to immutable commit SHAs (verified against upstream
  tag refs): checkout `11d5960a…`, setup-node `49933ea5…`,
  upload-sarif `6f5948df…`.
- `npm ci --ignore-scripts`: the lockfile audit shows only `fsevents`
  (macOS-only) and `mongodb-memory-server` (local tests only) declare install
  scripts; CI runs the scanner, not tests, so no third-party install code
  executes in CI. Exact versions remain pinned by package-lock.json.

### Tests / docs
- `backend/tests/ci-gate.test.js` — 6 new tests: record/verify step ordering
  and semantics, no hardcoded hash, `--ignore-scripts`, full-SHA action
  pinning, and functional unchanged/modified baseline hash checks.
- Docs updated: `docs/ci-cd-github-actions.md`,
  `docs/baseline-regression-intelligence.md`.

### Result
- `npm test` — **550 passed** (544 Phase 6D + 6 new). `test:corpus:strict` —
  gate passed. Self-scan — exit 0 (unchanged).

## Phase 6D — Baseline-aware CI regression intelligence (2026-09-06)

Built on the Phase 6C baseline: the CLI now classifies every finding as
**NEW / BASELINED / RESOLVED** against the committed baseline and the CI gate is
baseline-aware. Security-first: baseline matching never mutates severity,
confidence, or evidence; baselined findings stay fully visible; malformed
baselines remain fail-visible (exit 2); CI never rewrites the baseline.

### Finding identity
- Reused the Phase 6C `baselineSignature` (`filePath::ruleId::line`, normalized)
  as the documented baseline comparison key — deterministic across machines, CI,
  and repeated scans. Line is part of the identity by design: a moved finding is
  re-classified NEW (fail-safe drift). The finding-level `comparisonKey`
  (rescan/SARIF fingerprints) is untouched.

### Baseline classification (`backend/src/cli/cli.js`)
- New `classifyBaseline()`: current findings become **NEW** or **BASELINED**;
  unmatched baseline entries are reported **RESOLVED** (never current findings,
  never fail CI, never auto-removed).
- **Severity-escalation guard**: baseline entries may optionally record
  `severity`; a BASELINED finding that is now more severe is re-added to the
  `--fail-on` gate. Phase 6C entries record no severity → behavior unchanged.
- **Tighter baseline validation** (all fail-visible, exit 2): integer non-negative
  `line`, non-empty string `filePath`/`ruleId`, length caps, control-character
  rejection, and unknown-`severity` rejection.
- Table output shows `[NEW]` / `[BASELINED]` markers and a Baseline summary
  section; JSON gains per-finding `baselineStatus` (+ `baselineEscalated`) and a
  `baseline` summary block; stderr prints a classification summary.

### SARIF (`backend/src/services/sarifService.js`)
- All findings remain in SARIF 2.1.0 output; `baselineStatus` / `baselineEscalated`
  are exposed as valid additive `properties` metadata.

### Docs
- **`docs/baseline-regression-intelligence.md`** (new) — authoritative semantics,
  comparison-key algorithm, `--fail-on` interaction, escalation policy, CI
  behavior, malformed handling, severity invariant, developer review workflow.
- Updated `docs/ci-cd-github-actions.md`, `docs/sarif-reporting.md`,
  `docs/self-scan-triage.md`, `README.md`; `.github/workflows/vulnlens.yml`
  comments refreshed (no permission/scope changes).

### Result
- Self-scan with the committed baseline: 17 BASELINED, 1 NEW (informational),
  0 RESOLVED, 0 escalations → `--fail-on high` exits 0.
- `npm test`: **543 passed** (510 Phase 6C + 33 new). `test:corpus:strict`:
  **100 % precision/recall**. SARIF validated 2.1.0 with findings retained.

## Phase 6C — Self-scan triage & CI green gate (2026-09-05)

Security self-scan hardening so the CI security gate (`--fail-on high`) can pass
for known, reviewed findings while still failing on genuinely new vulnerabilities.

### Genuine fixes
- **`backend/src/config/env.js`** — removed the hardcoded `JWT_SECRET`
  `'dev-secret-change-me'` fallback. Non-production now generates an **ephemeral**
  random secret at boot (`crypto.randomBytes(48)`); production still **fails
  closed** when `JWT_SECRET` is missing.

### Scanner rule precision (13 false positives eliminated)
- **`hardcodedSecrets.js`** — `jwtSecret` now requires a quoted **literal**
  (`jwtSecret = '…'`, `jwt.sign(payload, '…')`); bare env references
  (`env.JWT_SECRET`) are no longer flagged.
- **`dangerousFunctions.js`** — `child-process` requires the `child_process`
  module token or Node `*Sync` spawn helpers (removes RegExp/Mongoose `.exec()`
  false positives); `regex-dos` narrowed to user-controlled `new RegExp(input)`.
- **`fileHandling.js`** — `multer-no-limits` no longer flags configs that declare
  `limits:`.
- **`sensitiveData.js`** — `log-secret` is quote-aware (strips string
  literals/comments) so message text is not flagged while real secret **values**
  still are.

### Committed self-scan baseline (new)
- **`backend/vulnlens.baseline.json`** — 17 documented, reviewed scanner
  self-reference entries (the scanner flags its own rule patterns/examples).
- **`backend/src/cli/cli.js`** — new `--baseline <file>` option; baseline matching
  findings stay **visible** in reports but are excluded from the `--fail-on` gate
  (fail-safe: drift/malformed baseline re-opens the gate or exits 2).
- **Tests** — `backend/tests/ci-baseline.test.js` (11 tests: positive, negative,
  missing, malformed).

### Docs
- **`docs/self-scan-triage.md`** (new) — 45-row triage matrix, per-HIGH analysis,
  BEFORE/AFTER counts, baseline inventory.
- **`docs/ci-cd-github-actions.md`**, **README.md**, `.github/workflows/vulnlens.yml`
  — updated for the baseline and the now-green gate.

### Result
- Self-scan findings: **45 → 18**; high/critical **10 → 6**, all remaining high
  are baselined scanner self-references.
- `npm test`: **510 passed**. `test:corpus:strict`: **100 % precision/recall**.

## Earlier phases

See the `## Phase roadmap` section in `README.md` for the tracked progress of
Phases 1–6B (backend/scanner architecture through the CI security gate).