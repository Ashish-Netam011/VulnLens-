# Changelog

All notable changes to **VulnLens** are documented here, grouped by phase. The
project uses a phase-based roadmap (see `README.md` → Phase roadmap).

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