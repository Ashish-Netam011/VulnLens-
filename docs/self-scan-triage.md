# Self-Scan Triage (Phase 6C)

This document is the **authoritative triage** of every finding VulnLens produces
when it scans its own `backend/src`. It explains what each finding is, why it was
caused, and what was done about it — including the rule-precision fixes and the
committed self-reference baseline that lets the `--fail-on high` CI gate go green.

- **Scope scanned:** `backend/src`
- **Scanner:** the production `vulnlens` CLI (deterministic, AI-free, DB-free)
- **Before:** 45 findings (10 at/above `high`) — CI gate **red**
- **After:**  18 findings (6 at `high`, all self-references) — CI gate **green** via baseline
- **Baseline:** `backend/vulnlens.baseline.json` (17 committed entries)

## Outcome summary

| Metric | Before | After |
|---|---|---|
| Total findings | 45 | 18 |
| `critical` / `high` | 10 | 6 |
| `medium` | 7 | 1 |
| `low` | 28 | 11 |
| `--fail-on high` exit | 1 (red) | 0 (green) |

## Classification

| Class | Count | Meaning |
|---|---|---|
| **GENUINE** | 1 | Real vulnerability — **fixed** (`env.js` JWT secret) |
| **False positive (FP)** | 13 | App code flagged by an imprecise rule — **fixed in rule** |
| **SAFE_INTENTIONAL** | 1 | Safe, deliberate code flagged by over-broad rule — **rule fixed** |
| **Informational** | 1 | `tempfile-upload` on `routes/scans.js` — intentional, retained |
| **SELF_REFERENCE** | 29 | Scanner flags its own patterns/examples — 12 eliminated by rule fixes; the irreducible **17** are baselined |

> Reconciliation: the earlier estimate of "30 self-references" split the `tempfile-upload`
> informational finding into that bucket; this table counts it separately for precision.

## The one genuine fix

**`backend/src/config/env.js` — hardcoded JWT_SECRET fallback.**

Before, the config fell back to the literal `'dev-secret-change-me'`, which any reader of the
source could use to forge tokens. Now:

- **Non-production:** an **ephemeral** secret is generated at boot via
  `crypto.randomBytes(48).toString('hex')`. It is never persisted and never appears as a
  literal in source, so it cannot leak from the repository. Sessions won't survive a
  restart, which is fine for local/CI development.
- **Production:** a missing `JWT_SECRET` is a **fatal fail-closed** startup error (unchanged
  behaviour, now keyed on presence rather than the old literal).

## Rule precision fixes (eliminate the app-side false positives + many self-references)

| Rule file | Fix | Removed |
|---|---|---|
| `hardcodedSecrets.js` — `jwtSecret` | Require a quoted **literal** value (`jwtSecret = '…'`, `jwt.sign(payload, '…')`). A bare `env.JWT_SECRET` reference is no longer flagged. | `authController.js:7`, `auth.js:15`, `hardcodedSecrets.js:12`, `sensitiveData.js:22` |
| `dangerousFunctions.js` — `child-process` | Require the `child_process` module token or Node's `*Sync` spawn helpers. A bare `.exec(`/`.spawn(` no longer matches unrelated methods (RegExp#exec, Mongoose `Query#exec`). | dashboard/project/scan controllers, `reportService`, `sarifService`, and scanner `re.exec()` self-loops |
| `dangerousFunctions.js` — `regex-dos` | Drop the broad `(`/`+` heuristic; only flag user-controlled `new RegExp(input)`. | `validation.js:78` (SAFE_INTENTIONAL), `hardcodedSecrets.js:18`, `sqlInjection.js:9,16` |
| `fileHandling.js` — `multer-no-limits` | Negative lookahead so a config that already declares `limits:` is **not** flagged. | `routes/scans.js:23` |
| `sensitiveData.js` — `log-secret` | Operate on a copy with string literals/comments stripped (quote-aware), so static **message text** (`'FATAL: JWT_SECRET must be set…'`) is not flagged while real **value** logging (`err.password`, `authToken`) still is. | `env.js:41`, `ruleRichData.js:32` |

All fixes were validated against the corpus: `test:corpus:strict` stays
**100 % precision / 100 % recall / 0 over-claims**, and the full suite passes.
## The 45-row BEFORE matrix

Legend: severity at time of scan · class · disposition
(`FIXED` = corrected in source, `RULE` = eliminated by a rule fix, `BASELINE` = baselined self-reference, `RETAIN` = intentionally kept).

| # | Rule | File:Line | Sev | Class | Disposition |
|---|---|---|---|---|---|
| 1 | hardcoded-jwtSecret | src/config/env.js:19 | high | **GENUINE** | **FIXED** (ephemeral secret) |
| 2 | log-secret | src/config/env.js:41 | med | FP | **RULE** (message text, not value) |
| 3 | hardcoded-jwtSecret | src/controllers/authController.js:7 | high | FP | **RULE** (env ref, not literal) |
| 4 | child-process | src/controllers/dashboardController.js:18 | low | FP | **RULE** (`.exec()` = Mongoose) |
| 5 | child-process | src/controllers/projectController.js:20 | low | FP | **RULE** |
| 6 | child-process | src/controllers/projectController.js:94 | low | FP | **RULE** |
| 7 | child-process | src/controllers/scanController.js:24 | low | FP | **RULE** |
| 8 | child-process | src/controllers/scanController.js:155 | low | FP | **RULE** |
| 9 | hardcoded-jwtSecret | src/middleware/auth.js:15 | high | FP | **RULE** (env ref) |
| 10 | multer-no-limits | src/routes/scans.js:23 | low | FP | **RULE** (`limits:` present) |
| 11 | tempfile-upload | src/routes/scans.js:28 | info | Informational | **RETAIN** (upload endpoint note) |
| 12 | eval | src/scanner/rules/dangerousFunctions.js:10 | high | SELF_REF | **BASELINE** (`title: 'eval() Used'`) |
| 13 | child-process | src/scanner/rules/dangerousFunctions.js:3 | low | SELF_REF | **BASELINE** (doc comment word) |
| 14 | child-process | src/scanner/rules/dangerousFunctions.js:23 | low | SELF_REF | **RULE** (`.exec(` pattern text) |
| 15 | child-process | src/scanner/rules/dangerousFunctions.js:56 | low | SELF_REF | **RULE** (`re.exec(` loop) |
| 16 | deserialize | src/scanner/rules/dangerousFunctions.js:30 | low | SELF_REF | **BASELINE** |
| 17 | child-process | src/scanner/rules/fileHandling.js:49 | low | SELF_REF | **RULE** (`re.exec(` loop) |
| 18 | hardcoded-password | src/scanner/rules/hardcodedSecrets.js:54 | high | SELF_REF | **BASELINE** (`password: 'password'` friendlyName) |
| 19 | hardcoded-secret | src/scanner/rules/hardcodedSecrets.js:55 | high | SELF_REF | **BASELINE** (`secret: 'secret/token'` friendlyName) |
| 20 | hardcoded-jwtSecret | src/scanner/rules/hardcodedSecrets.js:12 | high | SELF_REF | **RULE** (regex source text) |
| 21 | child-process | src/scanner/rules/hardcodedSecrets.js:26 | low | SELF_REF | **RULE** |
| 22 | regex-dos | src/scanner/rules/hardcodedSecrets.js:18 | med | SELF_REF | **RULE** (regex source text) |
| 23 | child-process | src/scanner/rules/misconfiguration.js:49 | low | SELF_REF | **RULE** |
| 24 | hardcoded-jwtSecret | src/scanner/rules/sensitiveData.js:22 | high | SELF_REF | **RULE** |
| 25 | child-process | src/scanner/rules/sensitiveData.js:56 | low | SELF_REF | **RULE** |
| 26 | child-process | src/scanner/rules/sqlInjection.js:63 | low | SELF_REF | **RULE** |
| 27 | regex-dos | src/scanner/rules/sqlInjection.js:9 | med | SELF_REF | **RULE** |
| 28 | regex-dos | src/scanner/rules/sqlInjection.js:16 | med | SELF_REF | **RULE** |
| 29 | child-process | src/scanner/rules/weakCrypto.js:56 | low | SELF_REF | **RULE** |
| 30 | document-write | src/scanner/rules/xss.js:24 | low | SELF_REF | **BASELINE** (`title: 'document.write() Used'`) |
| 31 | child-process | src/scanner/rules/xss.js:56 | low | SELF_REF | **RULE** |
| 32 | document-write | src/scanner/ast.js:202 | low | SELF_REF | **BASELINE** (comment `// document.write(...)`) |
| 33 | child-process | src/scanner/ast.js:299 | low | SELF_REF | **BASELINE** (`saw(/child_process…)`) |
| 34 | sql-assign-concat | src/scanner/richDataBase.js:15 | low | SELF_REF | **BASELINE** (secureExample `"…" + req.query.id`) |
| 35 | innerhtml | src/scanner/richDataBase.js:25 | low | SELF_REF | **BASELINE** (secureExample `el.innerHTML`) |
| 36 | hardcoded-secret | src/scanner/ruleRichData.js:32 | high | SELF_REF | **BASELINE** (example `console.log("token:", token)`) |
| 37 | eval | src/scanner/ruleRichData.js:22 | high | SELF_REF | **BASELINE** (example `eval(userExpression)`) |
| 38 | child-process | src/scanner/ruleRichData.js:16 | low | SELF_REF | **BASELINE** |
| 39 | md5 | src/scanner/ruleRichData.js:42 | med | SELF_REF | **BASELINE** (example `crypto.createHash("md5")`) |
| 40 | log-secret | src/scanner/ruleRichData.js:32 | med | SELF_REF | **BASELINE** |
| 41 | child-process | src/services/reportService.js:13 | low | FP | **RULE** (Mongoose `.exec()`) |
| 42 | child-process | src/services/reportService.js:25 | low | FP | **RULE** |
| 43 | child-process | src/services/reportService.js:32 | low | FP | **RULE** |
| 44 | child-process | src/services/sarifService.js:262 | low | FP | **RULE** |
| 45 | regex-dos | src/utils/validation.js:78 | med | SAFE_INTENTIONAL | **RULE** (benign extension regex) |
## Per-HIGH analysis (the findings that blocked the gate)

All 10 `high` findings are covered. After the fixes and the baseline, **none** of them should
regress silently — each is fully accounted for:

| Rule | File:Line | Why it's high | Resolution |
|---|---|---|---|
| hardcoded-jwtSecret | `env.js:19` | **Genuine** hardcoded signing secret | **FIXED** in source (Step A) |
| hardcoded-jwtSecret | `authController.js:7` | FP: arg is `env.JWT_SECRET`, not a literal | **RULE** (literal-only) |
| hardcoded-jwtSecret | `auth.js:15` | FP: arg is `env.JWT_SECRET`, not a literal | **RULE** (literal-only) |
| eval | `dangerousFunctions.js:10` | Self-ref: rule's own `title: 'eval() Used'` | **BASELINE** |
| hardcoded-password | `hardcodedSecrets.js:54` | Self-ref: `password: 'password'` friendlyName label | **BASELINE** |
| hardcoded-secret | `hardcodedSecrets.js:55` | Self-ref: `secret: 'secret/token'` friendlyName label | **BASELINE** |
| hardcoded-jwtSecret | `hardcodedSecrets.js:12` | Self-ref: rule regex source text | **RULE** (eliminated) |
| hardcoded-jwtSecret | `sensitiveData.js:22` | Self-ref: rule regex source text | **RULE** (eliminated) |
| hardcoded-secret | `ruleRichData.js:32` | Self-ref: insecure doc example | **BASELINE** |
| eval | `ruleRichData.js:22` | Self-ref: insecure doc example | **BASELINE** |

The **6 irreducible self-reference HIGH findings that remain** are `dangerousFunctions:10`,
`hardcodedSecrets:54`, `hardcodedSecrets:55`, `hardcodedSecrets:58` (the new `friendlyName`
entry surfaced after the old line-12 self-reference was eliminated), `ruleRichData:32`, and
`ruleRichData:22`. The committed baseline suppresses exactly these from the gate.

## The 18 AFTER findings

Current scan result (line numbers reflect the code after the fixes):

| Rule | File:Line | Sev | Disposition |
|---|---|---|---|
| tempfile-upload | src/routes/scans.js:28 | low | retained (informational) |
| eval | src/scanner/rules/dangerousFunctions.js:10 | high | baseline |
| child-process | src/scanner/rules/dangerousFunctions.js:3 | low | baseline |
| child-process | src/scanner/rules/dangerousFunctions.js:23 | low | baseline |
| child-process | src/scanner/rules/dangerousFunctions.js:28 | low | baseline |
| deserialize | src/scanner/rules/dangerousFunctions.js:35 | low | baseline |
| hardcoded-password | src/scanner/rules/hardcodedSecrets.js:54 | high | baseline |
| hardcoded-secret | src/scanner/rules/hardcodedSecrets.js:55 | high | baseline |
| hardcoded-jwtSecret | src/scanner/rules/hardcodedSecrets.js:58 | high | baseline |
| document-write | src/scanner/rules/xss.js:24 | low | baseline |
| document-write | src/scanner/ast.js:202 | low | baseline |
| child-process | src/scanner/ast.js:299 | low | baseline |
| sql-assign-concat | src/scanner/richDataBase.js:15 | low | baseline |
| innerhtml | src/scanner/richDataBase.js:25 | low | baseline |
| hardcoded-secret | src/scanner/ruleRichData.js:32 | high | baseline |
| eval | src/scanner/ruleRichData.js:22 | high | baseline |
| child-process | src/scanner/ruleRichData.js:16 | low | baseline |
| md5 | src/scanner/ruleRichData.js:42 | med | baseline |

Note: `hardcodedSecrets.js:58` in the AFTER scan is the `friendlyName` entry
(`jwtSecret: 'JWT signing secret'`); it is a new self-reference surfaced after the old line-12
self-reference was eliminated by the literal-only fix, so it is added to the baseline.
## Baseline inventory

`backend/vulnlens.baseline.json` holds **17 entries** — the irreducible scanner
self-references that survive the rule fixes. Signature = `filePath::ruleId::line`.

| filePath | ruleId | line |
|---|---|---|
| src/scanner/rules/dangerousFunctions.js | eval | 10 |
| src/scanner/rules/dangerousFunctions.js | child-process | 3 |
| src/scanner/rules/dangerousFunctions.js | child-process | 23 |
| src/scanner/rules/dangerousFunctions.js | child-process | 28 |
| src/scanner/rules/dangerousFunctions.js | deserialize | 35 |
| src/scanner/rules/hardcodedSecrets.js | hardcoded-password | 54 |
| src/scanner/rules/hardcodedSecrets.js | hardcoded-secret | 55 |
| src/scanner/rules/hardcodedSecrets.js | hardcoded-jwtSecret | 58 |
| src/scanner/rules/xss.js | document-write | 24 |
| src/scanner/ast.js | document-write | 202 |
| src/scanner/ast.js | child-process | 299 |
| src/scanner/richDataBase.js | sql-assign-concat | 15 |
| src/scanner/richDataBase.js | innerhtml | 25 |
| src/scanner/ruleRichData.js | hardcoded-secret | 32 |
| src/scanner/ruleRichData.js | eval | 22 |
| src/scanner/ruleRichData.js | child-process | 16 |
| src/scanner/ruleRichData.js | md5 | 42 |

### Why these cannot be "fixed" by the rules

Each remaining self-reference is a genuine occurrence of the pattern the rule exists to
catch, appearing in the scanner's own documentation/example code:

- **eval** on `dangerousFunctions.js:10` and `ruleRichData.js:22` — literal `eval(` in a rule
  title and an insecure-code example. The rule's purpose is to flag `eval(`, so it must also
  flag its own example.
- **friendlyName labels** (`hardcoded-password:54`, `hardcoded-secret:55`,
  `hardcoded-jwtSecret:58`) — the rules see `password: 'password'`, `secret: 'secret/token'`,
  `jwtSecret: 'JWT signing secret'` and correctly identify them as credential-shaped literals.
  They are metadata, not secrets.
- **child-process** matches the module token in comments/patterns; `ast.js:299` is a
  library-detection regex, and the `dangerousFunctions.js` entries are the rule's own comment
  + pattern text.
- **document-write, innerhtml, sql-assign-concat, md5, log-secret, deserialize** — each fires
  on the scanner's own example snippet that demonstrates the vulnerable pattern.

Forcing the rules to ignore their own examples would weaken them for real code, so these are
**documented, reviewed, and pinned in the baseline** instead.

## Gate verification (how we know it works)

```bash
# GREEN for the reviewed self-references (findings stay visible, gate excludes them)
node bin/vulnlens.js scan src --fail-on high --baseline vulnlens.baseline.json ; echo $?   # 0

# Same result via auto-discovery (no flag; vulnlens.baseline.json is in cwd)
node bin/vulnlens.js scan src --fail-on high --quiet ; echo $?                              # 0

# A genuinely new HIGH (jwt.sign with a hardcoded literal) STILL fails the gate
node bin/vulnlens.js scan <dir-with-real-high> --fail-on high --baseline vulnlens.baseline.json ; echo $?  # 1

# Baseline is fail-safe / fail-visible:
#   explicit missing file          -> exit 2
#   malformed JSON                 -> exit 2
#   a drifted line stops matching  -> finding returns to the gate (exit 1)
```

## Validation gates (all green)

- `npm test` — **510 passed, 0 failed** (incl. 11 new baseline tests, 15 ci-gate tests)
- `test:corpus:strict` — **100 % precision / 100 % recall, 0 over-claims** (gate passes)
- SARIF export — valid **SARIF 2.1.0**, written even on gate failure
- CI workflow — `--baseline vulnlens.baseline.json` wired in; red-result note removed
  (`.github/workflows/vulnlens.yml`)

---

## Phase 6D addendum — baseline-aware classification

The 18 AFTER findings now carry explicit regression-intelligence statuses:

- **17 BASELINED** — the committed self-reference entries (`filePath::ruleId::line`
  keys all match the current scan). They remain **visible** in table / JSON / SARIF
  output and are excluded from the `--fail-on` gate.
- **1 NEW** — `tempfile-upload` on `src/routes/scans.js:28` (informational,
  retained by design; below the `high` gate threshold).
- **0 RESOLVED** — no baselined self-reference has drifted.
- **0 escalations** — the committed entries record no `severity`, so Phase 6C
  gating semantics are preserved exactly.

Gate result with the committed baseline: `--fail-on high` → **exit 0** (green).
Without the baseline, the 6 HIGH self-references return to the gate → **exit 1**.

Full semantics (NEW / BASELINED / RESOLVED, comparison keys, escalation guard,
fail-visible malformed-baseline handling) are documented in
**`docs/baseline-regression-intelligence.md`**.