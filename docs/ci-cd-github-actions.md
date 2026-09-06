# CI/CD with GitHub Actions (Phase 6B)

This repository includes a **GitHub Actions** workflow that runs the production
`vulnlens` CLI (Phase 6A) on every pull request and push to `main`, uploads the
resulting **SARIF 2.1.0** report to **GitHub Code Scanning**, and enforces a
**fail-on severity threshold** as a security gate.

The workflow reuses the exact same deterministic, AI-free, DB-free scanner
pipeline as the CLI and the API. It requires **no secrets**, **no MongoDB**, and
**no network** to the AI providers.

## Workflow file

- **Path:** `.github/workflows/vulnlens.yml`
- **Job:** `security-scan` ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ `VulnLens Security Gate`
- **Runner:** `ubuntu-latest`
- **Node:** 20 (via `actions/setup-node@v4`, with npm cache)
- **Working directory:** `backend`

## What it does (step by step)

1. **Checkout** the repository (`actions/checkout@v4`).
2. **Setup Node.js** with the npm cache keyed on `backend/package-lock.json`.
3. **Install** dependencies with `npm ci` (exact, reproducible).
4. **Scan** `backend/src` and emit SARIF:
   ```bash
   npm run vulnlens -- scan src \
     --format sarif \
     --output "$GITHUB_WORKSPACE/vulnlens.sarif" \
     --baseline vulnlens.baseline.json \
     --fail-on "${VULNLENS_FAIL_ON:-high}"
   ```
   The CLI **writes the SARIF file before it derives its exit code**, so the file
   exists even when the gate fails. The exit code is captured into
   `VULNLENS_EXIT` via `$GITHUB_ENV` (the job does **not** stop early).
5. **Upload SARIF** to Code Scanning with
   `github/codeql-action/upload-sarif@v3`. It runs with `if: always()` so results
   are reported even when the gate is red, and is only skipped if no SARIF file
   was produced at all (a CLI usage/scanner error).
6. **Enforce the gate** by re-exiting with the captured `VULNLENS_EXIT`
   (fail-closed default of `3` if it was never captured).

## Timeline / ordering guarantee

```
scan step ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬exit-code captured (never aborts)ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬â€œÃ‚Â¶ upload SARIF (always)
                                                     ÃƒÂ¢Ã¢â‚¬ÂÃ¢â‚¬Å¡
                                   enforce gate (always) ÃƒÂ¢Ã¢â‚¬â€Ã¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ÃƒÂ¢Ã¢â‚¬ÂÃ¢â€šÂ¬ exit $VULNLENS_EXIT
```

Because SARIF is written before the exit code is derived, **a failing security
gate still produces a Code Scanning alert** ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â the upload step and the gate are
independent steps and both run on `always()`.

## Exit-code contract

| Code | Meaning | Result |
|---|---|---|
| `0` | PASS ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â no NEW (non-baselined) findings at/above the threshold | Job green |
| `1` | SECURITY GATE FAILED ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â NEW finding(s) at/above `--fail-on` | Job red |
| `2` | WORKFLOW ERROR ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â CLI usage/configuration error | Job red |
| `3` | SCANNER ERROR ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â scanner/runtime error | Job red |

Exit `2`/`3` are **never** converted into success. The gate step simply re-exits
with the captured code, so the failure is visible and actionable.
## Configuring the threshold

The default gate threshold is **`high`** (a `critical`-or-`high` finding fails
the gate). Override it **without editing the workflow** by setting a repository
**Actions variable** named `VULNLENS_FAIL_ON`:

| Value | Gate fails on |
|---|---|
| `critical` | a `critical` finding |
| `high` (default) | `critical` \| `high` |
| `medium` | `critical` \| `high` \| `medium` |
| `low` | `critical` \| `high` \| `medium` \| `low` |
| `none` | never (report only, always green) |

> Actions **variables** (not secrets) are the right place for this: they can be
> set per-environment/repo by any user with write access and are readable by
> workflows, so no secret vault is needed.
>
> ```yaml
> # in .github/workflows/vulnlens.yml
> VULNLENS_FAIL_ON: ${{ vars.VULNLENS_FAIL_ON || 'high' }}
> ```

## Permissions & security posture

The workflow uses **least-privilege** permissions and never touches secrets:

```yaml
permissions:
  contents: read          # actions/checkout reads source
  security-events: write  # upload-sarif writes Code Scanning alerts
```

- Uses `pull_request` (not `pull_request_target`), so it is **fork-safe** ÃƒÂ¢Ã¢â€šÂ¬Ã¢â‚¬Â it
  never runs with the base-repo token on untrusted PR code.
- No `issues`, `pull-requests`, or other write scopes.
- No `${{ secrets.* }}` references anywhere.
## Self-scan baseline (green CI for reviewed findings)

VulnLens is a security scanner, and scanning `backend/src` legitimately produces a
small set of **HIGH** findings that are SELF-REFERENCES: the scanner flags its own
rule patterns, `friendlyName` labels, AST library-detection regexes, and
`secureExample` snippets. These are **known, reviewed, and irreducible**.

They are documented in **`docs/self-scan-triage.md`** (a full 45-row triage matrix)
and committed to **`backend/vulnlens.baseline.json`**. The CLI `--baseline` option
keeps these findings **visible** in the SARIF/table/json report but **excludes them
from the `--fail-on` gate**, so CI is green for the reviewed self-references while
still failing on any genuinely **new** HIGH finding.

### How the baseline is enforced (Phase 6D classification)

- `--baseline <file>` loads a JSON list of `{ filePath, ruleId, line }` entries
  (optional additive `severity` / `message` per entry).
- If no flag is given, the CLI auto-loads `vulnlens.baseline.json` from the
  working directory (the workflow backend/ dir) when present.
- Every current finding is classified **NEW** (absent from the baseline — gates
  normally) or **BASELINED** (present in the baseline — stays visible in the
  report, excluded from the exit-code gate). Baseline entries with no matching
  current finding are reported **RESOLVED** (never current findings, never fail
  CI, never auto-removed from the baseline).
- **Severity escalation guard:** if a baseline entry records a `severity` and the
  current finding at the same key is more severe, the BASELINED finding is
  re-added to the gate. The committed 17-entry Phase 6C baseline has no recorded
  severities, so its behavior is unchanged.
- A **missing** (explicit) or **malformed** baseline is a workflow error (exit 2),
  never a silent suppression.
- Full semantics, comparison keys, and the review workflow are documented in
  **`docs/baseline-regression-intelligence.md`**.

### Fail-safe by design

A baseline entry suppresses a finding only when `filePath + ruleId + line` matches
exactly. If the code changes and a line moves, the entry stops matching and the
finding returns to the gate. The baseline thus **never** silently hides a drift;
it fails-visible instead.

### Keeping the baseline honest

1. **Triage** any new HIGH finding reported in the **Security** tab / `npm test`.
2. **Fix** genuine issues. Only self-references that cannot be sensibly eliminated
   belong in the baseline; every entry references its rationale in the triage doc.
3. Existing findings are stable (deterministic `comparisonKey` fingerprints), so
   the baseline matches deterministically and does not need re-massaging each run.
## Initial scope (and what is deferred)

- **Included:** `backend/src` only (first-party security-sensitive code).
- **Deferred:** full-repository scanning and `frontend/` scanning.

Why: the recursive directory scanner does **not** exclude `node_modules`. Pointing
the workflow at the repository root would have the 100-file cap consumed entirely
by dependency files inside `node_modules`. CI therefore targets the first-party
`backend/src` source tree directly. A generalised path-exclusion mechanism and
full-repo / frontend coverage are follow-up work.

## Adding scans / extending

To add another first-party directory later (e.g. `frontend/src`), either:

- Add a second scan step writing to a separate SARIF file and upload it, or
- Introduce a proper include/exclude list and widen the target to `..`.

Keep the "write SARIF before deriving exit code" and "capture ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢ capture ÃƒÂ¢Ã¢â‚¬Â Ã¢â‚¬â„¢
enforce" patterns so alerting stays decoupled from the gate.

## Testing the gate locally (no hosted runner)

Because this repository has no Git remote yet, a hosted run cannot be exercised
here. The workflow's structure and the CLI contract are covered by unit tests at
`backend/tests/ci-gate.test.js`. A local simulation reproduces the exit-code and
SARIF-preservation semantics:

```bash
# PASS (clean input, no baseline needed)
node backend/bin/vulnlens.js scan <clean-dir> --format sarif \
  --output /tmp/v.sarif --fail-on high ; echo "exit=$?"

# GREEN for reviewed self-references: baseline excludes them from the gate
cd backend
node bin/vulnlens.js scan src --format sarif --output /tmp/v.sarif \
  --baseline vulnlens.baseline.json --fail-on high ; echo "exit=$?"   # 0
cd -

# FAILS on a genuinely new HIGH even with a baseline; SARIF is still written
node backend/bin/vulnlens.js scan <dir-with-new-high> --format sarif \
  --output /tmp/v.sarif --baseline vulnlens.baseline.json \
  --fail-on high ; echo "exit=$?"   # 1
ls -l /tmp/v.sarif   # exists despite exit 1

## Phase 6E — CI & baseline integrity hardening

Three hardening measures ensure the security gate cannot silently weaken via
baseline, workflow, or dependency modification.

### 1. Baseline runtime immutability

The committed `backend/vulnlens.baseline.json` is trusted security metadata.
The job hashes it with `sha256sum` (SHA-256, exact file contents) **immediately
after checkout**, then re-verifies the hash **after the scan** in an
`if: always()` step that fails the job on any mismatch:

```text
checkout → record SHA-256 → install/scan/upload → verify SHA-256 → enforce gate
```

- A **legitimately committed baseline change** (a reviewed PR edit) passes: it
  simply records a different hash at job start. The check never compares
  against a hardcoded or stale hash.
- A **runtime modification** (any process changing, deleting, or replacing the
  baseline during the job) fails the job — the gate cannot be silently
  weakened.
- Only file hashes are logged, never contents. The CLI schema validation
  (malformed baseline → exit 2) is unchanged and separate; the hash check is
  an additional integrity layer, not a substitute.

### 2. SHA-pinned third-party actions

All three actions are pinned to immutable commit SHAs (verified 2026-09-06
against the upstream tag refs via the GitHub API), so a mutated tag can never
inject code:

| Action | Pinned SHA | Upstream tag |
|---|---|---|
| `actions/checkout` | `11d5960a326750d5838078e36cf38b85af677262` | `v4` |
| `actions/setup-node` | `49933ea5288caeca8642d1e84afbd3f7d6820020` | `v4` |
| `github/codeql-action/upload-sarif` | `6f5948dfacef28e207b48d0905cf90c03365536d` | `v3` |

Updates are manual (documented in inline comments); this is the accepted
trade-off for immutability.

### 3. No dependency lifecycle scripts in CI

The install step runs `npm ci --ignore-scripts`. Verified against
`backend/package-lock.json` (lockfileVersion 3): exactly two packages declare
install scripts — `fsevents` (an optional macOS-only dependency, not installed
on the ubuntu runner) and `mongodb-memory-server` (its postinstall downloads
database binaries for local tests). The CI job runs the **scanner, not
tests**, so neither script is required. Skipping scripts removes all
third-party code execution at install time while exact versions stay pinned by
the lockfile. Local developer installs are unaffected (`allowScripts` for the
database package remains in `package.json`).
