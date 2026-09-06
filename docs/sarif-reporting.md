# SARIF 2.1.0 Reporting (Phase 3)

VulnLens can export any scan as a **SARIF 2.1.0** (Static Analysis Results
Interchange Format) document for use in CI systems such as **GitHub Code Scanning**.

SARIF is a **reporting format only**. It consumes the exact same deterministic findings
used by JSON reports, the dashboard, and rescan verification. It does **not** run a second
scanner and does **not** re-evaluate severity.

---

## Endpoint

| | |
|---|---|
| Route | `GET /api/reports/:scanId/sarif` |
| Auth | Required (`Authorization: Bearer <jwt>`), same `protect` middleware as all report routes |
| Authorization | Enforced inside `generateSarif` — owner-only, identical to JSON reports (403 for non-owner, 404 for missing scan) |
| Content-Type | `application/sarif+json` |
| Content-Disposition | `attachment; filename="vulnlens-scan-<scanId>.sarif"` |
| Works for | single-file scans, folder scans, code-only, dependency-only, and mixed/empty scans |

---

## Document shape (2.1.0)

```jsonc
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": { "driver": { "name": "VulnLens", "rules": [ /* one per ruleId */ ] } },
      "results": [ "(one per finding)" ]
    }
  ]
}
```

A scan with **zero findings** still produces valid SARIF with `results: []`.

---

## Severity mapping (deterministic)

SARIF `level` is derived from the existing **deterministic** finding severity. It is never
influenced by AI.

| VulnLens severity | SARIF level |
|---|---|
| `critical` | `error` |
| `high` | `error` |
| `medium` | `warning` |
| `low` | `note` |
| `informational` | `note` |
| unknown / missing | `note` (safe fallback) |

---

## Finding → SARIF mapping

| VulnLens finding | SARIF result |
|---|---|
| `ruleId` | `result.ruleId` |
| `title` | `result.message.text` |
| `severity` | `result.level` (see mapping above) |
| `filePath` | `locations[0].physicalLocation.artifactLocation.uri` (normalized) |
| `line` | `locations[0].physicalLocation.region.startLine` (omitted if absent) |
| `column` | `region.startColumn` (when present) |
| `endLine` | `region.endLine` (when present) |
| `comparisonKey` | `partialFingerprints.primaryLocationLineHash` (SHA-256, stable) |
| `baselineStatus` (Phase 6D, when classified) | `properties.baselineStatus` — `"NEW"` or `"BASELINED"`; additive metadata, never removes results |
| `baselineEscalated` (Phase 6D) | `properties.baselineEscalated` — `true` when a BASELINED finding is more severe than its recorded baseline severity |

### Code findings (`properties: { kind: "code" }`)

- `vulnerabilityType`, `category`, `confidence`

### Dependency findings (`properties: { kind: "dependency" }`)

- `packageName`, `installedVersion`, `dependencyType`, `cve`, `affectedRange`,
  `fixedVersion`, `advisoryUrl`
- Artifact location points at the manifest / lockfile

### driver.rules

Rules are deduplicated by `ruleId` and carry `id`, `name`, `shortDescription`,
`fullDescription`, `help`, and `defaultConfiguration.level`. Raw secret values / masked
code snippets are **never** emitted.

---

## Path handling (safety)

Artifact URIs are normalized to safe, portable relative paths:

- Windows backslashes → `/`  ·  Drive letters stripped (`C:`)
- Leading `/` stripped (absolute → relative)
- Homedir prefixes removed (`Users/<name>`, `home/<name>`, `Documents and Settings/<name>`)
- `..` / `.` traversal segments dropped  ·  Long paths truncated to 255 chars
- URI-unsafe characters percent-encoded

A local path like `C:\Users\Ashish\...\src\auth\login.js` is sanitized — server,
username, and drive information is never leaked.

---

## Stable fingerprints

`partialFingerprints.primaryLocationLineHash = SHA-256(comparisonKey)` (truncated to 32 hex
chars). VulnLens `comparisonKey`s are path-namespaced for folder scans, so **identical
snippets in different files remain separate results** with distinct fingerprints. No
timestamps, random values, array positions, or db ids are used.

---

## Frontend

A **Download SARIF** button sits next to **Download Report** on the scan detail page. It
uses an **authenticated** `blob` download (so the Bearer token is sent), downloads
`vulnlens-scan-<scanId>.sarif`, and works for every scan type.

---

## CI/CD: GitHub Code Scanning

The SARIF output is compatible with GitHub's `code-scanning/sarifs` upload API:

```bash
# After producing vulnlens-scan-<id>.sarif
curl -X POST \
  -H "Authorization: Bearer $GH_TOKEN" \
  -H "Accept: application/vnd.github+json" \
  "https://api.github.com/repos/$REPO_OWNER/$REPO_NAME/code-scanning/sarifs" \
  --data-binary @- <<'JSON'
{
  "commit_sha": "$GITHUB_SHA",
  "ref": "$GITHUB_REF",
  "sarif": "<base64 of the sarif file>",
  "check_name": "VulnLens",
  "tool_name": "VulnLens"
}
JSON
```

### Production GitHub Actions workflow

A turnkey workflow **already exists** in this repository:
`.github/workflows/vulnlens.yml`. It runs the production `vulnlens` CLI on every
pull request and push to `main`, uploads SARIF to Code Scanning, and enforces a
configurable `--fail-on` threshold as a security gate.

```yaml
# .github/workflows/vulnlens.yml (abridged — see the file for the full workflow)
name: vulnlens
on:
  pull_request:
  push: { branches: [main] }
permissions:
  contents: read
  security-events: write
jobs:
  security-scan:
    runs-on: ubuntu-latest
    defaults: { run: { working-directory: backend } }
    env: { VULNLENS_FAIL_ON: "${{ vars.VULNLENS_FAIL_ON || 'high' }}" }
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-node@v4
        with: { node-version: 20, cache: npm, cache-dependency-path: backend/package-lock.json }
      - run: npm ci
      - name: Scan with VulnLens
        run: |
          set +e
          npm run vulnlens -- scan src --format sarif \
            --output "$GITHUB_WORKSPACE/vulnlens.sarif" \
            --fail-on "${VULNLENS_FAIL_ON:-high}"
          echo "VULNLENS_EXIT=$?" >> "$GITHUB_ENV"
          set -e
      - name: Upload SARIF to Code Scanning
        if: always() && hashFiles('vulnlens.sarif') != ''
        uses: github/codeql-action/upload-sarif@v3
        with: { sarif_file: "${{ github.workspace }}/vulnlens.sarif" }
      - name: Enforce security gate
        if: always()
        run: exit "${VULNLENS_EXIT:-3}"
```

See **[`ci-cd-github-actions.md`](./ci-cd-github-actions.md)** for the full
explanation: exit-code mapping, threshold override via the `VULNLENS_FAIL_ON`
Actions variable, least-privilege permissions, and why the initial CI result is
expected to be red until the `backend/src` findings are triaged.

---

## CI security gate

VulnLens ships a **fail-on severity gate** via the production CLI's `--fail-on`
flag (default `high`) and the GitHub Actions workflow
(`.github/workflows/vulnlens.yml`):

- CRITICAL / HIGH → **FAIL**  ·  MEDIUM → **WARN** (report-only at this threshold)  ·  LOW / INFO → **INFO**
- The gate is fail-closed by default and configurable per-repo via the
  `VULNLENS_FAIL_ON` Actions variable. See
  **[`ci-cd-github-actions.md`](./ci-cd-github-actions.md)** for details.

Since Phase 6D, the gate is **baseline-aware**: findings are classified
**NEW** / **BASELINED** / **RESOLVED** against a committed baseline (see
**[`baseline-regression-intelligence.md`](./baseline-regression-intelligence.md)**),
and only NEW (plus severity-escalated BASELINED) findings count toward
`--fail-on`. All findings — NEW and BASELINED — remain in the SARIF report with
their `baselineStatus` in `properties`.

---

## Limitations

- **Initial CI scope** — the GitHub Actions workflow scans `backend/src` only
  (first-party code). Full-repository / `frontend` scanning is deferred until the
  recursive scanner gains a path-exclusion mechanism (see
  `ci-cd-github-actions.md`).
- **Initial CI result is red** — the fail-closed `high` gate currently fails on
  untriaged `backend/src` findings. This is intentional and documented
  (`ci-cd-github-actions.md`).
- **Path recovery** — when a finding already carries a local absolute path (defense in
  depth), interior directory names beyond the drive/user prefix may remain. In practice
  VulnLens stores already-sanitized relative paths.