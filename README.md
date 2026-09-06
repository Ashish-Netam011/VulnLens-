# VulnLens AI

AI-powered cybersecurity analysis platform that combines rule-based static scanning
with AI explanations, rescan verification, and secure code reports.

## Architecture

- **`backend/`** â€” Node.js + Express API (ESM), MongoDB via Mongoose, modular security scanner.
- **`frontend/`** â€” React + Vite + Tailwind dark-theme dashboard (SPA).

```
â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   /api   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”
â”‚  Frontend    â”‚ â”€â”€â”€â”€â”€â”€â”€â–¶ â”‚  Express backend                       â”‚
â”‚  React/Vite  â”‚ â—€â”€â”€â”€â”€â”€â”€â”€ â”‚  auth Â· projects Â· scans Â· dashboard   â”‚
â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜          â”‚  reports                                â”‚
                         â”‚       â”‚                                 â”‚
                         â”‚       â–¼                                 â”‚
                         â”‚  â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”   â”Œâ”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â” â”‚
                         â”‚  â”‚  Scanner     â”‚   â”‚  AI providers    â”‚ â”‚
                         â”‚  â”‚  (8 rules)   â”‚   â”‚ (facade/fallback)â”‚ â”‚
                         â”‚  â”‚  + risk scoreâ”‚   â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜ â”‚
                         â”‚  â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜                        â”‚
                         â””â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”€â”˜
```

## Features

- **Rule-based static scanner** â€” 8 categories: hardcoded secrets, SQL injection,
  XSS, dangerous functions, weak crypto, misconfiguration, sensitive data, file handling.
- **Single-file & folder scanning** â€” paste code, upload a `.js`/`.py`/`.java` file, or
  select an entire **project folder**; every supported source file is scanned and
  findings are attributed to their relative file path (`.jsx`, `.ts`, `.go`, `.rb`, `.php`, â€¦).
- **Risk scoring (0â€“100)** â€” deterministic, severity-weighted, independent of AI.
- **AI explanations** â€” pluggable providers (OpenRouter cloud or Ollama local) with a
  rule-authored fallback so the app works fully offline with `AI_PROVIDER=none`.
- **Rescan verification** â€” stable `comparisonKey` diffing (namespaced per file) into
  resolved/remaining/new; works for single-file and folder scans alike.
- **Secure report download** â€” JSON report generation per scan, with a per-file breakdown
  for folder scans.
- **SARIF 2.1.0 export** â€” download any scan as standard SARIF (`vulnlens-scan-<id>.sarif`)
  for CI/CD and GitHub Code Scanning; deterministic `comparisonKey`-based fingerprints.
- **Production CLI** â€” `vulnlens scan <path>` with table / JSON / SARIF output and CI
  exit codes. Reuses the exact same scanner pipeline, AI-free and DB-free, with path
  sanitization, binary/secret handling, and `--fail-on` thresholds.
- **Baseline-aware regression intelligence** - `--baseline <file>` (or auto-discovered
  `vulnlens.baseline.json`) classifies every finding **NEW / BASELINED / RESOLVED**
  against a committed, reviewed baseline. Baselined findings stay visible in table,
  JSON, and SARIF output and are excluded from `--fail-on` (never hidden, never
  severity-downgraded, with a severity-escalation guard). See
  `docs/baseline-regression-intelligence.md`.
- **CI security gate** â€” a GitHub Actions workflow (`.github/workflows/vulnlens.yml`)
  scans `backend/src` on every PR and push to `main`, uploads SARIF to GitHub Code
  Scanning, and fails on a configurable severity threshold (default `high`, overridable
  via the `VULNLENS_FAIL_ON` Actions variable). See `docs/ci-cd-github-actions.md`.
- **Dependency / CVE scanning** â€” OSV-backed advisory detection bundled into findings and
  reports.
- **Auth & security** â€” JWT auth, bcrypt password hashing, Zod validation, rate limiting,
  helmet security headers, CORS, ownership-isolated data.

## Getting started

### Prerequisites

- Node.js 18+ (ESM)
- A MongoDB database. This setup uses a **free MongoDB Atlas cloud cluster**
  (no local install required â€” just a connection string).

### 1. Backend

```bash
cd backend
npm install
# Put your Atlas connection string into backend/.env as MONGODB_URI, e.g.:
#   MONGODB_URI=mongodb+srv://user:pass@cluster0.xxxxx.mongodb.net/vulnlens?retryWrites=true&w=majority
npm start          # http://localhost:5000
```

Tests (no database needed â€” scanner + rescan logic):

```bash
cd backend
npm test           # 10 tests (scanner incl. multi-file + rescan) pass
```

### 2. Frontend

```bash
cd frontend
npm install
npm run dev        # http://localhost:3000  (proxies /api to :5000)
```

### 3. Production build

```bash
cd frontend && npm run build   # outputs to frontend/dist
```

### 4. Command-line interface

Run a scan from the terminal (no database, no AI, no network required):

```bash
cd backend
npm run vulnlens -- scan ./src                 # table output (default)
npm run vulnlens -- scan ./src --format json
npm run vulnlens -- scan ./src --format sarif --output vulnlens.sarif
npm run vulnlens -- scan ./src --fail-on medium
npm run vulnlens -- scan ./src --baseline vulnlens.baseline.json
npm run vulnlens -- scan ./src/server.js       # single file
```

Or invoke the binary directly, or via the installed `bin` entry when linked:

```bash
node bin/vulnlens.js scan ./src
```

**Options**

| Option | Description |
|---|---|
| `--format <f>` | `table` (default) \| `json` \| `sarif` |
| `--output <file>` | Write results to file (full payload to file, summary to stderr) |
| `--fail-on <s>` | Exit `1` if findings meet threshold â€” `critical` \| `high` (default) \| `medium` \| `low` \| `none` |
| `--baseline <file>` | Committed baseline JSON; matching findings stay visible but are excluded from the `--fail-on` gate |
| `--quiet` | Suppress the stderr summary |
| `--version`, `-V` | Print version |
| `--help`, `-h` | Show help |

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Scan completed; no findings meet the failure threshold |
| `1` | Scan completed; findings meet the failure threshold |
| `2` | CLI usage or configuration error |
| `3` | Scanner or runtime error |

The CLI reuses the same deterministic scanner pipeline as the API, so findings,
severity counts, and risk scores are identical to a folder scan through the web UI.
Output paths are always relative and sanitized; symlinks and binary files are skipped,
and secrets are masked.

### 5. Continuous integration (GitHub Actions)

A **CI security gate** is configured at `.github/workflows/vulnlens.yml`:

- Runs the production CLI on every **pull request** and **push to `main`**.
- Scans **`backend/src`**, emits **SARIF**, and uploads it to **GitHub Code
  Scanning** â€” even when the gate is red (results are never suppressed).
- Fails the job when findings meet the threshold (`--fail-on`, default **`high`**),
  overridable per-repo via the **`VULNLENS_FAIL_ON`** Actions variable.
- **Self-scan baseline:** the scanner's own reviewed self-references are pinned in
  `backend/vulnlens.baseline.json` and excluded from the gate via `--baseline`, so
  CI is **green** for known self-references while still failing on genuinely new
  HIGH findings. See **[`docs/self-scan-triage.md`](docs/self-scan-triage.md)**.
- Uses least-privilege permissions (`contents: read`, `security-events: write`),
  no secrets, and is fork-safe (`pull_request`, not `pull_request_target`).

See **[`docs/ci-cd-github-actions.md`](docs/ci-cd-github-actions.md)** for the
full exit-code mapping, configuration, and the self-scan baseline.

## Environment variables (backend)

See `backend/.env.example`. Key settings:

| Variable | Default | Purpose |
|---|---|---|
| `PORT` | `5000` | API port |
| `MONGODB_URI` | `mongodb+srv://â€¦` (Atlas) | Database connection string |
| `JWT_SECRET` | ephemeral (random per boot) | JWT signing; **required in production** (fail-closed) |
| `AI_PROVIDER` | `none` | `none` \| `openrouter` \| `ollama` |
| `OPENROUTER_API_KEY` | â€” | OpenRouter API key |
| `OLLAMA_BASE_URL` | `http://localhost:11434` | Local Ollama endpoint |

## Phase roadmap

1. âœ… Backend + scanner architecture (8 rule categories)
2. âœ… Auth, projects, scans, dashboard, reports + routes/controllers
3. âœ… AI provider abstraction + fallback enrichment
4. âœ… Rescan comparison service
5. âœ… Frontend SPA (dashboard, projects, scan detail, findings modal)
6. â³ End-to-end smoke test
7. â³ Hardening: CSP tuning, input sanitization review
8. â³ Additional backend API tests, docs, deployment config
