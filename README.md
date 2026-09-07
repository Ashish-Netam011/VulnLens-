# VulnLens AI

**Deterministic, static-analysis security scanner with an AI copilot that
explains and fixes findings - not one that guesses them.**

[![CI - VulnLens Security Gate](https://github.com/Ashish-Netam011/VulnLens/actions/workflows/vulnlens.yml/badge.svg)](https://github.com/Ashish-Netam011/VulnLens/actions/workflows/vulnlens.yml)

VulnLens finds real vulnerabilities in your code, shows you the evidence and the
attack path, keeps your CI gate honest with baseline-aware regression
intelligence, and exports standard SARIF for GitHub Code Scanning. The scanner
that decides is deterministic and rule-based; the AI only explains and advises.

---

## Table of contents

1. [Problem](#problem)
2. [Solution](#solution)
3. [Key features](#key-features)
4. [AI integration: "the scanner decides, AI explains"](#ai-integration)
5. [Architecture](#architecture)
6. [Security design](#security-design)
7. [Tech stack](#tech-stack)
8. [Repository layout](#repository-layout)
9. [Getting started](#getting-started)
10. [Command-line interface](#command-line-interface)
11. [Environment variables](#environment-variables)
12. [Development commands & testing](#development-commands--testing)
13. [Demo workflow](#demo-workflow)
14. [CI security gate](#ci-security-gate)
15. [Documentation](#documentation)
16. [Limitations](#limitations)
17. [Project context](#project-context)
18. [AI tools disclosure](#ai-tools-disclosure)
19. [License](#license)

## Problem

Static analysis tools fall into two camps that are hard to trust:

- **Rule-based scanners** are deterministic and explainable, but often noisy
  and limited to "here is a problem" with no help fixing it.
- **AI "vulnerability detectors"** sound impressive but hallucinate findings,
  which makes them useless (and dangerous) as a CI gate.

Engineering teams need a scanner that **never fabricates a finding**, can gate
deploys on real regressions, and still helps developers understand and fix what
it found.

## Solution

VulnLens separates the two jobs cleanly:

1. **A deterministic scanner is the source of truth.** Every finding comes from
   a rule, an evidence trail, and a confidence model. Same code, same machine,
   same repo -> identical results every run. No LLM is ever consulted to decide
   whether something is a vulnerability.
2. **The AI Security Copilot works only after detection.** Given a concrete,
   already-detected finding, it explains the vulnerability, its impact, and how
   to fix it - with a secure code example. It cannot add, remove, downgrade, or
   hide findings.

That split makes VulnLens suitable as a **CI security gate**: baseline-aware,
deterministic, and explainable end to end.

## Key features

- **Rule-based scanning across 8 vulnerability families** - hardcoded secrets,
  SQL injection, XSS, dangerous functions, weak crypto, security
  misconfiguration, sensitive-data exposure, and unsafe file handling.
- **Project-folder, single-file, and pasted-code scanning.** Scan a whole
  directory tree or one file. Supported extensions include JavaScript /
  TypeScript (`js`, `jsx`, `ts`, `tsx`, `mjs`, `cjs`) with AST parsing, plus
  Python, Java, C, C++, C#, Go, Ruby, PHP, shell, JSON/YAML, HTML/CSS, and SQL.
- **Reproducible 0-100 security score** - deterministic, severity-weighted, and
  independent of the AI layer.
- **Evidence-based findings** with severity, confidence, verdict, the matched
  pattern, and the exact code region.
- **Source-to-sink data-flow analysis** - targeted taint analysis that traces
  attacker-controlled input through propagation to dangerous sinks and renders
  the path (SOURCE -> propagation -> SINK).
- **Rescan verification** - stable, deterministic `comparisonKey` fingerprints
  classify findings into resolved / remaining / new when code changes.
- **Baseline-aware CI regression intelligence** - scan against a committed
  baseline to label every finding **NEW / BASELINED / RESOLVED**. Baselined
  findings stay **visible** (never hidden, never severity-downgraded) but are
  excluded from the `--fail-on` gate, so known, reviewed findings do not block
  CI while genuinely new HIGH findings still do. A severity-escalation guard
  re-arms the gate if a baselined finding gets worse.
- **SARIF 2.1.0 export** - download or emit standard SARIF with deterministic
  fingerprints for GitHub Code Scanning and any SARIF-compatible tooling.
- **Dependency / CVE intelligence** - OSV.dev-backed advisory detection (no API
  key required) folded into scan results and reports.
- **AI Security Copilot** - per-finding explanation and remediation guidance via
  pluggable providers (OpenRouter cloud or a local Ollama), with a rule-authored
  fallback so the app works fully offline.
- **Production CLI** - AI-free, database-free `vulnlens scan <path>` with table /
  JSON / SARIF output, CI exit codes, and `--fail-on` thresholds.
- **Auth & multi-user isolation** - JWT auth, bcrypt password hashing, Zod
  input validation, rate limiting, helmet security headers, CORS, and
  owner-scoped data.

## AI integration

> **The scanner decides. AI explains.**

- **Deterministic core:** rule engine -> evidence builder -> confidence engine ->
  verdict engine -> risk score. None of these layers calls an LLM.
- **Optional Copilot (`POST /api/ai/explain`):** given one finding (severity,
  rule, file, line, affected code, evidence), it produces a structured
  explanation: what the vulnerability is, why it matters, how it could be
  exploited, and a secure fix with example code. The request schema is bounded
  so attacker-supplied evidence can never blow up a prompt budget.
- **Providers:** `openrouter` (cloud), `ollama` (local, private), or `none`
  (offline rule-authored explanations). No provider means no network call for
  explanations.
- **A clear contract:** the Copilot can never add, remove, re-severity, or hide
  a finding. AI output is explicitly advisory.

## Architecture

```
                         /api
  +------------------+  <---->  +------------------------------------+
  | React + Vite SPA |          | Express backend (auth, projects,   |
  | dark-theme       |          | scans, dashboard, reports, AI)     |
  | "Investigation   |          +------------------------------------+
  |  Cockpit" UI     |                 |                 |
  +------------------+                 v                 v
                              +----------------+   +------------------+
                              |  Scanner core  |   | AI providers     |
                              |  8 rule families|  | (facade +        |
                              |  + data flow    |   |  fallback)       |
                              |  + evidence     |   +------------------+
                              |  + verdict/score|
                              +----------------+
                                   | reused by
                                   v
                         +---------------------+
                         | Production CLI      |
                         | (table/json/sarif,  |
                         |  --baseline,        |
                         |  --fail-on)         |
                         +---------------------+
```

The **scanner core is shared** by the web API, the CLI, and the CI workflow, so
a scan through the web UI and a scan in CI produce identical findings.

## Security design

- **Deterministic by construction** - findings never depend on an LLM, so the
  result is reproducible on any machine and in CI.
- **Fail-closed gating** - the CLI exits non-zero when a finding meets the
  `--fail-on` threshold; the CI job fails. Missing or malformed baselines are
  workflow errors (exit `2`), never silent suppressions.
- **Baselines suppress gates, not findings** - a baselined HIGH stays a HIGH and
  stays visible. Only CI failure behavior changes, and only for entries that
  still match their `comparisonKey` at the same or lower severity.
- **Self-scanning** - VulnLens scans its own `backend/src` in CI. The scanner's
  reviewed self-references are pinned in `backend/vulnlens.baseline.json` and
  triaged in `docs/self-scan-triage.md`, so CI stays green for known findings
  while failing on new ones.
- **Hardened CI** - third-party actions are SHA-pinned, dependencies install
  with `npm ci --ignore-scripts`, the baseline is SHA-256-checked immutable
  during the job, and the workflow uses least-privilege permissions.
- **API hardening** - JWT with a production fail-closed secret policy, bcrypt
  hashing, strict Zod validation, per-route rate limiting, helmet, CORS
  allow-listing, and strict file/path sanitization on uploads.
- **Credential hygiene** - real credentials never ship in the repo; only
  placeholder `.env.example` values are committed. See
  [Environment variables](#environment-variables).

## Tech stack

| Layer    | Technology                                                           |
|----------|----------------------------------------------------------------------|
| Backend  | Node.js (ESM), Express, MongoDB + Mongoose, Zod, JWT, bcrypt         |
| Scanner  | Acorn AST parsing, custom rule engine, data-flow / taint analysis    |
| AI       | Provider facade (OpenRouter, Ollama) + deterministic fallback        |
| Frontend | React 18, Vite, Tailwind CSS, Recharts, lucide-react, axios         |
| CI/CD    | GitHub Actions, SARIF 2.1.0 + GitHub Code Scanning                   |
| Advisories | OSV.dev API (no key required)                                      |

## Repository layout

```
.
|-- backend/
|   |-- bin/vulnlens.js          # production CLI entry point
|   |-- src/
|   |   |-- scanner/             # rules, evidence, data flow, verdict, score
|   |   |-- ai/                  # copilot + provider facade
|   |   |-- cli/                 # CLI argument parsing + reporting
|   |   |-- routes/ controllers/ services/ models/ middleware/ utils/
|   |-- tests/                   # unit + integration suites, security fixtures
|   |-- vulnlens.baseline.json   # committed self-scan baseline
|   `-- .env.example             # placeholder env template (no secrets)
|-- frontend/                    # React + Vite SPA
|-- docs/                        # deep-dive docs per phase
|-- .github/workflows/vulnlens.yml  # CI security gate
`-- README.md
```

## Getting started

### Prerequisites

- Node.js 18+ (ESM).
- For the web app: a MongoDB database - a free **MongoDB Atlas** cluster works
  (no local install needed), or any MongoDB 4.4+.
- For AI explanations: an OpenRouter API key **or** a local Ollama server.
  Neither is required - the app and CLI run fully without AI.

### 1. Backend

```bash
cd backend
npm install
cp .env.example .env        # then fill in MONGODB_URI and your JWT secret
npm run dev                 # http://localhost:5000
```

The backend serves the API, the dashboard data, the scanner, and the AI Copilot
endpoint.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev                 # http://localhost:3000 (proxies /api to :5000)
```

Register an account, create a project, and run your first scan from the web UI.

### 3. Or skip the database entirely: use the CLI

The CLI is **AI-free and database-free** - no MongoDB, no network:

```bash
cd backend
node bin/vulnlens.js scan ../README.md        # single file
node bin/vulnlens.js scan ./src               # whole folder
node bin/vulnlens.js scan ./src --format json
```

## Command-line interface

```
vulnlens scan <path> [options]
```

| Option            | Description                                                          |
|-------------------|----------------------------------------------------------------------|
| `--format <f>`    | `table` (default) \| `json` \| `sarif`                               |
| `--output <file>` | Write results to a file (full payload to file, summary to stderr)    |
| `--fail-on <s>`   | Exit `1` if findings meet threshold: `critical` \| `high` (default) \| `medium` \| `low` \| `none` |
| `--baseline <f>`  | Committed baseline JSON; matching findings stay visible but are excluded from the `--fail-on` gate. Auto-discovers `vulnlens.baseline.json` when present |
| `--quiet`         | Suppress the stderr summary                                          |
| `-V`, `--version` | Print version                                                        |
| `-h`, `--help`    | Show help                                                            |

**Exit codes**

| Code | Meaning                                                       |
|------|---------------------------------------------------------------|
| `0`  | Scan completed; no findings meet the failure threshold         |
| `1`  | Scan completed; findings meet the failure threshold (gate red) |
| `2`  | CLI usage or configuration error (e.g. malformed baseline)     |
| `3`  | Scanner or runtime error                                       |

Paths are always output relative and sanitized; symlinks and binary files are
skipped; matched secrets are masked, never printed.

## Environment variables

All configuration lives in `backend/.env` (see `backend/.env.example` for the
full template with placeholder values - real secrets are never committed).

| Variable                 | Default                     | Purpose                                   |
|--------------------------|-----------------------------|-------------------------------------------|
| `PORT`                   | `5000`                      | API port                                  |
| `MONGODB_URI`            | `mongodb+srv://...`         | Database connection string                |
| `JWT_SECRET`             | random per boot (dev)       | JWT signing - **required** in production (server fails closed if weak) |
| `JWT_EXPIRES_IN`         | `7d`                        | Token lifetime                            |
| `AI_PROVIDER`            | `none`                      | `none` \| `openrouter` \| `ollama`         |
| `OPENROUTER_API_KEY`     | -                           | OpenRouter API key (cloud AI)             |
| `OPENROUTER_MODEL`       | `meta-llama/llama-3.1-8b-instruct` | Cloud model                       |
| `OLLAMA_BASE_URL`        | `http://localhost:11434`    | Local Ollama endpoint                     |
| `OLLAMA_MODEL`           | `codellama`                 | Local model                                |
| `AI_TIMEOUT_MS` / `AI_MAX_RETRIES` | `30000` / `1`     | AI reliability knobs                       |
| `RATE_LIMIT_*` / `AUTH_RATE_LIMIT_*` | -                 | API + auth rate limits                    |
| `MAX_FILE_SIZE_BYTES`    | `2097152`                   | Upload limit                               |
| `CORS_ORIGIN`            | -                           | Allowed frontend origin (production)       |
| `OSV_API_URL`            | `https://api.osv.dev/...`   | CVE lookup endpoint (no key required)      |

## Development commands & testing

```bash
# Backend
cd backend
npm run dev          # watch mode dev server
npm start            # production start
npm test             # full unit + integration suite (scanner, rules, baseline,
                     # SARIF, CI gate, data flow, copilot, auth, security...)
npm run test:corpus  # scan the built-in vulnerable-code corpus
npm run test:corpus:strict   # corpus with zero-over-claim gate (precision gate)
npm run vulnlens -- scan ./src --format table   # CLI smoke test

# Frontend
cd frontend
npm run dev          # dev server on :3000
npm run build        # production build to frontend/dist
npm run preview      # preview the production build
```

The backend test suite includes a **corpus gate** that fails if the scanner
over-claims on known-clean code, and the CI workflow self-scans `backend/src`
against the committed baseline.

## Demo workflow

Recommended 5-minute demo: **Scan -> Finding -> Source Context -> Data Flow ->
AI Copilot -> Remediation**.

1. **Scan** - open the web app, create a project, and upload a sample project
   folder (or paste vulnerable code). The scan runs the same deterministic
   pipeline the CLI uses and shows severity counts, a 0-100 score, and per-file
   results. (`POST /api/scans/upload` or `POST /api/scans`)
2. **Finding** - open the Findings list; filter by severity and rule. Each
   finding shows rule, severity, confidence, verdict, file, line, evidence, and
   message.
3. **Source Context** - open a finding to see the exact code region in a
   line-numbered source viewer, pulled from the scan's own stored sources
   (`GET /api/scans/:id/source?file=...&around=...`).
4. **Data Flow** - for tainted findings, expand the attack path rendered as
   SOURCE -> propagation -> SINK (e.g. an HTTP request body flowing into an
   eval-like sink). Findings include the correlated function-analysis evidence.
5. **AI Copilot** - click "Explain with Copilot" on the finding
   (`POST /api/ai/explain`). It returns what the vulnerability is, why it
   matters, how it could be exploited, and a secure rewrite. It never
   re-judges the finding.
6. **Remediation** - apply the suggested fix, rescan the same project, and use
   the **comparison** view to confirm the finding moved from "new/remaining" to
   "resolved". Export the report as JSON or SARIF for the record
   (`GET /api/reports/:id/sarif`).

A CLI-only variant works with no database:

```bash
cd backend
node bin/vulnlens.js scan <sample-dir>                     # see the finding
node bin/vulnlens.js scan <sample-dir> --format json       # structured
node bin/vulnlens.js scan <sample-dir> --format sarif --output out.sarif
node bin/vulnlens.js scan <sample-dir> --baseline vulnlens.baseline.json
```

**What VulnLens demonstrates out of the box** - realistic findings for each of
the 8 rule families (hardcoded secrets, SQL injection, XSS, dangerous
functions, weak crypto, misconfiguration, sensitive data, file handling), plus
source-to-sink data-flow paths and OSV dependency advisories. Synthetic
vulnerable-code fixtures live under `backend/tests/security-fixtures/` for
trying the CLI and the web UI on demand.

## CI security gate

`.github/workflows/vulnlens.yml` runs on every pull request and push to `main`:

- Scans `backend/src` with the production CLI, emits **SARIF 2.1.0**, and
  uploads it to **GitHub Code Scanning** (results are never suppressed, even
  when the gate fails).
- Fails the job when a **NEW** (non-baselined) finding meets the threshold
  (`--fail-on`, default `high`). Reviewed self-references are excluded via the
  committed baseline; severity escalations are re-armed by the escalation guard.
- Overridable per repository with a `VULNLENS_FAIL_ON` Actions variable.
- Least-privilege permissions (`contents: read`, `security-events: write`), no
  secrets, SHA-pinned actions, fork-safe (`pull_request`, not
  `pull_request_target`), and baseline immutability checks.

## Documentation

| Topic                                                        | Doc |
|--------------------------------------------------------------|-----|
| Scanner & analysis pipeline internals                        | `backend/docs/SECURITY-ANALYSIS.md` |
| Baseline-aware regression intelligence (NEW/BASELINED/RESOLVED) | `docs/baseline-regression-intelligence.md` |
| CI/CD with GitHub Actions + Code Scanning                    | `docs/ci-cd-github-actions.md` |
| SARIF 2.1.0 reporting                                        | `docs/sarif-reporting.md` |
| Self-scan triage (every finding on `backend/src`)            | `docs/self-scan-triage.md` |
| Source-to-sink data-flow analysis                            | `docs/taint-dataflow.md` |
| AI Security Copilot contract                                 | `docs/ai-copilot.md` |
| Frontend "Security Investigation Cockpit" design             | `docs/ui-redesign.md` |
| Product requirements                                        | `PRD.md` |
| Security hardening review                                    | `SECURITY_HARDENING_REPORT.md` |

## Phase roadmap

- [x] **Phases 1-5** - scanner core (8 rule families, evidence, confidence,
  verdict, risk score), API + auth + projects + scans + reports, AI provider
  abstraction with deterministic fallback, rescan comparison, frontend SPA.
- [x] **Phase 6 (A-E)** - production CLI, SARIF 2.1.0, CI security gate with
  GitHub Code Scanning, self-scan triage + committed baseline,
  baseline-aware regression intelligence, CI hardening (SHA-pinned actions,
  no install scripts, baseline immutability).
- [x] **Phase 7** - targeted source-to-sink data-flow analysis with flow-path
  evidence.
- [x] **Phase 8** - AI Security Copilot for finding explanation & remediation.
- [x] **UI/UX** - "Security Investigation Cockpit" redesign (source viewer,
  data-flow graph, copilot panel).

## Limitations

- **Deterministic heuristics, not proofs.** Rules can produce false positives
  and false negatives. The corpus gate keeps over-claims at zero on the built-in
  corpus, but VulnLens is a triage aid, not a replacement for manual security
  review or for standards compliance.
- **Depth varies by language.** AST-based analysis is strongest for
  JavaScript/TypeScript; other supported languages rely on pattern and
  lightweight analysis.
- **AI is advisory only.** LLM explanations can be wrong; they never affect the
  finding set, severity, score, or gate.
- **Scope of CI scan.** The CI workflow scans first-party `backend/src`; the
  scanner does not descend into `node_modules` by design.
- **Not a compliance tool.** No CWE/OWASP certification, no SLA, no warranty.

## Project context

VulnLens is a phased, full-stack security engineering project (product
requirements: `PRD.md`): build a deterministic scanner, wrap it in a real web
product with auth and reporting, then make it trustworthy enough to gate CI -
ending with AI that helps developers act on findings instead of second-guessing
them. It was built to demonstrate the complete arc of a security product,
including self-hosting its own scanner as a CI gate.

## AI tools disclosure

- **In-product AI:** the optional AI Copilot calls external LLM providers
  (OpenRouter or a local Ollama) **only after** a deterministic finding exists,
  to explain it and suggest remediation. When `AI_PROVIDER=none`, no external AI
  is used at all. The scanner, verdicts, severities, scores, baselines, and CI
  gate never depend on AI.
- **AI-assisted development:** portions of this project were developed with
  AI-assisted coding tools. All code was reviewed, and security behavior is
  covered by automated tests and the self-scan CI gate.

## License

MIT - see [LICENSE](LICENSE).
